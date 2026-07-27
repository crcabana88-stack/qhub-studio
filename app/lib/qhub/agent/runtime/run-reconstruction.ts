/**
 * QHUB Agent Framework — No-replay run reconstruction guard (PURE)
 * app/lib/qhub/agent/runtime/run-reconstruction.ts
 *
 * Recovery on start / resume / restart must NEVER re-execute a completed
 * consequential node (model call, Gate 04 submission, approval, connector,
 * adapter, or receipt) merely to rebuild state. Instead, the authoritative QHub
 * run-step records are folded back into structured graph state, and execution
 * begins only at the next permitted node.
 *
 * This module is provider-neutral and dependency-free. It:
 *   1. reconstructs the ordered governed results from stored run steps;
 *   2. proves the reconstruction is faithful (contiguous, decision-consistent);
 *   3. fails closed on a tampered prior result (input-hash mismatch) or a missing
 *      prior step, rather than replaying consequential work to "repair" state.
 */

import type { GovernedActionResult } from './provider';
import type { RunActionDecision } from '~/lib/qhub/agent/agent-run';

/** The subset of a durable run-step record needed to rebuild state safely. */
export interface StoredRunStep {
  step_index: number;
  action_type: string | null;
  decision: RunActionDecision | null;
  reason_codes: string[];
  receipt_id: string | null;

  /** sha256(stableStringify(material_parameters)) recorded at execution time. */
  input_hash: string | null;
}

export type ReconstructionReason =
  | 'NON_CONTIGUOUS_STEPS'
  | 'MISSING_PRIOR_STEP'
  | 'PRIOR_RESULT_TAMPERED'
  | 'INCONSISTENT_DECISION';

export type RunTerminal = 'NONE' | 'DENIED' | 'AWAITING_APPROVAL';

export interface ReconstructionResult {
  ok: boolean;
  reason?: ReconstructionReason;

  /** Governed results of the executed steps, in order (empty when !ok). */
  prior_results: GovernedActionResult[];

  /** The next node/step the run may execute (the pause index when awaiting). */
  next_step_index: number;

  terminal: RunTerminal;
}

const EXECUTED: ReadonlySet<RunActionDecision> = new Set<RunActionDecision>(['ALLOW', 'SIMULATED', 'EXECUTED']);

function fail(reason: ReconstructionReason): ReconstructionResult {
  // Fail closed: no usable prior_results, no forward progress.
  return { ok: false, reason, prior_results: [], next_step_index: 0, terminal: 'NONE' };
}

/**
 * Reconstruct run state from the authoritative stored steps WITHOUT re-executing
 * any node. `expectedInputHash` maps a step_index to the input hash a faithful,
 * deterministic re-derivation of that step would produce; a mismatch means the
 * stored evidence was tampered with and we fail closed instead of replaying.
 *
 * A `null` expected hash for an index means "no expectation available" (the
 * caller could not re-derive it) and is treated as unverifiable → fail closed
 * for any consequential (executed) step, so we never trust unverifiable evidence.
 */
export function reconstructRunState(
  steps: StoredRunStep[],
  expectedInputHash: (stepIndex: number) => string | null,
): ReconstructionResult {
  const ordered = [...steps].sort((a, b) => a.step_index - b.step_index);

  // Contiguity from 0 — a gap means a prior step is missing from evidence.
  for (let i = 0; i < ordered.length; i++) {
    if (ordered[i].step_index !== i) {
      return fail(i < ordered.length && ordered[i].step_index > i ? 'MISSING_PRIOR_STEP' : 'NON_CONTIGUOUS_STEPS');
    }
  }

  const prior: GovernedActionResult[] = [];

  for (const step of ordered) {
    const decision = step.decision;

    if (!decision) {
      return fail('INCONSISTENT_DECISION');
    }

    // Tamper / unverifiable-evidence check for every executed (side-effecting) step.
    if (EXECUTED.has(decision)) {
      const expected = expectedInputHash(step.step_index);

      if (expected === null || step.input_hash === null || step.input_hash !== expected) {
        return fail('PRIOR_RESULT_TAMPERED');
      }

      prior.push({
        decision,
        reason_codes: step.reason_codes ?? [],
        receipt_id: step.receipt_id,
        safe_result: step.receipt_id ? { execution_status: 'RECONSTRUCTED' } : null,
      });
      continue;
    }

    if (decision === 'DENY') {
      // A denied step is terminal; nothing after it may have executed.
      return { ok: true, prior_results: prior, next_step_index: step.step_index, terminal: 'DENIED' };
    }

    if (decision === 'REQUIRE_APPROVAL') {
      /*
       * The pause point: resume executes THIS step exactly once (as E2). The
       * consequential node has not run, so there is nothing to replay.
       */
      return { ok: true, prior_results: prior, next_step_index: step.step_index, terminal: 'AWAITING_APPROVAL' };
    }

    return fail('INCONSISTENT_DECISION');
  }

  // All recorded steps executed cleanly; the next node is the one after the last.
  return { ok: true, prior_results: prior, next_step_index: ordered.length, terminal: 'NONE' };
}
