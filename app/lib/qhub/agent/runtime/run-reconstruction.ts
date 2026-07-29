/**
 * QHUB Agent Framework — No-replay run reconstruction guard (PRODUCTION, PURE)
 * app/lib/qhub/agent/runtime/run-reconstruction.ts
 *
 * The SINGLE provider-neutral component used by production `resumeAgentRun` AND by
 * tests to recover a paused run WITHOUT re-executing any completed consequential
 * node. Recovery folds the authoritative durable run-step records back into
 * structured state; execution begins only at the next permitted node.
 *
 * `reconstructForResume` re-DERIVES each step's canonical proposed action by
 * calling the provider's pure `step()` (which only PROPOSES — it never invokes a
 * model, submits to Gate 04, runs a tool/connector, or writes a receipt) and
 * verifies the re-derived action's input hash against the stored evidence. It
 * fails closed on any ownership, continuity, tamper, or binding mismatch, so no
 * provider step, Gate 04 request, approval consumption, adapter run, receipt, or
 * partial persistence can follow a bad reconstruction.
 */

import { createHash } from 'node:crypto';
import type { AgentRuntimeProvider, GovernedActionResult, ProposedAction } from './provider';
import type { RunActionDecision } from '~/lib/qhub/agent/agent-run';
import { canonicalActionRequestString } from '~/lib/qhub/enforcement-plan';
import type { CanonicalActionRequest } from '~/lib/qhub/enforcement';
import { computeStepResultHash, type StepResultHashInput } from './step-result-hash';
import type { SafeResult } from './safe-result';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/** Deterministic, order-independent stringify used for content hashes. */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') {
    return JSON.stringify(v);
  }

  if (Array.isArray(v)) {
    return `[${v.map(stableStringify).join(',')}]`;
  }

  const keys = Object.keys(v as Record<string, unknown>).sort();

  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((v as Record<string, unknown>)[k])}`).join(',')}}`;
}

/** Canonical input hash of a proposed action — MUST match the orchestrator's. */
export function inputHashOf(action: ProposedAction): string {
  return sha256(stableStringify(action.material_parameters ?? null));
}

/** The durable run-step fields needed to rebuild state safely (evidence only). */
export interface StoredRunStep {
  run_id: string;
  org_id: string;
  step_index: number;
  step_kind: string;
  action_type: string | null;
  decision: RunActionDecision | null;
  reason_codes: string[];
  receipt_id: string | null;

  /** sha256(stableStringify(material_parameters)) recorded at execution time. */
  input_hash: string | null;
  evaluation_id: string | null;

  /** Server-computed canonical result hash (NULL only for legacy/pending rows). */
  result_hash: string | null;

  /** Persisted, server-owned safe result (NULL only for legacy/pending rows). */
  safe_result: Record<string, unknown> | null;

  /** result_hash of the immediately preceding finalized step (NULL at step 0). */
  previous_step_hash: string | null;
}

const EXECUTED: ReadonlySet<RunActionDecision> = new Set<RunActionDecision>(['ALLOW', 'SIMULATED', 'EXECUTED']);

/**
 * Rebuild a governed result from a PERSISTED, finalized executed step — using the
 * stored server-owned safe_result (never a RECONSTRUCTED placeholder). Only call
 * after `executedContinuityReason` has confirmed the step is finalized + linked.
 */
function executedResult(step: StoredRunStep): GovernedActionResult {
  return {
    decision: step.decision as RunActionDecision,
    reason_codes: step.reason_codes ?? [],
    receipt_id: step.receipt_id,
    safe_result: step.safe_result,
  };
}

/**
 * Fail-closed continuity check for one already-executed step, given the result
 * hash of the immediately preceding executed step (`prevHash`, NULL before the
 * first). A legacy row (NULL continuity) is NON-resumable; a broken previous-step
 * link is a tamper/transplant signal. Returns null when the step is sound.
 */
function executedContinuityReason(
  step: StoredRunStep,
  prevHash: string | null,
): 'NON_RESUMABLE_LEGACY_CONTINUITY' | 'CONTINUITY_CHAIN_BROKEN' | null {
  if (step.result_hash === null || step.safe_result === null) {
    return 'NON_RESUMABLE_LEGACY_CONTINUITY';
  }

  const expectedPrev = step.step_index === 0 ? null : prevHash;

  if ((step.previous_step_hash ?? null) !== expectedPrev) {
    return 'CONTINUITY_CHAIN_BROKEN';
  }

  return null;
}

/*
 * --------------------------------------------------------------------------
 * Full result-hash recomputation from CURRENT authoritative data (Blocker H)
 * --------------------------------------------------------------------------
 */

/** Authoritative run + version identity needed to recompute a step result hash. */
export interface ResultHashRecomputeRun {
  run_id: string;
  org_id: string;
  qhub_app_id: string;
  agent_id: string;
  agent_version_id: string;
  release_candidate_id: string | null;
  release_candidate_hash: string | null;
  manifest_hash: string;
  runtime_provider_id: string;
  runtime_provider_version: string;
}

/** The authoritative Gate 04 evaluation fields bound into a step's result hash. */
export interface StoredEvaluationForHash {
  evaluation_id: string;
  action_request_id: string | null;
  action_digest: string | null;
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string | null;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string | null;
}

export type ResultHashVerifyReason =
  | 'NON_RESUMABLE_LEGACY_CONTINUITY'
  | 'MISSING_EVALUATION_FOR_HASH'
  | 'RESULT_HASH_MISMATCH';

export interface ResultHashVerifyResult {
  ok: boolean;
  reason?: ResultHashVerifyReason;
  step_index?: number;
}

/**
 * Recompute every FINALIZED step's result_hash from CURRENT authoritative run/
 * version/evaluation data and compare it to the stored value. Detects drift in
 * any hash-bound authoritative record and any stored-hash tampering. Fails closed
 * on a legacy row, a missing evaluation, or a mismatch. The database independently
 * recomputes on write; this is the runtime's pre-Gate-04 defense in depth.
 */
export function verifyStoredResultHashes(
  run: ResultHashRecomputeRun,
  steps: StoredRunStep[],
  evaluationById: Map<string, StoredEvaluationForHash>,
): ResultHashVerifyResult {
  const ordered = [...steps].sort((a, b) => a.step_index - b.step_index);

  for (const step of ordered) {
    if (step.result_hash === null) {
      continue; // pending (REQUIRE_APPROVAL) rows carry no continuity yet
    }

    if (step.safe_result === null) {
      return { ok: false, reason: 'NON_RESUMABLE_LEGACY_CONTINUITY', step_index: step.step_index };
    }

    const ev = step.evaluation_id ? evaluationById.get(step.evaluation_id) : undefined;

    if (step.evaluation_id && !ev) {
      return { ok: false, reason: 'MISSING_EVALUATION_FOR_HASH', step_index: step.step_index };
    }

    const input: StepResultHashInput = {
      org_id: run.org_id,
      qhub_app_id: run.qhub_app_id,
      agent_id: run.agent_id,
      agent_version_id: run.agent_version_id,
      release_candidate_id: run.release_candidate_id,
      release_candidate_hash: run.release_candidate_hash,
      manifest_hash: run.manifest_hash,
      run_id: run.run_id,
      runtime_provider_id: run.runtime_provider_id,
      runtime_provider_version: run.runtime_provider_version,
      step_index: step.step_index,
      step_kind: step.step_kind,
      action_type: step.action_type,
      input_hash: step.input_hash,
      decision: step.decision as string,
      evaluation_id: step.evaluation_id,
      action_request_id: ev?.action_request_id ?? null,
      action_digest: ev?.action_digest ?? null,
      policy_profile_id: ev?.policy_profile_id ?? null,
      policy_profile_version: ev?.policy_profile_version ?? null,
      policy_profile_hash: ev?.policy_profile_hash ?? null,
      enforcement_plan_id: ev?.enforcement_plan_id ?? null,
      enforcement_plan_version: ev?.enforcement_plan_version ?? null,
      enforcement_plan_hash: ev?.enforcement_plan_hash ?? null,
      receipt_id: step.receipt_id,
      safe_result: step.safe_result as unknown as SafeResult,
      previous_step_hash: step.previous_step_hash,
    };

    if (computeStepResultHash(input) !== step.result_hash) {
      return { ok: false, reason: 'RESULT_HASH_MISMATCH', step_index: step.step_index };
    }
  }

  return { ok: true };
}

/*
 * --------------------------------------------------------------------------
 * Structural reconstruction (decision-history level)
 * --------------------------------------------------------------------------
 */

export type ReconstructionReason =
  | 'NON_CONTIGUOUS_STEPS'
  | 'MISSING_PRIOR_STEP'
  | 'PRIOR_RESULT_TAMPERED'
  | 'NON_RESUMABLE_LEGACY_CONTINUITY'
  | 'CONTINUITY_CHAIN_BROKEN'
  | 'INCONSISTENT_DECISION';

export type RunTerminal = 'NONE' | 'DENIED' | 'AWAITING_APPROVAL';

export interface ReconstructionResult {
  ok: boolean;
  reason?: ReconstructionReason;
  prior_results: GovernedActionResult[];
  next_step_index: number;
  terminal: RunTerminal;
}

function fail(reason: ReconstructionReason): ReconstructionResult {
  return { ok: false, reason, prior_results: [], next_step_index: 0, terminal: 'NONE' };
}

/**
 * Fold stored steps into ordered governed results WITHOUT re-executing anything.
 * `expectedInputHash` gives the input hash a faithful re-derivation of a step
 * would produce; a mismatch (or an unverifiable executed step) fails closed.
 */
export function reconstructRunState(
  steps: StoredRunStep[],
  expectedInputHash: (stepIndex: number) => string | null,
): ReconstructionResult {
  const ordered = [...steps].sort((a, b) => a.step_index - b.step_index);

  for (let i = 0; i < ordered.length; i++) {
    if (ordered[i].step_index !== i) {
      return fail(ordered[i].step_index > i ? 'MISSING_PRIOR_STEP' : 'NON_CONTIGUOUS_STEPS');
    }
  }

  const prior: GovernedActionResult[] = [];
  let prevHash: string | null = null;

  for (const step of ordered) {
    const decision = step.decision;

    if (!decision) {
      return fail('INCONSISTENT_DECISION');
    }

    if (EXECUTED.has(decision)) {
      const expected = expectedInputHash(step.step_index);

      if (expected === null || step.input_hash === null || step.input_hash !== expected) {
        return fail('PRIOR_RESULT_TAMPERED');
      }

      const continuity = executedContinuityReason(step, prevHash);

      if (continuity) {
        return fail(continuity);
      }

      prior.push(executedResult(step));
      prevHash = step.result_hash;
      continue;
    }

    if (decision === 'DENY') {
      return { ok: true, prior_results: prior, next_step_index: step.step_index, terminal: 'DENIED' };
    }

    if (decision === 'REQUIRE_APPROVAL') {
      return { ok: true, prior_results: prior, next_step_index: step.step_index, terminal: 'AWAITING_APPROVAL' };
    }

    return fail('INCONSISTENT_DECISION');
  }

  return { ok: true, prior_results: prior, next_step_index: ordered.length, terminal: 'NONE' };
}

/*
 * --------------------------------------------------------------------------
 * Production resume reconstruction (provider-neutral, re-derives via step())
 * --------------------------------------------------------------------------
 */

/** Authoritative run identity — every field comes from the durable run row. */
export interface RunIdentity {
  run_id: string;
  org_id: string;
  agent_id: string;
  agent_version_id: string;
  release_candidate_hash: string | null;
  qhub_app_id: string;
  current_state: string;
  current_step: number;
  pending_evaluation_id: string | null;
}

export type ResumeReconstructionReason =
  | 'RUN_NOT_RESUMABLE'
  | 'PENDING_EVALUATION_MISMATCH'
  | 'STEP_OWNERSHIP_MISMATCH'
  | 'NON_CONTIGUOUS_STEPS'
  | 'MISSING_PRIOR_STEP'
  | 'PRIOR_RESULT_TAMPERED'
  | 'NON_RESUMABLE_LEGACY_CONTINUITY'
  | 'CONTINUITY_CHAIN_BROKEN'
  | 'INCONSISTENT_DECISION'
  | 'PAUSED_STEP_MISMATCH'
  | 'PAUSED_STEP_NOT_PENDING'
  | 'PAUSED_ACTION_HASH_MISMATCH'
  | 'DUPLICATE_TERMINAL_RECEIPT'
  | 'PROVIDER_REPROPOSE_FAILED';

export interface ResumeReconstruction {
  ok: boolean;
  reason?: ResumeReconstructionReason;

  /** Governed results of the already-executed prior steps, in order. */
  prior_results: GovernedActionResult[];

  /** The pause step index (= run.current_step). */
  pause_index: number;

  /**
   * The exact canonical action to resume, re-derived by the provider and proven
   * (by input-hash equality) to match the persisted paused step. The orchestrator
   * submits THIS as the E2 action; it never invents a materially different one.
   */
  paused_action?: ProposedAction;
}

function resumeFail(reason: ResumeReconstructionReason): ResumeReconstruction {
  return { ok: false, reason, prior_results: [], pause_index: 0 };
}

/**
 * Reconstruct a paused run for resume. Validates state, pending-evaluation
 * binding, per-step tenant/run ownership, contiguity, stored-result continuity,
 * and the paused step's exact action/approval binding — re-deriving each proposed
 * action via the provider's pure `step()` (no execution). Fails closed on any
 * mismatch. On success, returns the reconstructed prior results and the exact
 * paused action to resume from.
 */
export async function reconstructForResume(params: {
  provider: AgentRuntimeProvider;
  run: RunIdentity;
  steps: StoredRunStep[];
  approvedEvaluationId: string;
}): Promise<ResumeReconstruction> {
  const { provider, run, steps, approvedEvaluationId } = params;

  if (run.current_state !== 'AWAITING_APPROVAL') {
    return resumeFail('RUN_NOT_RESUMABLE');
  }

  if (!run.pending_evaluation_id || run.pending_evaluation_id !== approvedEvaluationId) {
    return resumeFail('PENDING_EVALUATION_MISMATCH');
  }

  // Per-step ownership: every step must belong to this exact run + tenant.
  for (const s of steps) {
    if (s.run_id !== run.run_id || s.org_id !== run.org_id) {
      return resumeFail('STEP_OWNERSHIP_MISMATCH');
    }
  }

  const ordered = [...steps].sort((a, b) => a.step_index - b.step_index);
  const pauseIndex = run.current_step;

  // Contiguity: steps must be exactly 0..pauseIndex.
  for (let i = 0; i < ordered.length; i++) {
    if (ordered[i].step_index !== i) {
      return resumeFail(ordered[i].step_index > i ? 'MISSING_PRIOR_STEP' : 'NON_CONTIGUOUS_STEPS');
    }
  }

  if (ordered.length !== pauseIndex + 1) {
    // A step after the pause (already executed) or a missing pause step.
    return ordered.length > pauseIndex + 1
      ? resumeFail('DUPLICATE_TERMINAL_RECEIPT')
      : resumeFail('MISSING_PRIOR_STEP');
  }

  const priorResults: GovernedActionResult[] = [];
  let prevHash: string | null = null;

  for (let i = 0; i <= pauseIndex; i++) {
    const stored = ordered[i];

    // Pure re-derivation: step() only PROPOSES. No model/Gate04/tool/receipt.
    const out = await provider.step({ step_index: i, prior_results: priorResults });

    if (out.kind !== 'PROPOSE' || !out.proposed_actions || out.proposed_actions.length === 0) {
      return resumeFail('PROVIDER_REPROPOSE_FAILED');
    }

    const rederivedHash = inputHashOf(out.proposed_actions[0]);

    if (i < pauseIndex) {
      if (!stored.decision || !EXECUTED.has(stored.decision)) {
        return resumeFail('INCONSISTENT_DECISION');
      }

      if (stored.input_hash === null || stored.input_hash !== rederivedHash) {
        return resumeFail('PRIOR_RESULT_TAMPERED');
      }

      /*
       * Persisted continuity: legacy rows are non-resumable; a broken previous-step
       * link is a tamper/transplant signal. Uses the PERSISTED safe_result.
       */
      const continuity = executedContinuityReason(stored, prevHash);

      if (continuity) {
        return resumeFail(continuity);
      }

      priorResults.push(executedResult(stored));
      prevHash = stored.result_hash;
      continue;
    }

    // The pause step: must be pending approval for the exact approved evaluation.
    if (stored.decision !== 'REQUIRE_APPROVAL') {
      return resumeFail('PAUSED_STEP_NOT_PENDING');
    }

    if (stored.evaluation_id !== approvedEvaluationId) {
      return resumeFail('PAUSED_STEP_MISMATCH');
    }

    if (stored.receipt_id) {
      return resumeFail('DUPLICATE_TERMINAL_RECEIPT');
    }

    if (stored.input_hash === null || stored.input_hash !== rederivedHash) {
      return resumeFail('PAUSED_ACTION_HASH_MISMATCH');
    }

    return { ok: true, prior_results: priorResults, pause_index: pauseIndex, paused_action: out.proposed_actions[0] };
  }

  // Unreachable given ordered.length === pauseIndex + 1, but fail closed.
  return resumeFail('MISSING_PRIOR_STEP');
}

/*
 * --------------------------------------------------------------------------
 * Complete paused-action binding verification (pre-Gate-04)
 * --------------------------------------------------------------------------
 */

/** The authoritative Gate 04 evaluation persisted for the paused step. */
export interface PersistedEvaluation {
  evaluation_id: string;
  action_request_id: string | null;
  action_digest: string;
  decision: string;
  org_id: string;
  qhub_app_id: string;
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string;
}

/** Run-row identity fields required to verify the complete binding. */
export interface ResumeBindingRun {
  org_id: string;
  qhub_app_id: string;
  run_id: string;
  agent_id: string;
  agent_version_id: string;
  release_candidate_hash: string | null;
  runtime_provider: string;
  runtime_provider_version: string;
  policy_profile_hash: string;
  enforcement_plan_hash: string;
}

/** Version-row identity fields (from getAgentVersion). */
export interface ResumeBindingVersion {
  agent_version_id: string;
  manifest_hash: string;
  execution_environment: string;
  release_candidate_hash: string | null;
}

export type BindingReason =
  | 'EVALUATION_NOT_PENDING'
  | 'EVALUATION_MISMATCH'
  | 'MISSING_ACTION_REQUEST_ID'
  | 'EVALUATION_TENANT_APP_MISMATCH'
  | 'RUN_VERSION_MISMATCH'
  | 'POLICY_PROFILE_MISMATCH'
  | 'ENFORCEMENT_PLAN_MISMATCH'
  | 'PROVIDER_IDENTITY_MISMATCH'
  | 'RELEASE_HASH_MISMATCH'
  | 'ACTION_DIGEST_MISMATCH';

function mapEnvironment(target: string): 'PREVIEW' | 'INTERNAL' | 'PRODUCTION' {
  if (target === 'PRODUCTION') {
    return 'PRODUCTION';
  }

  if (target === 'STAGING') {
    return 'INTERNAL';
  }

  return 'PREVIEW';
}

/**
 * Verify the COMPLETE paused-action authorization identity against the persisted,
 * server-owned Gate 04 evaluation (loaded via the paused step's evaluation_id) and
 * the run/version rows — BEFORE any E2 Gate 04 submission. The persisted
 * `action_digest` is the canonical anchor: the re-derived action's digest,
 * recomputed the exact Gate 04 way from the persisted policy/plan the evaluation
 * was scoped to, MUST equal it. Any mismatch fails closed (the caller performs no
 * Gate 04 submission, approval consumption, adapter run, or receipt).
 */
export function verifyPausedActionBinding(params: {
  run: ResumeBindingRun;
  version: ResumeBindingVersion;
  provider: { provider_id: string; provider_version: string };
  evaluation: PersistedEvaluation;
  pausedAction: ProposedAction;
  approvedEvaluationId: string;
  conversationId: string;
}): { ok: boolean; reason?: BindingReason; recomputed_action_digest?: string } {
  const { run, version, provider, evaluation, pausedAction, approvedEvaluationId, conversationId } = params;

  if (evaluation.decision !== 'REQUIRE_APPROVAL') {
    return { ok: false, reason: 'EVALUATION_NOT_PENDING' };
  }

  if (evaluation.evaluation_id !== approvedEvaluationId) {
    return { ok: false, reason: 'EVALUATION_MISMATCH' };
  }

  if (!evaluation.action_request_id) {
    return { ok: false, reason: 'MISSING_ACTION_REQUEST_ID' };
  }

  if (evaluation.org_id !== run.org_id || evaluation.qhub_app_id !== run.qhub_app_id) {
    return { ok: false, reason: 'EVALUATION_TENANT_APP_MISMATCH' };
  }

  if (version.agent_version_id !== run.agent_version_id) {
    return { ok: false, reason: 'RUN_VERSION_MISMATCH' };
  }

  if (evaluation.policy_profile_hash !== run.policy_profile_hash) {
    return { ok: false, reason: 'POLICY_PROFILE_MISMATCH' };
  }

  if (evaluation.enforcement_plan_hash !== run.enforcement_plan_hash) {
    return { ok: false, reason: 'ENFORCEMENT_PLAN_MISMATCH' };
  }

  if (run.runtime_provider !== provider.provider_id || run.runtime_provider_version !== provider.provider_version) {
    return { ok: false, reason: 'PROVIDER_IDENTITY_MISMATCH' };
  }

  if ((version.release_candidate_hash ?? null) !== (run.release_candidate_hash ?? null)) {
    return { ok: false, reason: 'RELEASE_HASH_MISMATCH' };
  }

  /*
   * Recompute the server-owned canonical action digest from the re-derived action
   * + the persisted policy/plan the evaluation was scoped to. Must equal the anchor.
   */
  const request: CanonicalActionRequest = {
    tenant_id: run.org_id,
    qhub_app_id: run.qhub_app_id,
    action_request_id: evaluation.action_request_id, // excluded from the digest
    action_type: pausedAction.action_type,
    target_resource: pausedAction.target_resource,
    operation: pausedAction.operation,
    material_parameters_hash: sha256(stableStringify(pausedAction.material_parameters ?? null)),
    model_identity: pausedAction.model_identity ?? null,
    provider_identity: null,
    tool_identity: null,
    environment: mapEnvironment(version.execution_environment),
    app_version_ref: conversationId,

    // ids are excluded from the digest; versions + hashes bind it.
    policy_profile_id: evaluation.policy_profile_id ?? '',
    policy_profile_version: evaluation.policy_profile_version ?? 0,
    policy_profile_hash: evaluation.policy_profile_hash,
    enforcement_plan_id: evaluation.enforcement_plan_id ?? '',
    enforcement_plan_version: evaluation.enforcement_plan_version ?? 0,
    enforcement_plan_hash: evaluation.enforcement_plan_hash,
  };
  const recomputed = sha256(canonicalActionRequestString(request));

  if (recomputed !== evaluation.action_digest) {
    return { ok: false, reason: 'ACTION_DIGEST_MISMATCH', recomputed_action_digest: recomputed };
  }

  return { ok: true, recomputed_action_digest: recomputed };
}
