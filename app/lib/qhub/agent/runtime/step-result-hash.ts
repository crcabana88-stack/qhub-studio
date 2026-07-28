/**
 * QHUB Agent Framework — Canonical STEP RESULT HASH (PURE)
 * app/lib/qhub/agent/runtime/step-result-hash.ts
 *
 * Computes `result_hash` for a finalized run step from a FIXED, versioned set of
 * authoritative fields. The hash binds tenant/app/agent/version/release identity,
 * run + runtime-provider identity, the step's governed decision and evidence, the
 * Gate 04 evaluation identity (action request, digest, policy/plan versions +
 * hashes), the receipt reference, the canonical safe result, and the prior step's
 * hash — so changing ANY material field changes the hash, and no step can be
 * transplanted across runs, agents, versions, or releases.
 *
 * The encoding is length-prefixed and null-distinguishing (see `cell`): every
 * field is `<utf8-byte-length>:<value>;`, or `-1:;` for null. This is unambiguous
 * without a trusted separator, so the SQL half
 * (qhub_agent_step_result_hash / qhub_compute_agent_step_result_hash in
 * 20260728_agent_run_step_result_continuity.sql) reproduces the identical bytes
 * and therefore the identical SHA-256. app/test/agent-step-result-hash.test.ts
 * pins TS↔SQL parity and per-field sensitivity with shared fixtures.
 *
 * The database — never a caller — computes the authoritative result_hash. This
 * module exists so the runtime and the executable parity fixtures can reproduce
 * and verify it; it is NOT a trusted input to the RPC.
 */

import { createHash } from 'node:crypto';
import { cell, canonicalSafeResult, type SafeResult } from './safe-result';

/** Fixed canonical-payload version. Bound as the first field of the preimage. */
export const RESULT_HASH_SCHEMA_VERSION = 'agent-step-result-1.0.0';

const sha256Hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** Decimal text for an integer field, or null. */
function intCell(v: number | null): string {
  return cell(v === null ? null : String(v));
}

/**
 * Every authoritative field of the canonical step-result payload. Ids/hashes are
 * text; versions and step_index are integers; evaluation-derived fields are null
 * for a step with no Gate 04 evaluation; safe_result is the validated safe result
 * (or null before finalization).
 */
export interface StepResultHashInput {
  // Tenant / app / agent / version / release identity (from the run + version).
  org_id: string;
  qhub_app_id: string;
  agent_id: string;
  agent_version_id: string;
  release_candidate_id: string | null;
  release_candidate_hash: string | null;
  manifest_hash: string;

  // Run + runtime-provider identity (from the run).
  run_id: string;
  runtime_provider_id: string;
  runtime_provider_version: string;

  // The step's governed evidence.
  step_index: number;
  step_kind: string;
  action_type: string | null;
  input_hash: string | null;
  decision: string;
  evaluation_id: string | null;

  // Gate 04 evaluation identity (from qhub_control_evaluations; null when none).
  action_request_id: string | null;
  action_digest: string | null;
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string | null;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string | null;

  // Execution + continuity.
  receipt_id: string | null;
  safe_result: SafeResult | null;
  previous_step_hash: string | null;
}

/**
 * The exact canonical preimage (UTF-8 text) hashed to produce result_hash. Every
 * field appears once, in this fixed order. Exposed for parity fixtures.
 */
export function canonicalStepResultString(f: StepResultHashInput): string {
  return (
    cell(RESULT_HASH_SCHEMA_VERSION) +
    cell(f.org_id) +
    cell(f.qhub_app_id) +
    cell(f.agent_id) +
    cell(f.agent_version_id) +
    cell(f.release_candidate_id) +
    cell(f.release_candidate_hash) +
    cell(f.manifest_hash) +
    cell(f.run_id) +
    cell(f.runtime_provider_id) +
    cell(f.runtime_provider_version) +
    intCell(f.step_index) +
    cell(f.step_kind) +
    cell(f.action_type) +
    cell(f.input_hash) +
    cell(f.decision) +
    cell(f.evaluation_id) +
    cell(f.action_request_id) +
    cell(f.action_digest) +
    cell(f.policy_profile_id) +
    intCell(f.policy_profile_version) +
    cell(f.policy_profile_hash) +
    cell(f.enforcement_plan_id) +
    intCell(f.enforcement_plan_version) +
    cell(f.enforcement_plan_hash) +
    cell(f.receipt_id) +
    cell(f.safe_result === null ? null : canonicalSafeResult(f.safe_result)) +
    cell(f.previous_step_hash)
  );
}

/** Compute the canonical result_hash (hex SHA-256). Mirrors the SQL function. */
export function computeStepResultHash(f: StepResultHashInput): string {
  return sha256Hex(canonicalStepResultString(f));
}
