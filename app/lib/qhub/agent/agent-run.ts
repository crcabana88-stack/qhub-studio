/**
 * QHUB Agent Framework Foundation — Canonical Agent Run model (PURE)
 * app/lib/qhub/agent/agent-run.ts
 *
 * A run is one supervised execution of a governed agent. Evidence stores hashes,
 * safe summaries, structured decisions, and receipt references — NEVER raw
 * prompts, chain-of-thought, credentials, or sensitive data.
 */

import type { AgentOperatingMode } from './agent-manifest';
import type { GovernedActionType } from '~/lib/qhub/enforcement';

export type AgentRunState =
  | 'CREATED'
  | 'RUNNING'
  | 'AWAITING_APPROVAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'SUSPENDED';

export const RUN_MODEL_VERSION = 'agent-run-1.0.0';

/** A structured decision for one proposed action within a run (safe metadata only). */
export type RunActionDecision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'SIMULATED' | 'EXECUTED';

export interface AgentRunStep {
  step_index: number;
  step_kind: 'MODEL_INVOCATION' | 'TOOL_ACTION' | 'CONNECTOR_ACTION' | 'ANALYSIS' | 'PROPOSAL';
  action_type: GovernedActionType | null;

  /** Gate 04 evaluation id for this step's governed action, if any. */
  evaluation_id: string | null;
  decision: RunActionDecision | null;
  reason_codes: string[];
  receipt_id: string | null;

  /** Hash of the step's material input (never the raw content). */
  input_hash: string | null;

  /** Short, safe summary — no chain-of-thought, no sensitive data. */
  summary: string;
  created_at: string;
}

export interface AgentRun {
  run_id: string;
  agent_id: string;
  agent_version_id: string;
  release_candidate_id: string | null;
  release_candidate_hash: string | null;
  org_id: string;
  qhub_app_id: string;
  initiating_user_id: string;
  operating_mode: AgentOperatingMode;
  runtime_provider: string;
  runtime_provider_version: string;
  current_state: AgentRunState;
  current_step: number;
  policy_profile_hash: string;
  enforcement_plan_hash: string;
  primary_model: string;
  input_hash: string;
  output_hash: string | null;
  proposed_action_count: number;
  approved_action_count: number;
  denied_action_count: number;

  /** Idempotency key — one run per (agent_version, key); replays return the same run. */
  idempotency_key: string;
  error_reference: string | null;
  started_at: string;
  completed_at: string | null;
  run_hash: string;
}

/** Canonical preimage for `run_hash`. Excludes mutable counters/state/timestamps. */
export function canonicalRunString(
  r: Pick<
    AgentRun,
    | 'agent_id'
    | 'agent_version_id'
    | 'release_candidate_hash'
    | 'org_id'
    | 'qhub_app_id'
    | 'initiating_user_id'
    | 'operating_mode'
    | 'runtime_provider'
    | 'runtime_provider_version'
    | 'policy_profile_hash'
    | 'enforcement_plan_hash'
    | 'primary_model'
    | 'input_hash'
    | 'idempotency_key'
  >,
): string {
  return JSON.stringify({
    run_model_version: RUN_MODEL_VERSION,
    agent_id: r.agent_id,
    agent_version_id: r.agent_version_id,
    release_candidate_hash: r.release_candidate_hash,
    org_id: r.org_id,
    qhub_app_id: r.qhub_app_id,
    initiating_user_id: r.initiating_user_id,
    operating_mode: r.operating_mode,
    runtime_provider: r.runtime_provider,
    runtime_provider_version: r.runtime_provider_version,
    policy_profile_hash: r.policy_profile_hash,
    enforcement_plan_hash: r.enforcement_plan_hash,
    primary_model: r.primary_model,
    input_hash: r.input_hash,
    idempotency_key: r.idempotency_key,
  });
}
