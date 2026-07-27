/**
 * QHUB Agent Framework Foundation — Runtime provider interface (PURE contract)
 * app/lib/qhub/agent/runtime/provider.ts
 *
 * A replaceable boundary between QHUB governance and any agent reasoning engine
 * (local mock now; ADK / LangGraph / internal runtime later). The provider ONLY
 * proposes actions and receives GOVERNED results — it never receives credentials,
 * unrestricted connector clients, or a direct execution path, so it structurally
 * cannot bypass Gate 04. QHUB owns identity, manifest, permissions, policy,
 * enforcement, approvals, lifecycle, evidence, and provider selection.
 */

import type { AgentManifest } from '~/lib/qhub/agent/agent-manifest';
import type { GovernedActionType } from '~/lib/qhub/enforcement';

/** Safe, read-only manifest projection given to a provider (no hashes to forge with). */
export interface RuntimeManifestView {
  agent_id: string;
  agent_version_id: string;
  operating_mode: AgentManifest['operating_mode'];
  autonomy_level: AgentManifest['autonomy_level'];
  primary_model: string;
  approved_models: string[];
  approved_tool_ids: string[];
  approved_connector_ids: string[];
  goal_definition: string;
  execution_environment: AgentManifest['execution_environment'];
}

/** An action the provider wants QHUB to govern. The provider cannot execute it. */
export interface ProposedAction {
  step_kind: 'MODEL_INVOCATION' | 'TOOL_ACTION' | 'CONNECTOR_ACTION';
  action_type: GovernedActionType;
  target_resource: string;
  operation: string;

  /** Material parameters — hashed server-side, never persisted raw. */
  material_parameters: unknown;
  model_identity?: string | null;

  /** Short, safe summary shown in the run view (no chain-of-thought). */
  summary: string;
}

/** The governed outcome QHUB feeds back to the provider (no secrets, no raw data). */
export interface GovernedActionResult {
  decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'SIMULATED' | 'EXECUTED';
  reason_codes: string[];
  receipt_id: string | null;

  /** Safe, structured result the provider may reason over (e.g. a simulated ack). */
  safe_result: Record<string, unknown> | null;
}

export interface RuntimeInitContext {
  manifest: RuntimeManifestView;

  /** Synthetic/test inputs only in SIMULATION. */
  synthetic_inputs: Record<string, unknown>;
}

export interface RuntimeStepInput {
  /**
   * Zero-based index of the step to execute. Supplied by the orchestrator from
   * durable run state so a provider resumes deterministically after an approval
   * pause that spans requests (the provider holds no cross-request memory).
   */
  step_index: number;

  /** Governed results of the actions proposed in the previous step, in order. */
  prior_results: GovernedActionResult[];
}

export interface RuntimeStepOutput {
  kind: 'PROPOSE' | 'COMPLETE' | 'FAIL';

  /** Actions to be governed by Gate 04 (only when kind === 'PROPOSE'). */
  proposed_actions?: ProposedAction[];

  /** Safe summary of terminal output (COMPLETE) — no sensitive content. */
  output_summary?: string;
  error_reason?: string;
}

export interface AgentRuntimeProvider {
  readonly provider_id: string;
  readonly provider_version: string;
  init(ctx: RuntimeInitContext): Promise<void>;

  /** Execute exactly one supervised reasoning/workflow cycle. */
  step(input: RuntimeStepInput): Promise<RuntimeStepOutput>;

  /** Cooperative cancellation (kill switch / suspension / timeout). */
  cancel(): void;
}
