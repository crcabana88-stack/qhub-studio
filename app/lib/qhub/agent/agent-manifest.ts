/**
 * QHUB Agent Framework Foundation — Canonical Agent Manifest (PURE)
 * app/lib/qhub/agent/agent-manifest.ts
 *
 * Types + canonical serializers for a governed agent. A QHUB agent is never an
 * unbounded chatbot: it is identified, versioned, classified, policy-bound,
 * release-bound, permissioned, supervised, observable, suspendable, governed by
 * Gate 04, and approved through Gate 05.
 *
 * PURE: no I/O, no crypto, no secrets. Identical canonical input → identical
 * string. The manifest is ALWAYS constructed and hashed server-side; the browser
 * never supplies a trusted tenant, owner, policy, plan, release approval, role,
 * autonomy level, runtime authority, tool/data scope, manifest hash, or status.
 */

import type { RiskTier } from '~/lib/qhub/classification';
import type { GovernedActionType } from '~/lib/qhub/enforcement';
import type { TargetEnvironment } from '~/lib/qhub/release-candidate';

export const AGENT_MANIFEST_VERSION = 'agent-manifest-1.0.0';

/**
 * Closed operating-mode vocabulary. BOUNDED_AUTONOMOUS_AGENT is a manifest option
 * only — it stays simulation-only/disabled in this phase (no unrestricted
 * production autonomy). See {@link isProductionAutonomyEnabled}.
 */
export type AgentOperatingMode =
  | 'ASSISTANT' // recommendations / draft output; no consequential actions
  | 'WORKFLOW_AGENT' // predefined internal workflow steps; no open-ended planning
  | 'SUPERVISED_ACTION_AGENT' // may propose consequential actions; Gate 04 approval where policy assigns
  | 'BOUNDED_AUTONOMOUS_AGENT'; // manifest-only in this phase; simulation-only/disabled

export const IMPLEMENTED_OPERATING_MODES: AgentOperatingMode[] = [
  'ASSISTANT',
  'WORKFLOW_AGENT',
  'SUPERVISED_ACTION_AGENT',
];

/** Production autonomy is NOT enabled in this phase. Kept as a single choke point. */
export function isProductionAutonomyEnabled(): boolean {
  return false;
}

/** Agent autonomy declaration (distinct from classification AutonomyLevel). */
export type AgentAutonomyLevel = 'NONE' | 'HUMAN_IN_LOOP' | 'HUMAN_ON_LOOP' | 'BOUNDED';

/** A single approved tool the agent may request Gate 04 to execute. */
export interface AgentToolGrant {
  tool_id: string;

  /** Governed-action type this tool maps to (the Gate 04 action it can propose). */
  action_type: GovernedActionType;
  permitted_operations: string[];
  blocked_operations: string[];
}

/** A single approved connector (staging simulation only in this phase). */
export interface AgentConnectorGrant {
  connector_id: string;
  action_type: GovernedActionType;
  data_access_scopes: string[];
}

/** Hard limits enforced by the run orchestrator (fail-closed on breach). */
export interface AgentActionLimits {
  max_actions_per_run: number;
  max_model_calls_per_run: number;
  max_runtime_seconds: number;
  max_approval_wait_seconds: number;

  /** Optional monetary ceiling for consequential financial actions (minor units). */
  max_financial_amount_minor?: number | null;
}

/**
 * The canonical, versioned Agent Manifest. `manifest_hash` is server-computed
 * from {@link canonicalAgentManifestString}; ids/timestamps/status are excluded
 * so a re-freeze of identical material content is idempotent.
 */
export interface AgentManifest {
  manifest_version: string;

  // ── Identity ──
  agent_id: string;
  agent_version_id: string;
  qhub_app_id: string;
  org_id: string;
  name: string;
  description: string;
  business_purpose: string;
  owner_user_id: string;
  owning_team: string | null;
  created_by: string;
  created_at: string;

  // ── Release / governance binding (all server-authoritative) ──
  release_candidate_id: string | null;
  release_candidate_hash: string | null;
  deployment_decision_id: string | null;
  classification_version: number;
  risk_tier: RiskTier;
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string;

  // ── Runtime ──
  runtime_provider: string;
  runtime_provider_version: string;
  execution_environment: TargetEnvironment;
  operating_mode: AgentOperatingMode;
  autonomy_level: AgentAutonomyLevel;

  // ── Model ──
  approved_models: string[];
  primary_model: string;
  fallback_model_policy: string;
  model_config_hash: string;

  // ── Tools / connectors / data / network ──
  approved_tools: AgentToolGrant[];
  approved_connectors: AgentConnectorGrant[];
  network_access_policy: 'NONE' | 'ALLOWLIST_ONLY';

  // ── Behavior ──
  system_instruction_hash: string;
  goal_definition: string;
  prohibited_goals: string[];
  escalation_rules: string[];
  human_approval_required: boolean;
  action_limits: AgentActionLimits;
  stop_conditions: string[];

  // ── Supervision ──
  required_approver_roles: string[];
  designated_supervisor_user_id: string | null;
  kill_switch_bound: boolean;
  review_frequency: string | null;
}

/**
 * Canonical string over the manifest's MATERIAL content — the `manifest_hash`
 * preimage. Excludes ids/timestamps and mutable lifecycle. Any material change
 * (models, tools, connectors, instructions, limits, autonomy, runtime provider,
 * environment, policy, plan, release binding) yields a different hash and MUST
 * create a new agent version.
 */
export function canonicalAgentManifestString(
  m: Omit<AgentManifest, 'agent_id' | 'agent_version_id' | 'created_at' | 'created_by'>,
): string {
  const sortTools = (t: AgentToolGrant[]) =>
    [...t]
      .map((x) => ({
        tool_id: x.tool_id,
        action_type: x.action_type,
        permitted_operations: [...x.permitted_operations].sort(),
        blocked_operations: [...x.blocked_operations].sort(),
      }))
      .sort((a, b) => a.tool_id.localeCompare(b.tool_id));
  const sortConnectors = (c: AgentConnectorGrant[]) =>
    [...c]
      .map((x) => ({
        connector_id: x.connector_id,
        action_type: x.action_type,
        data_access_scopes: [...x.data_access_scopes].sort(),
      }))
      .sort((a, b) => a.connector_id.localeCompare(b.connector_id));

  return JSON.stringify({
    manifest_version: m.manifest_version,
    qhub_app_id: m.qhub_app_id,
    org_id: m.org_id,
    name: m.name,
    description: m.description,
    business_purpose: m.business_purpose,
    owner_user_id: m.owner_user_id,
    owning_team: m.owning_team,
    release_candidate_id: m.release_candidate_id,
    release_candidate_hash: m.release_candidate_hash,
    deployment_decision_id: m.deployment_decision_id,
    classification_version: m.classification_version,
    risk_tier: m.risk_tier,
    policy_profile_id: m.policy_profile_id,
    policy_profile_version: m.policy_profile_version,
    policy_profile_hash: m.policy_profile_hash,
    enforcement_plan_id: m.enforcement_plan_id,
    enforcement_plan_version: m.enforcement_plan_version,
    enforcement_plan_hash: m.enforcement_plan_hash,
    runtime_provider: m.runtime_provider,
    runtime_provider_version: m.runtime_provider_version,
    execution_environment: m.execution_environment,
    operating_mode: m.operating_mode,
    autonomy_level: m.autonomy_level,
    approved_models: [...m.approved_models].sort(),
    primary_model: m.primary_model,
    fallback_model_policy: m.fallback_model_policy,
    model_config_hash: m.model_config_hash,
    approved_tools: sortTools(m.approved_tools),
    approved_connectors: sortConnectors(m.approved_connectors),
    network_access_policy: m.network_access_policy,
    system_instruction_hash: m.system_instruction_hash,
    goal_definition: m.goal_definition,
    prohibited_goals: [...m.prohibited_goals].sort(),
    escalation_rules: [...m.escalation_rules].sort(),
    human_approval_required: m.human_approval_required,
    action_limits: {
      max_actions_per_run: m.action_limits.max_actions_per_run,
      max_model_calls_per_run: m.action_limits.max_model_calls_per_run,
      max_runtime_seconds: m.action_limits.max_runtime_seconds,
      max_approval_wait_seconds: m.action_limits.max_approval_wait_seconds,
      max_financial_amount_minor: m.action_limits.max_financial_amount_minor ?? null,
    },
    stop_conditions: [...m.stop_conditions].sort(),
    required_approver_roles: [...m.required_approver_roles].sort(),
    designated_supervisor_user_id: m.designated_supervisor_user_id,
    kill_switch_bound: m.kill_switch_bound,
    review_frequency: m.review_frequency,
  });
}
