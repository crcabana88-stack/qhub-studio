/**
 * QHUB Agent Framework Foundation — Server-authoritative manifest builder
 * app/lib/qhub/agent/agent-manifest.server.ts
 *
 * Builds and hashes the Agent Manifest server-side. The browser supplies only
 * descriptive intent (name, purpose, requested models/tools/limits); QHUB sets
 * every trusted field (tenant, owner, classification, policy, plan, tier,
 * hashes) from durable governance state. The browser NEVER supplies a trusted
 * manifest hash — any client-provided hash is ignored.
 */

import { createHash, randomUUID } from 'node:crypto';
import { getOrCreateQhubApp, getClassification, getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan } from '~/lib/qhub/enforcement-store.server';
import {
  AGENT_MANIFEST_VERSION,
  canonicalAgentManifestString,
  IMPLEMENTED_OPERATING_MODES,
  type AgentManifest,
  type AgentOperatingMode,
  type AgentAutonomyLevel,
  type AgentToolGrant,
  type AgentConnectorGrant,
  type AgentActionLimits,
} from './agent-manifest';
import { LOCAL_SIMULATION_PROVIDER_ID, LOCAL_SIMULATION_PROVIDER_VERSION } from './runtime/local-simulation-provider';
import { assertAgentSchemaReady } from './agent-schema-check.server';
import type { TargetEnvironment } from '~/lib/qhub/release-candidate';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') {
    return JSON.stringify(v);
  }

  if (Array.isArray(v)) {
    return `[${v.map(stableStringify).join(',')}]`;
  }

  const keys = Object.keys(v as Record<string, unknown>).sort();

  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((v as Record<string, unknown>)[k])}`).join(',')}}`;
}

/** Browser-supplied intent for an agent manifest (all untrusted, descriptive). */
export interface AgentManifestDraftInput {
  session: { userId: string; orgId: string; role: string };
  conversationId: string;
  name: string;
  description: string;
  business_purpose: string;
  owning_team?: string | null;
  operating_mode: AgentOperatingMode;
  autonomy_level: AgentAutonomyLevel;
  primary_model: string;
  approved_models: string[];
  fallback_model_policy?: string;
  model_config?: Record<string, unknown>;
  approved_tools?: AgentToolGrant[];
  approved_connectors?: AgentConnectorGrant[];
  network_access_policy?: 'NONE' | 'ALLOWLIST_ONLY';
  system_instructions: string; // hashed server-side; raw text never stored on the manifest
  goal_definition: string;
  prohibited_goals?: string[];
  escalation_rules?: string[];
  human_approval_required?: boolean;
  action_limits: AgentActionLimits;
  stop_conditions?: string[];
  required_approver_roles?: string[];
  designated_supervisor_user_id?: string | null;
  review_frequency?: string | null;
  execution_environment?: TargetEnvironment;
  runtime_provider?: string;
  runtime_provider_version?: string;
  env: Record<string, string | undefined>;
}

export interface BuiltManifest {
  manifest: AgentManifest;
  manifest_hash: string;
  qhub_app_id: string;
  chain_id: string | null;
}

export type ManifestBuildError =
  | 'SCHEMA_NOT_READY'
  | 'UNIMPLEMENTED_OPERATING_MODE'
  | 'MISSING_CLASSIFICATION'
  | 'MISSING_POLICY_PROFILE'
  | 'MISSING_ENFORCEMENT_PLAN'
  | 'INVALID_LIMITS';

export interface ManifestBuildResult {
  ok: boolean;
  error?: ManifestBuildError;
  built?: BuiltManifest;
}

/**
 * Build the canonical manifest + hash from durable governance state. Returns a
 * fail-closed error if the operating mode is not implemented this phase, or if
 * the app lacks classification/policy/plan.
 */
export async function buildAgentManifest(
  input: AgentManifestDraftInput,
  opts: { agent_id?: string; agent_version_id?: string } = {},
): Promise<ManifestBuildResult> {
  /*
   * Fail closed before any governance read/write if the Agent Framework schema
   * is missing or misconfigured — no agent is created.
   */
  try {
    await assertAgentSchemaReady(input.env);
  } catch {
    return { ok: false, error: 'SCHEMA_NOT_READY' };
  }

  if (!IMPLEMENTED_OPERATING_MODES.includes(input.operating_mode)) {
    // BOUNDED_AUTONOMOUS_AGENT may exist only as a disabled/simulation-only option.
    return { ok: false, error: 'UNIMPLEMENTED_OPERATING_MODE' };
  }

  if (
    !Number.isFinite(input.action_limits.max_actions_per_run) ||
    input.action_limits.max_actions_per_run <= 0 ||
    input.action_limits.max_model_calls_per_run <= 0 ||
    input.action_limits.max_runtime_seconds <= 0
  ) {
    return { ok: false, error: 'INVALID_LIMITS' };
  }

  const app = await getOrCreateQhubApp(
    { conversationId: input.conversationId, orgId: input.session.orgId, userId: input.session.userId },
    input.env,
  );

  const classification = await getClassification(app.qhub_app_id, input.env);

  if (!classification) {
    return { ok: false, error: 'MISSING_CLASSIFICATION' };
  }

  const profile = await getPolicyProfile(app.qhub_app_id, input.env);

  if (!profile) {
    return { ok: false, error: 'MISSING_POLICY_PROFILE' };
  }

  const stored = await getActivePlan(app.qhub_app_id, input.session.orgId, input.env);

  if (!stored) {
    return { ok: false, error: 'MISSING_ENFORCEMENT_PLAN' };
  }

  const now = new Date().toISOString();
  const material: Omit<AgentManifest, 'agent_id' | 'agent_version_id' | 'created_at' | 'created_by'> = {
    manifest_version: AGENT_MANIFEST_VERSION,
    qhub_app_id: app.qhub_app_id,
    org_id: input.session.orgId, // server-authoritative tenant
    name: input.name,
    description: input.description,
    business_purpose: input.business_purpose,
    owner_user_id: input.session.userId, // server-authoritative owner = authenticated creator
    owning_team: input.owning_team ?? null,

    release_candidate_id: null, // bound later by a frozen Gate 05 release
    release_candidate_hash: null,
    deployment_decision_id: null,
    classification_version: classification.classification_version,
    risk_tier: profile.risk_tier,
    policy_profile_id: profile.policy_profile_id,
    policy_profile_version: profile.policy_profile_version,
    policy_profile_hash: profile.policy_profile_hash,
    enforcement_plan_id: stored.plan.enforcement_plan_id,
    enforcement_plan_version: stored.plan.enforcement_plan_version,
    enforcement_plan_hash: stored.plan.enforcement_plan_hash,

    runtime_provider: input.runtime_provider ?? LOCAL_SIMULATION_PROVIDER_ID,
    runtime_provider_version: input.runtime_provider_version ?? LOCAL_SIMULATION_PROVIDER_VERSION,
    execution_environment: input.execution_environment ?? 'STAGING',
    operating_mode: input.operating_mode,
    autonomy_level: input.autonomy_level,

    approved_models: input.approved_models,
    primary_model: input.primary_model,
    fallback_model_policy: input.fallback_model_policy ?? 'PRIMARY_ONLY',
    model_config_hash: sha256(stableStringify(input.model_config ?? {})),

    approved_tools: input.approved_tools ?? [],
    approved_connectors: input.approved_connectors ?? [],
    network_access_policy: input.network_access_policy ?? 'NONE',

    system_instruction_hash: sha256(input.system_instructions),
    goal_definition: input.goal_definition,
    prohibited_goals: input.prohibited_goals ?? [],
    escalation_rules: input.escalation_rules ?? [],
    human_approval_required: input.human_approval_required ?? true,
    action_limits: input.action_limits,
    stop_conditions: input.stop_conditions ?? [],

    required_approver_roles: input.required_approver_roles ?? ['owner'],
    designated_supervisor_user_id: input.designated_supervisor_user_id ?? null,
    kill_switch_bound: true,
    review_frequency: input.review_frequency ?? null,
  };

  const manifestHash = sha256(canonicalAgentManifestString(material));

  const manifest: AgentManifest = {
    ...material,
    agent_id: opts.agent_id ?? randomUUID(),
    agent_version_id: opts.agent_version_id ?? randomUUID(),
    created_by: input.session.userId,
    created_at: now,
  };

  return {
    ok: true,
    built: { manifest, manifest_hash: manifestHash, qhub_app_id: app.qhub_app_id, chain_id: app.chain_id ?? null },
  };
}

/** Recompute the manifest hash from a stored manifest (server-side verification). */
export function computeManifestHash(manifest: AgentManifest): string {
  const {
    agent_id: _agentId,
    agent_version_id: _versionId,
    created_at: _createdAt,
    created_by: _createdBy,
    ...material
  } = manifest;

  return sha256(canonicalAgentManifestString(material));
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
