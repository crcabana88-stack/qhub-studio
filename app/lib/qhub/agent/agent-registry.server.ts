/**
 * QHUB Agent Framework Foundation — Agent Registry (SERVER ONLY, tenant-scoped)
 * app/lib/qhub/agent/agent-registry.server.ts
 *
 * A private, per-customer registry. Server-authoritative and org-scoped: every
 * read/write is filtered by org_id; there is no cross-tenant discovery and no
 * marketplace. Immutable version content (manifest + hash) is separated from
 * mutable agent lifecycle state.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { AgentManifest } from './agent-manifest';
import type { AgentLifecycleState } from './agent-lifecycle';
import type { AgentOperatingMode } from './agent-manifest';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[AgentRegistry] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

export interface AgentRow {
  agent_id: string;
  org_id: string;
  qhub_app_id: string;
  name: string;
  owner_user_id: string;
  owning_team: string | null;
  current_version_id: string | null;
  current_lifecycle_state: AgentLifecycleState;
  current_operating_mode: AgentOperatingMode;
  risk_tier: string;
  kill_switch_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface AgentVersionRow {
  agent_version_id: string;
  agent_id: string;
  org_id: string;
  qhub_app_id: string;
  manifest: AgentManifest;
  manifest_hash: string;
  manifest_version: string;
  operating_mode: AgentOperatingMode;
  autonomy_level: string;
  risk_tier: string;
  policy_profile_hash: string;
  enforcement_plan_hash: string;
  release_candidate_id: string | null;
  release_candidate_hash: string | null;
  deployment_decision_id: string | null;
  frozen: boolean;
  created_by: string;
  created_at: string;
}

/** Create a new draft agent with its first (unfrozen) version. */
export async function createDraftAgent(
  params: { manifest: AgentManifest; manifest_hash: string },
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; agent_id?: string; agent_version_id?: string; reason?: string }> {
  const sb = admin(env);
  const m = params.manifest;

  const { error: aErr } = await sb.from('qhub_agents').insert({
    agent_id: m.agent_id,
    org_id: m.org_id,
    qhub_app_id: m.qhub_app_id,
    name: m.name,
    owner_user_id: m.owner_user_id,
    owning_team: m.owning_team,
    current_version_id: m.agent_version_id,
    current_lifecycle_state: 'DRAFT',
    current_operating_mode: m.operating_mode,
    risk_tier: m.risk_tier,
    kill_switch_active: false,
    created_by: m.created_by,
  });

  if (aErr) {
    return { ok: false, reason: aErr.message };
  }

  const vRes = await insertVersion(sb, params);

  if (!vRes.ok) {
    // Roll back the just-created agent so no partial record survives.
    await sb.from('qhub_agents').delete().eq('agent_id', m.agent_id).eq('org_id', m.org_id);

    return { ok: false, reason: vRes.reason };
  }

  return { ok: true, agent_id: m.agent_id, agent_version_id: m.agent_version_id };
}

/** Create a new immutable version for an existing agent (material change). */
export async function createAgentVersion(
  params: { manifest: AgentManifest; manifest_hash: string },
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; agent_version_id?: string; reason?: string }> {
  const sb = admin(env);
  const m = params.manifest;

  const existing = await getAgent(m.agent_id, m.org_id, env);

  if (!existing) {
    return { ok: false, reason: 'AGENT_NOT_FOUND' };
  }

  const vRes = await insertVersion(sb, params);

  if (!vRes.ok) {
    return { ok: false, reason: vRes.reason };
  }

  // Point the agent at the new version; new material change resets to DRAFT.
  await sb
    .from('qhub_agents')
    .update({
      current_version_id: m.agent_version_id,
      current_operating_mode: m.operating_mode,
      current_lifecycle_state: 'DRAFT',
      updated_at: new Date().toISOString(),
    })
    .eq('agent_id', m.agent_id)
    .eq('org_id', m.org_id);

  return { ok: true, agent_version_id: m.agent_version_id };
}

async function insertVersion(
  sb: SupabaseClient,
  params: { manifest: AgentManifest; manifest_hash: string },
): Promise<{ ok: boolean; reason?: string }> {
  const m = params.manifest;
  const { error } = await sb.from('qhub_agent_versions').insert({
    agent_version_id: m.agent_version_id,
    agent_id: m.agent_id,
    org_id: m.org_id,
    qhub_app_id: m.qhub_app_id,
    manifest: m,
    manifest_hash: params.manifest_hash,
    manifest_version: m.manifest_version,
    operating_mode: m.operating_mode,
    autonomy_level: m.autonomy_level,
    risk_tier: m.risk_tier,
    policy_profile_hash: m.policy_profile_hash,
    enforcement_plan_hash: m.enforcement_plan_hash,
    release_candidate_id: m.release_candidate_id,
    release_candidate_hash: m.release_candidate_hash,
    deployment_decision_id: m.deployment_decision_id,
    frozen: false,
    created_by: m.created_by,
  });

  if (error) {
    return { ok: false, reason: error.message };
  }

  return { ok: true };
}

export async function getAgent(
  agentId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<AgentRow | null> {
  const sb = admin(env);
  const { data } = await sb.from('qhub_agents').select('*').eq('agent_id', agentId).eq('org_id', orgId).maybeSingle();

  return (data as AgentRow) ?? null;
}

export async function listAgents(orgId: string, env: Record<string, string | undefined>): Promise<AgentRow[]> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_agents')
    .select('*')
    .eq('org_id', orgId)
    .order('created_at', { ascending: false });

  return (data as AgentRow[]) ?? [];
}

export async function getAgentVersion(
  agentVersionId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<AgentVersionRow | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_agent_versions')
    .select('*')
    .eq('agent_version_id', agentVersionId)
    .eq('org_id', orgId)
    .maybeSingle();

  return (data as AgentVersionRow) ?? null;
}

/** Freeze a version's manifest (set-once). After freeze the content is immutable. */
export async function freezeAgentVersion(
  agentVersionId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_agent_versions')
    .update({ frozen: true })
    .eq('agent_version_id', agentVersionId)
    .eq('org_id', orgId)
    .eq('frozen', false)
    .select('agent_version_id');

  return Array.isArray(data) && data.length === 1;
}

/** Bind an approved Gate 05 release to a frozen version (set-once). */
export async function bindApprovedRelease(
  params: {
    agent_version_id: string;
    org_id: string;
    release_candidate_id: string;
    release_candidate_hash: string;
    deployment_decision_id: string;
  },
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_agent_versions')
    .update({
      release_candidate_id: params.release_candidate_id,
      release_candidate_hash: params.release_candidate_hash,
      deployment_decision_id: params.deployment_decision_id,
    })
    .eq('agent_version_id', params.agent_version_id)
    .eq('org_id', params.org_id)
    .eq('frozen', true)
    .is('release_candidate_id', null)
    .select('agent_version_id');

  return Array.isArray(data) && data.length === 1;
}

/**
 * Server-authoritative lookup of an APPROVED Gate 05 release for binding. Returns
 * the exact release hash + app + the APPROVE deployment-decision id, or null if
 * the release is not APPROVED for this tenant. The browser never supplies these.
 */
export async function getApprovedReleaseForBinding(
  releaseCandidateId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<{ release_candidate_hash: string; qhub_app_id: string; deployment_decision_id: string } | null> {
  const sb = admin(env);
  const { data: rc } = await sb
    .from('qhub_release_candidates')
    .select('release_candidate_hash, qhub_app_id, status')
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId)
    .maybeSingle();

  if (!rc || (rc as { status: string }).status !== 'APPROVED') {
    return null;
  }

  const { data: decision } = await sb
    .from('qhub_deployment_decisions')
    .select('decision_id')
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId)
    .eq('decision', 'APPROVE')
    .order('decided_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!decision) {
    return null;
  }

  return {
    release_candidate_hash: (rc as { release_candidate_hash: string }).release_candidate_hash,
    qhub_app_id: (rc as { qhub_app_id: string }).qhub_app_id,
    deployment_decision_id: (decision as { decision_id: string }).decision_id,
  };
}

/** Set the agent's mutable lifecycle state (transition already validated). */
export async function setLifecycleState(
  agentId: string,
  orgId: string,
  state: AgentLifecycleState,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb
    .from('qhub_agents')
    .update({ current_lifecycle_state: state, updated_at: new Date().toISOString() })
    .eq('agent_id', agentId)
    .eq('org_id', orgId);
}

/** Kill switch: suspend the agent and set the durable kill flag. */
export async function setKillSwitch(
  agentId: string,
  orgId: string,
  active: boolean,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  const patch: Record<string, unknown> = { kill_switch_active: active, updated_at: new Date().toISOString() };

  if (active) {
    patch.current_lifecycle_state = 'SUSPENDED';
  }

  await sb.from('qhub_agents').update(patch).eq('agent_id', agentId).eq('org_id', orgId);
}
