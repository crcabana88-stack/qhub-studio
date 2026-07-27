/**
 * QHUB Agent Framework Foundation — Lifecycle transition service (SERVER ONLY)
 * app/lib/qhub/agent/agent-lifecycle.server.ts
 *
 * Composes the pure transition guard with durable governance state (frozen
 * manifest, classification/policy/plan presence, Gate 05 release binding,
 * supervisor validity) and applies the transition. Server-authoritative and
 * fail-closed: the browser proposes a target state; QHUB decides.
 */

import {
  evaluateTransition,
  type AgentLifecycleState,
  type LifecycleReasonCode,
  type TransitionContext,
} from './agent-lifecycle';
import {
  getAgent,
  getAgentVersion,
  setLifecycleState,
  setKillSwitch,
  type AgentVersionRow,
} from './agent-registry.server';
import { checkReleaseBinding } from './agent-release-binding.server';
import { getClassification, getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan } from '~/lib/qhub/enforcement-store.server';

export interface TransitionAgentResult {
  ok: boolean;
  reason?: LifecycleReasonCode | 'AGENT_NOT_FOUND' | 'NO_CURRENT_VERSION';
  state?: AgentLifecycleState;
}

/** Build the transition context for an agent's current version from durable state. */
async function buildContext(
  version: AgentVersionRow,
  policyAllowsActive: boolean,
  hasValidSupervisor: boolean,
  env: Record<string, string | undefined>,
): Promise<TransitionContext> {
  const classification = await getClassification(version.qhub_app_id, env);
  const profile = await getPolicyProfile(version.qhub_app_id, env);
  const plan = await getActivePlan(version.qhub_app_id, version.org_id, env);
  const binding = await checkReleaseBinding(version, env);

  return {
    manifest_frozen: version.frozen,
    has_classification: !!classification,
    has_policy_profile: !!profile,
    has_enforcement_plan: !!plan,
    release_approved: binding.release_approved,
    release_stale: binding.release_stale,
    manifest_matches_release: binding.manifest_matches_release,
    has_valid_supervisor: hasValidSupervisor,
    policy_allows_active: policyAllowsActive,
    unresolved_exceptions: false,
    operating_mode: version.operating_mode,
  };
}

export async function transitionAgentState(input: {
  session: { userId: string; orgId: string; role: string };
  agent_id: string;
  to: AgentLifecycleState;

  /** Whether policy explicitly permits ACTIVE (server-derived; conservative default false). */
  policy_allows_active?: boolean;
  env: Record<string, string | undefined>;
}): Promise<TransitionAgentResult> {
  const agent = await getAgent(input.agent_id, input.session.orgId, input.env);

  if (!agent) {
    return { ok: false, reason: 'AGENT_NOT_FOUND' };
  }

  // SUSPENDED / RETIRED are always-permitted safety transitions.
  if (input.to === 'SUSPENDED' || input.to === 'RETIRED') {
    const guard = evaluateTransition(agent.current_lifecycle_state, input.to, {
      manifest_frozen: false,
      has_classification: false,
      has_policy_profile: false,
      has_enforcement_plan: false,
      release_approved: false,
      release_stale: false,
      manifest_matches_release: false,
      has_valid_supervisor: false,
      policy_allows_active: false,
      unresolved_exceptions: false,
      operating_mode: agent.current_operating_mode,
    });

    if (!guard.ok) {
      return { ok: false, reason: guard.reason };
    }

    await setLifecycleState(input.agent_id, input.session.orgId, input.to, input.env);

    return { ok: true, state: input.to };
  }

  if (!agent.current_version_id) {
    return { ok: false, reason: 'NO_CURRENT_VERSION' };
  }

  const version = await getAgentVersion(agent.current_version_id, input.session.orgId, input.env);

  if (!version) {
    return { ok: false, reason: 'NO_CURRENT_VERSION' };
  }

  const hasValidSupervisor =
    version.manifest.required_approver_roles.length > 0 &&
    (!!version.manifest.designated_supervisor_user_id || version.manifest.required_approver_roles.includes('owner'));

  const ctx = await buildContext(version, input.policy_allows_active ?? false, hasValidSupervisor, input.env);
  const guard = evaluateTransition(agent.current_lifecycle_state, input.to, ctx);

  if (!guard.ok) {
    return { ok: false, reason: guard.reason };
  }

  await setLifecycleState(input.agent_id, input.session.orgId, input.to, input.env);

  return { ok: true, state: input.to };
}

/** Kill switch: durable suspend. */
export async function killSwitchAgent(input: {
  session: { userId: string; orgId: string; role: string };
  agent_id: string;
  env: Record<string, string | undefined>;
}): Promise<{ ok: boolean }> {
  const agent = await getAgent(input.agent_id, input.session.orgId, input.env);

  if (!agent) {
    return { ok: false };
  }

  await setKillSwitch(input.agent_id, input.session.orgId, true, input.env);

  return { ok: true };
}
