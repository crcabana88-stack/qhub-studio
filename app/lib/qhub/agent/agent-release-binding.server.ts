/**
 * QHUB Agent Framework Foundation — Gate 05 release binding (SERVER ONLY)
 * app/lib/qhub/agent/agent-release-binding.server.ts
 *
 * An agent version may only enter SUPERVISED/ACTIVE if its exact frozen manifest
 * is bound to a Gate 05 release candidate that has DEPLOYMENT_APPROVED, whose
 * target environment matches, whose policy/plan remain current, and whose bound
 * hash still matches. Any material change invalidates the binding (fail-closed).
 */

import { getReleaseCandidate } from '~/lib/qhub/attestation-store.server';
import { getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan } from '~/lib/qhub/enforcement-store.server';
import type { AgentVersionRow } from './agent-registry.server';

export interface ReleaseBindingStatus {
  release_approved: boolean;
  release_stale: boolean;
  manifest_matches_release: boolean;
  reason: string[];
}

/**
 * Compute the current Gate 05 binding status for an agent version. Fail-closed:
 * an unbound or non-APPROVED release yields release_approved=false; policy/plan
 * drift yields release_stale=true; a hash mismatch yields manifest_matches_release=false.
 */
export async function checkReleaseBinding(
  version: AgentVersionRow,
  env: Record<string, string | undefined>,
): Promise<ReleaseBindingStatus> {
  const reason: string[] = [];

  if (!version.frozen) {
    reason.push('MANIFEST_NOT_FROZEN');
  }

  if (!version.release_candidate_id || !version.release_candidate_hash) {
    reason.push('NO_RELEASE_BINDING');

    return { release_approved: false, release_stale: false, manifest_matches_release: false, reason };
  }

  const rc = await getReleaseCandidate(version.release_candidate_id, version.org_id, env);

  if (!rc) {
    reason.push('RELEASE_NOT_FOUND');

    return { release_approved: false, release_stale: false, manifest_matches_release: false, reason };
  }

  const approved = rc.status === 'APPROVED';

  if (!approved) {
    reason.push('RELEASE_NOT_APPROVED');
  }

  // Exact-hash binding: the version must reference the exact release hash.
  const matches = version.release_candidate_hash === rc.release_candidate_hash;

  if (!matches) {
    reason.push('RELEASE_HASH_MISMATCH');
  }

  // Staleness: policy/plan must still match what the release froze.
  const profile = await getPolicyProfile(rc.qhub_app_id, env);
  const stored = await getActivePlan(rc.qhub_app_id, version.org_id, env);
  let stale = false;

  if (!profile || profile.policy_profile_hash !== rc.policy_profile_hash) {
    stale = true;
    reason.push('POLICY_STALE');
  }

  if (!stored || stored.plan.enforcement_plan_hash !== rc.enforcement_plan_hash) {
    stale = true;
    reason.push('PLAN_STALE');
  }

  return { release_approved: approved, release_stale: stale, manifest_matches_release: matches, reason };
}
