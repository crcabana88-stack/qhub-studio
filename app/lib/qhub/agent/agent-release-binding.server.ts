/**
 * QHUB Agent Framework Foundation — Gate 05 release binding (SERVER ONLY)
 * app/lib/qhub/agent/agent-release-binding.server.ts
 *
 * An agent version may only enter SUPERVISED/ACTIVE if its exact frozen manifest
 * is cryptographically bound into a Gate 05 release candidate that has
 * DEPLOYMENT_APPROVED, whose target environment matches, whose policy/plan remain
 * current, and whose bound hash still matches. An app-level release approval does
 * NOT authorize an agent unless the release provably contains the exact Agent
 * Manifest hash. Any material change invalidates the binding (fail-closed).
 *
 * Exact-version mechanism: the agent's release is frozen with a single dedicated
 * file-manifest entry `qhub://agent-manifest/<agent_version_id>` whose sha256 IS
 * the agent's manifest_hash. Because the release_candidate_hash incorporates
 * canonical_file_manifest_hash, the approved release cryptographically binds the
 * exact manifest — no Gate 05 semantics are changed to achieve this.
 */

import { createHash } from 'node:crypto';
import { getReleaseCandidate } from '~/lib/qhub/attestation-store.server';
import { getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan } from '~/lib/qhub/enforcement-store.server';
import { canonicalFileManifestString } from '~/lib/qhub/release-manifest';
import type { FileManifestEntry } from '~/lib/qhub/release-candidate';
import type { AgentVersionRow } from './agent-registry.server';

/** The single dedicated file entry that binds an agent manifest into its release. */
export function agentReleaseFileEntry(agentVersionId: string, manifestHash: string): FileManifestEntry {
  return { path: `qhub://agent-manifest/${agentVersionId}`, sha256: manifestHash, size: 0 };
}

/** Expected canonical_file_manifest_hash for an agent-bound release (server-computed). */
export function agentReleaseFileManifestHash(agentVersionId: string, manifestHash: string): string {
  return createHash('sha256')
    .update(canonicalFileManifestString([agentReleaseFileEntry(agentVersionId, manifestHash)]))
    .digest('hex');
}

export interface ReleaseBindingStatus {
  release_approved: boolean;
  release_stale: boolean;
  manifest_matches_release: boolean;
  reason: string[];
}

/**
 * Compute the current Gate 05 binding status for an agent version. Fail-closed:
 * an unbound or non-APPROVED release yields release_approved=false; policy/plan
 * drift yields release_stale=true; a hash mismatch OR a release that does not
 * cryptographically contain the exact agent manifest yields
 * manifest_matches_release=false.
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

  /*
   * Exact-hash binding: the version must reference the exact release hash AND the
   * release must cryptographically contain the exact agent manifest.
   */
  const hashMatches = version.release_candidate_hash === rc.release_candidate_hash;
  const manifestInRelease =
    (rc as { canonical_file_manifest_hash?: string }).canonical_file_manifest_hash ===
    agentReleaseFileManifestHash(version.agent_version_id, version.manifest_hash);
  const matches = hashMatches && manifestInRelease;

  if (!hashMatches) {
    reason.push('RELEASE_HASH_MISMATCH');
  }

  if (!manifestInRelease) {
    reason.push('AGENT_MANIFEST_NOT_IN_RELEASE');
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

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
