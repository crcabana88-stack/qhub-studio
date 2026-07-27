/**
 * QHUB Agent Framework Foundation — exact-version release binding tests
 * app/test/agent-release-binding.test.ts
 *
 * Proves the agent manifest is cryptographically bound into the Gate 05 release:
 * a release that does not contain the exact manifest hash cannot authorize the
 * agent, a changed manifest invalidates the binding, and the check is fully
 * server-computed (no browser-supplied hash can manufacture a match).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  getReleaseCandidate: vi.fn(),
  getPolicyProfile: vi.fn(),
  getActivePlan: vi.fn(),
}));

vi.mock('~/lib/qhub/attestation-store.server', () => ({ getReleaseCandidate: H.getReleaseCandidate }));
vi.mock('~/lib/qhub/qhub-app.server', () => ({ getPolicyProfile: H.getPolicyProfile }));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({ getActivePlan: H.getActivePlan }));

import { agentReleaseFileManifestHash, checkReleaseBinding } from '~/lib/qhub/agent/agent-release-binding.server';

const ENV = {};
const MANIFEST_HASH = 'a'.repeat(64);
const VERSION_ID = 'ver-1';

function version(over: any = {}): any {
  return {
    agent_version_id: VERSION_ID,
    org_id: 'client-smoke',
    qhub_app_id: 'app-1',
    manifest_hash: MANIFEST_HASH,
    frozen: true,
    release_candidate_id: 'rc-1',
    release_candidate_hash: 'RCHASH',
    policy_profile_hash: 'PPHASH',
    enforcement_plan_hash: 'EPHASH',
    ...over,
  };
}

function rc(over: any = {}): any {
  return {
    release_candidate_id: 'rc-1',
    org_id: 'client-smoke',
    qhub_app_id: 'app-1',
    status: 'APPROVED',
    release_candidate_hash: 'RCHASH',

    // A correct agent release binds the exact manifest as its file manifest.
    canonical_file_manifest_hash: agentReleaseFileManifestHash(VERSION_ID, MANIFEST_HASH),
    policy_profile_hash: 'PPHASH',
    enforcement_plan_hash: 'EPHASH',
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  H.getPolicyProfile.mockResolvedValue({ policy_profile_hash: 'PPHASH' });
  H.getActivePlan.mockResolvedValue({ plan: { enforcement_plan_hash: 'EPHASH' } });
});

describe('agent-exact Gate 05 release binding', () => {
  it('approves a release that cryptographically contains the exact manifest', async () => {
    H.getReleaseCandidate.mockResolvedValue(rc());

    const s = await checkReleaseBinding(version(), ENV);
    expect(s.release_approved).toBe(true);
    expect(s.release_stale).toBe(false);
    expect(s.manifest_matches_release).toBe(true);
  });

  it('rejects a release that does not contain the agent manifest hash (app-level approval is not enough)', async () => {
    // A release approved for the same app but NOT built from this manifest.
    H.getReleaseCandidate.mockResolvedValue(rc({ canonical_file_manifest_hash: 'f'.repeat(64) }));

    const s = await checkReleaseBinding(version(), ENV);
    expect(s.manifest_matches_release).toBe(false);
    expect(s.reason).toContain('AGENT_MANIFEST_NOT_IN_RELEASE');
  });

  it('changed manifest invalidates the binding (its hash is no longer in the release)', async () => {
    /*
     * The release was built for the ORIGINAL manifest; the version now carries a
     * changed manifest hash → the release no longer binds it.
     */
    H.getReleaseCandidate.mockResolvedValue(rc());

    const s = await checkReleaseBinding(version({ manifest_hash: 'b'.repeat(64) }), ENV);
    expect(s.manifest_matches_release).toBe(false);
    expect(s.reason).toContain('AGENT_MANIFEST_NOT_IN_RELEASE');
  });

  it('rejects a non-APPROVED release even when the manifest binding matches', async () => {
    H.getReleaseCandidate.mockResolvedValue(rc({ status: 'FROZEN' }));

    const s = await checkReleaseBinding(version(), ENV);
    expect(s.release_approved).toBe(false);
    expect(s.reason).toContain('RELEASE_NOT_APPROVED');
  });

  it('fails closed when the version is unbound', async () => {
    const s = await checkReleaseBinding(version({ release_candidate_id: null, release_candidate_hash: null }), ENV);
    expect(s.manifest_matches_release).toBe(false);
    expect(s.reason).toContain('NO_RELEASE_BINDING');
  });

  it('the expected file-manifest hash is deterministic and manifest-specific', () => {
    expect(agentReleaseFileManifestHash(VERSION_ID, MANIFEST_HASH)).toBe(
      agentReleaseFileManifestHash(VERSION_ID, MANIFEST_HASH),
    );
    expect(agentReleaseFileManifestHash(VERSION_ID, MANIFEST_HASH)).not.toBe(
      agentReleaseFileManifestHash(VERSION_ID, 'c'.repeat(64)),
    );
  });
});
