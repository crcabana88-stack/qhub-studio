/**
 * QHUB build-info diagnostic — route-level tests
 * app/test/build-info-route.test.ts
 *
 * Proves /api/system/build-info:
 *   - 401 for anon;
 *   - 200 + ready when the deployment (QHUB_BUILD_*) and on-image (QHUB_IMAGE_*)
 *     identities match on source + artifact + lockfile;
 *   - 503 when they mismatch;
 *   - safe UNAVAILABLE (200) in local dev when absent, but 503 in an enforced env;
 *   - never exposes a secret.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockGetSession } = vi.hoisted(() => ({ mockGetSession: vi.fn() }));

vi.mock('~/lib/auth/session', () => ({
  getSession: mockGetSession,
  getHmacSecret: vi.fn().mockReturnValue('test-secret-32-chars-minimum-ok!'),
}));

import { loader } from '~/routes/api.system.build-info';

function call(env: Record<string, string | undefined>) {
  return loader({
    request: new Request('https://qhub-studio.fly.dev/api/system/build-info'),
    context: { cloudflare: { env } },
    params: {},
  } as unknown as Parameters<typeof loader>[0]);
}

const MATCH = {
  QHUB_BUILD_SOURCE_COMMIT: 'commit-1',
  QHUB_BUILD_ARTIFACT_HASH: 'artifact-1',
  QHUB_BUILD_LOCKFILE_HASH: 'lock-1',
  QHUB_BUILD_AT: 't',
  QHUB_IMAGE_SOURCE_COMMIT: 'commit-1',
  QHUB_IMAGE_ARTIFACT_HASH: 'artifact-1',
  QHUB_IMAGE_LOCKFILE_HASH: 'lock-1',
  QHUB_IMAGE_BUILD_AT: 't',
};

describe('/api/system/build-info', () => {
  beforeEach(() => mockGetSession.mockReset());

  it('401 for an unauthenticated request', async () => {
    mockGetSession.mockResolvedValue(null);
    expect((await call(MATCH)).status).toBe(401);
  });

  it('200 + ready when deployment and on-image identities match', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const res = await call({ ...MATCH, QHUB_DEPLOY_ENV: 'staging' });
    expect(res.status).toBe(200);

    const b = (await res.json()) as Record<string, unknown>;
    expect(b.ready).toBe(true);
    expect(b.present).toBe(true);
    expect(b.assurance_model).toBe('DEPLOYED_IMAGE_INTEGRITY');
    expect(b.source_commit).toBe('commit-1');
    expect(b.lockfile_hash).toBe('lock-1');
    expect(b.mismatch_reason_codes).toEqual([]);
  });

  it('reports the build-environment fingerprint and assurance model', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const res = await call({
      ...MATCH,
      QHUB_DEPLOY_ENV: 'staging',
      QHUB_BUILD_ENVIRONMENT: 'node=v20;pnpm=9;platform=linux',
    });
    const b = (await res.json()) as Record<string, unknown>;
    expect(b.build_environment).toBe('node=v20;pnpm=9;platform=linux');
    expect(b.assurance_model).toBe('DEPLOYED_IMAGE_INTEGRITY');
  });

  it('503 on a source-commit mismatch', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const res = await call({ ...MATCH, QHUB_IMAGE_SOURCE_COMMIT: 'DIFFERENT', QHUB_DEPLOY_ENV: 'staging' });
    expect(res.status).toBe(503);

    const b = (await res.json()) as Record<string, unknown>;
    expect(b.ready).toBe(false);
    expect(b.mismatch_reason_codes).toContain('SOURCE_COMMIT_MISMATCH');
  });

  it('503 on a lockfile-hash mismatch', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const res = await call({ ...MATCH, QHUB_IMAGE_LOCKFILE_HASH: 'DIFFERENT', QHUB_DEPLOY_ENV: 'staging' });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { mismatch_reason_codes: string[] }).mismatch_reason_codes).toContain(
      'LOCKFILE_HASH_MISMATCH',
    );
  });

  it('local dev (no deploy env) reports UNAVAILABLE without 503 when identity absent', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const res = await call({ QHUB_DEPLOY_ENV: 'local' });
    expect(res.status).toBe(200);

    const b = (await res.json()) as Record<string, unknown>;
    expect(b.present).toBe(false);
    expect(b.ready).toBe(false);
  });

  it('staging with absent identity fails closed (503)', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });
    expect((await call({ QHUB_DEPLOY_ENV: 'staging' })).status).toBe(503);
  });

  it('never exposes a secret-bearing field', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', role: 'owner' });

    const b = (await (await call(MATCH)).json()) as Record<string, unknown>;
    expect(Object.keys(b).join(',').toLowerCase()).not.toMatch(/secret|service_role|password|api_key/);
  });
});
