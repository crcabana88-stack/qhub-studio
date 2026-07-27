/**
 * QHUB build-info diagnostic — route-level tests
 * app/test/build-info-route.test.ts
 *
 * Proves /api/system/build-info:
 *   - is 401 for an unauthenticated request;
 *   - reports source commit / artifact hash / build time from the deploy-injected
 *     bindings when authenticated;
 *   - returns a safe "unavailable" result (nulls, build_identity_present:false)
 *     when the bindings are absent — never an error, never a secret.
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

const IDENTITY = {
  QHUB_BUILD_SOURCE_COMMIT: '6ab2c2bc82dc67a3073de1eb457583773cab0ac6',
  QHUB_BUILD_ARTIFACT_HASH: '3f22857cd70b6b6ea033c0857bc9d9c486f7056d75c4ae86cb26e6d6d8420f56',
  QHUB_BUILD_AT: '2026-07-27T18:48:09.107Z',
};

describe('/api/system/build-info', () => {
  beforeEach(() => {
    mockGetSession.mockReset();
  });

  it('returns 401 for an unauthenticated request', async () => {
    mockGetSession.mockResolvedValue(null);

    const res = await call(IDENTITY);
    expect(res.status).toBe(401);
  });

  it('reports the injected build identity when authenticated', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u1', orgId: 'o1', role: 'owner' });

    const res = await call(IDENTITY);
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.source_commit).toBe(IDENTITY.QHUB_BUILD_SOURCE_COMMIT);
    expect(body.artifact_hash).toBe(IDENTITY.QHUB_BUILD_ARTIFACT_HASH);
    expect(body.built_at).toBe(IDENTITY.QHUB_BUILD_AT);
    expect(body.build_identity_present).toBe(true);
  });

  it('returns a safe unavailable result when bindings are absent', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u1', orgId: 'o1', role: 'owner' });

    const res = await call({});
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.source_commit).toBeNull();
    expect(body.artifact_hash).toBeNull();
    expect(body.built_at).toBeNull();
    expect(body.build_identity_present).toBe(false);

    // No secret-bearing fields are ever exposed.
    const keys = Object.keys(body).join(',').toLowerCase();
    expect(keys).not.toMatch(/secret|service_role|password|token|key(?!s)/);
  });
});
