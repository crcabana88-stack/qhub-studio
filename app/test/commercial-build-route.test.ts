/**
 * QHUB Commercial Launch R2 — /build loader (authoritative context enforcement)
 * app/test/commercial-build-route.test.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';

const { mockRequire, mockCountProjects } = vi.hoisted(() => ({
  mockRequire: vi.fn(),
  mockCountProjects: vi.fn(),
}));

vi.mock('~/lib/qhub/commercial/commercial-context.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/commercial-context.server')>();
  return { ...actual, requireCommercialContext: mockRequire };
});
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ countProjects: mockCountProjects }));

import { loader } from '~/routes/build';
import { resolveEntitlements } from '~/lib/qhub/commercial/entitlements.server';
import { computeCapabilities } from '~/lib/qhub/commercial/capabilities';

function makeCtx(planId: 'builder_beta' | 'none', status: 'active' | 'none'): CommercialContext {
  const resolved = resolveEntitlements({ planId, status });
  const capabilities = computeCapabilities({
    serviceState: resolved.serviceState,
    entitlements: resolved.entitlements,
    membershipActive: true,
    role: 'builder',
    isStaff: false,
    onboardingComplete: true,
    suspended: false,
  });

  return {
    userId: 'u1',
    email: 'u@x.com',
    orgId: 'org1',
    role: 'builder',
    membershipStatus: 'active',
    isStaff: false,
    staffRole: null,
    resolved,
    capabilities,
    onboardingComplete: true,
    suspended: false,
  };
}

function args() {
  return {
    context: { cloudflare: { env: {} } },
    params: {},
    request: new Request('https://app.qhub.test/build'),
  } as never;
}

async function load(): Promise<{ canBuildApp: boolean; canBuildAgent: boolean; appReasonCode: string | null }> {
  const res = (await loader(args())) as Response;
  return (await res.json()) as { canBuildApp: boolean; canBuildAgent: boolean; appReasonCode: string | null };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('/build loader', () => {
  it('redirects to /login when the guard denies with 401', async () => {
    mockRequire.mockResolvedValue({ ok: false, response: new Response(null, { status: 401 }) });

    await expect(loader(args())).rejects.toMatchObject({ status: 302 });
  });

  it('enables Build an App for an active Builder Beta org under the project limit', async () => {
    mockRequire.mockResolvedValue({ ok: true, ctx: makeCtx('builder_beta', 'active') });
    mockCountProjects.mockResolvedValue(2);

    const data = await load();
    expect(data.canBuildApp).toBe(true);
    expect(data.canBuildAgent).toBe(false);
  });

  it('disables Build an App at the project limit', async () => {
    mockRequire.mockResolvedValue({ ok: true, ctx: makeCtx('builder_beta', 'active') });
    mockCountProjects.mockResolvedValue(5);

    const data = await load();
    expect(data.canBuildApp).toBe(false);
    expect(data.appReasonCode).toBe('PROJECT_LIMIT_REACHED');
  });

  it('disables Build an App with no active plan (no APP_BUILD capability)', async () => {
    mockRequire.mockResolvedValue({ ok: true, ctx: makeCtx('none', 'none') });
    mockCountProjects.mockResolvedValue(0);

    const data = await load();
    expect(data.canBuildApp).toBe(false);
  });
});
