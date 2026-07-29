/**
 * QHUB Commercial Launch — /build loader server-side entitlement enforcement
 * app/test/commercial-build-route.test.ts
 *
 * The loader — not the browser — decides what is buildable. These tests drive the
 * loader directly to prove enforcement holds regardless of any UI state.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ResolvedEntitlements } from '~/lib/qhub/commercial/entitlements.server';

const { mockGetSession, mockLoadEntitlements, mockCountProjects } = vi.hoisted(() => ({
  mockGetSession: vi.fn(),
  mockLoadEntitlements: vi.fn(),
  mockCountProjects: vi.fn(),
}));

vi.mock('~/lib/auth/session', () => ({ getSession: mockGetSession }));

vi.mock('~/lib/qhub/commercial/entitlements.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/entitlements.server')>();
  return { ...actual, loadOrgEntitlements: mockLoadEntitlements };
});

vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ countProjects: mockCountProjects }));

import { loader } from '~/routes/build';
import { resolveEntitlements } from '~/lib/qhub/commercial/entitlements.server';

function ctx() {
  return {
    context: { cloudflare: { env: {} } },
    params: {},
    request: new Request('https://app.qhub.test/build'),
  } as never;
}

function resolved(planId: 'builder_beta' | 'guided_builder' | 'none', status: 'active' | 'none'): ResolvedEntitlements {
  return resolveEntitlements({ planId, status });
}

interface BuildData {
  canBuildApp: boolean;
  canBuildAgent: boolean;
  appReasonCode: string | null;
}

async function load(): Promise<BuildData> {
  const res = (await loader(ctx())) as Response;
  return (await res.json()) as BuildData;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('/build loader enforcement', () => {
  it('redirects to /login when unauthenticated', async () => {
    mockGetSession.mockResolvedValue(null);

    const res = (await loader(ctx())) as Response;
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });

  it('enables Build an App for an active Builder Beta org under the project limit', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'org1', email: 'a@b.com', role: 'admin' });
    mockLoadEntitlements.mockResolvedValue(resolved('builder_beta', 'active'));
    mockCountProjects.mockResolvedValue(2);

    const data = await load();
    expect(data.canBuildApp).toBe(true);
    expect(data.canBuildAgent).toBe(false);
  });

  it('disables Build an App at the project limit (server-enforced)', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'org1', email: 'a@b.com', role: 'admin' });
    mockLoadEntitlements.mockResolvedValue(resolved('builder_beta', 'active'));
    mockCountProjects.mockResolvedValue(5);

    const data = await load();
    expect(data.canBuildApp).toBe(false);
    expect(data.appReasonCode).toBe('PROJECT_LIMIT_REACHED');
  });

  it('disables Build an App entirely with no active plan', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'org1', email: 'a@b.com', role: 'admin' });
    mockLoadEntitlements.mockResolvedValue(resolved('none', 'none'));
    mockCountProjects.mockResolvedValue(0);

    const data = await load();
    expect(data.canBuildApp).toBe(false);
    expect(data.appReasonCode).toBe('APP_BUILDING_DISABLED');
  });

  it('never enables agent building', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'org1', email: 'a@b.com', role: 'admin' });
    mockLoadEntitlements.mockResolvedValue(resolved('guided_builder', 'active'));
    mockCountProjects.mockResolvedValue(0);

    const data = await load();
    expect(data.canBuildAgent).toBe(false);
  });
});
