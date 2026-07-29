/**
 * QHUB Commercial Launch R2 — requireCommercialContext (authoritative, fail-closed)
 * app/test/commercial-context.test.ts
 *
 * Proves authorization comes from the DATABASE (membership/staff), not the token's
 * user_metadata, and that config/identity/authorization failures fail closed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const {
  mockGetVerifiedUser,
  mockIsDevAuthAllowed,
  mockResolveMembership,
  mockResolveStaff,
  mockLoadEnt,
  mockOnboarding,
} = vi.hoisted(() => ({
  mockGetVerifiedUser: vi.fn(),
  mockIsDevAuthAllowed: vi.fn(),
  mockResolveMembership: vi.fn(),
  mockResolveStaff: vi.fn(),
  mockLoadEnt: vi.fn(),
  mockOnboarding: vi.fn(),
}));

vi.mock('~/lib/auth/session', () => ({
  getVerifiedUser: mockGetVerifiedUser,
  isDevAuthAllowed: mockIsDevAuthAllowed,
}));
vi.mock('~/lib/qhub/commercial/membership.server', () => ({
  resolveMembership: mockResolveMembership,
  resolveStaff: mockResolveStaff,
}));
vi.mock('~/lib/qhub/commercial/entitlements.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/entitlements.server')>();
  return { ...actual, loadOrgEntitlements: mockLoadEnt };
});
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ getOnboardingState: mockOnboarding }));

import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { resolveEntitlements } from '~/lib/qhub/commercial/entitlements.server';

const ENV = { SUPABASE_URL: 'https://x.supabase.co', SUPABASE_ANON_KEY: 'anon' };

function req(headers: Record<string, string> = {}) {
  return new Request('https://app.qhub.test/api/governance', { method: 'POST', headers });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockIsDevAuthAllowed.mockReturnValue(false);
  mockResolveStaff.mockResolvedValue({ isStaff: false, staffRole: null });
  mockOnboarding.mockResolvedValue({ completed: true });
  mockLoadEnt.mockResolvedValue(resolveEntitlements({ planId: 'builder_beta', status: 'active' }));
});

describe('requireCommercialContext', () => {
  it('fails closed (503) when auth config is missing', async () => {
    mockGetVerifiedUser.mockResolvedValue('missing_config');

    const r = await requireCommercialContext(req(), ENV, 'APP_BUILD');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.response.status).toBe(503);
  });

  it('returns 401 when unauthenticated', async () => {
    mockGetVerifiedUser.mockResolvedValue(null);

    const r = await requireCommercialContext(req(), ENV, 'APP_BUILD');
    expect(r.ok === false && r.response.status).toBe(401);
  });

  it('derives org + role from the DATABASE membership, not user_metadata', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
    mockResolveMembership.mockResolvedValue({ userId: 'u1', orgId: 'org-db', role: 'builder', status: 'active' });

    const r = await requireCommercialContext(req({ 'x-qhub-org': 'org-FORGED' }), ENV, 'APP_BUILD');
    expect(r.ok).toBe(true);

    if (r.ok) {
      expect(r.ctx.orgId).toBe('org-db');
      expect(r.ctx.role).toBe('builder');
    }

    /*
     * The requested (forged) org is passed to resolveMembership, which validates it
     * against the user's own memberships — never blindly trusted.
     */
    expect(mockResolveMembership).toHaveBeenCalledWith('u1', 'org-FORGED', ENV);
  });

  it('denies a suspended membership (fail closed)', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
    mockResolveMembership.mockResolvedValue({ userId: 'u1', orgId: 'org-db', role: 'builder', status: 'suspended' });

    const r = await requireCommercialContext(req(), ENV, 'APP_BUILD');
    expect(r.ok === false && r.response.status).toBe(403);
  });

  it('denies a caller with no membership (and not staff)', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
    mockResolveMembership.mockResolvedValue(null);

    const r = await requireCommercialContext(req(), ENV, 'APP_BUILD');
    expect(r.ok === false && r.response.status).toBe(403);
  });

  it('denies APP_BUILD when the subscription is canceled', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
    mockResolveMembership.mockResolvedValue({ userId: 'u1', orgId: 'org-db', role: 'builder', status: 'active' });
    mockLoadEnt.mockResolvedValue(resolveEntitlements({ planId: 'builder_beta', status: 'canceled' }));

    const r = await requireCommercialContext(req(), ENV, 'APP_BUILD');
    expect(r.ok === false && r.response.status).toBe(403);
  });

  it('allows staff via the authoritative staff record even without a membership', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'staff1', email: 's@x.com' });
    mockResolveMembership.mockResolvedValue(null);
    mockResolveStaff.mockResolvedValue({ isStaff: true, staffRole: 'engineer' });

    const r = await requireCommercialContext(req(), ENV, 'AGENT_BUILD');
    expect(r.ok).toBe(true);

    if (r.ok) {
      expect(r.ctx.isStaff).toBe(true);
      expect(r.ctx.capabilities.has('AGENT_BUILD')).toBe(true);
    }
  });

  it('denies a commercial customer the AGENT_BUILD capability', async () => {
    mockGetVerifiedUser.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
    mockResolveMembership.mockResolvedValue({ userId: 'u1', orgId: 'org-db', role: 'owner', status: 'active' });

    const r = await requireCommercialContext(req(), ENV, 'AGENT_BUILD');
    expect(r.ok === false && r.response.status).toBe(403);
  });
});
