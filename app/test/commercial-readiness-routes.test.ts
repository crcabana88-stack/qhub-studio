/**
 * QHUB Commercial Launch R4 — runtime routes fail closed on schema readiness
 * app/test/commercial-readiness-routes.test.ts
 *
 * With the schema NOT READY, every commercial route returns a safe response and does
 * ZERO protected work: no Stripe call, no intent/project/review/invitation write, no
 * model invocation. The staff diagnostic exposes a compact, non-secret status; a
 * non-staff caller receives only a generic guard response.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const EXPECTED = '2026-07-30.commercial-launch-r8';
const S = vi.hoisted(() => ({ rpc: vi.fn() }));

vi.mock('@supabase/supabase-js', () => ({ createClient: () => ({ rpc: S.rpc }) }));

const G = vi.hoisted(() => ({
  ctx: vi.fn(),
  project: vi.fn(),
  staff: vi.fn(),
  verified: vi.fn(),
  createIntent: vi.fn(),
  snapshot: vi.fn(),
  accept: vi.fn(),
  decide: vi.fn(),
  createProject: vi.fn(),
  createReview: vi.fn(),
  provider: vi.fn(),
  schema: vi.fn(),
  agent: vi.fn(),
}));

vi.mock('~/lib/qhub/commercial/commercial-context.server', () => ({
  requireCommercialContext: G.ctx,
  requireCommercialProject: G.project,
  requireStaff: G.staff,
}));
vi.mock('~/lib/auth/session', () => ({ getVerifiedUser: G.verified }));
vi.mock('~/lib/qhub/commercial/request-guards.server', () => ({
  isSameOrigin: () => true,
  checkRateLimit: () => ({ allowed: true }),
  readBoundedJson: async () => ({
    projectId: 'p1',
    idempotencyKey: 'k1',
    category: 'general',
    reason: 'r',
    planId: 'builder_beta',
    token: 't',
    invitationId: 'i1',
    decision: 'approved',
  }),
  appUrl: () => 'https://app.qhub.test/x',
  configuredAppOrigin: () => 'https://app.qhub.test',
}));
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({
  createCheckoutIntent: G.createIntent,
  getSubscriptionSnapshot: G.snapshot,
  acceptInvitation: G.accept,
  decideReviewAtomic: G.decide,
}));
vi.mock('~/lib/qhub/commercial/commercial-service.server', () => ({ createCommercialProject: G.createProject }));
vi.mock('~/lib/qhub/commercial/review.server', () => ({ createReviewRequest: G.createReview }));
vi.mock('~/lib/qhub/commercial/billing/stripe-provider.server', () => ({
  createBillingProvider: G.provider,
  planIdForConfiguredPrice: () => 'builder_beta',
}));
vi.mock('~/lib/qhub/schema-check.server', () => ({ getSchemaReadiness: G.schema }));
vi.mock('~/lib/qhub/agent/agent-schema-check.server', () => ({ getAgentSchemaReadiness: G.agent }));

import { resetCommercialReadinessCache } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { action as checkoutAction } from '~/routes/api.billing.checkout';
import { action as portalAction } from '~/routes/api.billing.portal';
import { action as projectsAction } from '~/routes/api.commercial.projects';
import { action as reviewsAction } from '~/routes/api.commercial.reviews';
import { action as decisionAction } from '~/routes/api.internal.commercial.reviews.$requestId.decision';
import { action as inviteAction } from '~/routes/api.commercial.invitations.accept';
import { loader as diagLoader } from '~/routes/api.system.schema-check';

const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };

function post(url: string) {
  return {
    request: new Request(`https://app.qhub.test${url}`, { method: 'POST', body: '{}' }),
    context: { cloudflare: { env: ENV } },
    params: { requestId: 'req1' },
  } as never;
}

function notReady() {
  S.rpc.mockResolvedValue({
    data: { expected_version: EXPECTED, ready: false, failed: ['version_mismatch'] },
    error: null,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  resetCommercialReadinessCache();

  // All guards pass so the ONLY thing blocking is schema readiness.
  const ctx = {
    ok: true,
    ctx: { userId: 'u1', email: 'u@x.com', orgId: 'org1', isStaff: true, projectId: 'p1', projectOrgId: 'org1' },
  };
  G.ctx.mockResolvedValue(ctx);
  G.project.mockResolvedValue(ctx);
  G.staff.mockResolvedValue(ctx);
  G.verified.mockResolvedValue({ userId: 'u1', email: 'u@x.com' });
  G.provider.mockReturnValue({
    isConfigured: () => true,
    expectedLivemode: () => false,
    createCheckoutSession: vi.fn(),
    createBillingPortalSession: vi.fn(),
  });
  G.snapshot.mockResolvedValue({ providerCustomerId: 'cus_1' });
  G.schema.mockResolvedValue({
    ready: true,
    expectedSchemaVersion: 'v',
    objects: [],
    missing: [],
    projectRef: 'ref',
    supabaseHost: 'h',
    checkedAt: 0,
  });
  G.agent.mockResolvedValue({ ready: true, expectedSchemaVersion: 'a', objects: [], missing: [] });
});

describe('billing routes fail closed BEFORE any Stripe call', () => {
  it('checkout → 503, no intent write, no Stripe session', async () => {
    notReady();

    const res = (await checkoutAction(post('/api/billing/checkout'))) as Response;
    expect(res.status).toBe(503);
    expect(G.createIntent).not.toHaveBeenCalled();
    expect(G.provider().createCheckoutSession).not.toHaveBeenCalled();
  });

  it('portal → 503, no Stripe portal session', async () => {
    notReady();

    const res = (await portalAction(post('/api/billing/portal'))) as Response;
    expect(res.status).toBe(503);
    expect(G.provider().createBillingPortalSession).not.toHaveBeenCalled();
  });
});

describe('commercial mutation routes fail closed BEFORE any write', () => {
  it('project creation → 503, no project write', async () => {
    notReady();

    const res = (await projectsAction(post('/api/commercial/projects'))) as Response;
    expect(res.status).toBe(503);
    expect(G.createProject).not.toHaveBeenCalled();
  });

  it('review submission → 503, no review write', async () => {
    notReady();

    const res = (await reviewsAction(post('/api/commercial/reviews'))) as Response;
    expect(res.status).toBe(503);
    expect(G.createReview).not.toHaveBeenCalled();
  });

  it('staff decision → 503, no decision/governance/audit write', async () => {
    notReady();

    const res = (await decisionAction(post('/api/internal/commercial/reviews/req1/decision'))) as Response;
    expect(res.status).toBe(503);
    expect(G.decide).not.toHaveBeenCalled();
  });

  it('invitation acceptance → 503, no seat/membership write', async () => {
    notReady();

    const res = (await inviteAction(post('/api/commercial/invitations/accept'))) as Response;
    expect(res.status).toBe(503);
    expect(G.accept).not.toHaveBeenCalled();
  });
});

describe('staff diagnostics — safe compact commercial readiness', () => {
  it('exposes state/expected/actual/failed/checkedAt without SQL or secrets', async () => {
    notReady();

    const res = (await diagLoader(post('/api/system/schema-check'))) as Response;
    const body = (await res.json()) as { commercial: Record<string, unknown> };

    expect(body.commercial.state).toBe('NOT_READY');
    expect(body.commercial.expectedSchemaVersion).toBe(EXPECTED);
    expect(body.commercial.ready).toBe(false);
    expect(Array.isArray(body.commercial.failed)).toBe(true);
    expect(typeof body.commercial.checkedAt).toBe('number');

    // No connection string, service key, or SQL text.
    expect(JSON.stringify(body.commercial)).not.toMatch(/postgres:\/\/|service_role|SELECT |CREATE /i);
  });

  it('a non-staff caller receives only the generic guard response (no commercial detail)', async () => {
    G.staff.mockResolvedValue({
      ok: false,
      response: new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 }),
    });

    const res = (await diagLoader(post('/api/system/schema-check'))) as Response;
    expect(res.status).toBe(403);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.commercial).toBeUndefined();
  });
});
