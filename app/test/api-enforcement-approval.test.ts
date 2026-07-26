/**
 * Gate 04 approval-route ownership and scope tests.
 *
 * Approval authority is reconstructed from authenticated and server-owned
 * state. Browser-provided tenant/app/status fields are never used.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const { getSession, getOrCreateQhubApp, getPolicyProfile, getActivePlan, getEvaluationById, grantApproval } =
  vi.hoisted(() => ({
    getSession: vi.fn(),
    getOrCreateQhubApp: vi.fn(),
    getPolicyProfile: vi.fn(),
    getActivePlan: vi.fn(),
    getEvaluationById: vi.fn(),
    grantApproval: vi.fn(),
  }));

vi.mock('~/lib/auth/session', () => ({ getSession }));
vi.mock('~/lib/qhub/qhub-app.server', () => ({ getOrCreateQhubApp, getPolicyProfile }));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({
  getActivePlan,
  getEvaluationById,
  grantApproval,
  revokeApproval: vi.fn(),
  setKillSwitch: vi.fn(),
}));

const APP_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_APP_ID = '22222222-2222-4222-8222-222222222222';
const EVALUATION_ID = '33333333-3333-4333-8333-333333333333';
const PLAN_ID = '44444444-4444-4444-8444-444444444444';
const DIGEST = 'a'.repeat(64);

const context = { cloudflare: { env: {} } } as any;

function request(body: Record<string, unknown>) {
  return new Request('http://localhost/api/enforcement', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      op: 'grant_approval',
      conversationId: 'conv-1',
      evaluationId: EVALUATION_ID,
      attestationType: 'OWNER_ATTESTATION',
      actionDigest: DIGEST,
      ...body,
    }),
  });
}

function evaluation(overrides: Record<string, unknown> = {}) {
  return {
    evaluation_id: EVALUATION_ID,
    org_id: 'tenant-a',
    qhub_app_id: APP_ID,
    decision: 'REQUIRE_APPROVAL',
    action_digest: DIGEST,
    required_attestations: ['OWNER_ATTESTATION'],
    policy_profile_id: '55555555-5555-4555-8555-555555555555',
    policy_profile_hash: 'policy-hash',
    enforcement_plan_id: PLAN_ID,
    enforcement_plan_hash: 'plan-hash',
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  getSession.mockResolvedValue({ userId: 'owner-a', orgId: 'tenant-a', role: 'owner' });
  getOrCreateQhubApp.mockResolvedValue({ org_id: 'tenant-a', qhub_app_id: APP_ID });
  getEvaluationById.mockResolvedValue(evaluation());
  getPolicyProfile.mockResolvedValue({
    policy_profile_id: '55555555-5555-4555-8555-555555555555',
    policy_profile_hash: 'policy-hash',
  });
  getActivePlan.mockResolvedValue({
    enforcement_plan_id: PLAN_ID,
    enforcement_plan_hash: 'plan-hash',
  });
  grantApproval.mockResolvedValue({ ok: true, approvalId: 'approval-1' });
});

async function act(body: Record<string, unknown> = {}) {
  const { action } = await import('~/routes/api.enforcement');
  return action({ request: request(body), context, params: {} });
}

describe('POST /api/enforcement grant_approval', () => {
  it('persists a valid same-tenant approval using server-owned scope', async () => {
    const res = await act({ orgId: 'browser-forged', qhubAppId: OTHER_APP_ID, status: 'CONSUMED' });

    expect(res.status).toBe(200);
    expect(getEvaluationById).toHaveBeenCalledWith(EVALUATION_ID, 'tenant-a', {});
    expect(grantApproval).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: 'tenant-a',
        qhubAppId: APP_ID,
        actionDigest: DIGEST,
        approverId: 'owner-a',
        approverRole: 'owner',
      }),
      {},
    );
  });

  it('creates zero approval rows for a cross-tenant evaluation', async () => {
    getEvaluationById.mockResolvedValue(null);

    const res = await act();

    expect(res.status).toBe(403);
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('creates zero approval rows for a wrong-app evaluation', async () => {
    getEvaluationById.mockResolvedValue(evaluation({ qhub_app_id: OTHER_APP_ID }));

    const res = await act();

    expect(res.status).toBe(403);
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('creates zero approval rows when the authenticated tenant does not own the app', async () => {
    getOrCreateQhubApp.mockResolvedValue({ org_id: 'tenant-b', qhub_app_id: APP_ID });

    const res = await act();

    expect(res.status).toBe(403);
    expect(getEvaluationById).not.toHaveBeenCalled();
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('rejects a digest that does not match the evaluation', async () => {
    const res = await act({ actionDigest: 'b'.repeat(64) });

    expect(res.status).toBe(409);
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('rejects an evaluation that is not awaiting this approval', async () => {
    getEvaluationById.mockResolvedValue(evaluation({ decision: 'ALLOW' }));

    const res = await act();

    expect(res.status).toBe(409);
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('rejects stale policy or enforcement-plan bindings', async () => {
    getActivePlan.mockResolvedValue({ enforcement_plan_id: PLAN_ID, enforcement_plan_hash: 'changed' });

    const res = await act();

    expect(res.status).toBe(409);
    expect(grantApproval).not.toHaveBeenCalled();
  });

  it('returns only a generic rejection and no sensitive request data', async () => {
    getEvaluationById.mockResolvedValue(null);

    const res = await act({ rawPrompt: 'customer-secret-payload', credentials: 'do-not-return' });
    const body = await res.text();

    expect(body).not.toContain('customer-secret-payload');
    expect(body).not.toContain('do-not-return');
    expect(grantApproval).not.toHaveBeenCalled();
  });
});
