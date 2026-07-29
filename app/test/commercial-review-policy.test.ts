/**
 * QHUB Commercial Launch R4 — SERVER-DERIVED REVIEW POLICY VERSION
 * app/test/commercial-review-policy.test.ts
 *
 * The review policy version is strictly server-derived at submission and decision. The
 * browser can never choose or override it; a materially changed current policy forces
 * re-review; the decision binds and audits the server-derived version.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { currentReviewPolicyVersion } from '~/lib/qhub/commercial/governance-essentials';
import { testReadyToken } from '~/test/helpers/commercial-ready-token';

// ─── Decision route: browser policy version is ignored ──────────────────────────

const R = vi.hoisted(() => ({ staff: vi.fn(), ready: vi.fn(), meta: vi.fn(), decide: vi.fn() }));

vi.mock('~/lib/qhub/commercial/commercial-context.server', () => ({ requireStaff: R.staff }));

/*
 * Partial mocks: keep assertReadyToken / commercialTargetKey / real review.server helpers,
 * override only the two functions the route consumes.
 */
vi.mock('~/lib/qhub/commercial/commercial-schema-check.server', async (orig) => {
  const actual = await orig<typeof import('~/lib/qhub/commercial/commercial-schema-check.server')>();
  return { ...actual, requireCommercialReady: R.ready };
});
vi.mock('~/lib/qhub/commercial/review.server', async (orig) => {
  const actual = await orig<typeof import('~/lib/qhub/commercial/review.server')>();
  return { ...actual, getReviewDecisionMeta: R.meta };
});
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ decideReviewAtomic: R.decide }));
vi.mock('~/lib/qhub/commercial/request-guards.server', () => ({
  isSameOrigin: () => true,
  checkRateLimit: () => ({ allowed: true }),

  // The browser tries to force an arbitrary policy version — it must be ignored.
  readBoundedJson: async () => ({ decision: 'approved', reason: 'ok', policyVersion: 'ATTACKER-CHOSEN-v999' }),
}));

import { action as decisionAction } from '~/routes/api.internal.commercial.reviews.$requestId.decision';

function decisionReq() {
  return {
    request: new Request('https://app.qhub.test/api/internal/commercial/reviews/req1/decision', {
      method: 'POST',
      body: '{}',
    }),
    context: { cloudflare: { env: {} } },
    params: { requestId: 'req1' },
  } as never;
}

beforeEach(() => {
  vi.clearAllMocks();
  R.staff.mockResolvedValue({ ok: true, ctx: { userId: 'staff1', isStaff: true } });
  R.ready.mockResolvedValue({ ok: true, token: {} });
  R.decide.mockResolvedValue({ ok: true });
});

describe('staff decision route uses the SERVER-derived policy version', () => {
  it('ignores the browser policyVersion and binds the evaluated-under server version', async () => {
    R.meta.mockResolvedValue({ status: 'pending', policyVersion: currentReviewPolicyVersion() });

    const res = (await decisionAction(decisionReq())) as Response;
    expect(res.status).toBe(200);

    // decideReviewAtomic must receive the SERVER version, never the attacker's.
    expect(R.decide).toHaveBeenCalledTimes(1);

    const passed = R.decide.mock.calls[0][1] as { policyVersion: string };
    expect(passed.policyVersion).toBe(currentReviewPolicyVersion());
    expect(passed.policyVersion).not.toBe('ATTACKER-CHOSEN-v999');

    const body = (await res.json()) as { policyVersion: string };
    expect(body.policyVersion).toBe(currentReviewPolicyVersion());
  });

  it('requires re-review (409) when the request was evaluated under an older policy version', async () => {
    R.meta.mockResolvedValue({ status: 'pending', policyVersion: '2020-01-01.old-policy' });

    const res = (await decisionAction(decisionReq())) as Response;
    expect(res.status).toBe(409);

    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('policy_version_changed');

    // No decision/governance/audit write happens on a stale-policy request.
    expect(R.decide).not.toHaveBeenCalled();
  });

  it('404 when the request is unknown', async () => {
    R.meta.mockResolvedValue(null);

    const res = (await decisionAction(decisionReq())) as Response;
    expect(res.status).toBe(404);
    expect(R.decide).not.toHaveBeenCalled();
  });
});

// ─── review.server: submission stores the server version; decision binds it ─────

const SB = vi.hoisted(() => ({ insertRow: null as unknown, updates: [] as unknown[], reqRow: null as unknown }));

vi.mock('@supabase/supabase-js', () => {
  function builder(this: unknown) {
    const b: Record<string, unknown> = {};
    const chain = () => b;

    b.insert = (row: unknown) => {
      SB.insertRow = row;

      return b;
    };

    b.update = (row: unknown) => {
      SB.updates.push(row);

      return b;
    };
    b.select = chain;
    b.eq = chain;

    b.maybeSingle = async () => {
      // review request lookup returns the seeded row; insert returns a new id.
      if (SB.reqRow !== undefined && (b as { _isReqLookup?: boolean })._isReqLookup) {
        return { data: SB.reqRow, error: null };
      }

      return { data: { id: 'new-req-id' }, error: null };
    };

    return b;
  }

  return {
    createClient: () => ({
      from: (table: string) => {
        const b = (builder as unknown as () => Record<string, unknown>)();

        // Mark review-request selects so maybeSingle returns the seeded row.
        (b as { _isReqLookup?: boolean })._isReqLookup = table === 'qhub_manual_review_requests';

        return b;
      },
    }),
  };
});

import { createReviewRequest, decideReviewRequest } from '~/lib/qhub/commercial/review.server';

const CTX = { userId: 'u1', orgId: 'org1', isStaff: false } as never;
const STAFF = { userId: 'staff1', orgId: 'org1', isStaff: true } as never;
const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };

beforeEach(() => {
  SB.insertRow = null;
  SB.updates = [];
  SB.reqRow = null;
});

describe('review.server stores + binds the server-derived policy version', () => {
  it('createReviewRequest stamps the current server policy version on the request', async () => {
    const r = await createReviewRequest(CTX, { category: 'personal', reason: 'x' }, testReadyToken(ENV), ENV);
    expect(r.ok).toBe(true);
    expect((SB.insertRow as { policy_version?: string }).policy_version).toBe(currentReviewPolicyVersion());
  });

  it('decideReviewRequest binds the evaluated-under version and never a browser value', async () => {
    SB.reqRow = {
      id: 'req1',
      category: 'personal',
      status: 'pending',
      org_id: 'org1',
      project_id: 'p1',
      policy_version: currentReviewPolicyVersion(),
    };

    const r = await decideReviewRequest(
      STAFF,
      { requestId: 'req1', decision: 'approved', reason: 'ok' },
      testReadyToken(ENV),
      ENV,
    );
    expect(r.ok).toBe(true);

    /*
     * The request row is stamped with the server policy version; the governance row is
     * stamped with the same server version under review_policy_version.
     */
    const versions = SB.updates.map(
      (u) =>
        (u as { policy_version?: string; review_policy_version?: string }).policy_version ??
        (u as { review_policy_version?: string }).review_policy_version,
    );
    expect(versions).toContain(currentReviewPolicyVersion());
  });

  it('decideReviewRequest rejects a request evaluated under a materially older policy', async () => {
    SB.reqRow = {
      id: 'req1',
      category: 'personal',
      status: 'pending',
      org_id: 'org1',
      project_id: 'p1',
      policy_version: '2020-01-01.old-policy',
    };

    const r = await decideReviewRequest(
      STAFF,
      { requestId: 'req1', decision: 'approved', reason: 'ok' },
      testReadyToken(ENV),
      ENV,
    );
    expect(r.ok === false && r.error).toBe('policy_version_changed');
    expect(SB.updates).toEqual([]); // no write on stale policy
  });
});
