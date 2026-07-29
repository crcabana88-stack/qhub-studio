/**
 * QHUB Commercial Launch R5 — REVIEW REQUEST IDENTITY BINDS POLICY VERSION
 * app/test/commercial-review-identity.test.ts
 *
 * The server-derived review-request identity (request_hash) binds the current policy
 * version (and requester), so a NEW applicable policy version yields a DISTINCT request —
 * a legitimate re-review after a policy change — while an exact repeat under the SAME
 * policy is idempotent. Prior requests remain immutable (a distinct hash never mutates the
 * old row; the unique(org_id, request_hash) constraint dedupes only exact repeats).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { testReadyToken } from '~/test/helpers/commercial-ready-token';

const H = vi.hoisted(() => ({ policy: vi.fn(), inserts: [] as Array<Record<string, unknown>> }));

// Control the server-derived policy version.
vi.mock('~/lib/qhub/commercial/governance-essentials', async (orig) => {
  const actual = await orig<typeof import('~/lib/qhub/commercial/governance-essentials')>();
  return { ...actual, currentReviewPolicyVersion: H.policy };
});

// Capture the inserted review-request row (its request_hash).
vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    from: () => {
      const b: Record<string, unknown> = {};

      b.insert = (row: Record<string, unknown>) => {
        H.inserts.push(row);

        return b;
      };
      b.select = () => b;
      b.eq = () => b;
      b.maybeSingle = async () => ({ data: { id: 'rid' }, error: null });

      return b;
    },
  }),
}));

import { createReviewRequest } from '~/lib/qhub/commercial/review.server';

const CTX = { userId: 'u1', orgId: 'org1', isStaff: false } as never;
const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };
const INPUT = { projectId: 'p1', category: 'personal', reason: 'sensitive customer data' };

beforeEach(() => {
  H.inserts = [];
  H.policy.mockReturnValue('2026-07-30.governance-essentials.v1');
});

describe('review request identity binds the server-derived policy version', () => {
  it('an exact repeat under the SAME policy version produces the SAME request identity', async () => {
    await createReviewRequest(CTX, INPUT, testReadyToken(ENV), ENV);
    await createReviewRequest(CTX, INPUT, testReadyToken(ENV), ENV);

    expect(H.inserts).toHaveLength(2);
    expect(H.inserts[0].request_hash).toBe(H.inserts[1].request_hash);
    expect(H.inserts[0].policy_version).toBe('2026-07-30.governance-essentials.v1');
  });

  it('a NEW policy version produces a DISTINCT request identity (re-review is allowed)', async () => {
    H.policy.mockReturnValue('2026-07-30.governance-essentials.v1');
    await createReviewRequest(CTX, INPUT, testReadyToken(ENV), ENV);

    H.policy.mockReturnValue('2027-01-01.governance-essentials.v2'); // policy changed
    await createReviewRequest(CTX, INPUT, testReadyToken(ENV), ENV);

    expect(H.inserts[0].request_hash).not.toBe(H.inserts[1].request_hash);
    expect(H.inserts[0].policy_version).toBe('2026-07-30.governance-essentials.v1');
    expect(H.inserts[1].policy_version).toBe('2027-01-01.governance-essentials.v2');
  });

  it('a different requester produces a distinct request identity', async () => {
    await createReviewRequest(CTX, INPUT, testReadyToken(ENV), ENV);
    await createReviewRequest({ ...(CTX as object), userId: 'u2' } as never, INPUT, testReadyToken(ENV), ENV);

    expect(H.inserts[0].request_hash).not.toBe(H.inserts[1].request_hash);
  });
});
