/**
 * QHUB Commercial Launch R2 — manual-review authority + governance gates
 * app/test/commercial-review-governance.test.ts
 */

import { describe, it, expect } from 'vitest';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import {
  createReviewRequest,
  decideReviewRequest,
  setStaffOverride,
  isProhibitedCategory,
} from '~/lib/qhub/commercial/review.server';
import {
  isModelInvocationAllowed,
  isPublicationAllowed,
  buildEvidenceExport,
  type GovernanceRecord,
} from '~/lib/qhub/commercial/governance-essentials.server';

function ctx(over: Partial<CommercialContext> = {}): CommercialContext {
  return {
    userId: 'u1',
    email: 'u@x.com',
    orgId: 'org1',
    role: 'builder',
    membershipStatus: 'active',
    isStaff: false,
    staffRole: null,
    resolved: { entitlements: {} as never, serviceState: 'active', planId: 'builder_beta', status: 'active' },
    capabilities: new Set(),
    onboardingComplete: true,
    suspended: false,
    ...over,
  };
}

const ENV = {}; // never reached in these pre-DB branches

describe('manual review authority (pre-DB guards)', () => {
  it('rejects prohibited categories from the queue', async () => {
    const r = await createReviewRequest(ctx(), { category: 'mnpi', reason: 'x' }, ENV);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toBe('prohibited_category');
  });

  it('rejects non-review-eligible categories', async () => {
    const r = await createReviewRequest(ctx(), { category: 'public', reason: 'x' }, ENV);
    expect(r.ok === false && r.error).toBe('not_review_eligible');
  });

  it('a non-staff caller cannot decide a review', async () => {
    const r = await decideReviewRequest(
      ctx({ isStaff: false }),
      { requestId: 'r1', decision: 'approved', reason: 'ok', policyVersion: 'v1' },
      ENV,
    );
    expect(r.ok === false && r.error).toBe('staff_required');
  });

  it('a non-staff caller cannot set an entitlement override', async () => {
    const r = await setStaffOverride(
      ctx({ isStaff: false }),
      { orgId: 'org1', reason: 'x', startsAt: 'now', endsAt: 'later' },
      ENV,
    );
    expect(r.ok === false && r.error).toBe('staff_required');
  });

  it('prohibited-category predicate', () => {
    expect(isProhibitedCategory('mnpi')).toBe(true);
    expect(isProhibitedCategory('secrets')).toBe(true);
    expect(isProhibitedCategory('personal')).toBe(false);
  });
});

describe('governance gates', () => {
  const base: GovernanceRecord = {
    projectId: 'p1',
    orgId: 'org1',
    disposition: 'proceed',
    declarationComplete: true,
    acknowledged: true,
    reviewState: 'none',
    riskTier: 'T1',
  };

  it('allows model invocation only when complete + acknowledged + proceed', () => {
    expect(isModelInvocationAllowed(base)).toBe(true);
    expect(isModelInvocationAllowed({ ...base, acknowledged: false })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, declarationComplete: false })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, disposition: 'prohibited' })).toBe(false);
    expect(isModelInvocationAllowed(null)).toBe(false);
  });

  it('allows manual-review disposition only after approval', () => {
    expect(isModelInvocationAllowed({ ...base, disposition: 'manual_review', reviewState: 'requested' })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, disposition: 'manual_review', reviewState: 'approved' })).toBe(true);
  });

  it('gates publication on approval / clean proceed', () => {
    expect(isPublicationAllowed({ ...base, disposition: 'proceed' })).toBe(true);
    expect(isPublicationAllowed({ ...base, disposition: 'manual_review', reviewState: 'requested' })).toBe(false);
    expect(isPublicationAllowed({ ...base, disposition: 'manual_review', reviewState: 'approved' })).toBe(true);
    expect(isPublicationAllowed({ ...base, disposition: 'prohibited' })).toBe(false);
  });

  it('evidence export contains no secrets/prompt content', () => {
    const ev = buildEvidenceExport(base);
    expect(ev).toMatchObject({ project_id: 'p1', disposition: 'proceed', schema: 'qhub-governance-essentials-1.0.0' });
    expect(JSON.stringify(ev)).not.toMatch(/prompt|secret|password/i);
  });
});
