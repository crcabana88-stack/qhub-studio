/**
 * QHUB Commercial Launch R2 — manual-review authority + governance gates
 * app/test/commercial-review-governance.test.ts
 */

import { describe, it, expect } from 'vitest';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { createReviewRequest, setStaffOverride, isProhibitedCategory } from '~/lib/qhub/commercial/review.server';
import {
  isModelInvocationAllowed,
  isPublicationAllowed,
  buildEvidenceExport,
  assertBoundReviewAuthorization,
  type GovernanceRecord,
  type ApprovedReviewBinding,
} from '~/lib/qhub/commercial/governance-essentials.server';
import {
  currentReviewPolicyVersion,
  currentGovernancePolicyCardVersion,
  currentRequiredAcknowledgmentVersion,
} from '~/lib/qhub/commercial/governance-essentials';
import { testReadyToken } from '~/test/helpers/commercial-ready-token';

/*
 * These tests only exercise pre-DB guard branches (they return before any write), so a
 * nominal token is enough to satisfy the signature.
 */
const TOKEN = testReadyToken({});

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
    const r = await createReviewRequest(ctx(), { category: 'mnpi', reason: 'x' }, TOKEN, ENV);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toBe('prohibited_category');
  });

  it('rejects non-review-eligible categories', async () => {
    const r = await createReviewRequest(ctx(), { category: 'public', reason: 'x' }, TOKEN, ENV);
    expect(r.ok === false && r.error).toBe('not_review_eligible');
  });

  it('a non-staff caller cannot set an entitlement override', async () => {
    const r = await setStaffOverride(
      ctx({ isStaff: false }),
      { orgId: 'org1', reason: 'x', startsAt: 'now', endsAt: 'later' },
      TOKEN,
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
    reviewPolicyVersion: currentReviewPolicyVersion(),
    policyCardVersion: currentGovernancePolicyCardVersion(),
    acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
  };

  it('allows model invocation only when complete + acknowledged + proceed', () => {
    expect(isModelInvocationAllowed(base)).toBe(true);
    expect(isModelInvocationAllowed({ ...base, acknowledged: false })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, declarationComplete: false })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, disposition: 'prohibited' })).toBe(false);
    expect(isModelInvocationAllowed(null)).toBe(false);
  });

  it('allows manual-review disposition only after approval under the CURRENT policy', () => {
    expect(isModelInvocationAllowed({ ...base, disposition: 'manual_review', reviewState: 'requested' })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, disposition: 'manual_review', reviewState: 'approved' })).toBe(true);

    // R6: an approval decided under an OLDER policy version is STALE and cannot authorize.
    expect(
      isModelInvocationAllowed({
        ...base,
        disposition: 'manual_review',
        reviewState: 'approved',
        reviewPolicyVersion: '2020-01-01.old-policy',
      }),
    ).toBe(false);
  });

  it('R7: a stale acknowledgment version blocks authorization (build + publication)', () => {
    expect(isModelInvocationAllowed({ ...base, acknowledgmentVersion: '2020-01-01.old-ack' })).toBe(false);
    expect(isPublicationAllowed({ ...base, acknowledgmentVersion: '2020-01-01.old-ack' })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, acknowledgmentVersion: null })).toBe(false);
  });

  it('R7: a stale Governance policy-card version blocks authorization (build + publication)', () => {
    expect(isModelInvocationAllowed({ ...base, policyCardVersion: '2020-01-01.old-card' })).toBe(false);
    expect(isPublicationAllowed({ ...base, policyCardVersion: '2020-01-01.old-card' })).toBe(false);
    expect(isModelInvocationAllowed({ ...base, policyCardVersion: null })).toBe(false);
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

describe('R9 §10: assertBoundReviewAuthorization requires a fully-bound, current approved review', () => {
  const HASH = 'a'.repeat(64);
  const boundBase: GovernanceRecord = {
    projectId: 'p1',
    orgId: 'org1',
    disposition: 'manual_review',
    declarationComplete: true,
    acknowledged: true,
    reviewState: 'approved',
    riskTier: 'T1',
    reviewPolicyVersion: currentReviewPolicyVersion(),
    policyCardVersion: currentGovernancePolicyCardVersion(),
    acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
    recordVersion: 4,
    declarationIdentityHash: HASH,
    acknowledgmentRecordId: 'ack-1',
  };

  const matchingBinding: ApprovedReviewBinding = {
    governanceRecordVersion: 4,
    declarationIdentityHash: HASH,
    acknowledgmentRecordId: 'ack-1',
    acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
    requiredAcknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
    policyVersion: currentReviewPolicyVersion(),
    requesterUserId: 'u1',
  };

  it('a clean proceed disposition needs no approved-review binding', () => {
    expect(assertBoundReviewAuthorization({ ...boundBase, disposition: 'proceed', reviewState: 'none' }).ok).toBe(true);
  });

  it('a fully-bound, current approved review authorizes', () => {
    expect(assertBoundReviewAuthorization({ ...boundBase, approvedReview: matchingBinding }).ok).toBe(true);
  });

  it('a manual_review approval with NO loaded binding is non-authorizing (legacy NULL review blocks)', () => {
    expect(assertBoundReviewAuthorization({ ...boundBase, approvedReview: null }).reason).toBe(
      'non_authorizing_legacy_review',
    );
  });

  it('a binding with ANY null field is non-authorizing', () => {
    for (const k of Object.keys(matchingBinding) as Array<keyof ApprovedReviewBinding>) {
      const broken = { ...matchingBinding, [k]: null } as ApprovedReviewBinding;
      expect(assertBoundReviewAuthorization({ ...boundBase, approvedReview: broken }).reason, k).toBe(
        'non_authorizing_legacy_review',
      );
    }
  });

  it('a stale binding (declaration hash / record version / ack drift) is rejected before side effects', () => {
    expect(
      assertBoundReviewAuthorization({
        ...boundBase,
        approvedReview: { ...matchingBinding, declarationIdentityHash: 'b'.repeat(64) },
      }).reason,
    ).toBe('review_binding_stale');
    expect(
      assertBoundReviewAuthorization({
        ...boundBase,
        approvedReview: { ...matchingBinding, governanceRecordVersion: 5 },
      }).reason,
    ).toBe('review_binding_stale');
    expect(
      assertBoundReviewAuthorization({
        ...boundBase,
        approvedReview: { ...matchingBinding, acknowledgmentRecordId: 'other' },
      }).reason,
    ).toBe('review_binding_stale');
  });

  it('a stale acknowledgment / governance version blocks at the record level (before binding)', () => {
    expect(
      assertBoundReviewAuthorization({ ...boundBase, acknowledged: false, approvedReview: matchingBinding }).reason,
    ).toBe('acknowledgment_required');
    expect(
      assertBoundReviewAuthorization({
        ...boundBase,
        policyCardVersion: '2020-01-01.old',
        approvedReview: matchingBinding,
      }).reason,
    ).toBe('governance_stale_version');
  });
});
