/**
 * QHUB Gate 04 — exact approval-set pre-check tests (adversarial)
 * app/test/approval-set.test.ts
 *
 * Proves checkApprovalSet (used before any E2 submission on resume) accepts ONLY
 * the exact valid approval set — bound to the exact action_digest + policy + plan,
 * with correct role, distinct signer (SoD), and GRANTED status — and rejects every
 * wrong/expired/revoked/consumed/incomplete/self-approval case.
 */

import { describe, it, expect } from 'vitest';
import { checkApprovalSet } from '~/lib/qhub/enforcement-decision';
import type { ApprovalRequirement, GatheredApproval } from '~/lib/qhub/enforcement';

const DIGEST = 'digest-A';
const PPH = 'PPHASH';
const EPH = 'EPHASH';
const ACTOR = 'user-initiator';

const ownerReq: ApprovalRequirement = {
  requirement_id: 'REQ-OWNER',
  attestation_type: 'OWNER_ATTESTATION',
  applies_to: ['EXTERNAL_DATA_TRANSMISSION'],
  min_approvals: 1,
  distinct_approvers: false,
  roles: ['owner'],
};
const dualReq: ApprovalRequirement = {
  requirement_id: 'REQ-DUAL',
  attestation_type: 'DUAL_CONTROL',
  applies_to: ['EXTERNAL_DATA_TRANSMISSION'],
  min_approvals: 2,
  distinct_approvers: true,
  roles: [],
};

function appr(over: Partial<GatheredApproval> = {}): GatheredApproval {
  return {
    attestation_type: 'OWNER_ATTESTATION',
    approver_id: 'owner-1',
    approver_role: 'owner',
    scoped_action_digest: DIGEST,
    scoped_policy_profile_hash: PPH,
    scoped_enforcement_plan_hash: EPH,
    status: 'GRANTED',
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    ...over,
  };
}

const base = {
  requiredAttestations: ['OWNER_ATTESTATION'],
  approvalRequirements: [ownerReq],
  actionDigest: DIGEST,
  policyProfileHash: PPH,
  enforcementPlanHash: EPH,
  actorId: ACTOR,
};

describe('checkApprovalSet — exact approval binding', () => {
  it('the exact valid approval set is accepted', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr()] }).ok).toBe(true);
  });

  it('approval for action B cannot resume action A (digest mismatch)', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ scoped_action_digest: 'digest-B' })] }).ok).toBe(false);
  });

  it('approval scoped to another app/tenant policy cannot resume (policy hash mismatch)', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ scoped_policy_profile_hash: 'OTHER' })] }).ok).toBe(false);
  });

  it('approval scoped to a superseded plan cannot resume (plan hash mismatch)', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ scoped_enforcement_plan_hash: 'OLD' })] }).ok).toBe(false);
  });

  it('expired approval cannot resume', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ status: 'EXPIRED' })] }).ok).toBe(false);
  });

  it('revoked approval cannot resume', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ status: 'REVOKED' })] }).ok).toBe(false);
  });

  it('consumed approval cannot resume', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ status: 'CONSUMED' })] }).ok).toBe(false);
  });

  it('wrong approver role cannot resume', () => {
    expect(checkApprovalSet({ ...base, gathered: [appr({ approver_role: 'builder' })] }).ok).toBe(false);
  });

  it('unknown required attestation (no matching plan requirement) fails closed', () => {
    expect(checkApprovalSet({ ...base, requiredAttestations: ['GHOST'], gathered: [appr()] }).reason).toBe(
      'UNKNOWN_REQUIRED_ATTESTATION',
    );
  });

  it('incomplete dual control cannot resume (only one distinct approver)', () => {
    const r = checkApprovalSet({
      ...base,
      requiredAttestations: ['DUAL_CONTROL'],
      approvalRequirements: [dualReq],
      gathered: [appr({ attestation_type: 'DUAL_CONTROL', approver_id: 'a', approver_role: 'governance' })],
    });
    expect(r.ok).toBe(false);
  });

  it('self-approval cannot satisfy a distinct-approver requirement', () => {
    const r = checkApprovalSet({
      ...base,
      requiredAttestations: ['DUAL_CONTROL'],
      approvalRequirements: [dualReq],
      actorId: 'a',
      gathered: [
        appr({ attestation_type: 'DUAL_CONTROL', approver_id: 'a', approver_role: 'governance' }),
        appr({ attestation_type: 'DUAL_CONTROL', approver_id: 'b', approver_role: 'governance' }),
      ],
    });

    // Actor 'a' cannot count toward the distinct quorum → only 1 distinct approver.
    expect(r.ok).toBe(false);
  });

  it('complete dual control from two distinct non-actor approvers is accepted', () => {
    const r = checkApprovalSet({
      ...base,
      requiredAttestations: ['DUAL_CONTROL'],
      approvalRequirements: [dualReq],
      actorId: ACTOR,
      gathered: [
        appr({ attestation_type: 'DUAL_CONTROL', approver_id: 'a', approver_role: 'governance' }),
        appr({ attestation_type: 'DUAL_CONTROL', approver_id: 'b', approver_role: 'governance' }),
      ],
    });
    expect(r.ok).toBe(true);
  });

  it('no unrelated approval is accepted as a substitute (missing required set)', () => {
    expect(checkApprovalSet({ ...base, gathered: [] }).ok).toBe(false);
  });
});
