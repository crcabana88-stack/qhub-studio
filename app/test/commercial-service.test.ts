/**
 * QHUB Commercial Launch R3 — protected service-layer enforcement
 * app/test/commercial-service.test.ts
 *
 * The service layer requires an authoritative CommercialExecutionContext and
 * re-checks capability + Governance Essentials + credits — it never trusts a
 * caller claiming it already passed authorization.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CommercialExecutionContext } from '~/lib/qhub/commercial/commercial-context.server';
import type { GovernanceRecord } from '~/lib/qhub/commercial/governance-essentials.server';

const H = vi.hoisted(() => ({ getGov: vi.fn(), consume: vi.fn(), assert: vi.fn() }));

vi.mock('~/lib/qhub/commercial/governance-essentials.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/governance-essentials.server')>();
  return { ...actual, getGovernanceRecord: H.getGov };
});
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ consumeBuildCredit: H.consume }));

/*
 * Deterministic readiness injection: the service gates on assertReadyToken(). We mock it
 * (no production bypass — the module is mocked) so a READY case is a no-op and a NOT-READY
 * case throws, exactly like a target/version mismatch would at runtime.
 */
vi.mock('~/lib/qhub/commercial/commercial-schema-check.server', () => ({
  assertReadyToken: H.assert,
}));

// A stand-in token — its shape is irrelevant because assertReadyToken is mocked.
const TOKEN = { schemaVersion: '2026-07-30.commercial-launch-r8', targetKey: 't', checkedAt: '0' } as never;

function makeNotReady() {
  H.assert.mockImplementation(() => {
    throw new Error('commercial schema not ready');
  });
}

import {
  invokeCommercialModel,
  canonicalRequestHash,
  exportCommercialProject,
  requestCommercialPublication,
} from '~/lib/qhub/commercial/commercial-service.server';
import {
  currentReviewPolicyVersion,
  currentGovernancePolicyCardVersion,
  currentRequiredAcknowledgmentVersion,
} from '~/lib/qhub/commercial/governance-essentials';

function execCtx(caps: string[] = ['MODEL_INVOKE', 'CODE_EXPORT']): CommercialExecutionContext {
  return {
    userId: 'u1',
    email: 'u@x.com',
    orgId: 'org1',
    role: 'builder',
    membershipStatus: 'active',
    isStaff: false,
    staffRole: null,
    resolved: {
      entitlements: { maxProjects: 5 } as never,
      serviceState: 'active',
      planId: 'builder_beta',
      status: 'active',
    },
    capabilities: new Set(caps as never),
    onboardingComplete: true,
    suspended: false,
    projectId: 'p1',
    projectOrgId: 'org1',
  };
}

const goodGov: GovernanceRecord = {
  projectId: 'p1',
  orgId: 'org1',
  disposition: 'proceed',
  declarationComplete: true,
  acknowledged: true,
  reviewState: 'none',
  riskTier: 'T1',
  reviewPolicyVersion: null,
  policyCardVersion: currentGovernancePolicyCardVersion(),
  acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
};

const req = {
  model: 'm',
  provider: 'p',
  inputHash: 'ih',
  action: 'BUILD',
  template: 'blank',
  units: 1,
  governanceVersion: '1',
};

beforeEach(() => {
  vi.clearAllMocks();
  H.getGov.mockResolvedValue(goodGov);
  H.consume.mockResolvedValue({ ok: true, remaining: 9, ledger_id: 'L1' });
  H.assert.mockReturnValue(undefined); // READY: token valid (no throw)
});

describe('invokeCommercialModel', () => {
  it('rejects a non-execution context (no project binding)', async () => {
    const bad = { userId: 'u1', capabilities: new Set(['MODEL_INVOKE']) } as never;
    const r = await invokeCommercialModel(bad, req, 'k1', TOKEN, {}, async () => 'ran');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toBe('missing_execution_context');
  });

  it('rejects without the MODEL_INVOKE capability', async () => {
    const r = await invokeCommercialModel(execCtx([]), req, 'k1', TOKEN, {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('capability_denied');
    expect(H.consume).not.toHaveBeenCalled();
  });

  it('blocks when the Governance Essentials gate is not satisfied', async () => {
    H.getGov.mockResolvedValue({ ...goodGov, acknowledged: false });

    const r = await invokeCommercialModel(execCtx(), req, 'k1', TOKEN, {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('governance_gate_blocked');
    expect(H.consume).not.toHaveBeenCalled();
  });

  it('blocks a suspended context', async () => {
    const ctx = { ...execCtx(), suspended: true };
    const r = await invokeCommercialModel(ctx, req, 'k1', TOKEN, {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('suspended');
  });

  it('consumes credit BEFORE running the model and returns the balance', async () => {
    const order: string[] = [];
    H.consume.mockImplementation(async () => {
      order.push('credit');
      return { ok: true, remaining: 5, ledger_id: 'L1' };
    });

    const r = await invokeCommercialModel(execCtx(), req, 'k1', TOKEN, {}, async () => {
      order.push('model');
      return 'ran';
    });
    expect(r.ok).toBe(true);
    expect(order).toEqual(['credit', 'model']); // credit first
  });

  it('does not run the model when credit is denied', async () => {
    H.consume.mockResolvedValue({ ok: false, reason: 'insufficient_credits' });

    let ran = false;
    const r = await invokeCommercialModel(execCtx(), req, 'k1', TOKEN, {}, async () => {
      ran = true;
      return 'ran';
    });
    expect(r.ok === false && r.reason).toBe('insufficient_credits');
    expect(ran).toBe(false);
  });

  it('binds a canonical, message-count-independent request hash', async () => {
    const a = await canonicalRequestHash(execCtx(), req);
    const b = await canonicalRequestHash(execCtx(), { ...req, inputHash: 'DIFFERENT' });
    expect(a).not.toBe(b);

    // Same material request → same hash regardless of when it is computed.
    const c = await canonicalRequestHash(execCtx(), req);
    expect(a).toBe(c);
  });

  it('fails closed BEFORE credit consumption when the readiness token is invalid', async () => {
    makeNotReady();

    let ran = false;
    const r = await invokeCommercialModel(execCtx(), req, 'k1', TOKEN, {}, async () => {
      ran = true;
      return 'ran';
    });
    expect(r.ok === false && r.reason).toBe('schema_not_ready');
    expect(H.consume).not.toHaveBeenCalled(); // no credit decrement
    expect(ran).toBe(false); // no model call
  });
});

describe('exportCommercialProject', () => {
  it('requires CODE_EXPORT capability', async () => {
    expect((await exportCommercialProject(execCtx(['CODE_EXPORT']), TOKEN, {})).ok).toBe(true);
    expect((await exportCommercialProject(execCtx([]), TOKEN, {})).ok).toBe(false);
  });

  it('fails closed when the readiness token is invalid', async () => {
    makeNotReady();

    const r = await exportCommercialProject(execCtx(['CODE_EXPORT']), TOKEN, {});
    expect(r.ok === false && r.reason).toBe('schema_not_ready');
  });
});

describe('R6 current-policy authorization blocks stale reviews BEFORE side effects', () => {
  // An approval decided under an OLDER policy version — stale, cannot authorize.
  const staleApproval: GovernanceRecord = {
    projectId: 'p1',
    orgId: 'org1',
    disposition: 'manual_review',
    declarationComplete: true,
    acknowledged: true,
    reviewState: 'approved',
    riskTier: 'T1',
    reviewPolicyVersion: '2020-01-01.old-policy', // stale policy version
    policyCardVersion: currentGovernancePolicyCardVersion(),
    acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
  };

  /*
   * A CURRENT-policy approval that is also FULLY BOUND (R9): the loaded approved-review binding
   * matches the record's Governance + acknowledgment identity + the current required/policy versions.
   */
  const HASH = 'a'.repeat(64);
  const currentApproval: GovernanceRecord = {
    ...staleApproval,
    reviewPolicyVersion: currentReviewPolicyVersion(),
    recordVersion: 4,
    declarationIdentityHash: HASH,
    acknowledgmentRecordId: 'ack-rec-1',
    approvedReview: {
      governanceRecordVersion: 4,
      declarationIdentityHash: HASH,
      acknowledgmentRecordId: 'ack-rec-1',
      acknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
      requiredAcknowledgmentVersion: currentRequiredAcknowledgmentVersion(),
      policyVersion: currentReviewPolicyVersion(),
      requesterUserId: 'u1',
    },
  };

  it('build/model is blocked on a stale approval (no credit consumed, no model run)', async () => {
    H.getGov.mockResolvedValue(staleApproval);

    let ran = false;
    const r = await invokeCommercialModel(execCtx(), req, 'k1', TOKEN, {}, async () => {
      ran = true;
      return 'x';
    });
    expect(r.ok === false && r.reason).toBe('governance_gate_blocked');
    expect(H.consume).not.toHaveBeenCalled();
    expect(ran).toBe(false);
  });

  it('evidence export is blocked on a stale approval', async () => {
    H.getGov.mockResolvedValue(staleApproval);

    const r = await exportCommercialProject(execCtx(['CODE_EXPORT']), TOKEN, {});
    expect(r.ok === false && r.reason).toBe('review_review_stale_policy');
  });

  it('publication is blocked on a stale approval', async () => {
    H.getGov.mockResolvedValue(staleApproval);

    const r = await requestCommercialPublication(execCtx(['PUBLISH_REQUEST'] as never), TOKEN, {});
    expect(r.ok === false && r.reason).toBe('review_review_stale_policy');
  });

  it('a current-policy approval authorizes export + publication', async () => {
    H.getGov.mockResolvedValue(currentApproval);

    expect((await exportCommercialProject(execCtx(['CODE_EXPORT']), TOKEN, {})).ok).toBe(true);
    expect((await requestCommercialPublication(execCtx(['PUBLISH_REQUEST'] as never), TOKEN, {})).ok).toBe(true);
  });
});
