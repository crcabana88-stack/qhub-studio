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

const H = vi.hoisted(() => ({ getGov: vi.fn(), consume: vi.fn(), ready: vi.fn() }));

vi.mock('~/lib/qhub/commercial/governance-essentials.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/governance-essentials.server')>();
  return { ...actual, getGovernanceRecord: H.getGov };
});
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({ consumeBuildCredit: H.consume }));

// Deterministic readiness injection (no production bypass — the module is mocked).
vi.mock('~/lib/qhub/commercial/commercial-schema-check.server', () => ({
  getCommercialSchemaReadiness: H.ready,
}));

const READY = {
  state: 'READY',
  expected: '2026-07-30.commercial-launch-r4',
  version: '2026-07-30.commercial-launch-r4',
  failed: [],
  checkedAt: 0,
};
const NOT_READY = {
  state: 'NOT_READY',
  expected: '2026-07-30.commercial-launch-r4',
  failed: ['version_mismatch'],
  checkedAt: 0,
};

import {
  invokeCommercialModel,
  canonicalRequestHash,
  exportCommercialProject,
} from '~/lib/qhub/commercial/commercial-service.server';

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
  H.ready.mockResolvedValue(READY);
});

describe('invokeCommercialModel', () => {
  it('rejects a non-execution context (no project binding)', async () => {
    const bad = { userId: 'u1', capabilities: new Set(['MODEL_INVOKE']) } as never;
    const r = await invokeCommercialModel(bad, req, 'k1', {}, async () => 'ran');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toBe('missing_execution_context');
  });

  it('rejects without the MODEL_INVOKE capability', async () => {
    const r = await invokeCommercialModel(execCtx([]), req, 'k1', {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('capability_denied');
    expect(H.consume).not.toHaveBeenCalled();
  });

  it('blocks when the Governance Essentials gate is not satisfied', async () => {
    H.getGov.mockResolvedValue({ ...goodGov, acknowledged: false });

    const r = await invokeCommercialModel(execCtx(), req, 'k1', {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('governance_gate_blocked');
    expect(H.consume).not.toHaveBeenCalled();
  });

  it('blocks a suspended context', async () => {
    const ctx = { ...execCtx(), suspended: true };
    const r = await invokeCommercialModel(ctx, req, 'k1', {}, async () => 'ran');
    expect(r.ok === false && r.reason).toBe('suspended');
  });

  it('consumes credit BEFORE running the model and returns the balance', async () => {
    const order: string[] = [];
    H.consume.mockImplementation(async () => {
      order.push('credit');
      return { ok: true, remaining: 5, ledger_id: 'L1' };
    });

    const r = await invokeCommercialModel(execCtx(), req, 'k1', {}, async () => {
      order.push('model');
      return 'ran';
    });
    expect(r.ok).toBe(true);
    expect(order).toEqual(['credit', 'model']); // credit first
  });

  it('does not run the model when credit is denied', async () => {
    H.consume.mockResolvedValue({ ok: false, reason: 'insufficient_credits' });

    let ran = false;
    const r = await invokeCommercialModel(execCtx(), req, 'k1', {}, async () => {
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

  it('fails closed BEFORE credit consumption when the schema is NOT READY', async () => {
    H.ready.mockResolvedValue(NOT_READY);

    let ran = false;
    const r = await invokeCommercialModel(execCtx(), req, 'k1', {}, async () => {
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
    expect((await exportCommercialProject(execCtx(['CODE_EXPORT']), {})).ok).toBe(true);
    expect((await exportCommercialProject(execCtx([]), {})).ok).toBe(false);
  });

  it('fails closed when the schema is NOT READY', async () => {
    H.ready.mockResolvedValue(NOT_READY);

    const r = await exportCommercialProject(execCtx(['CODE_EXPORT']), {});
    expect(r.ok === false && r.reason).toBe('schema_not_ready');
  });
});
