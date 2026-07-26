/**
 * QHUB Gate 04 — central entry point integration/adversarial tests
 * app/test/enforcement-server.test.ts
 *
 * Mocks the durable layer + governance ledger to exercise enforceGovernedAction:
 * fail-closed preconditions, DENY-no-side-effect, decision-ledger-failure,
 * single-use claim, idempotency dedup, cross-tenant block, action-event
 * references, and no-raw-params-in-evidence.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { buildPolicyProfile, canonicalPolicyString } from '~/lib/qhub/policy-engine';
import type { ClassificationSignals, RiskTier } from '~/lib/qhub/classification';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const H = vi.hoisted(() => ({
  getOrCreateQhubApp: vi.fn(),
  getChainId: vi.fn(),
  getClassification: vi.fn(),
  getPolicyProfile: vi.fn(),
  assertSchema: vi.fn(),
  getActivePlan: vi.fn(),
  persistActivePlan: vi.fn(),
  gatherApprovals: vi.fn(),
  getKillSwitch: vi.fn(),
  getEvaluationByIdempotency: vi.fn(),
  insertEvaluation: vi.fn(),
  claimEvaluation: vi.fn(),
  consumeApprovals: vi.fn(),
  markActionEvidence: vi.fn(),
  recordControlDecision: vi.fn(),
  recordAiModelInvokedDirect: vi.fn(),
  recordGovernedActionReceipt: vi.fn(),
  providerInvoke: vi.fn(),
}));

vi.mock('~/lib/qhub/qhub-app.server', () => ({
  getOrCreateQhubApp: H.getOrCreateQhubApp,
  getChainId: H.getChainId,
  getClassification: H.getClassification,
  getPolicyProfile: H.getPolicyProfile,
}));
vi.mock('~/lib/qhub/schema-check.server', () => ({
  assertGovernanceSchemaReady: H.assertSchema,
  SchemaNotReadyError: class extends Error {},
}));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({
  getActivePlan: H.getActivePlan,
  persistActivePlan: H.persistActivePlan,
  gatherApprovals: H.gatherApprovals,
  getKillSwitch: H.getKillSwitch,
  getEvaluationByIdempotency: H.getEvaluationByIdempotency,
  insertEvaluation: H.insertEvaluation,
  claimEvaluation: H.claimEvaluation,
  consumeApprovalsForDigest: H.consumeApprovals,
  markActionEvidence: H.markActionEvidence,
}));
vi.mock('~/lib/qhub/governance-service.server', () => ({
  createGovernanceService: () => ({
    recordControlDecision: H.recordControlDecision,
    recordAiModelInvokedDirect: H.recordAiModelInvokedDirect,
    recordGovernedActionReceipt: H.recordGovernedActionReceipt,
  }),
}));

const ENV = { QHUB_HMAC_SECRET: 'x', SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };
const SIM_ENV = {
  ...ENV,
  QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS: '1',
  QHUB_DEPLOY_ENV: 'staging',
  FLY_APP_NAME: 'qhub-studio',
  QHUB_PUBLIC_HOSTNAME: 'qhub-studio.fly.dev',
  SUPABASE_URL: 'https://jsjsanmaahvmynblmzkq.supabase.co',
};

function signals(o: Partial<ClassificationSignals> = {}): ClassificationSignals {
  return {
    data_classes: [],
    integration_types: ['NONE'],
    ai_behavior: 'NONE',
    autonomy_level: 'NONE',
    deployment_surface: 'INTERNAL',
    regulatory_domains: ['NONE_IDENTIFIED'],
    ...o,
  };
}

function profileFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: any[] = ['NONE_IDENTIFIED']) {
  const p = buildPolicyProfile({
    qhub_app_id: 'app-1',
    classification_version: 1,
    classification_reference: 'chain-1',
    risk_tier: tier,
    regulatory_domains: domains,
    signals: signals({ ...s, regulatory_domains: domains }),
    policy_profile_version: 1,
    generated_by: 'svc',
  });
  p.policy_profile_id = 'pp-1';
  p.policy_profile_hash = sha256(canonicalPolicyString(p)); // recompute passes
  p.generated_at = 'x';

  return p;
}

function classificationFor(
  tier: RiskTier,
  s: Partial<ClassificationSignals> = {},
  domains: any[] = ['NONE_IDENTIFIED'],
) {
  const sig = signals(s);
  return {
    classification_version: 1,
    risk_tier: tier,
    risk_floor: tier,
    ai_proposed_tier: tier,
    classification_method: 'HUMAN_CONFIRMED',
    regulatory_domains: domains,
    data_classes: sig.data_classes,
    integration_types: sig.integration_types,
    ai_behavior: sig.ai_behavior,
    autonomy_level: sig.autonomy_level,
    deployment_surface: sig.deployment_surface,
    rationale: 'x',
    floor_reasons: [],
    confidence: 0.9,
    confirmed_by: 'u',
    confirmed_at: 'x',
    classifier_version: 'v',
  };
}

async function enforce(over: any = {}, tier: RiskTier = 'T0', s: Partial<ClassificationSignals> = {}) {
  const { enforceGovernedAction } = await import('~/lib/qhub/enforcement.server');
  const profile = profileFor(tier, s);
  H.getClassification.mockResolvedValue(classificationFor(tier, s));
  H.getPolicyProfile.mockResolvedValue(profile);

  return enforceGovernedAction({
    session: { userId: 'user-1', orgId: 'client-smoke', role: 'builder' },
    conversationId: 'conv-1',
    action: {
      action_type: 'AI_MODEL_INVOCATION',
      target_resource: 'studio://generate',
      operation: 'stream',
      model_identity: 'claude-sonnet-4-6',
      provider_identity: 'Anthropic',
      environment: 'PREVIEW',
      ...(over.action ?? {}),
    },
    sessionId: 's',
    env: ENV,
    internalExecution: {
      action_type: 'AI_MODEL_INVOCATION',
      invoke: H.providerInvoke,
    },
    ...over,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  H.getOrCreateQhubApp.mockResolvedValue({ qhub_app_id: 'app-1', org_id: 'client-smoke', chain_id: 'chain-1' });
  H.getChainId.mockResolvedValue('chain-1');
  H.assertSchema.mockResolvedValue(undefined);
  H.getActivePlan.mockResolvedValue(null);
  H.persistActivePlan.mockImplementation(async (plan: any) => ({
    enforcement_plan_id: plan.enforcement_plan_id,
    org_id: 'client-smoke',
    qhub_app_id: plan.qhub_app_id,
    enforcement_plan_version: plan.enforcement_plan_version,
    policy_profile_id: plan.policy_profile_id,
    policy_profile_hash: plan.policy_profile_hash,
    enforcement_plan_hash: plan.enforcement_plan_hash,
    status: 'ACTIVE',
    plan,
  }));
  H.gatherApprovals.mockResolvedValue([]);
  H.getKillSwitch.mockResolvedValue(false);
  H.getEvaluationByIdempotency.mockResolvedValue(null);
  H.insertEvaluation.mockResolvedValue({ ok: true });
  H.claimEvaluation.mockResolvedValue(true);
  H.consumeApprovals.mockResolvedValue(true);
  H.markActionEvidence.mockResolvedValue(true);
  H.recordControlDecision.mockResolvedValue({ ok: true });
  H.recordAiModelInvokedDirect.mockResolvedValue({ ok: true, qhubAppId: 'app-1' });
  H.recordGovernedActionReceipt.mockResolvedValue({ ok: true, eventId: 'event-1', eventHash: 'a'.repeat(64), seq: 4 });
  H.providerInvoke.mockResolvedValue({ stream: true });
});

describe('fail-closed preconditions block (tests 19-22)', () => {
  it('schema not ready → DENY, no decision event, no side effect', async () => {
    H.assertSchema.mockRejectedValue(new Error('drift'));

    const r = await enforce();
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('SCHEMA_NOT_READY');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
  });

  it('missing classification → DENY', async () => {
    const { enforceGovernedAction } = await import('~/lib/qhub/enforcement.server');
    H.getClassification.mockResolvedValue(null);
    H.getPolicyProfile.mockResolvedValue(profileFor('T0'));

    const r = await enforceGovernedAction({
      session: { userId: 'u', orgId: 'client-smoke', role: 'builder' },
      conversationId: 'c',
      action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 't', operation: 'o', environment: 'PREVIEW' },
      sessionId: 's',
      env: ENV,
    });
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('CLASSIFICATION_MISSING');
  });

  it('missing policy → DENY', async () => {
    const { enforceGovernedAction } = await import('~/lib/qhub/enforcement.server');
    H.getClassification.mockResolvedValue(classificationFor('T0'));
    H.getPolicyProfile.mockResolvedValue(null);

    const r = await enforceGovernedAction({
      session: { userId: 'u', orgId: 'client-smoke', role: 'builder' },
      conversationId: 'c',
      action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 't', operation: 'o', environment: 'PREVIEW' },
      sessionId: 's',
      env: ENV,
    });
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('POLICY_MISSING');
  });

  it('cross-tenant app ownership → DENY (tests 10/11)', async () => {
    H.getOrCreateQhubApp.mockResolvedValue({ qhub_app_id: 'app-1', org_id: 'OTHER-ORG', chain_id: 'chain-1' });

    const r = await enforce();
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('TENANT_MISMATCH');
  });
});

describe('durable enforcement plan binding', () => {
  function storedPlan(plan: any) {
    return {
      enforcement_plan_id: plan.enforcement_plan_id,
      org_id: 'client-smoke',
      qhub_app_id: plan.qhub_app_id,
      enforcement_plan_version: plan.enforcement_plan_version,
      policy_profile_id: plan.policy_profile_id,
      policy_profile_hash: plan.policy_profile_hash,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'ACTIVE',
      plan,
    };
  }

  it('plan persistence failure emits no decision or action event', async () => {
    H.persistActivePlan.mockResolvedValue(null);

    const r = await enforce();
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('PLAN_COMPILE_FAILED');
    expect(H.insertEvaluation).not.toHaveBeenCalled();
    expect(H.recordControlDecision).not.toHaveBeenCalled();
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
  });

  it('rejects a persisted plan whose durable id differs from its plan body', async () => {
    H.persistActivePlan.mockImplementation(async (plan: any) => ({
      enforcement_plan_id: 'different-database-id',
      org_id: 'client-smoke',
      qhub_app_id: plan.qhub_app_id,
      enforcement_plan_version: plan.enforcement_plan_version,
      policy_profile_id: plan.policy_profile_id,
      policy_profile_hash: plan.policy_profile_hash,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'ACTIVE',
      plan,
    }));

    const r = await enforce();
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('PLAN_COMPILE_FAILED');
    expect(H.insertEvaluation).not.toHaveBeenCalled();
    expect(H.recordControlDecision).not.toHaveBeenCalled();
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
  });

  it('rejects cross-tenant and wrong-app stored plan reuse', async () => {
    H.getActivePlan.mockResolvedValue({
      enforcement_plan_id: 'plan-1',
      org_id: 'other-tenant',
      qhub_app_id: 'other-app',
      enforcement_plan_version: 1,
      policy_profile_id: null,
      policy_profile_hash: 'policy-hash',
      enforcement_plan_hash: 'plan-hash',
      status: 'ACTIVE',
      plan: {
        enforcement_plan_id: 'plan-1',
        qhub_app_id: 'other-app',
        policy_profile_id: null,
        policy_profile_hash: 'policy-hash',
        enforcement_plan_hash: 'plan-hash',
      },
    });

    const r = await enforce();
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('PLAN_HASH_MISMATCH');
    expect(H.insertEvaluation).not.toHaveBeenCalled();
  });

  it('reuses the durable identity of an identical active plan after restart', async () => {
    const first = await enforce();
    const compiled = H.persistActivePlan.mock.calls[0][0];
    H.getActivePlan.mockResolvedValue(storedPlan(compiled));
    H.persistActivePlan.mockClear();

    const afterRestart = await enforce();

    expect(afterRestart.enforcement_plan_id).toBe(first.enforcement_plan_id);
    expect(H.persistActivePlan).not.toHaveBeenCalled();
  });

  it('persists a new durable plan when the policy profile changes', async () => {
    await enforce({}, 'T0');

    const prior = H.persistActivePlan.mock.calls[0][0];
    H.getActivePlan.mockResolvedValue(storedPlan(prior));
    H.persistActivePlan.mockClear();

    await enforce({}, 'T1');

    expect(H.persistActivePlan).toHaveBeenCalledOnce();
    expect(H.persistActivePlan.mock.calls[0][0].policy_profile_hash).not.toBe(prior.policy_profile_hash);
  });

  it('rejects a stored plan hash mismatch before evaluation persistence', async () => {
    await enforce();

    const prior = H.persistActivePlan.mock.calls[0][0];
    const tampered = { ...prior, enforcement_plan_hash: '0'.repeat(64) };
    H.getActivePlan.mockResolvedValue(storedPlan(tampered));
    H.insertEvaluation.mockClear();

    const r = await enforce();

    expect(r.reason_codes).toContain('PLAN_HASH_MISMATCH');
    expect(H.insertEvaluation).not.toHaveBeenCalled();
  });
});

describe('ALLOW path emits AI event referencing the exact evaluation (test 15)', () => {
  it('records decision BEFORE side effect and passes evaluation refs', async () => {
    const r = await enforce();
    expect(r.decision).toBe('ALLOW');
    expect(H.recordControlDecision).toHaveBeenCalledOnce();
    expect(H.recordAiModelInvokedDirect).toHaveBeenCalledOnce();
    expect(H.providerInvoke).toHaveBeenCalledOnce();

    const enfArg = H.recordAiModelInvokedDirect.mock.calls[0][0].enforcement;
    expect(enfArg.evaluation_id).toBe(r.evaluation_id);
    expect(enfArg.action_digest).toBe(r.action_digest);
    expect(enfArg.enforcement_plan_hash).toBe(r.enforcement_plan_hash);
    expect(r.side_effect_performed).toBe(true);
    expect(r.internal_execution_result).toEqual({ stream: true });
  });

  it('does not emit AI_MODEL_INVOKED when the provider invocation fails', async () => {
    H.providerInvoke.mockRejectedValue(new Error('provider unavailable'));

    const r = await enforce();

    expect(r.execution_status).toBe('FAILED');
    expect(r.reason_codes).toContain('ADAPTER_EXECUTION_FAILED');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(H.markActionEvidence).toHaveBeenCalledWith(expect.any(String), 'client-smoke', 'FAILED', ENV);
  });

  it('provider invocation precedes AI_MODEL_INVOKED evidence', async () => {
    const order: string[] = [];
    H.providerInvoke.mockImplementation(async () => {
      order.push('provider');

      return { stream: true };
    });
    H.recordAiModelInvokedDirect.mockImplementation(async () => {
      order.push('event');

      return { ok: true };
    });

    await enforce();
    expect(order).toEqual(['provider', 'event']);
  });
});

describe('DENY never reaches the side-effect adapter (test 3/16)', () => {
  it('kill switch active → DENY, decision recorded, no AI event', async () => {
    H.getKillSwitch.mockResolvedValue(true);

    // Kill switch (IR-KILL-SWITCH) is a T3 baseline control guarding AI invocation.
    const r = await enforce({}, 'T3', {
      data_classes: ['MNPI'],
      integration_types: ['TRADING_OR_ORDERS'],
      autonomy_level: 'AUTONOMOUS',
      deployment_surface: 'PRODUCTION',
    });
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('KILL_SWITCH_ACTIVE');
    expect(H.recordControlDecision).toHaveBeenCalledOnce(); // DENY IS recorded
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(r.side_effect_performed).toBe(false);
  });
});

describe('decision-ledger failure prevents execution (test 14)', () => {
  it('recordControlDecision ok:false → no side effect', async () => {
    H.recordControlDecision.mockResolvedValue({ ok: false });

    const r = await enforce();
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(r.side_effect_performed).toBe(false);
    expect(r.reason_codes).toContain('DECISION_RECORD_FAILED');
  });
});

describe('approval-consumption failure prevents execution', () => {
  it('fails closed before the protected side effect', async () => {
    H.consumeApprovals.mockResolvedValue(false);

    const r = await enforce();
    expect(r.reason_codes).toContain('APPROVAL_CONSUMPTION_FAILED');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(r.side_effect_performed).toBe(false);
  });
});

describe('single-use claim / replay (tests 2/13)', () => {
  it('claim already taken → no second side effect', async () => {
    H.claimEvaluation.mockResolvedValue(false);

    const r = await enforce();
    expect(r.reason_codes).toContain('REPLAY_DENIED');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(r.side_effect_performed).toBe(false);
  });

  it('idempotency dedup → duplicate returns prior decision, no re-execute', async () => {
    H.getEvaluationByIdempotency.mockResolvedValue({
      evaluation_id: 'e-prior',
      action_request_id: 'r-prior',
      decision: 'ALLOW',
      reason_codes: ['ALLOWED_BASELINE'],
      action_type: 'AI_MODEL_INVOCATION',
      qhub_app_id: 'app-1',
      action_digest: 'd',
      control_results: [],
    });

    const r = await enforce({ idempotencyKey: 'dup-1' });
    expect(r.evaluation_id).toBe('e-prior');
    expect(r.reason_codes).toContain('REPLAY_DENIED');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
  });
});

describe('durable staging governed-action receipts', () => {
  it('records exactly one external-transmission simulation receipt after claim', async () => {
    const r = await enforce(
      {
        conversationId: 'gate04-r2-receipt-test',
        env: SIM_ENV,
        action: {
          action_type: 'EXTERNAL_DATA_TRANSMISSION',
          target_resource: 'https://commission-staging-noop.invalid/reconcile',
          operation: 'write_simulation',
          material_parameters: { synthetic: true, dataset: 'redacted', mode: 'no-op' },
          environment: 'PREVIEW',
          app_version_ref: 'gate04-r2-receipt-test',
        },
      },
      'T0',
      { integration_types: ['BUSINESS_SYSTEM_WRITE'] },
    );

    expect(r.decision).toBe('ALLOW');
    expect(r.adapter_executed).toBe(true);
    expect(r.external_effect_performed).toBe(false);
    expect(r.side_effect_performed).toBe(false);
    expect(r.execution_mode).toBe('SIMULATION');
    expect(r.execution_status).toBe('SIMULATED_SUCCESS');
    expect(r.receipt?.evaluation_id).toBe(r.evaluation_id);
    expect(r.receipt?.action_request_id).toBe(r.action_request_id);
    expect(r.receipt?.action_digest).toBe(r.action_digest);
    expect(H.recordGovernedActionReceipt).toHaveBeenCalledOnce();
    expect(H.markActionEvidence).toHaveBeenCalledWith(r.evaluation_id, 'client-smoke', 'COMMITTED', SIM_ENV);

    const evidence = JSON.stringify(H.recordGovernedActionReceipt.mock.calls[0][0]);
    expect(evidence).not.toContain('redacted');
    expect(evidence).not.toContain('material_parameters');
  });

  it('receipt-ingest failure does not report success and preserves the single-use claim', async () => {
    H.recordGovernedActionReceipt.mockResolvedValue({ ok: false });

    const r = await enforce(
      {
        conversationId: 'gate04-r2-receipt-failure',
        env: SIM_ENV,
        action: {
          action_type: 'EXTERNAL_DATA_TRANSMISSION',
          target_resource: 'https://commission-staging-noop.invalid/reconcile',
          operation: 'write_simulation',
          material_parameters: { synthetic: true },
          environment: 'PREVIEW',
          app_version_ref: 'gate04-r2-receipt-failure',
        },
      },
      'T0',
      { integration_types: ['BUSINESS_SYSTEM_WRITE'] },
    );

    expect(r.reason_codes).toContain('RECEIPT_RECORD_FAILED');
    expect(r.execution_status).toBe('FAILED');
    expect(r.receipt).toBeNull();
    expect(r.evidence_recorded).toBe(false);
    expect(H.claimEvaluation).toHaveBeenCalledOnce();
    expect(H.markActionEvidence).toHaveBeenCalledWith(r.evaluation_id, 'client-smoke', 'FAILED', SIM_ENV);
  });

  it('adapter failure does not report success or emit a receipt event', async () => {
    const { getGovernedActionAdapter } = await import('~/lib/qhub/governed-action-adapters.server');
    const adapter = getGovernedActionAdapter('EXTERNAL_DATA_TRANSMISSION')!;
    const execute = vi.spyOn(adapter, 'execute').mockRejectedValueOnce(new Error('synthetic adapter failure'));

    const r = await enforce(
      {
        conversationId: 'gate04-r2-adapter-failure',
        env: SIM_ENV,
        action: {
          action_type: 'EXTERNAL_DATA_TRANSMISSION',
          target_resource: 'https://commission-staging-noop.invalid/reconcile',
          operation: 'write_simulation',
          material_parameters: { synthetic: true },
          environment: 'PREVIEW',
          app_version_ref: 'gate04-r2-adapter-failure',
        },
      },
      'T0',
      { integration_types: ['BUSINESS_SYSTEM_WRITE'] },
    );

    expect(r.execution_status).toBe('FAILED');
    expect(r.reason_codes).toContain('ADAPTER_EXECUTION_FAILED');
    expect(r.receipt).toBeNull();
    expect(r.side_effect_performed).toBe(false);
    expect(H.recordGovernedActionReceipt).not.toHaveBeenCalled();
    execute.mockRestore();
  });

  it('a failed COMMITTED transition does not return a successful receipt', async () => {
    H.markActionEvidence.mockResolvedValueOnce(false).mockResolvedValueOnce(true);

    const r = await enforce(
      {
        conversationId: 'gate04-r2-state-failure',
        env: SIM_ENV,
        action: {
          action_type: 'EXTERNAL_DATA_TRANSMISSION',
          target_resource: 'https://commission-staging-noop.invalid/reconcile',
          operation: 'write_simulation',
          material_parameters: { synthetic: true },
          environment: 'PREVIEW',
          app_version_ref: 'gate04-r2-state-failure',
        },
      },
      'T0',
      { integration_types: ['BUSINESS_SYSTEM_WRITE'] },
    );

    expect(H.recordGovernedActionReceipt).toHaveBeenCalledOnce();
    expect(r.reason_codes).toContain('RECEIPT_RECORD_FAILED');
    expect(r.execution_status).toBe('FAILED');
    expect(r.receipt).toBeNull();
    expect(r.evidence_recorded).toBe(false);
  });

  it('missing adapter converts a would-be ALLOW to DENY before the claim', async () => {
    const r = await enforce({ internalExecution: undefined });

    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toEqual(['ADAPTER_NOT_CONFIGURED']);
    expect(H.recordControlDecision).toHaveBeenCalledOnce();
    expect(H.claimEvaluation).not.toHaveBeenCalled();
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
    expect(H.recordGovernedActionReceipt).not.toHaveBeenCalled();
  });

  it('a replay result never executes an adapter or records a second receipt', async () => {
    H.getEvaluationByIdempotency.mockResolvedValue({
      evaluation_id: 'e-prior',
      action_request_id: 'r-prior',
      decision: 'ALLOW',
      reason_codes: ['ALLOWED_BASELINE'],
      action_type: 'EXTERNAL_DATA_TRANSMISSION',
      qhub_app_id: 'app-1',
      action_digest: 'd',
      control_results: [],
    });

    const r = await enforce({
      idempotencyKey: 'duplicate',
      conversationId: 'gate04-r2-replay',
      env: SIM_ENV,
      action: {
        action_type: 'EXTERNAL_DATA_TRANSMISSION',
        target_resource: 'https://commission-staging-noop.invalid/reconcile',
        operation: 'write_simulation',
        material_parameters: { synthetic: true },
        environment: 'PREVIEW',
        app_version_ref: 'gate04-r2-replay',
      },
    });

    expect(r.reason_codes).toContain('REPLAY_DENIED');
    expect(r.receipt).toBeNull();
    expect(H.claimEvaluation).not.toHaveBeenCalled();
    expect(H.recordGovernedActionReceipt).not.toHaveBeenCalled();
  });

  it('concurrent duplicate requests create at most one durable receipt', async () => {
    let authoritative: any = null;
    H.insertEvaluation.mockImplementation(async (row: any) => {
      if (!authoritative) {
        authoritative = row;

        return { ok: true };
      }

      return { ok: false, duplicate: true, existing: authoritative };
    });

    const request = {
      idempotencyKey: 'concurrent-duplicate',
      conversationId: 'gate04-r2-concurrent',
      env: SIM_ENV,
      action: {
        action_type: 'EXTERNAL_DATA_TRANSMISSION',
        target_resource: 'https://commission-staging-noop.invalid/reconcile',
        operation: 'write_simulation',
        material_parameters: { synthetic: true },
        environment: 'PREVIEW',
        app_version_ref: 'gate04-r2-concurrent',
      },
    };

    const [first, second] = await Promise.all([
      enforce(request, 'T0', { integration_types: ['BUSINESS_SYSTEM_WRITE'] }),
      enforce(request, 'T0', { integration_types: ['BUSINESS_SYSTEM_WRITE'] }),
    ]);

    expect([first, second].filter((result) => result.receipt)).toHaveLength(1);
    expect(H.recordGovernedActionReceipt).toHaveBeenCalledOnce();
    expect([first, second].some((result) => result.reason_codes.includes('REPLAY_DENIED'))).toBe(true);
  });
});

describe('no secrets / raw params in evidence (test 30)', () => {
  it('CONTROL_DECISION_RECORDED payload carries only hashes, never raw material_parameters', async () => {
    await enforce({
      action: {
        action_type: 'AI_MODEL_INVOCATION',
        target_resource: 't',
        operation: 'o',
        environment: 'PREVIEW',
        material_parameters: { secret: 'super-secret-value', prompt: 'confidential' },
      },
    });

    const payload = H.recordControlDecision.mock.calls[0][0].payload;
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('super-secret-value');
    expect(serialized).not.toContain('confidential');
    expect(payload).not.toHaveProperty('material_parameters');
    expect(payload.action_digest).toMatch(/^[0-9a-f]{64}$/);
  });
});
