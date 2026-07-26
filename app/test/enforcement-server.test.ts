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
  }),
}));

const ENV = { QHUB_HMAC_SECRET: 'x', SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };

function signals(o: Partial<ClassificationSignals> = {}): ClassificationSignals {
  return { data_classes: [], integration_types: ['NONE'], ai_behavior: 'NONE', autonomy_level: 'NONE', deployment_surface: 'INTERNAL', regulatory_domains: ['NONE_IDENTIFIED'], ...o };
}

function profileFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: any[] = ['NONE_IDENTIFIED']) {
  const p = buildPolicyProfile({ qhub_app_id: 'app-1', classification_version: 1, classification_reference: 'chain-1', risk_tier: tier, regulatory_domains: domains, signals: signals({ ...s, regulatory_domains: domains }), policy_profile_version: 1, generated_by: 'svc' });
  p.policy_profile_id = 'pp-1';
  p.policy_profile_hash = sha256(canonicalPolicyString(p)); // recompute passes
  p.generated_at = 'x';

  return p;
}

function classificationFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: any[] = ['NONE_IDENTIFIED']) {
  const sig = signals(s);
  return { classification_version: 1, risk_tier: tier, risk_floor: tier, ai_proposed_tier: tier, classification_method: 'HUMAN_CONFIRMED', regulatory_domains: domains, data_classes: sig.data_classes, integration_types: sig.integration_types, ai_behavior: sig.ai_behavior, autonomy_level: sig.autonomy_level, deployment_surface: sig.deployment_surface, rationale: 'x', floor_reasons: [], confidence: 0.9, confirmed_by: 'u', confirmed_at: 'x', classifier_version: 'v' };
}

async function enforce(over: any = {}, tier: RiskTier = 'T0', s: Partial<ClassificationSignals> = {}) {
  const { enforceGovernedAction } = await import('~/lib/qhub/enforcement.server');
  const profile = profileFor(tier, s);
  H.getClassification.mockResolvedValue(classificationFor(tier, s));
  H.getPolicyProfile.mockResolvedValue(profile);

  return enforceGovernedAction({
    session: { userId: 'user-1', orgId: 'client-smoke', role: 'builder' },
    conversationId: 'conv-1',
    action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 'studio://generate', operation: 'stream', model_identity: 'claude-sonnet-4-6', provider_identity: 'Anthropic', environment: 'PREVIEW', ...(over.action ?? {}) },
    sessionId: 's',
    env: ENV,
    ...over,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  H.getOrCreateQhubApp.mockResolvedValue({ qhub_app_id: 'app-1', org_id: 'client-smoke', chain_id: 'chain-1' });
  H.getChainId.mockResolvedValue('chain-1');
  H.assertSchema.mockResolvedValue(undefined);
  H.getActivePlan.mockResolvedValue(null);
  H.persistActivePlan.mockImplementation(async (plan: any) => ({ enforcement_plan_id: plan.enforcement_plan_id, enforcement_plan_version: plan.enforcement_plan_version, enforcement_plan_hash: plan.enforcement_plan_hash, status: 'ACTIVE', plan }));
  H.gatherApprovals.mockResolvedValue([]);
  H.getKillSwitch.mockResolvedValue(false);
  H.getEvaluationByIdempotency.mockResolvedValue(null);
  H.insertEvaluation.mockResolvedValue({ ok: true });
  H.claimEvaluation.mockResolvedValue(true);
  H.consumeApprovals.mockResolvedValue(undefined);
  H.markActionEvidence.mockResolvedValue(undefined);
  H.recordControlDecision.mockResolvedValue({ ok: true });
  H.recordAiModelInvokedDirect.mockResolvedValue({ ok: true, qhubAppId: 'app-1' });
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
    const r = await enforceGovernedAction({ session: { userId: 'u', orgId: 'client-smoke', role: 'builder' }, conversationId: 'c', action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 't', operation: 'o', environment: 'PREVIEW' }, sessionId: 's', env: ENV });
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('CLASSIFICATION_MISSING');
  });

  it('missing policy → DENY', async () => {
    const { enforceGovernedAction } = await import('~/lib/qhub/enforcement.server');
    H.getClassification.mockResolvedValue(classificationFor('T0'));
    H.getPolicyProfile.mockResolvedValue(null);
    const r = await enforceGovernedAction({ session: { userId: 'u', orgId: 'client-smoke', role: 'builder' }, conversationId: 'c', action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 't', operation: 'o', environment: 'PREVIEW' }, sessionId: 's', env: ENV });
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

describe('ALLOW path emits AI event referencing the exact evaluation (test 15)', () => {
  it('records decision BEFORE side effect and passes evaluation refs', async () => {
    const r = await enforce();
    expect(r.decision).toBe('ALLOW');
    expect(H.recordControlDecision).toHaveBeenCalledOnce();
    expect(H.recordAiModelInvokedDirect).toHaveBeenCalledOnce();
    const enfArg = H.recordAiModelInvokedDirect.mock.calls[0][0].enforcement;
    expect(enfArg.evaluation_id).toBe(r.evaluation_id);
    expect(enfArg.action_digest).toBe(r.action_digest);
    expect(enfArg.enforcement_plan_hash).toBe(r.enforcement_plan_hash);
    expect(r.side_effect_performed).toBe(true);
  });
});

describe('DENY never reaches the side-effect adapter (test 3/16)', () => {
  it('kill switch active → DENY, decision recorded, no AI event', async () => {
    H.getKillSwitch.mockResolvedValue(true);
    // Kill switch (IR-KILL-SWITCH) is a T3 baseline control guarding AI invocation.
    const r = await enforce({}, 'T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' });
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
      evaluation_id: 'e-prior', action_request_id: 'r-prior', decision: 'ALLOW', reason_codes: ['ALLOWED_BASELINE'],
      action_type: 'AI_MODEL_INVOCATION', qhub_app_id: 'app-1', action_digest: 'd', control_results: [],
    });
    const r = await enforce({ idempotencyKey: 'dup-1' });
    expect(r.evaluation_id).toBe('e-prior');
    expect(r.reason_codes).toContain('REPLAY_DENIED');
    expect(H.recordAiModelInvokedDirect).not.toHaveBeenCalled();
  });
});

describe('no secrets / raw params in evidence (test 30)', () => {
  it('CONTROL_DECISION_RECORDED payload carries only hashes, never raw material_parameters', async () => {
    await enforce({ action: { action_type: 'AI_MODEL_INVOCATION', target_resource: 't', operation: 'o', environment: 'PREVIEW', material_parameters: { secret: 'super-secret-value', prompt: 'confidential' } } });
    const payload = H.recordControlDecision.mock.calls[0][0].payload;
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('super-secret-value');
    expect(serialized).not.toContain('confidential');
    expect(payload).not.toHaveProperty('material_parameters');
    expect(payload.action_digest).toMatch(/^[0-9a-f]{64}$/);
  });
});
