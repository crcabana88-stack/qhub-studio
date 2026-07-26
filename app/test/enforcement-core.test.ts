/**
 * QHUB Gate 04 — deterministic core tests (digest, plan hash, compiler, engine)
 * app/test/enforcement-core.test.ts
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import type { ClassificationResult, ClassificationSignals, RegulatoryDomain, RiskTier } from '~/lib/qhub/classification';
import { buildPolicyProfile, type PolicyEngineInput } from '~/lib/qhub/policy-engine';
import type { PolicyProfile } from '~/lib/qhub/policy';
import { compileEnforcementPlan, canonicalEnforcementPlanString, canonicalActionRequestString } from '~/lib/qhub/enforcement-plan';
import { evaluate } from '~/lib/qhub/enforcement-decision';
import type { CanonicalActionRequest, DecisionEngineInput, GatheredApproval, GovernedActionType } from '~/lib/qhub/enforcement';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function signals(overrides: Partial<ClassificationSignals> = {}): ClassificationSignals {
  return {
    data_classes: [],
    integration_types: ['NONE'],
    ai_behavior: 'NONE',
    autonomy_level: 'NONE',
    deployment_surface: 'INTERNAL',
    regulatory_domains: ['NONE_IDENTIFIED'],
    ...overrides,
  };
}

function classification(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: RegulatoryDomain[] = ['NONE_IDENTIFIED']): ClassificationResult {
  const sig = signals({ ...s, regulatory_domains: domains });
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
    confirmed_by: 'user-1',
    confirmed_at: '2026-07-26T00:00:00Z',
    classifier_version: 'gate02-classifier-1.0.0',
  };
}

function profileFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: RegulatoryDomain[] = ['NONE_IDENTIFIED']): PolicyProfile {
  const input: PolicyEngineInput = {
    qhub_app_id: 'app-1',
    classification_version: 1,
    classification_reference: 'chain-1',
    risk_tier: tier,
    regulatory_domains: domains,
    signals: signals({ ...s, regulatory_domains: domains }),
    policy_profile_version: 1,
    generated_by: 'svc',
  };
  const p = buildPolicyProfile(input);
  p.policy_profile_id = 'pp-1';
  p.policy_profile_hash = sha256('policy-' + tier);
  p.generated_at = '2026-07-26T00:00:00Z';

  return p;
}

function planFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, domains: RegulatoryDomain[] = ['NONE_IDENTIFIED']) {
  const profile = profileFor(tier, s, domains);
  const plan = compileEnforcementPlan({ profile, classification: classification(tier, s, domains), enforcement_plan_version: 1 });
  plan.enforcement_plan_id = 'ep-1';
  plan.generated_at = '2026-07-26T00:00:00Z';
  plan.enforcement_plan_hash = sha256(canonicalEnforcementPlanString(plan));

  return plan;
}

function request(plan: ReturnType<typeof planFor>, action: GovernedActionType, over: Partial<CanonicalActionRequest> = {}): CanonicalActionRequest {
  return {
    tenant_id: 'client-smoke',
    qhub_app_id: 'app-1',
    action_request_id: 'req-1',
    action_type: action,
    target_resource: 'studio://generate',
    operation: 'invoke',
    material_parameters_hash: sha256('params-1'),
    model_identity: 'claude-sonnet-4-6',
    provider_identity: 'Anthropic',
    tool_identity: null,
    environment: 'PREVIEW',
    app_version_ref: null,
    policy_profile_id: plan.policy_profile_id,
    policy_profile_version: plan.policy_profile_version,
    policy_profile_hash: plan.policy_profile_hash,
    enforcement_plan_id: plan.enforcement_plan_id,
    enforcement_plan_version: plan.enforcement_plan_version,
    enforcement_plan_hash: plan.enforcement_plan_hash,
    ...over,
  };
}

function digestOf(r: CanonicalActionRequest): string {
  return sha256(canonicalActionRequestString(r));
}

function evalInput(plan: ReturnType<typeof planFor>, req: CanonicalActionRequest, over: Partial<DecisionEngineInput> = {}): DecisionEngineInput {
  return {
    request: req,
    action_digest: digestOf(req),
    plan,
    risk_tier: plan.risk_tier,
    environment: req.environment,
    autonomy_requested: 'NONE',
    kill_switch_active: false,
    approvals: [],
    limit_usage: {},
    actor_id: 'user-1',
    actor_role: 'builder',
    ...over,
  };
}

// ─── Action digest ────────────────────────────────────────────────────────────

describe('action digest', () => {
  const plan = planFor('T0', { data_classes: ['PUBLIC'] });

  it('is stable for identical input (test 24)', () => {
    const r = request(plan, 'AI_MODEL_INVOCATION');
    expect(digestOf(r)).toBe(digestOf({ ...r }));
  });

  it('changes when material parameters change (test 26)', () => {
    const a = request(plan, 'AI_MODEL_INVOCATION', { material_parameters_hash: sha256('A') });
    const b = request(plan, 'AI_MODEL_INVOCATION', { material_parameters_hash: sha256('B') });
    expect(digestOf(a)).not.toBe(digestOf(b));
  });

  it('changes when action_type / target / environment change', () => {
    const base = request(plan, 'AI_MODEL_INVOCATION');
    expect(digestOf(base)).not.toBe(digestOf(request(plan, 'AI_MODEL_INVOCATION', { target_resource: 'studio://other' })));
    expect(digestOf(base)).not.toBe(digestOf(request(plan, 'AI_MODEL_INVOCATION', { environment: 'PRODUCTION' })));
  });
});

// ─── Enforcement plan hash ────────────────────────────────────────────────────

describe('enforcement plan hash', () => {
  it('is stable for identical canonical input (test 25)', () => {
    const a = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] });
    const b = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] });
    expect(canonicalEnforcementPlanString(a)).toBe(canonicalEnforcementPlanString(b));
  });

  it('changes when the policy profile hash changes (test 8/9 — revision invalidates)', () => {
    const a = planFor('T2', { data_classes: ['CLIENT_PII'] });
    const b = profileFor('T2', { data_classes: ['CLIENT_PII'] });
    b.policy_profile_hash = sha256('policy-REVISED');
    const bPlan = compileEnforcementPlan({ profile: b, classification: classification('T2', { data_classes: ['CLIENT_PII'] }), enforcement_plan_version: 2 });
    expect(canonicalEnforcementPlanString(a)).not.toBe(canonicalEnforcementPlanString(bPlan));
  });
});

// ─── Compiler ─────────────────────────────────────────────────────────────────

describe('plan compiler', () => {
  it('T0: only AI invocation is protected; no approvals/limits/kill-switch', () => {
    const p = planFor('T0', { data_classes: ['PUBLIC'] });
    expect(p.protected_action_types).toEqual(['AI_MODEL_INVOCATION']);
    expect(p.approval_requirements).toHaveLength(0);
    expect(p.kill_switch_required).toBe(false);
  });

  it('T2: owner attestation requirement; external + db actions protected', () => {
    const p = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, ['BOOKS_AND_RECORDS', 'SEC']);
    expect(p.protected_action_types).toEqual(expect.arrayContaining(['AI_MODEL_INVOCATION', 'EXTERNAL_DATA_TRANSMISSION', 'DATABASE_MUTATION']));
    expect(p.approval_requirements.map((r) => r.attestation_type)).toContain('OWNER_ATTESTATION');
  });

  it('T3: preview-only, kill switch, dual control, no-unrestricted-autonomy', () => {
    const p = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    expect(p.kill_switch_required).toBe(true);
    expect(p.preview_only_actions.length).toBeGreaterThan(0);
    expect(p.no_unrestricted_autonomy_actions).toContain('TRADING_OR_ORDER_ROUTING');
    expect(p.approval_requirements.some((r) => r.requirement_id === 'REQ-DUAL' && r.min_approvals === 2)).toBe(true);
  });
});

// ─── Decision engine ──────────────────────────────────────────────────────────

describe('decision engine', () => {
  it('A/T0: AI invocation ALLOWs at baseline', () => {
    const plan = planFor('T0', { data_classes: ['PUBLIC'] });
    const r = evaluate(evalInput(plan, request(plan, 'AI_MODEL_INVOCATION')));
    expect(r.decision).toBe('ALLOW');
    expect(r.reason_codes).toContain('ALLOWED_BASELINE');
  });

  it('ungoverned action type is DENIED (fail-closed)', () => {
    const plan = planFor('T0', { data_classes: ['PUBLIC'] });
    const r = evaluate(evalInput(plan, request(plan, 'TRADING_OR_ORDER_ROUTING')));
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('ACTION_TYPE_NOT_PROTECTED');
  });

  it('B/T2: consequential external action REQUIRES owner approval (test 4/28)', () => {
    const plan = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, ['BOOKS_AND_RECORDS']);
    const req = request(plan, 'EXTERNAL_DATA_TRANSMISSION', { environment: 'PRODUCTION', target_resource: 'https://sor.example.com/write' });
    const r = evaluate(evalInput(plan, req));
    expect(r.decision).toBe('REQUIRE_APPROVAL');
    expect(r.required_attestations).toContain('OWNER_ATTESTATION');
  });

  it('B/T2: a valid owner approval scoped to THIS digest yields ALLOW', () => {
    const plan = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, ['BOOKS_AND_RECORDS']);
    const req = request(plan, 'EXTERNAL_DATA_TRANSMISSION', { environment: 'PRODUCTION' });
    const dg = digestOf(req);
    const approval: GatheredApproval = {
      attestation_type: 'OWNER_ATTESTATION', approver_id: 'owner-1', approver_role: 'owner',
      scoped_action_digest: dg, scoped_policy_profile_hash: plan.policy_profile_hash, scoped_enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'GRANTED', expires_at: '2999-01-01T00:00:00Z',
    };
    const r = evaluate(evalInput(plan, req, { approvals: [approval] }));
    expect(r.decision).toBe('ALLOW');
    expect(r.reason_codes).toContain('ALLOWED_APPROVED');
  });

  it('approval scoped to a DIFFERENT digest cannot authorize (test 1/5)', () => {
    const plan = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, ['BOOKS_AND_RECORDS']);
    const req = request(plan, 'EXTERNAL_DATA_TRANSMISSION', { environment: 'PRODUCTION' });
    const approval: GatheredApproval = {
      attestation_type: 'OWNER_ATTESTATION', approver_id: 'owner-1', approver_role: 'owner',
      scoped_action_digest: sha256('OTHER-DIGEST'), scoped_policy_profile_hash: plan.policy_profile_hash, scoped_enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'GRANTED', expires_at: '2999-01-01T00:00:00Z',
    };
    const r = evaluate(evalInput(plan, req, { approvals: [approval] }));
    expect(r.decision).toBe('REQUIRE_APPROVAL');
  });

  it('expired/revoked/consumed approval fails closed (test 6/7)', () => {
    const plan = planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, ['BOOKS_AND_RECORDS']);
    const req = request(plan, 'EXTERNAL_DATA_TRANSMISSION', { environment: 'PRODUCTION' });
    const dg = digestOf(req);
    for (const status of ['EXPIRED', 'REVOKED', 'CONSUMED'] as const) {
      const approval: GatheredApproval = {
        attestation_type: 'OWNER_ATTESTATION', approver_id: 'owner-1', approver_role: 'owner',
        scoped_action_digest: dg, scoped_policy_profile_hash: plan.policy_profile_hash, scoped_enforcement_plan_hash: plan.enforcement_plan_hash,
        status, expires_at: '2020-01-01T00:00:00Z',
      };
      expect(evaluate(evalInput(plan, req, { approvals: [approval] })).decision).toBe('REQUIRE_APPROVAL');
    }
  });

  it('C/T3: unrestricted autonomous production action is DENIED (test 27)', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const req = request(plan, 'TRADING_OR_ORDER_ROUTING', { environment: 'PRODUCTION' });
    const r = evaluate(evalInput(plan, req, { autonomy_requested: 'UNRESTRICTED' }));
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('UNRESTRICTED_AUTONOMY_DENIED');
  });

  it('C/T3: AI invocation in PREVIEW is permitted', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const r = evaluate(evalInput(plan, request(plan, 'AI_MODEL_INVOCATION', { environment: 'PREVIEW' })));
    expect(r.decision).toBe('ALLOW');
  });

  it('kill switch active → DENY, no matter the action (test 16)', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const r = evaluate(evalInput(plan, request(plan, 'AI_MODEL_INVOCATION'), { kill_switch_active: true }));
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('KILL_SWITCH_ACTIVE');
  });

  it('C/T3: production requires dual control; a single approver is insufficient', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const req = request(plan, 'TRADING_OR_ORDER_ROUTING', { environment: 'PRODUCTION' });
    const dg = digestOf(req);
    const mk = (approver: string): GatheredApproval => ({
      attestation_type: 'AUTHORIZED_GOVERNANCE_APPROVAL', approver_id: approver, approver_role: 'governance',
      scoped_action_digest: dg, scoped_policy_profile_hash: plan.policy_profile_hash, scoped_enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'GRANTED', expires_at: '2999-01-01T00:00:00Z',
    });
    // restricted autonomy so NO_UNRESTRICTED_AUTONOMY passes; one governance approval → still REQUIRE_APPROVAL (dual)
    const one = evaluate(evalInput(plan, req, { autonomy_requested: 'RESTRICTED', approvals: [mk('gov-1')], actor_id: 'user-1' }));
    expect(one.decision).toBe('REQUIRE_APPROVAL');
    // two DISTINCT governance approvals + owner → ALLOW
    const owner: GatheredApproval = { ...mk('owner-1'), attestation_type: 'OWNER_ATTESTATION', approver_role: 'owner' };
    const two = evaluate(evalInput(plan, req, { autonomy_requested: 'RESTRICTED', approvals: [mk('gov-1'), mk('gov-2'), owner], actor_id: 'user-1' }));
    expect(two.decision).toBe('ALLOW');
  });

  it('self-approval cannot satisfy an independent (dual-control) requirement', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const req = request(plan, 'TRADING_OR_ORDER_ROUTING', { environment: 'PRODUCTION' });
    const dg = digestOf(req);
    const mk = (approver: string): GatheredApproval => ({
      attestation_type: 'AUTHORIZED_GOVERNANCE_APPROVAL', approver_id: approver, approver_role: 'governance',
      scoped_action_digest: dg, scoped_policy_profile_hash: plan.policy_profile_hash, scoped_enforcement_plan_hash: plan.enforcement_plan_hash,
      status: 'GRANTED', expires_at: '2999-01-01T00:00:00Z',
    });
    // actor is one of the two approvers → only 1 independent → dual control unsatisfied
    const r = evaluate(evalInput(plan, req, { autonomy_requested: 'RESTRICTED', approvals: [mk('user-1'), mk('gov-2')], actor_id: 'user-1' }));
    expect(r.decision).toBe('REQUIRE_APPROVAL');
    expect(r.reason_codes).toContain('DUAL_CONTROL_REQUIRED');
  });

  it('model not on the allowlist is DENIED', () => {
    const plan = planFor('T3', { data_classes: ['MNPI'], integration_types: ['TRADING_OR_ORDERS'], autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' }, ['SEC', 'FINRA', 'CFTC']);
    const req = request(plan, 'AI_MODEL_INVOCATION', { model_identity: 'evil-model-9000' });
    const r = evaluate(evalInput(plan, req));
    expect(r.decision).toBe('DENY');
    expect(r.reason_codes).toContain('MODEL_NOT_APPROVED');
  });
});
