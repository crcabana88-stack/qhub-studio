/**
 * QHUB Gate 05 — attestation service integration/adversarial tests
 * app/test/attestation-server.test.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { buildPolicyProfile, canonicalPolicyString } from '~/lib/qhub/policy-engine';
import { compileEnforcementPlan, canonicalEnforcementPlanString } from '~/lib/qhub/enforcement-plan';
import type { ClassificationSignals, RiskTier } from '~/lib/qhub/classification';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const H = vi.hoisted(() => ({
  getOrCreateQhubApp: vi.fn(), getChainId: vi.fn(), getClassification: vi.fn(), getPolicyProfile: vi.fn(),
  assertSchema: vi.fn(), getActivePlan: vi.fn(),
  getReleaseCandidate: vi.fn(), getReleaseCandidateCount: vi.fn(), upsertReleaseCandidate: vi.fn(),
  freezeRC: vi.fn(), supersede: vi.fn(), setStatus: vi.fn(), insertAttestation: vi.fn(),
  getAttestationsForRelease: vi.fn(), revokeAttestation: vi.fn(), recordDecision: vi.fn(),
  recordReleaseEvent: vi.fn(),
}));

vi.mock('~/lib/qhub/qhub-app.server', () => ({ getOrCreateQhubApp: H.getOrCreateQhubApp, getChainId: H.getChainId, getClassification: H.getClassification, getPolicyProfile: H.getPolicyProfile }));
vi.mock('~/lib/qhub/schema-check.server', () => ({ assertGovernanceSchemaReady: H.assertSchema, SchemaNotReadyError: class extends Error {} }));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({ getActivePlan: H.getActivePlan }));
vi.mock('~/lib/qhub/attestation-store.server', () => ({
  getReleaseCandidate: H.getReleaseCandidate, getReleaseCandidateCount: H.getReleaseCandidateCount,
  upsertReleaseCandidate: H.upsertReleaseCandidate, freezeReleaseCandidate: H.freezeRC, supersedeOtherReleases: H.supersede,
  setReleaseStatus: H.setStatus, insertAttestation: H.insertAttestation, getAttestationsForRelease: H.getAttestationsForRelease,
  revokeAttestation: H.revokeAttestation, recordDeploymentDecision: H.recordDecision,
}));
vi.mock('~/lib/qhub/governance-service.server', () => ({ createGovernanceService: () => ({ recordReleaseEvent: H.recordReleaseEvent }) }));

const ENV = { QHUB_HMAC_SECRET: 'x', SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };

function signals(o: Partial<ClassificationSignals> = {}): ClassificationSignals {
  return { data_classes: [], integration_types: ['NONE'], ai_behavior: 'NONE', autonomy_level: 'NONE', deployment_surface: 'INTERNAL', regulatory_domains: ['NONE_IDENTIFIED'], ...o };
}
function profileFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, d: any[] = ['NONE_IDENTIFIED']) {
  const p = buildPolicyProfile({ qhub_app_id: 'app-1', classification_version: 1, classification_reference: 'c', risk_tier: tier, regulatory_domains: d, signals: signals({ ...s, regulatory_domains: d }), policy_profile_version: 1, generated_by: 'svc' });
  p.policy_profile_id = 'pp-1'; p.policy_profile_hash = sha256(canonicalPolicyString(p)); p.generated_at = 'x';
  return p;
}
function planFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, d: any[] = ['NONE_IDENTIFIED']) {
  const plan = compileEnforcementPlan({ profile: profileFor(tier, s, d), classification: { classification_version: 1, risk_tier: tier, data_classes: signals(s).data_classes, integration_types: signals(s).integration_types, ai_behavior: signals(s).ai_behavior, autonomy_level: signals(s).autonomy_level, deployment_surface: signals(s).deployment_surface, regulatory_domains: d } as any, enforcement_plan_version: 1 });
  plan.enforcement_plan_id = 'ep-1'; plan.generated_at = 'x'; plan.enforcement_plan_hash = sha256(canonicalEnforcementPlanString(plan));
  return plan;
}

const T3S = { data_classes: ['MNPI' as const], integration_types: ['TRADING_OR_ORDERS' as const], autonomy_level: 'AUTONOMOUS' as const, deployment_surface: 'PRODUCTION' as const };
const T3D = ['SEC', 'FINRA', 'CFTC'];

function rcRow(tier: RiskTier, over: any = {}) {
  const p = profileFor(tier, tier === 'T3' ? T3S : { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, tier === 'T3' ? T3D : ['BOOKS_AND_RECORDS']);
  const plan = planFor(tier, tier === 'T3' ? T3S : { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, tier === 'T3' ? T3D : ['BOOKS_AND_RECORDS']);
  H.getPolicyProfile.mockResolvedValue(p);
  H.getActivePlan.mockResolvedValue({ plan });
  H.getClassification.mockResolvedValue({ classification_version: 1 });
  return { release_candidate_id: 'rc-1', org_id: 'client-smoke', qhub_app_id: 'app-1', qhub_app_version: 1, release_candidate_hash: 'RCHASH', status: 'AWAITING_ATTESTATION', target_environment: 'PRODUCTION', risk_tier: tier, classification_version: 1, policy_profile_id: 'pp-1', policy_profile_version: 1, policy_profile_hash: p.policy_profile_hash, enforcement_plan_id: 'ep-1', enforcement_plan_version: 1, enforcement_plan_hash: plan.enforcement_plan_hash, release_scope: 'full', ...over };
}
function att(purpose: string, role: string, signer: string, over: any = {}) {
  return { attestation_id: 'a-' + signer + purpose, attestation_purpose: purpose, signer_role: role, signer_user_id: signer, status: 'VALID', release_candidate_hash: 'RCHASH', target_environment: 'PRODUCTION', ...over };
}

async function evaluate(over: any = {}) {
  const { evaluateReleaseForDeployment } = await import('~/lib/qhub/attestation.server');
  return evaluateReleaseForDeployment({ session: { userId: 'user-1', orgId: 'client-smoke', role: 'builder' }, conversationId: 'conv-1', release_candidate_id: 'rc-1', target_environment: 'PRODUCTION', sessionId: 's', env: ENV, ...over });
}
async function sign(over: any = {}) {
  const { signAttestation } = await import('~/lib/qhub/attestation.server');
  return signAttestation({ session: { userId: 'user-1', orgId: 'client-smoke', role: 'owner' }, conversationId: 'conv-1', release_candidate_id: 'rc-1', attestation_purpose: 'BUSINESS_OWNER', sessionId: 's', env: ENV, ...over });
}

beforeEach(() => {
  vi.clearAllMocks();
  H.assertSchema.mockResolvedValue(undefined);
  H.getChainId.mockResolvedValue('chain-1');
  H.freezeRC.mockResolvedValue(true); H.supersede.mockResolvedValue(undefined); H.setStatus.mockResolvedValue(undefined);
  H.insertAttestation.mockResolvedValue({ ok: true }); H.recordDecision.mockResolvedValue(true);
  H.recordReleaseEvent.mockResolvedValue({ ok: true });
  H.getAttestationsForRelease.mockResolvedValue([]);
});

describe('signAttestation authority (tests 10/11/12)', () => {
  it('rejects a signer whose role is not authorized for the purpose', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    const r = await sign({ session: { userId: 'u', orgId: 'client-smoke', role: 'builder' }, attestation_purpose: 'BUSINESS_OWNER' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('SIGNER_NOT_AUTHORIZED');
  });
  it('rejects cross-tenant signing', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2', { org_id: 'OTHER' }));
    const r = await sign();
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('TENANT_MISMATCH');
  });
  it('accepts an authorized owner and binds it to the exact release hash', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    const r = await sign();
    expect(r.ok).toBe(true);
    const evtPayload = H.recordReleaseEvent.mock.calls[0][0].payload;
    expect(evtPayload.release_candidate_hash).toBe('RCHASH');
  });
});

describe('evaluate for deployment (tests 18-22)', () => {
  it('T2 missing owner attestation → REJECT (test 21)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    H.getAttestationsForRelease.mockResolvedValue([]);
    const r = await evaluate();
    expect(r.decision).toBe('REJECT');
    expect(r.reason_codes).toContain('MISSING_ATTESTATION');
  });
  it('T2 with valid owner attestation → APPROVE (test 19/22)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1')]);
    const r = await evaluate();
    expect(r.decision).toBe('APPROVE');
  });
  it('attestation for a DIFFERENT release hash cannot approve (test 18)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1', { release_candidate_hash: 'OTHER' })]);
    expect((await evaluate()).decision).toBe('REJECT');
  });
  it('expired/revoked attestation is ignored (tests 15/16)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1', { status: 'EXPIRED' }), att('BUSINESS_OWNER', 'owner', 'owner-2', { status: 'REVOKED' })]);
    expect((await evaluate()).decision).toBe('REJECT');
  });
  it('T3 needs owner + two DISTINCT governance signers (tests 13/14/20)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T3'));
    // owner + one governance → REJECT (dual control needs 2 distinct)
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1'), att('GOVERNANCE', 'governance', 'gov-1')]);
    expect((await evaluate()).decision).toBe('REJECT');
    // owner + SAME governance signer twice → still REJECT (not distinct)
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1'), att('GOVERNANCE', 'governance', 'gov-1'), att('GOVERNANCE', 'governance', 'gov-1', { attestation_id: 'dup' })]);
    expect((await evaluate()).decision).toBe('REJECT');
    // owner + two distinct governance + technology (CHANGE) → APPROVE
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1'), att('GOVERNANCE', 'governance', 'gov-1'), att('GOVERNANCE', 'compliance', 'gov-2'), att('TECHNOLOGY', 'owner', 'owner-1')]);
    expect((await evaluate()).decision).toBe('APPROVE');
  });
});

describe('staleness & environment invalidation (tests 6/7/8)', () => {
  it('policy revision invalidates (POLICY_STALE)', async () => {
    const rc = rcRow('T2'); H.getReleaseCandidate.mockResolvedValue(rc);
    H.getPolicyProfile.mockResolvedValue({ ...(await import('~/lib/qhub/policy-engine')), policy_profile_hash: 'CHANGED' } as any);
    // simpler: return a profile with a different hash
    H.getPolicyProfile.mockResolvedValue({ policy_profile_hash: 'DIFFERENT' });
    expect((await evaluate()).reason_codes).toContain('POLICY_STALE');
  });
  it('target-environment mismatch → REJECT (test 8)', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2', { target_environment: 'STAGING' }));
    expect((await evaluate({ target_environment: 'PRODUCTION' })).reason_codes).toContain('ENVIRONMENT_MISMATCH');
  });
  it('superseded release → REJECT', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2', { status: 'SUPERSEDED' }));
    expect((await evaluate()).reason_codes).toContain('NOT_FROZEN');
  });
});

describe('ledger-write failure prevents approval (test 26)', () => {
  it('APPROVE downgraded to REJECT when the DEPLOYMENT_APPROVED event fails', async () => {
    H.getReleaseCandidate.mockResolvedValue(rcRow('T2'));
    H.getAttestationsForRelease.mockResolvedValue([att('BUSINESS_OWNER', 'owner', 'owner-1')]);
    H.recordReleaseEvent.mockResolvedValue({ ok: false });
    const r = await evaluate();
    expect(r.decision).toBe('REJECT');
    expect(r.reason_codes).toContain('DECISION_RECORD_FAILED');
  });
});
