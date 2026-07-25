/**
 * QHUB Gate 03 — Policy governance integration tests
 * app/test/policy-governance.test.ts
 *
 * Exercises the server-authoritative policy assignment path and the Phase-0
 * proposal-based classification hardening, with the durable identity layer
 * mocked so the signing/POST path runs without live Supabase/AWS.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const {
  mockGetOrCreateQhubApp,
  mockGetChainId,
  mockGetClassification,
  mockPersistClassification,
  mockGetProposal,
  mockMarkProposalConsumed,
  mockPersistPolicyProfile,
  mockGetPolicyProfile,
  mockUpdatePolicyStatus,
} = vi.hoisted(() => ({
  mockGetOrCreateQhubApp: vi.fn(),
  mockGetChainId: vi.fn(),
  mockGetClassification: vi.fn(),
  mockPersistClassification: vi.fn(),
  mockGetProposal: vi.fn(),
  mockMarkProposalConsumed: vi.fn(),
  mockPersistPolicyProfile: vi.fn(),
  mockGetPolicyProfile: vi.fn(),
  mockUpdatePolicyStatus: vi.fn(),
}));

vi.mock('~/lib/qhub/qhub-app.server', () => ({
  getOrCreateQhubApp: mockGetOrCreateQhubApp,
  persistChainId: vi.fn(),
  getChainId: mockGetChainId,
  getPersistedRiskTier: vi.fn().mockResolvedValue('T2'),
  persistClassification: mockPersistClassification,
  getClassification: mockGetClassification,
  getProposal: mockGetProposal,
  markProposalConsumed: mockMarkProposalConsumed,
  persistPolicyProfile: mockPersistPolicyProfile,
  getPolicyProfile: mockGetPolicyProfile,
  updatePolicyStatus: mockUpdatePolicyStatus,
  SchemaMissingError: class SchemaMissingError extends Error {},
}));

/*
 * The schema-readiness guard is orthogonal to the governance logic under test
 * here — treat the connected project as migrated so these tests exercise the
 * classification/policy path (schema drift is covered in schema-contract.test.ts).
 */
vi.mock('~/lib/qhub/schema-check.server', () => ({
  assertGovernanceSchemaReady: vi.fn().mockResolvedValue(undefined),
  SchemaNotReadyError: class SchemaNotReadyError extends Error {},
}));

function appRecord(overrides: Record<string, unknown> = {}) {
  return {
    qhub_app_id: 'app-uuid',
    org_id: 'org-abc',
    chain_id: 'chain-1',
    conversation_id: 'conv-1',
    risk_tier: 'T2',
    ...overrides,
  };
}

function classification(tier: string, extra: Record<string, unknown> = {}) {
  return {
    classification_version: 1,
    risk_tier: tier,
    risk_floor: tier,
    ai_proposed_tier: tier,
    classification_method: 'HUMAN_CONFIRMED',
    regulatory_domains: ['NONE_IDENTIFIED'],
    data_classes: ['PUBLIC'],
    integration_types: ['NONE'],
    ai_behavior: 'NONE',
    autonomy_level: 'NONE',
    deployment_surface: 'INTERNAL',
    rationale: 'x',
    floor_reasons: [],
    confidence: 0.9,
    confirmed_by: 'user-1',
    confirmed_at: '2026-07-25T00:00:00Z',
    classifier_version: 'gate02-classifier-1.0.0',
    ...extra,
  };
}

const ENV = { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' };

beforeEach(() => {
  vi.clearAllMocks();
  mockGetOrCreateQhubApp.mockResolvedValue(appRecord());
  mockGetChainId.mockResolvedValue('chain-1');
  mockPersistPolicyProfile.mockResolvedValue(undefined);
  mockUpdatePolicyStatus.mockResolvedValue(undefined);
  mockGetPolicyProfile.mockResolvedValue(null);
});

async function svc() {
  const { GovernanceService } = await import('~/lib/qhub/governance-service.server');
  return new GovernanceService({ userId: 'user-1', orgId: 'org-abc', sessionId: 's', env: ENV });
}

describe('POLICY_ASSIGN requires a confirmed classification', () => {
  it('blocks when no classification is present', async () => {
    mockGetClassification.mockResolvedValue(null);

    const s = await svc();
    const r = await s.handleIntent({ action: 'POLICY_ASSIGN', conversationId: 'conv-1' });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Classification required/i);
  });
});

describe('POLICY_ASSIGN writes a compact POLICY_PROFILE_ASSIGNED event', () => {
  it('posts the event, persists the profile, and stamps a hash', async () => {
    mockGetClassification.mockResolvedValue(
      classification('T2', {
        data_classes: ['CLIENT_PII', 'TRANSACTION_DATA'],
        integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'],
        regulatory_domains: ['BOOKS_AND_RECORDS', 'SEC'],
      }),
    );

    const bodies: any[] = [];
    const mockFetch = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      bodies.push(JSON.parse(opts.body as string));
      return Promise.resolve(new Response('{}', { status: 200 }));
    });
    vi.stubGlobal('fetch', mockFetch);

    const s = await svc();
    const r = await s.handleIntent({ action: 'POLICY_ASSIGN', conversationId: 'conv-1' });

    expect(r.ok).toBe(true);
    expect(r.policyProfile).toBeTruthy();
    expect(r.policyProfile!.policy_profile_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.policyProfile!.status).toBe('ASSIGNED');
    expect(mockPersistPolicyProfile).toHaveBeenCalledOnce();

    const body = bodies[0];
    expect(body.event_type).toBe('POLICY_PROFILE_ASSIGNED');
    expect(body.risk_tier).toBe('T2');

    // Compact payload: control IDs, not the full documents.
    expect(Array.isArray(body.payload.required_control_ids)).toBe(true);
    expect(body.payload.required_control_ids).toContain('IA-FORMAL-RBAC');
    expect(body.payload).not.toHaveProperty('required_controls');
    expect(body.payload.policy_profile_hash).toBe(r.policyProfile!.policy_profile_hash);

    vi.unstubAllGlobals();
  });
});

describe('POLICY_ACKNOWLEDGE flips status to ACKNOWLEDGED', () => {
  it('updates status via the durable layer', async () => {
    mockGetPolicyProfile.mockResolvedValue({ status: 'ASSIGNED', policy_profile_version: 1 } as any);

    const s = await svc();
    const r = await s.handleIntent({ action: 'POLICY_ACKNOWLEDGE', conversationId: 'conv-1' });
    expect(r.ok).toBe(true);
    expect(r.policyStatus).toBe('ACKNOWLEDGED');
    expect(mockUpdatePolicyStatus).toHaveBeenCalledWith('app-uuid', 'ACKNOWLEDGED', expect.anything());
  });
});

describe('Phase 0: classification confirm binds to a server proposal', () => {
  it('fails closed when the proposal is missing', async () => {
    mockGetProposal.mockResolvedValue(null);

    const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const s = await svc();
    const r = await s.handleIntent({
      action: 'CLASSIFICATION_CONFIRMED',
      conversationId: 'conv-1',
      proposalId: 'missing',
      confirmedTier: 'T0',
    });
    expect(r.ok).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled(); // never reaches the ledger
    vi.unstubAllGlobals();
  });

  it('uses authoritative proposal signals, not the browser, and marks it consumed', async () => {
    // Proposal says T2 with client PII; browser tries to confirm T0.
    mockGetProposal.mockResolvedValue({
      proposal_id: 'p1',
      org_id: 'org-abc',
      status: 'PENDING',
      expires_at: '2999-01-01T00:00:00Z',
      provisional: classification('T2', {
        risk_floor: 'T2',
        data_classes: ['CLIENT_PII'],
      }),
    });
    mockGetClassification.mockResolvedValue(null);

    const bodies: any[] = [];
    const mockFetch = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      bodies.push(JSON.parse(opts.body as string));
      return Promise.resolve(new Response('{}', { status: 200 }));
    });
    vi.stubGlobal('fetch', mockFetch);

    const s = await svc();
    const r = await s.handleIntent({
      action: 'CLASSIFICATION_CONFIRMED',
      conversationId: 'conv-1',
      proposalId: 'p1',
      confirmedTier: 'T0', // attempt to downgrade below the T2 floor
    });

    expect(r.ok).toBe(true);

    // Floor from authoritative signals wins — cannot be lowered to T0.
    expect(r.riskTier).toBe('T2');
    expect(bodies[0].payload.downgrade_below_floor_blocked).toBe(true);
    expect(mockMarkProposalConsumed).toHaveBeenCalledWith('p1', expect.anything());

    vi.unstubAllGlobals();
  });

  it('rejects a proposal belonging to another tenant', async () => {
    mockGetProposal.mockResolvedValue({
      proposal_id: 'p1',
      org_id: 'other-org',
      status: 'PENDING',
      expires_at: '2999-01-01T00:00:00Z',
      provisional: classification('T1'),
    });

    const s = await svc();
    const r = await s.handleIntent({
      action: 'CLASSIFICATION_CONFIRMED',
      conversationId: 'conv-1',
      proposalId: 'p1',
      confirmedTier: 'T1',
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/tenant/i);
  });
});
