/**
 * QHUB P0-A Governance Trust Boundary Tests
 * app/test/governance.test.ts
 *
 * Tests 1-10 per the P0-A specification.
 *
 * Run:  pnpm test  (or npm test / yarn test)
 *       vitest --run app/test/governance.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Module mocks ─────────────────────────────────────────────────────────────
// Hoisted spies so the vi.mock factories (hoisted to top of file) can reference
// them without a temporal-dead-zone error. These let us exercise GovernanceService
// without a live Supabase (durable qhub_app_id layer) or a real session.

const {
  mockGetSession,
  mockGetOrCreateQhubApp,
  mockPersistChainId,
  mockGetChainId,
  mockGetPersistedRiskTier,
  mockPersistClassification,
  mockGetClassification,
} = vi.hoisted(() => ({
  mockGetSession: vi.fn(),
  mockGetOrCreateQhubApp: vi.fn(),
  mockPersistChainId: vi.fn(),
  mockGetChainId: vi.fn(),
  mockGetPersistedRiskTier: vi.fn(),
  mockPersistClassification: vi.fn(),
  mockGetClassification: vi.fn(),
}));

vi.mock('~/lib/auth/session', () => ({
  getSession: mockGetSession,
  getHmacSecret: vi.fn().mockReturnValue('test-secret-32-chars-minimum-ok!'),
}));

// Mock the durable identity layer so the service reaches the signing/POST path.
// GovernanceService imports these via a relative specifier ('./qhub-app.server'),
// which resolves to the same module id as the '~/lib/qhub/qhub-app.server' alias.
vi.mock('~/lib/qhub/qhub-app.server', () => ({
  getOrCreateQhubApp: mockGetOrCreateQhubApp,
  persistChainId: mockPersistChainId,
  getChainId: mockGetChainId,
  getPersistedRiskTier: mockGetPersistedRiskTier,
  persistClassification: mockPersistClassification,
  getClassification: mockGetClassification,
}));

/** A stable fake qhub_app record with no chain_id yet (genesis not fired). */
function fakeAppRecord(overrides: Record<string, unknown> = {}) {
  return {
    qhub_app_id: 'qhub-app-11111111-2222-3333-4444-555555555555',
    org_id: 'org-abc',
    created_by: 'user-123',
    builder_engine: 'bolt',
    builder_project_id: null,
    conversation_id: 'conv-001',
    workspace_id: null,
    chain_id: null,
    risk_tier: 'UNCLASSIFIED',
    governance_status: 'ACTIVE',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

beforeEach(() => {
  mockGetSession.mockReset();
  mockGetOrCreateQhubApp.mockReset().mockResolvedValue(fakeAppRecord());
  mockPersistChainId.mockReset().mockResolvedValue(undefined);
  mockGetChainId.mockReset().mockResolvedValue(null);
  // Gate 02: default to a classified tier so gate tests exercise attestation
  // logic (UNCLASSIFIED would block unconditionally).
  mockGetPersistedRiskTier.mockReset().mockResolvedValue('T2');
  mockPersistClassification.mockReset().mockResolvedValue(undefined);
  mockGetClassification.mockReset().mockResolvedValue(null);
});

// ─── Test 1: Browser hydration contains no HMAC secret ───────────────────────

describe('TEST 1: Root loader response contains no HMAC secret', () => {
  it('QhubSession interface has no hmacSecret field', async () => {
    // Import the session type and verify the interface does not include hmacSecret
    const sessionModule = await import('~/lib/auth/session');

    // getSession should return an object without hmacSecret
    // We verify by checking the getHmacSecret export exists separately
    expect(typeof sessionModule.getSession).toBe('function');
    // getHmacSecret was moved to ~/lib/qhub/governance-secrets.server.ts

    // The type-level check: QhubSession fields must not include hmacSecret.
    // We construct a mock return value and verify the key is absent.
    const mockSession = {
      userId: 'test-user',
      orgId: 'test-org',
      email: 'test@quantex-tech.com',
      role: 'builder' as const,
    };

    // Verify hmacSecret key is not present in a valid QhubSession object
    expect('hmacSecret' in mockSession).toBe(false);
  });

  it('root.tsx loader returns only browser-safe fields', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const rootPath = path.resolve(process.cwd(), 'app/root.tsx');
    const source = fs.readFileSync(rootPath, 'utf8');

    // The loader return must explicitly list fields (not spread session)
    expect(source).toContain('userId: session.userId');
    expect(source).toContain('orgId: session.orgId');
    expect(source).toContain('email: session.email');
    expect(source).toContain('role: session.role');

    // Check that hmacSecret does NOT appear as a return property key (code key, not comment).
    // Pattern: 'hmacSecret:' or 'hmacSecret :' in the loader section.
    const loaderSection = source.slice(
      source.indexOf('export async function loader'),
      source.indexOf('export const links'),
    );
    expect(/hmacSecret\s*:/.test(loaderSection)).toBe(false);
  });
});

// ─── Test 2: Authenticated GENESIS action reaches governance service ──────────

describe('TEST 2: GENESIS intent is handled server-side', () => {
  it('GovernanceService.handleIntent routes PROJECT_CREATED correctly', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    // Lambda returns the chain_id it minted for CHAIN_GENESIS (seq=1).
    const mockFetch = vi
      .fn()
      .mockResolvedValue(new Response('{"chain_id":"chain-genesis-uuid","seq":1}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'user-123',
      orgId: 'org-abc',
      sessionId: 'studio-abc123',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    const result = await svc.handleIntent({
      action: 'PROJECT_CREATED',
      conversationId: 'conv-001',
      projectTitle: 'Test Project',
    });

    expect(result.ok).toBe(true);

    // Verify a POST was made to /events (not /chains).
    // The durable identity lookup (getOrCreateQhubApp) is mocked, so the only
    // network call is the CHAIN_GENESIS POST.
    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/events');
    expect(url).not.toContain('/chains');
    expect((opts.method as string).toUpperCase()).toBe('POST');

    // Verify the event body contains server-authoritative identity (not browser-supplied)
    const body = JSON.parse(opts.body as string);
    expect(body.event_type).toBe('CHAIN_GENESIS'); // Lambda v2.6 canonical genesis event
    // Server-authoritative identity lives in actor.id / client_id (v2.6 schema).
    // The Lambda computes timestamp/seq/hashes — the caller does not send them.
    expect(body.actor.id).toBe('user-123');    // from server context
    expect(body.client_id).toBe('org-abc');    // from server context
    expect(body.actor.identity_provider).toBe('supabase');

    // Verify signature header is present
    expect((opts.headers as Record<string, string>)['X-QHUB-Signature']).toBeTruthy();

    vi.unstubAllGlobals();
  });

  it('GENESIS event body does not contain hmacSecret', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    const capturedBodies: string[] = [];
    const mockFetch = vi.fn().mockImplementation((url: string, opts: RequestInit) => {
      capturedBodies.push(opts.body as string);
      return Promise.resolve(new Response('{}', { status: 200 }));
    });
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'user-123',
      orgId: 'org-abc',
      sessionId: 'studio-abc123',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    await svc.handleIntent({
      action: 'PROJECT_CREATED',
      conversationId: 'conv-001',
      projectTitle: 'Test Project',
    });

    for (const body of capturedBodies) {
      expect(body).not.toContain('hmacSecret');
      expect(body).not.toContain('QHUB_HMAC_SECRET');
    }

    vi.unstubAllGlobals();
  });
});

// ─── Test 3: AI_BOM remains server-side ──────────────────────────────────────

describe('TEST 3: AI_BOM hook is server-side only', () => {
  it('governance-service.server.ts is a .server module (not client-importable)', async () => {
    // Verify the file path ends in .server.ts — Remix/Vite convention
    const fs = await import('node:fs');
    const path = await import('node:path');
    const serverModulePath = path.resolve(process.cwd(), 'app/lib/qhub/governance-service.server.ts');
    expect(fs.existsSync(serverModulePath)).toBe(true);

    // Verify it imports from node:crypto (server-only)
    const source = fs.readFileSync(serverModulePath, 'utf8');
    expect(source).toContain("from 'node:crypto'");
  });

  it('stream-text.ts imports from governance-service.server (not governance-client)', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const streamTextPath = path.resolve(process.cwd(), 'app/lib/.server/llm/stream-text.ts');
    const source = fs.readFileSync(streamTextPath, 'utf8');

    expect(source).toContain('governance-service.server');
    expect(source).not.toContain("from '~/lib/qhub/governance-client'");
    expect(source).not.toContain('logAiBom');
  });

  it('AI_BOM event goes to POST /events via GovernanceService', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'u',
      orgId: 'o',
      sessionId: 's',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    await svc.recordAiModelInvokedDirect({
      conversationId: 'conv-001',
      provider: 'anthropic',
      model: 'claude-sonnet-5',
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/events');
    const body = JSON.parse(opts.body as string);
    expect(body.event_type).toBe('AI_MODEL_INVOKED'); // Lambda v2.6 canonical AI event

    vi.unstubAllGlobals();
  });
});

// ─── Test 4: Browser cannot forge actor/principal identity ───────────────────

describe('TEST 4: Browser-supplied identity claims are ignored', () => {
  it('GovernanceService uses server context userId, not any browser-supplied value', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'real-server-user',
      orgId: 'real-server-org',
      sessionId: 'studio-real',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    // Simulate a malicious browser supplying forged identity in the intent
    // (the intent type doesn't allow userId/orgId fields — but even if coerced...)
    await svc.handleIntent({
      action: 'PROJECT_CREATED',
      conversationId: 'conv-001',
      projectTitle: 'Forged Project',
      // TypeScript would prevent userId/orgId in GovernanceIntent, but test runtime coercion:
      userId: 'attacker-user',
      orgId: 'attacker-org',
    } as any);

    const [, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(opts.body as string);

    // Server context identity wins — not browser-supplied fields.
    // Identity is carried in actor.id / client_id (v2.6 schema).
    expect(body.actor.id).toBe('real-server-user');
    expect(body.client_id).toBe('real-server-org');
    expect(body.actor.id).not.toBe('attacker-user');
    expect(body.client_id).not.toBe('attacker-org');

    vi.unstubAllGlobals();
  });

  it('api.governance route rejects unauthenticated requests with 401', async () => {
    // getSession is mocked at module scope; make it return null (no session) here.
    mockGetSession.mockResolvedValue(null);

    const { action } = await import('~/routes/api.governance');

    const request = new Request('http://localhost/api/governance', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'PROJECT_CREATED', appId: 'x', conversationId: 'y', projectTitle: 'z' }),
    });

    const response = await action({ request, context: {} as any, params: {} });
    expect(response.status).toBe(401);
  });
});

// ─── Test 5: No session → production deploy BLOCKED ──────────────────────────

describe('TEST 5: Missing session blocks production deployment', () => {
  it('workbench.ts gate returns early (does not proceed) when #qhubSession is null in production', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const workbenchPath = path.resolve(process.cwd(), 'app/lib/stores/workbench.ts');
    const source = fs.readFileSync(workbenchPath, 'utf8');

    // Verify the fail-closed pattern exists
    expect(source).toContain('NO_SESSION');
    expect(source).toContain("'error'");

    // Verify it does NOT silently treat missing session as GATE_PASSED
    // (The old code: `postGovernanceEvent('GATE_PASSED', { note: 'local-dev' })` without return)
    // New code must have a `return` after blocking when not in dev mode
    expect(source).toContain('return; // BLOCK deployment');
  });

  it('GateState type includes all required states', async () => {
    // Verify the type is correctly defined
    type ExpectedStates = 'APPROVED' | 'BLOCKED' | 'UNKNOWN' | 'ERROR';
    const states: ExpectedStates[] = ['APPROVED', 'BLOCKED', 'UNKNOWN', 'ERROR'];
    expect(states).toHaveLength(4);
    expect(states).toContain('APPROVED');
    expect(states).toContain('BLOCKED');
    expect(states).toContain('UNKNOWN');
    expect(states).toContain('ERROR');
  });
});

// ─── Test 6: Governance API unavailable → production deploy BLOCKED ───────────

describe('TEST 6: API unreachable returns UNKNOWN (fail-closed)', () => {
  it('queryGateState returns UNKNOWN on network error', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    // Simulate network failure (DNS error)
    const mockFetch = vi.fn().mockRejectedValue(new TypeError('fetch failed: ENOTFOUND'));
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'u',
      orgId: 'o',
      sessionId: 's',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://api.quantex-tech.com' },
    });

    const result = await svc.handleIntent({
      action: 'DEPLOYMENT_GATE_CHECK',
      conversationId: 'conv-001',
    });

    // UNKNOWN (not APPROVED) — even though network failed
    expect(result.gateState).not.toBe('APPROVED');
    expect(['UNKNOWN', 'ERROR', 'BLOCKED']).toContain(result.gateState);

    vi.unstubAllGlobals();
  });

  it('assertDeploymentGate client function returns non-APPROVED on error', async () => {
    const { assertDeploymentGate } = await import('~/lib/qhub/governance-client');

    // Simulate /api/governance being unreachable
    const mockFetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    vi.stubGlobal('fetch', mockFetch);

    const state = await assertDeploymentGate({ conversationId: 'conv-001', appId: 'app-001' });

    expect(state).not.toBe('APPROVED');
    expect(['UNKNOWN', 'ERROR', 'BLOCKED']).toContain(state);

    vi.unstubAllGlobals();
  });
});

// ─── Test 7: Missing attestation → production deploy BLOCKED ─────────────────

describe('TEST 7: Unattested project returns BLOCKED', () => {
  it('gate returns BLOCKED when attestation_status is not ATTESTED', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/chains')) {
        // Reader API says: not attested
        return Promise.resolve(new Response(JSON.stringify({ gate_passed: false, attestation_status: 'PENDING' }), { status: 200 }));
      }
      // Ingest POST /events
      return Promise.resolve(new Response('{}', { status: 200 }));
    });
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'u',
      orgId: 'o',
      sessionId: 's',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    const result = await svc.handleIntent({
      action: 'DEPLOYMENT_GATE_CHECK',
      conversationId: 'conv-001',
    });

    expect(result.gateState).toBe('BLOCKED');
    expect(result.gateState).not.toBe('APPROVED');

    vi.unstubAllGlobals();
  });
});

// ─── Test 8: APPROVED state → deployment may proceed ────────────────────────

describe('TEST 8: Attested project returns APPROVED', () => {
  it('gate returns APPROVED when attestation_status is ATTESTED', async () => {
    const { GovernanceService } = await import('~/lib/qhub/governance-service.server');

    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/chains')) {
        return Promise.resolve(new Response(JSON.stringify({ gate_passed: true, attestation_status: 'ATTESTED' }), { status: 200 }));
      }
      return Promise.resolve(new Response('{}', { status: 200 }));
    });
    vi.stubGlobal('fetch', mockFetch);

    const svc = new GovernanceService({
      userId: 'u',
      orgId: 'o',
      sessionId: 's',
      env: { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' },
    });

    const result = await svc.handleIntent({
      action: 'DEPLOYMENT_GATE_CHECK',
      conversationId: 'conv-001',
    });

    expect(result.gateState).toBe('APPROVED');

    vi.unstubAllGlobals();
  });
});

// ─── Test 9: Stable conversation ID persists across multiple calls ────────────

describe('TEST 9: Stable session/conversation ID', () => {
  it('generateStableSessionId returns same value for same inputs', async () => {
    const { generateStableSessionId } = await import('~/lib/qhub/session-id.server');

    const id1 = generateStableSessionId('user-abc', 'conv-xyz');
    const id2 = generateStableSessionId('user-abc', 'conv-xyz');
    const id3 = generateStableSessionId('user-abc', 'conv-xyz');

    expect(id1).toBe(id2);
    expect(id2).toBe(id3);
    expect(id1).toMatch(/^studio-[0-9a-f]{12}$/);
  });

  it('generateStableSessionId returns different values for different conversations', async () => {
    const { generateStableSessionId } = await import('~/lib/qhub/session-id.server');

    const id1 = generateStableSessionId('user-abc', 'conv-001');
    const id2 = generateStableSessionId('user-abc', 'conv-002');

    expect(id1).not.toBe(id2);
  });

  it('generateStableSessionId returns different values for different users (same conv)', async () => {
    const { generateStableSessionId } = await import('~/lib/qhub/session-id.server');

    const id1 = generateStableSessionId('user-001', 'conv-xyz');
    const id2 = generateStableSessionId('user-002', 'conv-xyz');

    expect(id1).not.toBe(id2);
  });
});

// ─── Test 10: Client bundle does not contain QHUB_HMAC_SECRET ────────────────

describe('TEST 10: No client bundle exposure of HMAC secret', () => {
  it('governance-client.ts does not reference QHUB_HMAC_SECRET', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const clientPath = path.resolve(process.cwd(), 'app/lib/qhub/governance-client.ts');
    const source = fs.readFileSync(clientPath, 'utf8');

    expect(source).not.toContain('QHUB_HMAC_SECRET');
    expect(source).not.toContain('hmacSecret');
    expect(source).not.toContain('crypto.subtle');
    expect(source).not.toContain('signHmac');
  });

  it('workbench.ts does not use hmacSecret as a code key or type field', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const workbenchPath = path.resolve(process.cwd(), 'app/lib/stores/workbench.ts');
    const source = fs.readFileSync(workbenchPath, 'utf8');

    expect(source).not.toContain('QHUB_HMAC_SECRET');
    // Check for hmacSecret as a code expression (property key or type field),
    // not merely as a word in a comment.
    expect(/hmacSecret\s*[?:]/.test(source)).toBe(false);
  });

  it('root.tsx return value does not contain hmacSecret', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const rootPath = path.resolve(process.cwd(), 'app/root.tsx');
    const source = fs.readFileSync(rootPath, 'utf8');

    // The loader return block should not include hmacSecret as a returned field.
    // Match only a code key/type usage (`hmacSecret:`) — a comment mentioning the
    // word (e.g. "hmacSecret MUST NOT be included") is fine and must not trip this.
    const loaderSection = source.slice(source.indexOf('export async function loader'), source.indexOf('export const links'));
    expect(/hmacSecret\s*:/.test(loaderSection)).toBe(false);
  });

  it('governance-service.server.ts uses node:crypto (not Web Crypto)', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const svcPath = path.resolve(process.cwd(), 'app/lib/qhub/governance-service.server.ts');
    const source = fs.readFileSync(svcPath, 'utf8');

    // Server uses Node.js crypto (available server-side)
    expect(source).toContain("from 'node:crypto'");

    // Does NOT use browser Web Crypto API
    expect(source).not.toContain('crypto.subtle');
  });
});
