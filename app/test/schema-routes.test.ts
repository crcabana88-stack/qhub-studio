/**
 * QHUB schema-readiness — route-level fail-closed tests
 * app/test/schema-routes.test.ts
 *
 * Exercises the HTTP surface of the hardening:
 *   - /api/health is generic and public (no schema internals leaked)
 *   - /api/system/schema-check requires authentication (401 otherwise)
 *   - governance (classification confirm / policy assign) fails closed when the
 *     connected project is behind the code — no ledger event is emitted
 *   - the predeploy bypass is authorized only in a staging context
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { SchemaReadinessReport } from '~/lib/qhub/schema-check.server';

// ─── Hoisted mocks ────────────────────────────────────────────────────────────

const {
  mockGetSchemaReadiness,
  mockAssertGovernanceSchemaReady,
  mockGetSession,
  mockRequireStaff,
  mockGetAgentSchemaReadiness,
} = vi.hoisted(() => ({
  mockGetSchemaReadiness: vi.fn(),
  mockAssertGovernanceSchemaReady: vi.fn(),
  mockGetSession: vi.fn(),
  mockRequireStaff: vi.fn(),
  mockGetAgentSchemaReadiness: vi.fn(),
}));

/*
 * R3: /api/system/schema-check is Quantex-STAFF-ONLY. Bridge the staff guard to the
 * legacy getSession mock so existing auth cases keep working.
 */
vi.mock('~/lib/qhub/commercial/commercial-context.server', () => ({ requireStaff: mockRequireStaff }));

vi.mock('~/lib/qhub/schema-check.server', () => {
  class SchemaNotReadyError extends Error {
    report: unknown;
    constructor(report: unknown) {
      super('Connected Supabase project is behind the code');
      this.name = 'SchemaNotReadyError';
      this.report = report;
    }
  }

  return {
    getSchemaReadiness: mockGetSchemaReadiness,
    assertGovernanceSchemaReady: mockAssertGovernanceSchemaReady,
    SchemaNotReadyError,
  };
});

vi.mock('~/lib/qhub/agent/agent-schema-check.server', () => ({
  getAgentSchemaReadiness: mockGetAgentSchemaReadiness,
  assertAgentSchemaReady: vi.fn(),
}));

vi.mock('~/lib/auth/session', () => ({
  getSession: mockGetSession,
  getHmacSecret: vi.fn().mockReturnValue('test-secret-32-chars-minimum-ok!'),
}));

// Bridge the R3 staff guard to the legacy getSession mock: null → 401, else allow.
mockRequireStaff.mockImplementation(async () => {
  const s = await mockGetSession();

  if (!s) {
    return {
      ok: false,
      response: new Response(JSON.stringify({ ok: false, error: 'unauthenticated' }), { status: 401 }),
    };
  }

  return { ok: true, ctx: { userId: s.userId, orgId: s.orgId, role: s.role, isStaff: true } };
});

function readyReport(overrides: Partial<SchemaReadinessReport> = {}): SchemaReadinessReport {
  return {
    ready: true,
    expectedSchemaVersion: '2026-07-26.gate04',
    projectRef: 'jsjsanmaahvmynblmzkq',
    supabaseHost: 'jsjsanmaahvmynblmzkq.supabase.co',
    checkedAt: '2026-07-25T00:00:00Z',
    objects: [
      {
        table: 'qhub_applications',
        column: 'classification',
        migration: '20260725_qhub_classification',
        requiredBy: 'Gate 02',
        state: 'present',
      },
    ],
    missing: [],
    ...overrides,
  };
}

function notReadyReport(): SchemaReadinessReport {
  return readyReport({
    ready: false,
    missing: [
      {
        table: 'qhub_applications',
        column: 'classification',
        migration: '20260725_qhub_classification',
        requiredBy: 'Gate 02',
        state: 'missing',
      },
    ],
  });
}

const fakeContext = { cloudflare: { env: {} } } as any;

beforeEach(() => {
  vi.clearAllMocks();

  // Agent Framework readiness defaults to ready; individual tests override.
  mockGetAgentSchemaReadiness.mockResolvedValue({
    ready: true,
    expectedSchemaVersion: '2026-07-27.agent-foundation',
    projectRef: 'jsjsanmaahvmynblmzkq',
    supabaseHost: 'jsjsanmaahvmynblmzkq.supabase.co',
    checkedAt: '2026-07-27T00:00:00Z',
    objects: [],
    missing: [],
  });
});

// ─── /api/health — generic public response ────────────────────────────────────

describe('GET /api/health is generic and public', () => {
  it('returns 200 healthy with NO schema internals when ready', async () => {
    mockGetSchemaReadiness.mockResolvedValue(readyReport());

    const { loader } = await import('~/routes/api.health');
    const res = await loader({ request: new Request('http://x/api/health'), context: fakeContext, params: {} });

    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('healthy');

    // Must NOT leak any internal schema detail on the public surface.
    expect(body).not.toHaveProperty('schema');
    expect(body).not.toHaveProperty('projectRef');
    expect(body).not.toHaveProperty('missing');
    expect(body).not.toHaveProperty('supabaseHost');
    expect(body).not.toHaveProperty('expectedSchemaVersion');
    expect(JSON.stringify(body)).not.toContain('jsjsanmaahvmynblmzkq');
  });

  it('returns 503 degraded (still generic) when the project is behind', async () => {
    mockGetSchemaReadiness.mockResolvedValue(notReadyReport());

    const { loader } = await import('~/routes/api.health');
    const res = await loader({ request: new Request('http://x/api/health'), context: fakeContext, params: {} });

    expect(res.status).toBe(503);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('degraded');
    expect(body).not.toHaveProperty('missing');
    expect(JSON.stringify(body)).not.toContain('classification');
  });
});

// ─── /api/system/schema-check — authenticated detailed diagnostic ─────────────

describe('GET /api/system/schema-check requires authentication', () => {
  it('returns 401 when unauthenticated (no session)', async () => {
    mockGetSession.mockResolvedValue(null);

    const { loader } = await import('~/routes/api.system.schema-check');
    const res = await loader({
      request: new Request('http://x/api/system/schema-check'),
      context: fakeContext,
      params: {},
    });

    expect(res.status).toBe(401);
    expect(mockGetSchemaReadiness).not.toHaveBeenCalled(); // never probes for anon callers

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(false);
  });

  it('returns the detailed diff for an authenticated session', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', email: 'e', role: 'admin' });
    mockGetSchemaReadiness.mockResolvedValue(readyReport());

    const { loader } = await import('~/routes/api.system.schema-check');
    const res = await loader({
      request: new Request('http://x/api/system/schema-check'),
      context: fakeContext,
      params: {},
    });

    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.ok).toBe(true);
    expect(body.ready).toBe(true);
    expect(body.projectRef).toBe('jsjsanmaahvmynblmzkq'); // operator detail is allowed here
    expect(Array.isArray(body.objects)).toBe(true);
  });

  it('returns 503 to an authenticated caller when the project is behind', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u', orgId: 'o', email: 'e', role: 'admin' });
    mockGetSchemaReadiness.mockResolvedValue(notReadyReport());

    const { loader } = await import('~/routes/api.system.schema-check');
    const res = await loader({
      request: new Request('http://x/api/system/schema-check'),
      context: fakeContext,
      params: {},
    });

    expect(res.status).toBe(503);

    const body = (await res.json()) as any;
    expect(body.ready).toBe(false);
    expect(body.missing.length).toBe(1);
  });
});

// ─── Governance fails closed on schema drift ──────────────────────────────────

describe('governance fails closed when the schema is behind the code', () => {
  const ENV = { QHUB_HMAC_SECRET: 'test-secret-32-chars-minimum-ok!', QHUB_API_BASE: 'https://test.example.com' };

  async function drifted() {
    const schemaCheck = await import('~/lib/qhub/schema-check.server');
    mockAssertGovernanceSchemaReady.mockRejectedValue(
      new (schemaCheck.SchemaNotReadyError as any)({
        missing: [{ table: 'qhub_applications', column: 'classification' }],
        projectRef: 'wrong-project',
        expectedSchemaVersion: '2026-07-26.gate04',
      }),
    );

    const govMod = await import('~/lib/qhub/governance-service.server');

    return new govMod.GovernanceService({ userId: 'u', orgId: 'o', sessionId: 's', env: ENV });
  }

  it('blocks CLASSIFICATION_CONFIRMED and emits no ledger event', async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const svc = await drifted();
    const r = await svc.handleIntent({
      action: 'CLASSIFICATION_CONFIRMED',
      conversationId: 'conv-1',
      proposalId: 'p1',
      confirmedTier: 'T2',
    });

    expect(r.ok).toBe(false);
    expect(r.gateState).toBe('BLOCKED');
    expect(mockFetch).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it('blocks POLICY_ASSIGN and emits no ledger event', async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);

    const svc = await drifted();
    const r = await svc.handleIntent({ action: 'POLICY_ASSIGN', conversationId: 'conv-1' });

    expect(r.ok).toBe(false);
    expect(r.gateState).toBe('BLOCKED');
    expect(mockFetch).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });
});

// ─── Predeploy bypass is staging-only ─────────────────────────────────────────

describe('isDeployBypassAuthorized — staging-only', () => {
  it('refuses without the skip flag', async () => {
    const { isDeployBypassAuthorized } = await import('~/lib/qhub/schema-contract');
    expect(isDeployBypassAuthorized({}).allowed).toBe(false);
    expect(isDeployBypassAuthorized({ QHUB_DEPLOY_ENV: 'staging' }).allowed).toBe(false);
  });

  it('allows only skip-flag + staging marker', async () => {
    const { isDeployBypassAuthorized } = await import('~/lib/qhub/schema-contract');
    expect(isDeployBypassAuthorized({ QHUB_SKIP_SCHEMA_CHECK: '1', QHUB_DEPLOY_ENV: 'staging' }).allowed).toBe(true);
    expect(isDeployBypassAuthorized({ QHUB_SKIP_SCHEMA_CHECK: '1', FLY_APP_NAME: 'qhub-studio-staging' }).allowed).toBe(
      true,
    );
  });

  it('never bypasses production, even with the skip flag', async () => {
    const { isDeployBypassAuthorized } = await import('~/lib/qhub/schema-contract');
    const prod = isDeployBypassAuthorized({ QHUB_SKIP_SCHEMA_CHECK: '1', QHUB_DEPLOY_ENV: 'production' });
    expect(prod.allowed).toBe(false);
    expect(prod.reason).toBe('production-never-bypasses');

    const prodFly = isDeployBypassAuthorized({ QHUB_SKIP_SCHEMA_CHECK: '1', FLY_APP_NAME: 'qhub-studio-prod' });
    expect(prodFly.allowed).toBe(false);
  });

  it('refuses a skip flag with no environment marker at all', async () => {
    const { isDeployBypassAuthorized } = await import('~/lib/qhub/schema-contract');
    const d = isDeployBypassAuthorized({ QHUB_SKIP_SCHEMA_CHECK: '1' });
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('no-staging-marker');
  });
});
