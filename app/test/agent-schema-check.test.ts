/**
 * QHUB Agent Framework — schema readiness (TS layer) tests
 * app/test/agent-schema-check.test.ts
 *
 * Exercises getAgentSchemaReadiness / assertAgentSchemaReady with a mocked fetch,
 * proving fail-closed behavior and non-secret output. (Catalog-level failures —
 * missing table/FK/RLS/policy/privilege — are proven against real PostgreSQL in
 * agent-schema-verifier.test.ts.)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getAgentSchemaReadiness,
  assertAgentSchemaReady,
  EXPECTED_AGENT_SCHEMA_VERSION,
} from '~/lib/qhub/agent/agent-schema-check.server';

const SERVICE_KEY = 'super-secret-service-role-key-value';
let seq = 0;

/*
 * Distinct project ref on every call → the readiness cache never bleeds between
 * probes, so uncached assert() calls observe the freshly mocked fetch.
 */
const env = () => ({ SUPABASE_URL: `https://proj${(seq += 1)}.supabase.co`, SUPABASE_SERVICE_ROLE_KEY: SERVICE_KEY });

const READY_CHECKS = Array.from({ length: 20 }, (_, i) => ({
  identifier: `c${i}`,
  category: 'TABLE',
  ready: true,
  reason_code: 'OK',
}));

function mockFetch(opts: { table?: 'present' | 'missing'; rpc?: 'ready' | 'notready' | 'missing' | 'stale' }) {
  const { table = 'present', rpc = 'ready' } = opts;
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    const u = String(url);

    if (u.includes('/rpc/qhub_verify_agent_schema')) {
      if (rpc === 'missing') {
        return { ok: false, status: 404, json: async () => ({ code: 'PGRST202' }) } as any;
      }

      const body =
        rpc === 'stale'
          ? { expected_version: '1999-01-01.wrong', ready: true, checks: READY_CHECKS }
          : rpc === 'notready'
            ? {
                expected_version: EXPECTED_AGENT_SCHEMA_VERSION,
                ready: false,
                checks: [
                  { identifier: 'rls.enabled_all', category: 'RLS_ENABLED', ready: false, reason_code: 'RLS_DISABLED' },
                  ...READY_CHECKS,
                ],
              }
            : { expected_version: EXPECTED_AGENT_SCHEMA_VERSION, ready: true, checks: READY_CHECKS };

      return { ok: true, status: 200, json: async () => body } as any;
    }

    // table probe
    if (table === 'missing') {
      return { ok: false, status: 404, json: async () => ({ code: 'PGRST205' }) } as any;
    }

    return { ok: true, status: 200, json: async () => [] } as any;
    void init;
  }) as any;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('Agent Framework schema readiness (TS layer)', () => {
  it('reports READY when tables + verifier are healthy', async () => {
    mockFetch({ table: 'present', rpc: 'ready' });

    const r = await getAgentSchemaReadiness(env(), { force: true });
    expect(r.ready).toBe(true);
    expect(r.expectedSchemaVersion).toBe(EXPECTED_AGENT_SCHEMA_VERSION);
  });

  it('fails closed when a table is missing (tests 1-4)', async () => {
    mockFetch({ table: 'missing', rpc: 'ready' });
    expect((await getAgentSchemaReadiness(env(), { force: true })).ready).toBe(false);
  });

  it('fails closed when the verifier reports not-ready (tests 5-11)', async () => {
    mockFetch({ table: 'present', rpc: 'notready' });

    const r = await getAgentSchemaReadiness(env(), { force: true });
    expect(r.ready).toBe(false);
    expect(r.objects.some((o) => o.identifier === 'rls.enabled_all' && o.state === 'missing')).toBe(true);
  });

  it('fails closed when the verifier function is missing (test 12)', async () => {
    mockFetch({ table: 'present', rpc: 'missing' });
    expect((await getAgentSchemaReadiness(env(), { force: true })).ready).toBe(false);
  });

  it('fails closed on a stale/mismatched verifier version', async () => {
    mockFetch({ table: 'present', rpc: 'stale' });
    expect((await getAgentSchemaReadiness(env(), { force: true })).ready).toBe(false);
  });

  it('fails closed when credentials are absent', async () => {
    const r = await getAgentSchemaReadiness({}, { force: true });
    expect(r.ready).toBe(false);
  });

  it('assertAgentSchemaReady throws when not ready and resolves when ready', async () => {
    mockFetch({ table: 'missing', rpc: 'ready' });
    await expect(assertAgentSchemaReady(env())).rejects.toThrow();
    mockFetch({ table: 'present', rpc: 'ready' });
    await expect(assertAgentSchemaReady(env())).resolves.toBeUndefined();
  });

  it('readiness output contains no secrets (test 19)', async () => {
    mockFetch({ table: 'present', rpc: 'ready' });

    const r = await getAgentSchemaReadiness(env(), { force: true });
    expect(JSON.stringify(r)).not.toContain(SERVICE_KEY);
    expect(JSON.stringify(r)).not.toMatch(/service_role_key|password|secret/i);
  });
});
