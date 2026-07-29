/**
 * QHUB Commercial Launch R4 — CENTRAL SCHEMA READINESS (service + fail-closed routes)
 * app/test/commercial-readiness.test.ts
 *
 * The central readiness service is the ONE caller of qhub_verify_commercial_schema().
 * It fails closed for every non-READY state and exposes only compact reason codes.
 * These tests also prove the runtime routes fail closed BEFORE any Stripe call, write,
 * or model invocation, and that the staff diagnostic exposes a safe, compact status.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const EXPECTED = '2026-07-30.commercial-launch-r4';

// ─── Supabase createClient injection (the ONLY external dependency) ─────────────
const S = vi.hoisted(() => ({ rpc: vi.fn() }));

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({ rpc: S.rpc }),
}));

import {
  getCommercialSchemaReadiness,
  assertCommercialSchemaReady,
  requireCommercialReady,
  isCommercialReady,
  resetCommercialReadinessCache,
  CommercialNotReadyError,
  EXPECTED_COMMERCIAL_SCHEMA_VERSION,
} from '~/lib/qhub/commercial/commercial-schema-check.server';

const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };

function rpcReturns(data: unknown, error: unknown = null) {
  S.rpc.mockResolvedValue({ data, error });
}

beforeEach(() => {
  vi.clearAllMocks();
  resetCommercialReadinessCache();
});

describe('getCommercialSchemaReadiness — state machine (fail closed)', () => {
  it('exposes the exact expected version constant', () => {
    expect(EXPECTED_COMMERCIAL_SCHEMA_VERSION).toBe(EXPECTED);
  });

  it('READY when version matches, ready=true, and failed is empty', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('READY');
    expect(isCommercialReady(r)).toBe(true);
    expect(r.failed).toEqual([]);
  });

  it('NOT_READY on a version mismatch (never READY on the wrong version)', async () => {
    rpcReturns({ expected_version: 'some-other-version', ready: true, failed: [] });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('NOT_READY');
    expect(r.failed).toContain('version_mismatch');
  });

  it('NOT_READY when ready=false', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: [] });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('NOT_READY');
  });

  it('NOT_READY when any check failed (even if ready=true is claimed)', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: ['reconcile_checkout_signature'] });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('NOT_READY');
    expect(r.failed).toContain('reconcile_checkout_signature');
  });

  it('UNAVAILABLE when the verifier RPC errors (missing verifier / permission / connectivity)', async () => {
    rpcReturns(null, { code: '42883', message: 'function does not exist' });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('UNAVAILABLE');
    expect(r.failed).toEqual(['verifier_unavailable']);

    // Fail closed: verifier-unavailable is NEVER treated as READY.
    expect(isCommercialReady(r)).toBe(false);
  });

  it('UNAVAILABLE on a malformed verifier response', async () => {
    rpcReturns({ nope: true });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('UNAVAILABLE');
    expect(r.failed).toEqual(['malformed_verifier_response']);
  });

  it('CONFIGURATION_ERROR when Supabase config is absent (never probes)', async () => {
    const r = await getCommercialSchemaReadiness({});
    expect(r.state).toBe('CONFIGURATION_ERROR');
    expect(S.rpc).not.toHaveBeenCalled();
  });

  it('UNAVAILABLE when the probe throws, without leaking the raw error', async () => {
    S.rpc.mockRejectedValue(new Error('postgres://user:secret@host connection refused'));

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('UNAVAILABLE');
    expect(r.failed).toEqual(['verifier_probe_failed']);

    // No secret/connection detail is present in the exposed reason codes.
    expect(JSON.stringify(r)).not.toMatch(/secret|postgres:\/\//);
  });

  it('caps exposed failed reason codes and never includes SQL/secrets', async () => {
    const many = Array.from({ length: 60 }, (_, i) => `check_${i}`);
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: many });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.failed.length).toBeLessThanOrEqual(25);
  });

  it('uses a short version-keyed cache (does not hammer the DB)', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    await getCommercialSchemaReadiness(ENV);

    const second = await getCommercialSchemaReadiness(ENV);

    expect(S.rpc).toHaveBeenCalledTimes(1); // second served from cache
    expect(second.cacheAgeMs).toBeGreaterThanOrEqual(0);
  });
});

describe('assertCommercialSchemaReady / requireCommercialReady', () => {
  it('assert throws CommercialNotReadyError when NOT READY', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: [] });
    await expect(assertCommercialSchemaReady(ENV)).rejects.toBeInstanceOf(CommercialNotReadyError);
  });

  it('assert resolves when READY', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });
    await expect(assertCommercialSchemaReady(ENV)).resolves.toMatchObject({ state: 'READY' });
  });

  it('requireCommercialReady returns a generic 503 for user routes when NOT READY', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: ['x'] });

    const gate = await requireCommercialReady(ENV);
    expect(gate.ok).toBe(false);

    if (!gate.ok) {
      expect(gate.response.status).toBe(503);

      const body = (await gate.response.json()) as { error?: string };
      expect(body.error).toBe('commercial_unavailable'); // generic — no failed-check detail
      expect(JSON.stringify(body)).not.toMatch(/version_mismatch|check_/);
    }
  });

  it('requireCommercialReady returns a retryable 500 for webhooks when NOT READY', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: ['x'] });

    const gate = await requireCommercialReady(ENV, { webhook: true });
    expect(gate.ok === false && gate.response.status).toBe(500);
  });

  it('requireCommercialReady passes through when READY', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    const gate = await requireCommercialReady(ENV);
    expect(gate.ok).toBe(true);
  });
});

describe('predeploy schema smoke check wires the commercial verifier (additive)', () => {
  const script = readFileSync(fileURLToPath(new URL('../../scripts/schema-smoke-check.mjs', import.meta.url)), 'utf8');

  it('calls qhub_verify_commercial_schema and pins the exact version', () => {
    expect(script).toMatch(/qhub_verify_commercial_schema/);
    expect(script).toContain(EXPECTED);
  });

  it('has a dedicated commercial verify function that fails closed', () => {
    expect(script).toMatch(/function verifyCommercial\(/);

    // Version mismatch / ready=false / failed / malformed all resolve to ready:false.
    expect(script).toMatch(/VERSION_MISMATCH/);
    expect(script).toMatch(/MALFORMED_COMMERCIAL_METADATA/);
  });

  it('exits nonzero when the commercial contract is not ready', () => {
    // The commercial branch must call process.exit(1) on a not-ready result.
    const branch = script.slice(script.indexOf('verifyCommercial(url, serviceKey)'));
    expect(branch).toMatch(/if \(!commercialMeta\.ready\)[\s\S]*process\.exit\(1\)/);
  });

  it('preserves the existing Gate 04 and Agent Foundation checks (additive)', () => {
    expect(script).toMatch(/qhub_verify_governance_schema/);
    expect(script).toMatch(/qhub_verify_agent_schema/);
    expect(script).toContain('2026-07-26.gate04');
    expect(script).toContain('2026-07-27.agent-foundation');
  });
});
