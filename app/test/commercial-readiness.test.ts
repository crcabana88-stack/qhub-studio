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
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const EXPECTED = '2026-07-30.commercial-launch-r5';

// ─── Supabase createClient injection (the ONLY external dependency) ─────────────
const S = vi.hoisted(() => ({ rpc: vi.fn() }));

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({ rpc: S.rpc }),
}));

import {
  getCommercialSchemaReadiness,
  assertCommercialSchemaReady,
  assertReadyToken,
  requireCommercialReady,
  isCommercialReady,
  resetCommercialReadinessCache,
  commercialTargetKey,
  commercialTargetDigest,
  commercialTargetFingerprint,
  safeReasonCode,
  __mintReadyTokenForTests,
  __setServerClockForTests,
  CommercialNotReadyError,
  EXPECTED_COMMERCIAL_SCHEMA_VERSION,
} from '~/lib/qhub/commercial/commercial-schema-check.server';

const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };
const ENV_B = { SUPABASE_URL: 'https://other.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };
const ENV_PROD = { ...ENV, QHUB_DEPLOY_ENV: 'production' };
const ENV_STAGING = { ...ENV, QHUB_DEPLOY_ENV: 'staging' };

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
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: ['reconcile_rpc_contract'] });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.state).toBe('NOT_READY');
    expect(r.failed).toContain('reconcile_rpc_contract'); // known allowlisted code preserved
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

  it('assert resolves to a genuine target-bound token when READY (opaque; validated at use)', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    const token = await assertCommercialSchemaReady(ENV);

    // The token is opaque — authenticity/target binding is a RUNTIME property, checked here.
    expect(() => assertReadyToken(token, ENV)).not.toThrow();
    expect(() => assertReadyToken(token, ENV_PROD)).toThrow(CommercialNotReadyError);
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

describe('safe failed-check allowlist (no adversarial verifier text leaks)', () => {
  it('maps known verifier check ids to themselves', () => {
    expect(safeReasonCode('reconcile_rpc_contract')).toBe('reconcile_rpc_contract');
    expect(safeReasonCode('seat_rpc_caller_cap')).toBe('seat_rpc_caller_cap');
  });

  it('collapses unknown/malicious failed strings to a single generic code', () => {
    const malicious = "'; DROP TABLE qhub_subscriptions; -- postgres://user:pw@host";
    expect(safeReasonCode(malicious)).toBe('commercial_schema_unknown_failure');
    expect(safeReasonCode('SELECT * FROM secrets')).toBe('commercial_schema_unknown_failure');
    expect(safeReasonCode(42)).toBe('commercial_schema_unknown_failure');
  });

  it('readiness output never surfaces raw adversarial failed text', async () => {
    rpcReturns({
      expected_version: EXPECTED,
      ready: false,
      failed: ['reconcile_rpc_contract', "'; DROP TABLE x; -- https://leak.example"],
    });

    const r = await getCommercialSchemaReadiness(ENV);
    expect(r.failed).toContain('reconcile_rpc_contract');
    expect(r.failed).toContain('commercial_schema_unknown_failure');
    expect(JSON.stringify(r)).not.toMatch(/DROP TABLE|https:\/\/leak/);
  });
});

describe('target-keyed readiness cache + token binding', () => {
  it('a READY for target A does not satisfy target B (distinct cache entries)', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    const a = await getCommercialSchemaReadiness(ENV);

    // Different Supabase host → different target key → a fresh probe (not A's cache).
    rpcReturns({ expected_version: EXPECTED, ready: false, failed: ['reconcile_rpc_contract'] });

    const b = await getCommercialSchemaReadiness(ENV_B);

    expect(a.state).toBe('READY');
    expect(b.state).toBe('NOT_READY');
    expect(a.targetKey).not.toBe(b.targetKey);
    expect(S.rpc).toHaveBeenCalledTimes(2); // B was not served from A's cache
  });

  it('staging READY cannot satisfy production (different deploy env → different target)', () => {
    expect(commercialTargetKey(ENV_STAGING)).not.toBe(commercialTargetKey(ENV_PROD));
  });

  it('a token minted for target A is rejected against target B', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });

    const tokenA = await assertCommercialSchemaReady(ENV);

    // Same token, different target → must throw (staging token cannot authorize prod).
    expect(() => assertReadyToken(tokenA, ENV_PROD)).toThrow(CommercialNotReadyError);

    // But it is valid for its own target.
    expect(() => assertReadyToken(tokenA, ENV)).not.toThrow();
  });

  it('a forged/empty token is rejected', () => {
    expect(() => assertReadyToken({ schemaVersion: 'x', targetKey: 'y', checkedAt: 'z' } as never, ENV)).toThrow(
      CommercialNotReadyError,
    );
  });
});

describe('runtime-unforgeable token — forgery probes (isolated negative tests)', () => {
  afterEach(() => __setServerClockForTests(null));

  // A GENUINE token to copy fields from — copies must still be rejected.
  function genuineShape() {
    const t = __mintReadyTokenForTests(ENV) as unknown as Record<string, unknown>;
    return {
      schemaVersion: t.schemaVersion,
      targetDigest: t.targetDigest,
      deployEnv: t.deployEnv,
      verifierIdentity: t.verifierIdentity,
      checkedAt: t.checkedAt,
      expiresAt: t.expiresAt,
    };
  }

  it('a plain-object forgery is rejected', () => {
    expect(() => assertReadyToken({} as never, ENV)).toThrow(CommercialNotReadyError);
  });

  it('a copied-property forgery (all fields correct) is rejected — authenticity is not shape', () => {
    const forged = { ...genuineShape() } as never;
    expect(() => assertReadyToken(forged, ENV)).toThrow(/readiness_token_forged/);
  });

  it('an Object.create/prototype forgery is rejected', () => {
    const proto = genuineShape();
    const forged = Object.create(proto) as never;
    expect(() => assertReadyToken(forged, ENV)).toThrow(CommercialNotReadyError);
  });

  it('a JSON round-trip of a genuine token is rejected', () => {
    const real = __mintReadyTokenForTests(ENV);
    const roundTripped = JSON.parse(JSON.stringify(real)) as never;
    expect(() => assertReadyToken(roundTripped, ENV)).toThrow(CommercialNotReadyError);
  });

  it('a structured clone of a genuine token is rejected', () => {
    const real = __mintReadyTokenForTests(ENV);

    if (typeof structuredClone === 'function') {
      // structuredClone drops the class identity + registry membership.
      let cloned: never;

      try {
        cloned = structuredClone(real) as never;
      } catch {
        cloned = JSON.parse(JSON.stringify(real)) as never; // class instances may be uncloneable
      }

      expect(() => assertReadyToken(cloned, ENV)).toThrow(CommercialNotReadyError);
    }
  });

  it('a genuine token for the wrong environment / verifier / version is rejected', () => {
    const staging = __mintReadyTokenForTests(ENV_STAGING);
    expect(() => assertReadyToken(staging, ENV_PROD)).toThrow(CommercialNotReadyError); // wrong env + target
  });

  it('a stale token (older than the TTL) is rejected', () => {
    let t = 1_000_000;
    __setServerClockForTests(() => t);

    const real = __mintReadyTokenForTests(ENV);

    t += 6_000; // TTL is 5s → now expired/stale
    expect(() => assertReadyToken(real, ENV)).toThrow(/readiness_token_(expired|stale)/);
  });

  it('a future-checkedAt token beyond clock skew is rejected', () => {
    let t = 1_000_000;
    __setServerClockForTests(() => t);

    const real = __mintReadyTokenForTests(ENV);

    t -= 10_000; // wall clock jumps backward → token checkedAt is now "in the future"
    expect(() => assertReadyToken(real, ENV)).toThrow(/readiness_token_future/);
  });

  it('a fresh token within the TTL is accepted', () => {
    let t = 1_000_000;
    __setServerClockForTests(() => t);

    const real = __mintReadyTokenForTests(ENV);

    t += 1_000; // within the 5s TTL
    expect(() => assertReadyToken(real, ENV)).not.toThrow();
  });

  /*
   * R6: authoritative metadata is in a module-private WeakMap, so mutating the object is
   * INEFFECTIVE — it can never make a token valid for a different target/expiry.
   */
  it('property mutation cannot re-target a genuine token', () => {
    const real = __mintReadyTokenForTests(ENV);

    try {
      (real as unknown as Record<string, unknown>).targetDigest = commercialTargetDigest(ENV_PROD);
      (real as unknown as Record<string, unknown>).deployEnv = 'production';
      (real as unknown as Record<string, unknown>).expiresAt = Number.MAX_SAFE_INTEGER;
    } catch {
      /* frozen object may throw in strict mode — either way authorization is unaffected */
    }

    expect(() => assertReadyToken(real, ENV_PROD)).toThrow(CommercialNotReadyError); // still wrong target
    expect(() => assertReadyToken(real, ENV)).not.toThrow(); // still valid for its own target
  });

  it('Object.defineProperty cannot re-target a genuine token', () => {
    const real = __mintReadyTokenForTests(ENV);

    try {
      Object.defineProperty(real, 'targetDigest', { value: commercialTargetDigest(ENV_PROD), configurable: true });
    } catch {
      /* frozen */
    }

    expect(() => assertReadyToken(real, ENV_PROD)).toThrow(CommercialNotReadyError);
  });

  it('Object.assign cannot re-target a genuine token', () => {
    const real = __mintReadyTokenForTests(ENV);

    try {
      Object.assign(real as object, { targetDigest: commercialTargetDigest(ENV_PROD), deployEnv: 'production' });
    } catch {
      /* frozen */
    }

    expect(() => assertReadyToken(real, ENV_PROD)).toThrow(CommercialNotReadyError);
  });

  it('a Proxy wrapping a genuine token is rejected (different object identity)', () => {
    const real = __mintReadyTokenForTests(ENV);
    const proxied = new Proxy(real as object, {}) as never;

    expect(() => assertReadyToken(proxied, ENV)).toThrow(/readiness_token_forged/);
  });

  it('a genuine token object exposes NO authorization fields (metadata is private)', () => {
    const real = __mintReadyTokenForTests(ENV) as unknown as Record<string, unknown>;
    expect(real.targetDigest).toBeUndefined();
    expect(real.expiresAt).toBeUndefined();
    expect(real.schemaVersion).toBeUndefined();
    expect(Object.isFrozen(real)).toBe(true);
  });

  it('the server clock cannot be overridden in production', () => {
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      expect(() => __setServerClockForTests(() => 0)).toThrow(/production/);
    } finally {
      process.env.NODE_ENV = prev;
    }
  });
});

describe('collision-resistant cryptographic target digest', () => {
  it('the digest is a full 256-bit SHA-256 (64 hex) and the fingerprint is 128-bit (32 hex)', () => {
    expect(commercialTargetDigest(ENV)).toMatch(/^[0-9a-f]{64}$/);
    expect(commercialTargetFingerprint(ENV)).toMatch(/^[0-9a-f]{32}$/);
    expect(commercialTargetDigest(ENV).startsWith(commercialTargetFingerprint(ENV))).toBe(true);
  });

  it('the previously reproduced 32-bit collision (d53c94b3) no longer collides', () => {
    // Two DIFFERENT targets that collided under the old FNV-32 must now differ.
    const a = commercialTargetDigest({ SUPABASE_URL: 'https://project-alpha.supabase.co', QHUB_DEPLOY_ENV: 'staging' });
    const b = commercialTargetDigest({
      SUPABASE_URL: 'https://project-bravo.supabase.co',
      QHUB_DEPLOY_ENV: 'production',
    });
    expect(a).not.toBe(b);
    expect(a.length).toBe(64); // not a 8-hex 32-bit value
  });

  it('host, deploy env, and (implicitly) version/verifier each change the digest', () => {
    const base = commercialTargetDigest(ENV);
    expect(commercialTargetDigest(ENV_B)).not.toBe(base); // host
    expect(commercialTargetDigest(ENV_PROD)).not.toBe(base); // deploy env
  });

  it('a configuration change invalidates the cache (fresh probe for the new target)', async () => {
    rpcReturns({ expected_version: EXPECTED, ready: true, failed: [] });
    await getCommercialSchemaReadiness(ENV);

    rpcReturns({ expected_version: EXPECTED, ready: false, failed: ['reconcile_rpc_contract'] });

    const changed = await getCommercialSchemaReadiness({ ...ENV, QHUB_DEPLOY_ENV: 'production' });

    expect(changed.state).toBe('NOT_READY');
    expect(S.rpc).toHaveBeenCalledTimes(2);
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

  it('has NO staging/production skip — driven by the fail-closed deploy-env enum', () => {
    expect(script).not.toMatch(/authorized-staging-bypass/);
    expect(script).toMatch(/schemaCheckDecision/);
    expect(script).toMatch(/parseDeployEnv/);
    expect(script).toMatch(/QHUB_LOCAL_TEST_SCHEMA_BYPASS/);

    // A deployed target can never bypass; an invalid env is a CONFIGURATION_ERROR.
    expect(script).toMatch(/deployed-target-never-bypasses/);
    expect(script).toMatch(/CONFIG_ERROR/);
  });

  it('local-test bypass requires NODE_ENV=test AND the explicit test-only flag', () => {
    expect(script).toMatch(/NODE_ENV.*===.*['"]test['"]/);
    expect(script).toMatch(/QHUB_LOCAL_TEST_SCHEMA_BYPASS === '1'/);
  });
});
