/**
 * QHUB Commercial Launch R5 — CENTRAL COMMERCIAL SCHEMA READINESS (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-schema-check.server.ts
 *
 * The ONE place that calls qhub_verify_commercial_schema(). It requires the exact
 * version 2026-07-30.commercial-launch-r4, ready=true, and an empty failed[]; it fails
 * closed for every non-READY state and exposes only ALLOWLISTED, compact reason codes —
 * never SQL, secrets, Stripe payloads, tenant data, project URLs, or exception text.
 *
 * RUNTIME-UNFORGEABLE BOUNDARY: a READY result mints a genuine ReadyToken CLASS instance
 * (a JS #private-branded object registered in a module-private WeakSet). Ordinary code
 * cannot manufacture one — plain objects, Object.create/prototype tricks, JSON round-trips,
 * structured clones, copied fields, and `as CommercialReadyToken` casts are ALL rejected
 * at runtime because they are not in the registry. Validation also enforces a cryptographic
 * SHA-256 target digest, deployment environment, verifier identity, schema version, and
 * checkedAt/expiresAt freshness (TTL == cache TTL). The token cannot cross a network/request
 * boundary (a deserialized object is not registered).
 */

import { createHash } from 'node:crypto';
import { json } from '@remix-run/cloudflare';
import { createClient } from '@supabase/supabase-js';

export const EXPECTED_COMMERCIAL_SCHEMA_VERSION = '2026-07-30.commercial-launch-r4';

const VERIFIER_RPC = 'qhub_verify_commercial_schema';
const VERIFIER_IDENTITY = `${VERIFIER_RPC}@${EXPECTED_COMMERCIAL_SCHEMA_VERSION}`;

/** Readiness cache TTL, and the token TTL (a token is never fresher-lived than the cache). */
const CACHE_MS = 5_000;
const TOKEN_TTL_MS = CACHE_MS;
const CLOCK_SKEW_MS = 2_000;

export type ReadinessState = 'READY' | 'NOT_READY' | 'UNAVAILABLE' | 'CONFIGURATION_ERROR';

/**
 * Allowlist of KNOWN commercial verifier check identifiers (see the migration's
 * qhub_verify_commercial_schema()). Anything not in this set is collapsed to a single
 * generic code so an adversarial/compromised verifier can never inject arbitrary text
 * (SQL, URLs, tenant ids, stack traces) into our logs or staff diagnostics.
 */
const KNOWN_VERIFIER_CHECKS = new Set<string>([
  'checkout_consume_rpc_contract',
  'checkout_session_setup_contract',
  'credit_rpc_browser_exec',
  'credit_rpc_contract',
  'credit_rpc_overload',
  'invitation_active_uniqueness',
  'lease_mark_rpc_contract',
  'ledger_immutable_contract',
  'project_rpc_contract',
  'reconcile_rpc_contract',
  'review_audit_immutable',
  'review_rpc_contract',
  'seat_rpc_browser_exec',
  'seat_rpc_caller_cap',
  'seat_rpc_contract',
  'webhook_lease_contract',
  'webhook_rpc_contract',
  'webhook_state_contract',
]);

/** Our own (already-safe) internal reason codes, never sourced from the verifier body. */
const INTERNAL_REASON_CODES = new Set<string>([
  'missing_supabase_config',
  'verifier_unavailable',
  'malformed_verifier_response',
  'verifier_probe_failed',
  'version_mismatch',
  'readiness_token_forged',
  'readiness_token_version',
  'readiness_token_verifier',
  'readiness_token_target',
  'readiness_token_env',
  'readiness_token_malformed',
  'readiness_token_future',
  'readiness_token_expired',
  'readiness_token_stale',
]);

const UNKNOWN_FAILURE_CODE = 'commercial_schema_unknown_failure';

/** Map any failed-check name to a safe, compact code (unknown → generic). */
export function safeReasonCode(raw: unknown): string {
  if (typeof raw === 'string' && (KNOWN_VERIFIER_CHECKS.has(raw) || INTERNAL_REASON_CODES.has(raw))) {
    return raw;
  }

  return UNKNOWN_FAILURE_CODE;
}

export interface CommercialReadiness {
  state: ReadinessState;
  expected: string;
  version?: string;

  /** Allowlisted, safe reason codes only — never raw verifier text. */
  failed: string[];

  /** Non-reversible 128-bit target fingerprint (safe to surface to staff). */
  targetKey: string;
  checkedAt: number;
  cacheAgeMs?: number;
}

// ─── Server clock (overridable ONLY under test) ─────────────────────────────────

let clockNow: () => number = () => Date.now();

/**
 * Test-only server-clock override. Throws in production so the clock can never be moved
 * by application code at runtime. Pass null to restore the real clock.
 */
export function __setServerClockForTests(fn: (() => number) | null): void {
  if ((process.env.NODE_ENV ?? '').toLowerCase() === 'production') {
    throw new Error('server clock cannot be overridden in production');
  }

  clockNow = fn ?? (() => Date.now());
}

// ─── Cryptographic, collision-resistant target identity ─────────────────────────

function normalizedSupabaseHost(env: Record<string, string | undefined>): string {
  const raw = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';

  try {
    return new URL(raw).host.toLowerCase();
  } catch {
    return raw.trim().toLowerCase();
  }
}

function deploymentEnv(env: Record<string, string | undefined>): string {
  return (env.QHUB_DEPLOY_ENV ?? process.env.QHUB_DEPLOY_ENV ?? 'unknown').toLowerCase();
}

/** Deterministic canonical descriptor of the target (never exposed raw). */
function targetDescriptor(env: Record<string, string | undefined>): string {
  return JSON.stringify({
    v: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
    host: normalizedSupabaseHost(env),
    deployEnv: deploymentEnv(env),
    verifier: VERIFIER_IDENTITY,
  });
}

/**
 * Full SHA-256 target digest (256 bits) — the cache key and the token's target binding.
 * Collision-resistant (replaces the old 32-bit FNV that reproduced a cross-target
 * collision). A change to host / deploy env / schema version / verifier identity yields a
 * different digest, so target A can never satisfy target B and staging cannot satisfy prod.
 */
export function commercialTargetDigest(env: Record<string, string | undefined>): string {
  return createHash('sha256').update(targetDescriptor(env)).digest('hex');
}

/** Short (128-bit) NON-reversible fingerprint for diagnostics — never the raw host/URL. */
export function commercialTargetFingerprint(env: Record<string, string | undefined>): string {
  return commercialTargetDigest(env).slice(0, 32);
}

/** Back-compat alias — the cache key is the FULL 256-bit digest. */
export function commercialTargetKey(env: Record<string, string | undefined>): string {
  return commercialTargetDigest(env);
}

// ─── Runtime-authentic readiness token ──────────────────────────────────────────

/**
 * The real token. A JS #private field brands the CLASS, and every minted instance is
 * registered in a module-private WeakSet. Authenticity is proven by registry membership
 * at validation time, so no forged/copied/cloned/cast object can pass.
 */
class ReadyToken {
  readonly #authentic = true;
  readonly schemaVersion: string;
  readonly targetDigest: string;
  readonly deployEnv: string;
  readonly verifierIdentity: string;
  readonly checkedAt: number;
  readonly expiresAt: number;

  constructor(env: Record<string, string | undefined>, now: number) {
    this.schemaVersion = EXPECTED_COMMERCIAL_SCHEMA_VERSION;
    this.targetDigest = commercialTargetDigest(env);
    this.deployEnv = deploymentEnv(env);
    this.verifierIdentity = VERIFIER_IDENTITY;
    this.checkedAt = now;
    this.expiresAt = now + TOKEN_TTL_MS;
    void this.#authentic;
  }
}

/** Only genuine, module-minted instances live here. */
const tokenRegistry = new WeakSet<object>();

/**
 * Opaque handle. Application code receives this type but can never see the class or build
 * an instance — authenticity is a runtime property (registry membership), not a shape.
 */
export type CommercialReadyToken = { readonly __commercialReadyToken: unique symbol };

function mintReadyToken(env: Record<string, string | undefined>): CommercialReadyToken {
  const t = new ReadyToken(env, clockNow());
  tokenRegistry.add(t);

  return t as unknown as CommercialReadyToken;
}

/**
 * Test-only mint of a GENUINE (registered) token. Throws in production. This is not an
 * `as` bypass — it produces an authentic registry-backed token, and only under test.
 */
export function __mintReadyTokenForTests(env: Record<string, string | undefined>): CommercialReadyToken {
  if ((process.env.NODE_ENV ?? '').toLowerCase() === 'production') {
    throw new Error('__mintReadyTokenForTests is not available in production');
  }

  return mintReadyToken(env);
}

/**
 * Re-validate a token at the mutation choke point. Throws CommercialNotReadyError on ANY
 * failure: forgery (not registry-backed), wrong schema version / verifier / target digest /
 * deployment environment, malformed or future checkedAt, expiry, or age beyond the TTL.
 */
export function assertReadyToken(token: CommercialReadyToken, env: Record<string, string | undefined>): void {
  const now = clockNow();
  const t = token as unknown as ReadyToken | null | undefined;

  const fail = (code: string): never => {
    throw new CommercialNotReadyError({
      state: 'NOT_READY',
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      failed: [code],
      targetKey: commercialTargetFingerprint(env),
      checkedAt: now,
    });
  };

  /*
   * 1. Runtime authenticity — the single non-bypassable check. Only module-minted class
   * instances are registered; every forgery/clone/cast fails here.
   */
  if (!t || typeof t !== 'object' || !tokenRegistry.has(t)) {
    fail('readiness_token_forged');

    return;
  }

  // 2. Binding to the exact contract + target.
  if (t.schemaVersion !== EXPECTED_COMMERCIAL_SCHEMA_VERSION) {
    fail('readiness_token_version');
  }

  if (t.verifierIdentity !== VERIFIER_IDENTITY) {
    fail('readiness_token_verifier');
  }

  if (t.targetDigest !== commercialTargetDigest(env)) {
    fail('readiness_token_target');
  }

  if (t.deployEnv !== deploymentEnv(env)) {
    fail('readiness_token_env');
  }

  // 3. Freshness — checkedAt/expiresAt validated on every use, bounded by the cache TTL.
  if (!Number.isFinite(t.checkedAt) || !Number.isFinite(t.expiresAt)) {
    fail('readiness_token_malformed');
  }

  if (t.checkedAt > now + CLOCK_SKEW_MS) {
    fail('readiness_token_future');
  }

  if (now >= t.expiresAt) {
    fail('readiness_token_expired');
  }

  if (now - t.checkedAt > TOKEN_TTL_MS + CLOCK_SKEW_MS) {
    fail('readiness_token_stale');
  }
}

// ─── Target-keyed readiness cache ───────────────────────────────────────────────

const cache = new Map<string, { at: number; value: CommercialReadiness }>();

/** Test/maintenance hook — clears the entire target-keyed readiness cache. */
export function resetCommercialReadinessCache(): void {
  cache.clear();
}

export function isCommercialReady(r: CommercialReadiness): boolean {
  return r.state === 'READY';
}

/**
 * Resolve commercial schema readiness for the CURRENT target. Fails closed: any error,
 * malformed response, version mismatch, or failed check yields a non-READY state.
 * Reason codes are allowlisted. Cached per full target digest with a short TTL.
 */
export async function getCommercialSchemaReadiness(
  env: Record<string, string | undefined>,
): Promise<CommercialReadiness> {
  const now = clockNow();
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';
  const cacheKey = commercialTargetDigest(env);
  const fingerprint = commercialTargetFingerprint(env);

  if (!url || !key) {
    return {
      state: 'CONFIGURATION_ERROR',
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      failed: ['missing_supabase_config'],
      targetKey: fingerprint,
      checkedAt: now,
    };
  }

  const hit = cache.get(cacheKey);

  if (hit && now - hit.at < CACHE_MS) {
    return { ...hit.value, cacheAgeMs: now - hit.at };
  }

  const finalize = (r: Omit<CommercialReadiness, 'expected' | 'checkedAt' | 'targetKey'>): CommercialReadiness => {
    const value: CommercialReadiness = {
      ...r,
      failed: r.failed.map(safeReasonCode),
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      targetKey: fingerprint,
      checkedAt: now,
    };
    cache.set(cacheKey, { at: now, value });

    return value;
  };

  try {
    const sb = createClient(url, key, { auth: { persistSession: false } });
    const { data, error } = await sb.rpc(VERIFIER_RPC);

    if (error) {
      // Missing verifier / permission / connectivity — treat as UNAVAILABLE (fail closed).
      return finalize({ state: 'UNAVAILABLE', failed: ['verifier_unavailable'] });
    }

    const body = data as { expected_version?: unknown; ready?: unknown; failed?: unknown } | null;

    if (
      !body ||
      typeof body.ready !== 'boolean' ||
      !Array.isArray(body.failed) ||
      typeof body.expected_version !== 'string'
    ) {
      return finalize({ state: 'UNAVAILABLE', failed: ['malformed_verifier_response'] });
    }

    if (body.expected_version !== EXPECTED_COMMERCIAL_SCHEMA_VERSION) {
      return finalize({ state: 'NOT_READY', version: body.expected_version, failed: ['version_mismatch'] });
    }

    if (body.ready !== true || body.failed.length > 0) {
      return finalize({
        state: 'NOT_READY',
        version: body.expected_version,
        failed: (body.failed as unknown[]).slice(0, 25).map(safeReasonCode),
      });
    }

    return finalize({ state: 'READY', version: body.expected_version, failed: [] });
  } catch {
    // Never log the raw error (could carry connection/tenant detail); fail closed.
    return finalize({ state: 'UNAVAILABLE', failed: ['verifier_probe_failed'] });
  }
}

export class CommercialNotReadyError extends Error {
  readonly readiness: CommercialReadiness;

  constructor(readiness: CommercialReadiness) {
    // Include the allowlisted reason codes (safe — never raw verifier/tenant text).
    super(
      `commercial schema not ready: ${readiness.state}${readiness.failed.length ? ` (${readiness.failed.join(',')})` : ''}`,
    );
    this.name = 'CommercialNotReadyError';
    this.readiness = readiness;
  }
}

/**
 * Throw CommercialNotReadyError unless READY; otherwise return a target-bound, time-boxed
 * CommercialReadyToken. This (and requireCommercialReady) is the ONLY producer of a token.
 */
export async function assertCommercialSchemaReady(
  env: Record<string, string | undefined>,
): Promise<CommercialReadyToken> {
  const r = await getCommercialSchemaReadiness(env);

  if (r.state !== 'READY') {
    throw new CommercialNotReadyError(r);
  }

  return mintReadyToken(env);
}

/**
 * Route-level readiness gate. On READY returns a genuine token to thread into the protected
 * services; on any non-READY returns a fail-closed generic Response (503 for user routes,
 * 500-retryable for webhooks) — commercial callers never see check detail.
 */
export async function requireCommercialReady(
  env: Record<string, string | undefined>,
  opts: { webhook?: boolean } = {},
): Promise<{ ok: true; token: CommercialReadyToken } | { ok: false; response: Response }> {
  const r = await getCommercialSchemaReadiness(env);

  if (r.state === 'READY') {
    return { ok: true, token: mintReadyToken(env) };
  }

  return {
    ok: false,
    response: json({ ok: false, error: 'commercial_unavailable' }, { status: opts.webhook ? 500 : 503 }),
  };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
