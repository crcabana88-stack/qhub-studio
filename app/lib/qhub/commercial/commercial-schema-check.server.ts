/**
 * QHUB Commercial Launch R4 — CENTRAL COMMERCIAL SCHEMA READINESS (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-schema-check.server.ts
 *
 * The ONE place that calls qhub_verify_commercial_schema(). It requires the exact
 * version 2026-07-30.commercial-launch-r4, ready=true, and an empty failed[]; it fails
 * closed for every non-READY state and exposes only ALLOWLISTED, compact reason codes —
 * never SQL, secrets, Stripe payloads, tenant data, project URLs, or exception text.
 *
 * NON-BYPASSABLE BOUNDARY: a READY result mints a branded CommercialReadyToken bound to
 * the exact (schemaVersion, targetKey). Only this module constructs the token; every
 * exported commercial mutation/protected service requires it and re-validates it against
 * the current target before any protected side effect (see mutator() in the store).
 *
 * TARGET-KEYED: readiness (and the token) are scoped to a non-sensitive target key that
 * binds the schema version, normalized Supabase URL, deployment environment, and verifier
 * identity — so a READY for staging can never satisfy production, or target A satisfy B.
 */

import { json } from '@remix-run/cloudflare';
import { createClient } from '@supabase/supabase-js';

export const EXPECTED_COMMERCIAL_SCHEMA_VERSION = '2026-07-30.commercial-launch-r4';

const VERIFIER_RPC = 'qhub_verify_commercial_schema';
const VERIFIER_IDENTITY = `${VERIFIER_RPC}@${EXPECTED_COMMERCIAL_SCHEMA_VERSION}`;

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
  'readiness_token_mismatch',
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

  /** Non-reversible target fingerprint (safe to surface to staff). */
  targetKey: string;
  checkedAt: number;
  cacheAgeMs?: number;
}

// ─── Target key (non-sensitive, stable, non-reversible) ─────────────────────────

/** FNV-1a 32-bit → 8-hex. Non-cryptographic but non-reversible and non-sensitive. */
function fnv1a(input: string): string {
  let h = 0x811c9dc5;

  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }

  return (h >>> 0).toString(16).padStart(8, '0');
}

function normalizedSupabaseUrl(env: Record<string, string | undefined>): string {
  const raw = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';

  try {
    return new URL(raw).host.toLowerCase();
  } catch {
    return raw.trim().toLowerCase();
  }
}

/**
 * The readiness/token target key. Binds schema version + normalized Supabase host +
 * deployment environment + verifier identity. A READY for one target NEVER satisfies
 * another (staging vs production, project A vs B). Exposes no raw URL.
 */
export function commercialTargetKey(env: Record<string, string | undefined>): string {
  const host = normalizedSupabaseUrl(env);
  const deployEnv = (env.QHUB_DEPLOY_ENV ?? process.env.QHUB_DEPLOY_ENV ?? 'unknown').toLowerCase();
  const material = `${EXPECTED_COMMERCIAL_SCHEMA_VERSION}|${host}|${deployEnv}|${VERIFIER_IDENTITY}`;

  return fnv1a(material);
}

// ─── Branded, non-forgeable readiness token ─────────────────────────────────────

declare const readyBrand: unique symbol;

/**
 * Proof of an exact READY result for a specific target. Constructible ONLY by this
 * module (mintReadyToken). Callers cannot build it without an `as CommercialReadyToken`
 * cast, which the architecture test forbids outside this module + tests.
 */
export interface CommercialReadyToken {
  readonly [readyBrand]: true;
  readonly schemaVersion: typeof EXPECTED_COMMERCIAL_SCHEMA_VERSION;
  readonly targetKey: string;
  readonly checkedAt: string;
}

function mintReadyToken(env: Record<string, string | undefined>): CommercialReadyToken {
  // The ONLY sanctioned cast — this module is the sole token authority.
  return {
    schemaVersion: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
    targetKey: commercialTargetKey(env),
    checkedAt: new Date().toISOString(),
  } as CommercialReadyToken;
}

/**
 * Re-validate a token against the CURRENT target before a protected side effect. Throws
 * CommercialNotReadyError on any version/target mismatch (a token minted for staging or
 * an older schema can never authorize work here).
 */
export function assertReadyToken(token: CommercialReadyToken, env: Record<string, string | undefined>): void {
  const expectedTarget = commercialTargetKey(env);

  if (!token || token.schemaVersion !== EXPECTED_COMMERCIAL_SCHEMA_VERSION || token.targetKey !== expectedTarget) {
    throw new CommercialNotReadyError({
      state: 'NOT_READY',
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      failed: ['readiness_token_mismatch'],
      targetKey: expectedTarget,
      checkedAt: Date.now(),
    });
  }
}

// ─── Target-keyed readiness cache ───────────────────────────────────────────────

const CACHE_MS = 5_000;
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
 * Reason codes are allowlisted. Cached per target key with a short TTL.
 */
export async function getCommercialSchemaReadiness(
  env: Record<string, string | undefined>,
): Promise<CommercialReadiness> {
  const now = Date.now();
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';
  const targetKey = commercialTargetKey(env);

  if (!url || !key) {
    return {
      state: 'CONFIGURATION_ERROR',
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      failed: ['missing_supabase_config'],
      targetKey,
      checkedAt: now,
    };
  }

  const hit = cache.get(targetKey);

  if (hit && now - hit.at < CACHE_MS) {
    return { ...hit.value, cacheAgeMs: now - hit.at };
  }

  const finalize = (r: Omit<CommercialReadiness, 'expected' | 'checkedAt' | 'targetKey'>): CommercialReadiness => {
    const value: CommercialReadiness = {
      ...r,
      failed: r.failed.map(safeReasonCode),
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      targetKey,
      checkedAt: now,
    };
    cache.set(targetKey, { at: now, value });

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
    super(`commercial schema not ready: ${readiness.state}`);
    this.name = 'CommercialNotReadyError';
    this.readiness = readiness;
  }
}

/**
 * Throw CommercialNotReadyError unless READY; otherwise return a target-bound
 * CommercialReadyToken. This is the ONLY producer of the token.
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
 * Route-level readiness gate. On READY returns a target-bound token to thread into the
 * protected services; on any non-READY returns a fail-closed generic Response (503 for
 * user routes, 500-retryable for webhooks) — commercial callers never see check detail.
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
