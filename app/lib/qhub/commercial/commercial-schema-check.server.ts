/**
 * QHUB Commercial Launch R4 — CENTRAL COMMERCIAL SCHEMA READINESS (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-schema-check.server.ts
 *
 * The ONE place that calls qhub_verify_commercial_schema(). Every commercial route/
 * service asks THIS service for readiness — no route calls the verifier directly. It
 * requires the exact version 2026-07-30.commercial-launch-r4, ready=true, and an empty
 * failed[]. It fails closed for every non-READY state and exposes only compact, safe
 * reason codes — never SQL, secrets, Stripe payloads, or tenant data.
 *
 * States: READY | NOT_READY | UNAVAILABLE | CONFIGURATION_ERROR. A short version-keyed
 * cache avoids hammering the DB. Deterministic test injection is done by mocking this
 * module (there is NO production bypass flag).
 */

import { json } from '@remix-run/cloudflare';
import { createClient } from '@supabase/supabase-js';

export const EXPECTED_COMMERCIAL_SCHEMA_VERSION = '2026-07-30.commercial-launch-r4';

export type ReadinessState = 'READY' | 'NOT_READY' | 'UNAVAILABLE' | 'CONFIGURATION_ERROR';

export interface CommercialReadiness {
  state: ReadinessState;
  expected: string;
  version?: string;

  /** Compact, safe reason codes / verifier check names — never raw errors. */
  failed: string[];
  checkedAt: number;
  cacheAgeMs?: number;
}

const CACHE_MS = 5_000;
let cache: { at: number; value: CommercialReadiness } | null = null;

/** Test/maintenance hook — clears the short readiness cache. */
export function resetCommercialReadinessCache(): void {
  cache = null;
}

export function isCommercialReady(r: CommercialReadiness): boolean {
  return r.state === 'READY';
}

/**
 * Resolve commercial schema readiness. Fails closed: any error, malformed response,
 * version mismatch, or failed check yields a non-READY state. Reason codes only.
 */
export async function getCommercialSchemaReadiness(
  env: Record<string, string | undefined>,
): Promise<CommercialReadiness> {
  const now = Date.now();
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    return {
      state: 'CONFIGURATION_ERROR',
      expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
      failed: ['missing_supabase_config'],
      checkedAt: now,
    };
  }

  if (cache && now - cache.at < CACHE_MS) {
    return { ...cache.value, cacheAgeMs: now - cache.at };
  }

  const finalize = (r: Omit<CommercialReadiness, 'expected' | 'checkedAt'>): CommercialReadiness => {
    const value: CommercialReadiness = { ...r, expected: EXPECTED_COMMERCIAL_SCHEMA_VERSION, checkedAt: now };
    cache = { at: now, value };

    return value;
  };

  try {
    const sb = createClient(url, key, { auth: { persistSession: false } });
    const { data, error } = await sb.rpc('qhub_verify_commercial_schema');

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
        failed: (body.failed as string[]).slice(0, 25),
      });
    }

    return finalize({ state: 'READY', version: body.expected_version, failed: [] });
  } catch {
    // Never log the raw error (could carry connection detail); fail closed.
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

/** Throw CommercialNotReadyError unless READY. Callers must gate protected work on this. */
export async function assertCommercialSchemaReady(
  env: Record<string, string | undefined>,
): Promise<CommercialReadiness> {
  const r = await getCommercialSchemaReadiness(env);

  if (r.state !== 'READY') {
    throw new CommercialNotReadyError(r);
  }

  return r;
}

/**
 * Route-level readiness gate. Returns a fail-closed generic Response (503 for user
 * routes, 500-retryable for webhooks) when the commercial schema is not READY —
 * commercial callers never see the failed-check detail.
 */
export async function requireCommercialReady(
  env: Record<string, string | undefined>,
  opts: { webhook?: boolean } = {},
): Promise<{ ok: true } | { ok: false; response: Response }> {
  const r = await getCommercialSchemaReadiness(env);

  if (r.state === 'READY') {
    return { ok: true };
  }

  return {
    ok: false,
    response: json({ ok: false, error: 'commercial_unavailable' }, { status: opts.webhook ? 500 : 503 }),
  };
}
