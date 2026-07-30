/**
 * QHUB Schema Readiness Check — SERVER ONLY
 * app/lib/qhub/schema-check.server.ts
 *
 * Probes the CONNECTED Supabase project for the tables/columns the running code
 * requires (see schema-contract.ts) and reports an expected-vs-current diff.
 *
 * WHY THIS EXISTS:
 *   During Gate 03 live closure the deployed Studio was pointed at a Supabase
 *   project missing the Gate-02 migration, but nothing surfaced it because the
 *   persistence layer swallowed the error. This module makes schema drift a
 *   loud, first-class condition:
 *     - governance intents fail closed via assertGovernanceSchemaReady()
 *     - /api/health returns 503 when the project is behind the code
 *     - /api/system/schema-check exposes the non-secret diff
 *     - scripts/schema-smoke-check.mjs blocks deploys against an unmigrated DB
 *
 * PROBE PATTERN (from live closure):
 *   GET {SUPABASE_URL}/rest/v1/<table>?select=<col>&limit=1
 *   with the service key. 404 (PGRST205) / 400 (42703) ⇒ object missing.
 *
 * SECURITY: This module reads the service-role key to authenticate the probe
 *   but NEVER returns or logs it (nor the anon key / HMAC secret). Diagnostics
 *   are limited to the project ref (already public) and the Supabase host.
 */

import {
  EXPECTED_SCHEMA_VERSION,
  REQUIRED_SCHEMA_OBJECTS,
  SCHEMA_VERIFIER_RPC,
  isSchemaMissingError,
  projectRefFromUrl,
  type GovernanceSchemaCheck,
  type GovernanceSchemaVerification,
  type RequiredSchemaObject,
} from './schema-contract';

// ─── Report types (all fields are NON-SECRET) ─────────────────────────────────

export type SchemaObjectState = 'present' | 'missing' | 'unknown';

export interface SchemaObjectStatus extends RequiredSchemaObject {
  state: SchemaObjectState;

  /** HTTP status of the probe (when a request was made). */
  httpStatus?: number;

  /** Non-secret detail: PostgREST error code or a short reason. */
  detail?: string;

  /** Gate 04 metadata category and stable non-sensitive identifier. */
  category?: GovernanceSchemaCheck['category'];
  identifier?: string;
}

export interface SchemaReadinessReport {
  /** True only when every required object is confirmed present. */
  ready: boolean;

  /** The schema version the running code expects. */
  expectedSchemaVersion: string;

  /** Which project the code is connected to (public identifier, never a key). */
  projectRef: string | null;
  supabaseHost: string | null;

  checkedAt: string;

  objects: SchemaObjectStatus[];
  missing: SchemaObjectStatus[];

  /**
   * Set when readiness could NOT be determined (misconfig, auth failure,
   * network). Treated as not-ready by callers that fail closed.
   */
  error?: string;
}

// ─── In-isolate cache (probe is cheap but not free) ───────────────────────────

interface CacheEntry {
  report: SchemaReadinessReport;
  expiresAt: number;
}

const READY_TTL_MS = 60_000; // cache a healthy result for 60s
const NOT_READY_TTL_MS = 5_000; // re-check a drifting/erroring project quickly

const cache = new Map<string, CacheEntry>();

/** Log drift/errors once per isolate per project so boot logs are not spammy. */
const warnedProjects = new Set<string>();

// ─── Error thrown when the governance path must fail closed ───────────────────

export class SchemaNotReadyError extends Error {
  readonly report: SchemaReadinessReport;

  constructor(report: SchemaReadinessReport) {
    const names = report.missing.map((m) => `${m.table}.${m.column}`).join(', ');
    super(
      report.error
        ? `Schema readiness could not be verified: ${report.error}`
        : `Connected Supabase project is behind the code — missing: ${names || 'unknown'} ` +
            `(expected schema ${report.expectedSchemaVersion}, project ${report.projectRef ?? 'unknown'}).`,
    );
    this.name = 'SchemaNotReadyError';
    this.report = report;
  }
}

// ─── Credential resolution (values are used, never returned) ──────────────────

function resolveSupabaseCreds(env: Record<string, string | undefined>): { url: string; serviceKey: string } | null {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const serviceKey = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !serviceKey) {
    return null;
  }

  return { url, serviceKey };
}

// ─── Single-object probe ──────────────────────────────────────────────────────

async function probeObject(url: string, serviceKey: string, obj: RequiredSchemaObject): Promise<SchemaObjectStatus> {
  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/${obj.table}?select=${encodeURIComponent(obj.column)}&limit=1`;

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(8000),
    });

    if (res.ok) {
      return { ...obj, state: 'present', httpStatus: res.status };
    }

    // Non-2xx: inspect the body to distinguish "missing" from "cannot tell".
    const body = (await res.json().catch(() => null)) as {
      code?: string;
      message?: string;
      details?: string;
      hint?: string;
    } | null;

    if ((res.status === 404 || res.status === 400) && isSchemaMissingError(body ?? { message: '' })) {
      return {
        ...obj,
        state: 'missing',
        httpStatus: res.status,
        detail: body?.code ?? `HTTP ${res.status}`,
      };
    }

    // 401/403/5xx or an unrecognised 4xx — we cannot assert presence.
    return {
      ...obj,
      state: 'unknown',
      httpStatus: res.status,
      detail: body?.code ?? `HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      ...obj,
      state: 'unknown',
      detail: err instanceof Error ? err.name : 'probe failed',
    };
  }
}

async function probeMetadataContract(
  url: string,
  serviceKey: string,
): Promise<{ objects: SchemaObjectStatus[]; error?: string }> {
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/rest/v1/rpc/${SCHEMA_VERIFIER_RPC}`, {
      method: 'POST',
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: '{}',
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { code?: string } | null;
      return {
        objects: [
          {
            table: 'governance_schema',
            column: SCHEMA_VERIFIER_RPC,
            migration: '20260726_gate04_schema_assurance_approval_cleanup',
            requiredBy: 'Gate 04 metadata assurance',
            identifier: `function.${SCHEMA_VERIFIER_RPC}`,
            category: 'FUNCTION',
            state: res.status === 404 ? 'missing' : 'unknown',
            httpStatus: res.status,
            detail: body?.code ?? `HTTP ${res.status}`,
          },
        ],
        ...(res.status === 404 ? {} : { error: `Metadata verifier returned HTTP ${res.status}.` }),
      };
    }

    const verification = (await res.json()) as GovernanceSchemaVerification;

    if (
      verification?.expected_version !== EXPECTED_SCHEMA_VERSION ||
      typeof verification?.ready !== 'boolean' ||
      !Array.isArray(verification?.checks)
    ) {
      return { objects: [], error: 'Metadata verifier returned an invalid or stale contract.' };
    }

    const objects = verification.checks.map(
      (check): SchemaObjectStatus => ({
        table: 'governance_schema',
        column: check.identifier,
        migration: '20260726_gate04_schema_assurance_approval_cleanup',
        requiredBy: `Gate 04 ${check.category.toLowerCase()} assurance`,
        identifier: check.identifier,
        category: check.category,
        state: check.ready ? 'present' : 'missing',
        detail: check.reason_code,
      }),
    );

    if (verification.ready !== objects.every((o) => o.state === 'present')) {
      return { objects, error: 'Metadata verifier readiness summary is internally inconsistent.' };
    }

    return { objects };
  } catch (err) {
    return {
      objects: [],
      error: `Metadata verifier could not be reached (${err instanceof Error ? err.name : 'unknown error'}).`,
    };
  }
}

// ─── Public: readiness report (cached) ────────────────────────────────────────

/**
 * Probe the connected project and return an expected-vs-current readiness
 * report. Cached per project ref within the isolate. Pass { force: true } to
 * bypass the cache (used by the diagnostic route).
 */
export async function getSchemaReadiness(
  env: Record<string, string | undefined>,
  opts: { force?: boolean } = {},
): Promise<SchemaReadinessReport> {
  const creds = resolveSupabaseCreds(env);

  const projectRef = projectRefFromUrl(creds?.url);
  const supabaseHost = (() => {
    try {
      return creds?.url ? new URL(creds.url).host : null;
    } catch {
      return null;
    }
  })();

  // Misconfiguration: no URL/key at all. Not-ready, and don't cache a null key.
  if (!creds) {
    return {
      ready: false,
      expectedSchemaVersion: EXPECTED_SCHEMA_VERSION,
      projectRef,
      supabaseHost,
      checkedAt: new Date().toISOString(),
      objects: [],
      missing: [],
      error: 'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required to verify schema readiness.',
    };
  }

  const cacheKey = projectRef ?? creds.url;
  const now = Date.now();

  if (!opts.force) {
    const hit = cache.get(cacheKey);

    if (hit && hit.expiresAt > now) {
      return hit.report;
    }
  }

  const columnObjects = await Promise.all(
    REQUIRED_SCHEMA_OBJECTS.map((obj) => probeObject(creds.url, creds.serviceKey, obj)),
  );
  const metadata = await probeMetadataContract(creds.url, creds.serviceKey);
  const objects = [...columnObjects, ...metadata.objects];

  const missing = objects.filter((o) => o.state === 'missing');
  const unknown = objects.filter((o) => o.state === 'unknown');
  const ready = missing.length === 0 && unknown.length === 0 && !metadata.error;

  const report: SchemaReadinessReport = {
    ready,
    expectedSchemaVersion: EXPECTED_SCHEMA_VERSION,
    projectRef,
    supabaseHost,
    checkedAt: new Date().toISOString(),
    objects,
    missing,
    ...(metadata.error
      ? { error: metadata.error }
      : unknown.length > 0 && missing.length === 0
        ? {
            error: `Could not verify ${unknown.length} object(s): ${unknown.map((u) => `${u.table}.${u.column}`).join(', ')}`,
          }
        : {}),
  };

  cache.set(cacheKey, { report, expiresAt: now + (ready ? READY_TTL_MS : NOT_READY_TTL_MS) });

  // Loud, one-time warning when a project is behind the code (the missed signal).
  if (!ready && !warnedProjects.has(cacheKey)) {
    warnedProjects.add(cacheKey);
    console.error(
      `[SchemaCheck] SCHEMA DRIFT — project=${projectRef ?? 'unknown'} expects=${EXPECTED_SCHEMA_VERSION} ` +
        `missing=[${missing.map((m) => `${m.table}.${m.column} (${m.migration})`).join('; ') || 'none'}] ` +
        `unverified=[${unknown.map((u) => `${u.table}.${u.column}`).join('; ') || 'none'}]. ` +
        `Apply the pending migrations to this project before serving governance traffic.`,
    );
  }

  return report;
}

/**
 * Fail-closed guard for the governance path. Throws SchemaNotReadyError when the
 * connected project is behind the code so classification confirm / policy assign
 * cannot proceed against an unmigrated database.
 */
export async function assertGovernanceSchemaReady(env: Record<string, string | undefined>): Promise<void> {
  const report = await getSchemaReadiness(env);

  if (!report.ready) {
    throw new SchemaNotReadyError(report);
  }
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
