/**
 * QHUB Agent Framework — schema readiness guard (SERVER ONLY)
 * app/lib/qhub/agent/agent-schema-check.server.ts
 *
 * Fail-closed readiness for the four Agent Framework tables. Independent of
 * Gate 04's qhub_verify_governance_schema() so that verified contract stays
 * stable. Every agent operation asserts readiness BEFORE any create/run/state
 * change, so a missing or misconfigured schema produces no agent, no run, no
 * lifecycle change, no Gate 04 action, no adapter execution, no evidence event,
 * and no partial record.
 *
 * Does not rely only on PostgREST table probes: it also calls the service-role
 * metadata verifier (RLS, policies, FK validation, privileges, version).
 */

import {
  SchemaNotReadyError,
  type SchemaReadinessReport,
  type SchemaObjectStatus,
} from '~/lib/qhub/schema-check.server';
import { projectRefFromUrl, type RequiredSchemaObject } from '~/lib/qhub/schema-contract';

export const EXPECTED_AGENT_SCHEMA_VERSION = '2026-07-28.agent-result-continuity-r2';
export const AGENT_SCHEMA_VERIFIER_RPC = 'qhub_verify_agent_schema';

/** One representative column per Agent Framework table (first-line existence probe). */
export const AGENT_REQUIRED_OBJECTS: RequiredSchemaObject[] = [
  {
    table: 'qhub_agents',
    column: 'current_lifecycle_state',
    migration: '20260727_agent_framework_foundation',
    requiredBy: 'Agent registry identity + lifecycle',
  },
  {
    table: 'qhub_agent_versions',
    column: 'manifest_hash',
    migration: '20260727_agent_framework_foundation',
    requiredBy: 'Immutable agent version content',
  },
  {
    table: 'qhub_agent_runs',
    column: 'idempotency_key',
    migration: '20260727_agent_framework_foundation',
    requiredBy: 'Governed run records + replay safety',
  },
  {
    table: 'qhub_agent_run_steps',
    column: 'step_index',
    migration: '20260727_agent_framework_foundation',
    requiredBy: 'Governed run step evidence',
  },
  {
    table: 'qhub_agent_run_steps',
    column: 'result_hash',
    migration: '20260728_agent_run_step_result_continuity',
    requiredBy: 'Agent run-step result continuity (server-owned terminalization)',
  },
];

interface Creds {
  url: string;
  serviceKey: string;
}

function resolveCreds(env: Record<string, string | undefined>): Creds | null {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const serviceKey = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  return url && serviceKey ? { url, serviceKey } : null;
}

async function probeObject(creds: Creds, obj: RequiredSchemaObject): Promise<SchemaObjectStatus> {
  try {
    const res = await fetch(`${creds.url.replace(/\/$/, '')}/rest/v1/${obj.table}?select=${obj.column}&limit=0`, {
      headers: { apikey: creds.serviceKey, Authorization: `Bearer ${creds.serviceKey}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });

    if (res.ok) {
      return { ...obj, identifier: `${obj.table}.${obj.column}`, category: 'TABLE', state: 'present' };
    }

    const body = (await res.json().catch(() => null)) as { code?: string } | null;
    const missing =
      res.status === 404 ||
      body?.code === 'PGRST205' ||
      body?.code === 'PGRST204' ||
      body?.code === '42P01' ||
      body?.code === '42703';

    return {
      ...obj,
      identifier: `${obj.table}.${obj.column}`,
      category: 'TABLE',
      state: missing ? 'missing' : 'unknown',
      httpStatus: res.status,
      detail: body?.code ?? `HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      ...obj,
      identifier: `${obj.table}.${obj.column}`,
      category: 'TABLE',
      state: 'unknown',
      detail: err instanceof Error ? err.name : 'error',
    };
  }
}

async function probeVerifier(creds: Creds): Promise<{ objects: SchemaObjectStatus[]; error?: string }> {
  try {
    const res = await fetch(`${creds.url.replace(/\/$/, '')}/rest/v1/rpc/${AGENT_SCHEMA_VERIFIER_RPC}`, {
      method: 'POST',
      headers: {
        apikey: creds.serviceKey,
        Authorization: `Bearer ${creds.serviceKey}`,
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
            table: 'agent_schema',
            column: AGENT_SCHEMA_VERIFIER_RPC,
            migration: '20260727_agent_framework_foundation',
            requiredBy: 'Agent Framework metadata assurance',
            identifier: `function.${AGENT_SCHEMA_VERIFIER_RPC}`,
            category: 'FUNCTION',
            state: res.status === 404 ? 'missing' : 'unknown',
            httpStatus: res.status,
            detail: body?.code ?? `HTTP ${res.status}`,
          },
        ],
        ...(res.status === 404 ? {} : { error: `Agent verifier returned HTTP ${res.status}.` }),
      };
    }

    const v = (await res.json()) as {
      expected_version?: string;
      ready?: boolean;
      checks?: { identifier: string; category: string; ready: boolean; reason_code: string }[];
    };

    if (
      v?.expected_version !== EXPECTED_AGENT_SCHEMA_VERSION ||
      typeof v?.ready !== 'boolean' ||
      !Array.isArray(v?.checks)
    ) {
      return { objects: [], error: 'Agent verifier returned an invalid or stale contract.' };
    }

    const objects = v.checks.map(
      (c): SchemaObjectStatus => ({
        table: 'agent_schema',
        column: c.identifier,
        migration: '20260727_agent_framework_foundation',
        requiredBy: `Agent Framework ${c.category.toLowerCase()} assurance`,
        identifier: c.identifier,
        category: 'FUNCTION',
        state: c.ready ? 'present' : 'missing',
        detail: c.reason_code,
      }),
    );

    if (v.ready !== objects.every((o) => o.state === 'present')) {
      return { objects, error: 'Agent verifier readiness summary is internally inconsistent.' };
    }

    return { objects };
  } catch (err) {
    return {
      objects: [],
      error: `Agent verifier could not be reached (${err instanceof Error ? err.name : 'unknown error'}).`,
    };
  }
}

// Small isolate cache to avoid re-probing on every operation.
const cache = new Map<string, { report: SchemaReadinessReport; expiresAt: number }>();
const READY_TTL = 30_000;
const NOT_READY_TTL = 3_000;

/** Probe the connected project for Agent Framework readiness (cached). */
export async function getAgentSchemaReadiness(
  env: Record<string, string | undefined>,
  opts: { force?: boolean } = {},
): Promise<SchemaReadinessReport> {
  const creds = resolveCreds(env);
  const projectRef = projectRefFromUrl(creds?.url);
  const supabaseHost = (() => {
    try {
      return creds?.url ? new URL(creds.url).host : null;
    } catch {
      return null;
    }
  })();

  if (!creds) {
    return {
      ready: false,
      expectedSchemaVersion: EXPECTED_AGENT_SCHEMA_VERSION,
      projectRef,
      supabaseHost,
      checkedAt: new Date().toISOString(),
      objects: [],
      missing: [],
      error: 'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required to verify Agent Framework schema readiness.',
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

  const columns = await Promise.all(AGENT_REQUIRED_OBJECTS.map((o) => probeObject(creds, o)));
  const verifier = await probeVerifier(creds);
  const objects = [...columns, ...verifier.objects];
  const missing = objects.filter((o) => o.state === 'missing');
  const unknown = objects.filter((o) => o.state === 'unknown');
  const ready = missing.length === 0 && unknown.length === 0 && !verifier.error;

  const report: SchemaReadinessReport = {
    ready,
    expectedSchemaVersion: EXPECTED_AGENT_SCHEMA_VERSION,
    projectRef,
    supabaseHost,
    checkedAt: new Date().toISOString(),
    objects,
    missing,
    ...(verifier.error
      ? { error: verifier.error }
      : unknown.length > 0
        ? { error: `Could not verify ${unknown.length} Agent Framework object(s).` }
        : {}),
  };

  cache.set(cacheKey, { report, expiresAt: now + (ready ? READY_TTL : NOT_READY_TTL) });

  return report;
}

/**
 * Fail-closed guard for every Agent Framework operation. Throws
 * SchemaNotReadyError when the connected project lacks the Agent Framework schema
 * or its verifier reports a misconfiguration.
 */
export async function assertAgentSchemaReady(env: Record<string, string | undefined>): Promise<void> {
  const report = await getAgentSchemaReadiness(env);

  if (!report.ready) {
    throw new SchemaNotReadyError(report);
  }
}
