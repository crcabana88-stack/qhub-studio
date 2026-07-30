#!/usr/bin/env node
/**
 * QHUB schema smoke check — scripts/schema-smoke-check.mjs
 *
 * Pre/post-deploy gate. Probes the TARGET Supabase project for the tables and
 * columns the code requires and FAILS (exit 1) if any are missing — so a deploy
 * can never go out against an unmigrated project (the Gate 03 live-closure bug).
 *
 * Wired into `npm run deploy` (see package.json). Run standalone anytime:
 *     node scripts/schema-smoke-check.mjs
 *
 * Reads (never prints):
 *     SUPABASE_URL
 *     SUPABASE_SERVICE_ROLE_KEY
 *   from process.env, falling back to .env.local / .env in the repo root.
 *
 * Overrides (LOCAL TEST ONLY — never staging/production):
 *     QHUB_LOCAL_TEST_SCHEMA_BYPASS=1  + NODE_ENV=test + non-staging/prod QHUB_DEPLOY_ENV
 *     (a bypass attempt against any deployed target exits nonzero — no staging/prod skip)
 *
 * Output is NON-SECRET: project ref (public) + host only, never keys.
 *
 * KEEP IN SYNC with app/lib/qhub/schema-contract.ts (REQUIRED_SCHEMA_OBJECTS,
 * EXPECTED_SCHEMA_VERSION, SCHEMA_MISSING_CODES).
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseDeployEnv } from './deploy-env.mjs';

const EXPECTED_SCHEMA_VERSION = '2026-07-26.gate04';
const SCHEMA_VERIFIER_RPC = 'qhub_verify_governance_schema';

/*
 * Agent Framework schema — separate contract so Gate 04's stays stable.
 * KEEP IN SYNC with app/lib/qhub/agent/agent-schema-check.server.ts.
 */
const EXPECTED_AGENT_SCHEMA_VERSION = '2026-07-27.agent-foundation';
const AGENT_SCHEMA_VERIFIER_RPC = 'qhub_verify_agent_schema';

/*
 * Commercial Launch schema — separate contract with a DIFFERENT verifier shape:
 * qhub_verify_commercial_schema() returns { expected_version, ready, failed:[] }
 * (a compact failed-check-name array, not per-check {identifier,category,...}).
 * KEEP IN SYNC with app/lib/qhub/commercial/commercial-schema-check.server.ts.
 */
const EXPECTED_COMMERCIAL_SCHEMA_VERSION = '2026-07-30.commercial-launch-r5';
const COMMERCIAL_SCHEMA_VERIFIER_RPC = 'qhub_verify_commercial_schema';

/** @type {{table:string,column:string,migration:string}[]} */
const AGENT_REQUIRED_OBJECTS = [
  { table: 'qhub_agents', column: 'current_lifecycle_state', migration: '20260727_agent_framework_foundation' },
  { table: 'qhub_agent_versions', column: 'manifest_hash', migration: '20260727_agent_framework_foundation' },
  { table: 'qhub_agent_runs', column: 'idempotency_key', migration: '20260727_agent_framework_foundation' },
  { table: 'qhub_agent_run_steps', column: 'step_index', migration: '20260727_agent_framework_foundation' },
];

/** @type {{table:string,column:string,migration:string}[]} */
const REQUIRED_SCHEMA_OBJECTS = [
  { table: 'qhub_applications', column: 'qhub_app_id', migration: '20260723_qhub_applications' },
  { table: 'qhub_applications', column: 'classification', migration: '20260725_qhub_classification' },
  { table: 'qhub_applications', column: 'policy_profile', migration: '20260725_gate03_policy' },
  { table: 'qhub_classification_proposals', column: 'proposal_id', migration: '20260725_gate03_policy' },
  { table: 'qhub_enforcement_plans', column: 'enforcement_plan_hash', migration: '20260726_gate04_enforcement' },
  { table: 'qhub_control_evaluations', column: 'action_request_id', migration: '20260726_gate04_enforcement' },
  { table: 'qhub_control_approvals', column: 'consumed_by_evaluation', migration: '20260726_gate04_enforcement' },
  { table: 'qhub_applications', column: 'kill_switch_active', migration: '20260726_gate04_enforcement' },
];

const SCHEMA_MISSING_CODES = new Set(['PGRST205', 'PGRST204', '42P01', '42703']);

/**
 * Fail-closed schema-check gate driven by the ONE shared deploy-env parser.
 *
 *  - INVALID env (missing/empty/unknown/misspelled/mixed-case) → CONFIGURATION_ERROR,
 *    nonzero, NEVER a skip.
 *  - DEPLOYED (staging/production) → ALWAYS run every verifier; any bypass flag is refused.
 *  - LOCAL (local/test) → a bypass is authorized ONLY with NODE_ENV=test AND the explicit
 *    QHUB_LOCAL_TEST_SCHEMA_BYPASS=1; otherwise the verifiers run normally.
 *
 * @param {Record<string,string|undefined>} env
 * @returns {{action:'CONFIG_ERROR'|'SKIP'|'REFUSE'|'RUN', reason:string}}
 */
function schemaCheckDecision(env) {
  const parsed = parseDeployEnv(env.QHUB_DEPLOY_ENV);
  const attempted = env.QHUB_LOCAL_TEST_SCHEMA_BYPASS === '1' || env.QHUB_SKIP_SCHEMA_CHECK === '1';

  if (parsed.kind === 'INVALID') {
    return { action: 'CONFIG_ERROR', reason: 'deploy_env_invalid' };
  }

  if (parsed.kind === 'DEPLOYED') {
    // No skip flag works in staging/production — an attempt is a hard failure.
    return attempted
      ? { action: 'REFUSE', reason: 'deployed-target-never-bypasses' }
      : { action: 'RUN', reason: 'deployed' };
  }

  // LOCAL (local/test).
  if (!attempted) {
    return { action: 'RUN', reason: 'local-run' };
  }

  const isLocalTest = (env.NODE_ENV ?? '').toLowerCase() === 'test' && env.QHUB_LOCAL_TEST_SCHEMA_BYPASS === '1';

  return isLocalTest
    ? { action: 'SKIP', reason: 'authorized-local-test-bypass' }
    : { action: 'REFUSE', reason: 'local-test-only-requires-node-env-test-and-explicit-flag' };
}

// ─── Minimal .env loader (no dependency) ──────────────────────────────────────

function loadDotenv() {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = join(here, '..');

  for (const file of ['.env.local', '.env']) {
    try {
      const text = readFileSync(join(root, file), 'utf8');

      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();

        if (!trimmed || trimmed.startsWith('#')) {
          continue;
        }

        const eq = trimmed.indexOf('=');

        if (eq === -1) {
          continue;
        }

        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();
        value = value.replace(/^['"]|['"]$/g, '');

        if (!(key in process.env)) {
          process.env[key] = value;
        }
      }
    } catch {
      // file absent — fine
    }
  }
}

function projectRefFromUrl(url) {
  try {
    return new URL(url).host.split('.')[0] || null;
  } catch {
    return null;
  }
}

function isSchemaMissing(status, body) {
  if (body && body.code && SCHEMA_MISSING_CODES.has(body.code)) {
    return true;
  }

  const haystack = `${body?.message ?? ''} ${body?.details ?? ''}`.toLowerCase();

  return (
    (status === 404 || status === 400) &&
    (haystack.includes('does not exist') || haystack.includes('could not find') || haystack.includes('schema cache'))
  );
}

async function probe(url, serviceKey, obj) {
  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/${obj.table}?select=${encodeURIComponent(obj.column)}&limit=1`;

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });

    if (res.ok) {
      return { ...obj, state: 'present', httpStatus: res.status };
    }

    const body = await res.json().catch(() => null);

    if (isSchemaMissing(res.status, body)) {
      return { ...obj, state: 'missing', httpStatus: res.status, detail: body?.code ?? `HTTP ${res.status}` };
    }

    return { ...obj, state: 'unknown', httpStatus: res.status, detail: body?.code ?? `HTTP ${res.status}` };
  } catch (err) {
    return { ...obj, state: 'unknown', detail: err instanceof Error ? err.name : 'probe failed' };
  }
}

async function verifyMetadata(url, serviceKey, rpc = SCHEMA_VERIFIER_RPC, expectedVersion = EXPECTED_SCHEMA_VERSION) {
  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/rpc/${rpc}`;

  try {
    const res = await fetch(endpoint, {
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
      const body = await res.json().catch(() => null);
      return { ready: false, error: body?.code ?? `HTTP ${res.status}`, checks: [] };
    }

    const body = await res.json();

    if (
      body?.expected_version !== expectedVersion ||
      typeof body?.ready !== 'boolean' ||
      !Array.isArray(body?.checks)
    ) {
      return { ready: false, error: 'INVALID_OR_STALE_METADATA_CONTRACT', checks: [] };
    }

    const internallyReady = body.checks.every(
      (check) =>
        typeof check?.identifier === 'string' &&
        typeof check?.category === 'string' &&
        check?.ready === true &&
        check?.reason_code === 'OK',
    );

    return {
      ready: body.ready === true && internallyReady,
      checks: body.checks,
      ...(body.ready === internallyReady ? {} : { error: 'INCONSISTENT_METADATA_SUMMARY' }),
    };
  } catch (err) {
    return { ready: false, error: err instanceof Error ? err.name : 'METADATA_PROBE_FAILED', checks: [] };
  }
}

/**
 * Verify the Commercial Launch schema via qhub_verify_commercial_schema(). Fails
 * closed for a missing verifier, wrong version, ready=false, any failed check, a
 * malformed response, or an unavailable DB. Never prints SQL, keys, or payloads.
 * @returns {Promise<{ready:boolean, error?:string, failed:string[]}>}
 */
async function verifyCommercial(url, serviceKey) {
  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/rpc/${COMMERCIAL_SCHEMA_VERIFIER_RPC}`;

  try {
    const res = await fetch(endpoint, {
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
      const body = await res.json().catch(() => null);

      // Missing verifier / permission / connectivity — fail closed.
      return { ready: false, error: body?.code ?? `HTTP ${res.status}`, failed: [] };
    }

    const body = await res.json();

    if (
      typeof body?.ready !== 'boolean' ||
      !Array.isArray(body?.failed) ||
      typeof body?.expected_version !== 'string'
    ) {
      return { ready: false, error: 'MALFORMED_COMMERCIAL_METADATA', failed: [] };
    }

    if (body.expected_version !== EXPECTED_COMMERCIAL_SCHEMA_VERSION) {
      return { ready: false, error: 'VERSION_MISMATCH', failed: [String(body.expected_version)] };
    }

    if (body.ready !== true || body.failed.length > 0) {
      return { ready: false, error: 'NOT_READY', failed: body.failed.map(String).slice(0, 25) };
    }

    return { ready: true, failed: [] };
  } catch (err) {
    return { ready: false, error: err instanceof Error ? err.name : 'COMMERCIAL_PROBE_FAILED', failed: [] };
  }
}

async function main() {
  loadDotenv();

  const decision = schemaCheckDecision(process.env);

  if (decision.action === 'CONFIG_ERROR') {
    console.error(
      `[schema-smoke-check] FAIL (CONFIGURATION_ERROR / ${decision.reason}): QHUB_DEPLOY_ENV must be exactly ` +
        'one of local|test|staging|production. A missing/unknown/misspelled/mixed-case environment can never skip ' +
        'and can never deploy.',
    );
    process.exit(1);
  }

  if (decision.action === 'REFUSE') {
    console.error(
      `[schema-smoke-check] FAIL: schema-check bypass refused (${decision.reason}). ` +
        'Staging and production ALWAYS run Gate 01–05, Agent Foundation, and Commercial R4 verifiers. ' +
        'A bypass is honored ONLY for a local test process (QHUB_DEPLOY_ENV=local|test + NODE_ENV=test + ' +
        'QHUB_LOCAL_TEST_SCHEMA_BYPASS=1).',
    );
    process.exit(1);
  }

  if (decision.action === 'SKIP') {
    console.warn(
      `[schema-smoke-check] SKIPPED — authorized LOCAL TEST bypass (QHUB_DEPLOY_ENV=${process.env.QHUB_DEPLOY_ENV ?? ''}, ` +
        'NODE_ENV=test, QHUB_LOCAL_TEST_SCHEMA_BYPASS=1). Never honored for staging/production.',
    );
    process.exit(0);
  }

  const url = process.env.SUPABASE_URL ?? '';
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !serviceKey) {
    console.error(
      '[schema-smoke-check] FAIL: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required to verify the target ' +
        'project before deploy. There is no staging or production skip — set them.',
    );
    process.exit(1);
  }

  const projectRef = projectRefFromUrl(url);
  let host = null;

  try {
    host = new URL(url).host;
  } catch {
    /* ignore */
  }

  console.log(
    `[schema-smoke-check] expected=${EXPECTED_SCHEMA_VERSION} project=${projectRef ?? 'unknown'} host=${host ?? 'unknown'}`,
  );

  const results = await Promise.all(REQUIRED_SCHEMA_OBJECTS.map((o) => probe(url, serviceKey, o)));
  const metadata = await verifyMetadata(url, serviceKey);

  for (const r of results) {
    const mark = r.state === 'present' ? 'OK  ' : r.state === 'missing' ? 'MISS' : '??  ';
    console.log(`  [${mark}] ${r.table}.${r.column}  (${r.migration})${r.detail ? `  — ${r.detail}` : ''}`);
  }

  const missing = results.filter((r) => r.state === 'missing');
  const unknown = results.filter((r) => r.state === 'unknown');

  if (missing.length > 0) {
    console.error(
      `[schema-smoke-check] FAIL: target project ${projectRef ?? '(unknown)'} is BEHIND the code — ` +
        `${missing.length} object(s) missing: ${missing.map((m) => `${m.table}.${m.column}`).join(', ')}. ` +
        'Apply the pending migrations to this project before deploying.',
    );
    process.exit(1);
  }

  if (unknown.length > 0) {
    console.error(
      `[schema-smoke-check] FAIL: could not verify ${unknown.length} object(s) ` +
        `(${unknown.map((u) => `${u.table}.${u.column}`).join(', ')}). ` +
        'Check SUPABASE_URL / service key and connectivity to the target project.',
    );
    process.exit(1);
  }

  if (!metadata.ready) {
    const failed = metadata.checks.filter((check) => !check.ready);
    console.error(
      `[schema-smoke-check] FAIL: Gate 04 metadata contract is not ready — ` +
        `${metadata.error ?? failed.map((check) => `${check.category}:${check.identifier}:${check.reason_code}`).join(', ')}`,
    );
    process.exit(1);
  }

  console.log(`  [OK  ] ${metadata.checks.length} Gate 04 metadata invariants`);

  // ── Agent Framework schema (separate contract) ──
  const agentResults = await Promise.all(AGENT_REQUIRED_OBJECTS.map((o) => probe(url, serviceKey, o)));
  const agentMissing = agentResults.filter((r) => r.state !== 'present');

  if (agentMissing.length > 0) {
    console.error(
      `[schema-smoke-check] FAIL: Agent Framework schema is behind the code — missing: ` +
        `${agentMissing.map((m) => `${m.table}.${m.column} (${m.migration})`).join(', ')}`,
    );
    process.exit(1);
  }

  const agentMeta = await verifyMetadata(url, serviceKey, AGENT_SCHEMA_VERIFIER_RPC, EXPECTED_AGENT_SCHEMA_VERSION);

  if (!agentMeta.ready) {
    const failed = agentMeta.checks.filter((check) => !check.ready);
    console.error(
      `[schema-smoke-check] FAIL: Agent Framework metadata contract is not ready — ` +
        `${agentMeta.error ?? failed.map((check) => `${check.category}:${check.identifier}:${check.reason_code}`).join(', ')}`,
    );
    process.exit(1);
  }

  console.log(
    `  [OK  ] ${agentMeta.checks.length} Agent Framework metadata invariants (${EXPECTED_AGENT_SCHEMA_VERSION})`,
  );

  // ── Commercial Launch schema (separate contract, compact failed[] shape) ──
  const commercialMeta = await verifyCommercial(url, serviceKey);

  if (!commercialMeta.ready) {
    console.error(
      `[schema-smoke-check] FAIL: Commercial Launch metadata contract is not ready — ` +
        `${commercialMeta.error ?? 'NOT_READY'}${commercialMeta.failed.length ? `: ${commercialMeta.failed.join(', ')}` : ''}. ` +
        `Expected ${EXPECTED_COMMERCIAL_SCHEMA_VERSION}. Apply the unapplied commercial migration to this project before deploying.`,
    );
    process.exit(1);
  }

  console.log(`  [OK  ] Commercial Launch metadata contract (${EXPECTED_COMMERCIAL_SCHEMA_VERSION})`);

  console.log(
    `[schema-smoke-check] PASS: project ${projectRef ?? '(unknown)'} matches ${EXPECTED_SCHEMA_VERSION} + ${EXPECTED_AGENT_SCHEMA_VERSION} + ${EXPECTED_COMMERCIAL_SCHEMA_VERSION}.`,
  );
  process.exit(0);
}

main().catch((err) => {
  console.error('[schema-smoke-check] FAIL: unexpected error:', err);
  process.exit(1);
});
