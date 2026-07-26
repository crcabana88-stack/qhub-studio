/**
 * Gate 04 schema-assurance contract tests.
 *
 * These tests exercise the runtime verifier boundary with synthetic PostgREST
 * responses. No database is mutated and no credential value is logged.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { EXPECTED_SCHEMA_VERSION, REQUIRED_SCHEMA_OBJECTS } from '~/lib/qhub/schema-contract';

const ENV = {
  SUPABASE_URL: 'https://gate04-contract.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
};

type Check = {
  identifier: string;
  category: 'TABLE' | 'COLUMN' | 'CONSTRAINT' | 'INDEX' | 'RLS_ENABLED' | 'RLS_POLICY' | 'FUNCTION';
  ready: boolean;
  reason_code: string;
};

const baselineChecks: Check[] = [
  { identifier: 'table.enforcement_plans', category: 'TABLE', ready: true, reason_code: 'OK' },
  { identifier: 'column.evaluation_claim', category: 'COLUMN', ready: true, reason_code: 'OK' },
  { identifier: 'constraint.action_request_unique', category: 'CONSTRAINT', ready: true, reason_code: 'OK' },
  { identifier: 'index.active_plan_unique', category: 'INDEX', ready: true, reason_code: 'OK' },
  { identifier: 'index.evaluation_idempotency', category: 'INDEX', ready: true, reason_code: 'OK' },
  { identifier: 'rls.control_evaluations', category: 'RLS_ENABLED', ready: true, reason_code: 'OK' },
  { identifier: 'policy.control_evaluations_service_only', category: 'RLS_POLICY', ready: true, reason_code: 'OK' },
  { identifier: 'function.atomic_claim', category: 'FUNCTION', ready: true, reason_code: 'OK' },
  { identifier: 'function.atomic_approval_consumption', category: 'FUNCTION', ready: true, reason_code: 'OK' },
];

function installFetch(
  options: {
    checks?: Check[];
    version?: string;
    rpcStatus?: number;
    missingProbe?: { table: string; column: string };
  } = {},
) {
  const checks = options.checks ?? baselineChecks;
  const ready = checks.every((check) => check.ready);

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.includes('/rpc/qhub_verify_governance_schema')) {
        if (options.rpcStatus) {
          return new Response(JSON.stringify({ code: 'PGRST202' }), {
            status: options.rpcStatus,
            headers: { 'content-type': 'application/json' },
          });
        }

        return new Response(
          JSON.stringify({
            expected_version: options.version ?? EXPECTED_SCHEMA_VERSION,
            ready,
            checks,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      if (
        options.missingProbe &&
        url.includes(`/rest/v1/${options.missingProbe.table}?`) &&
        url.includes(`select=${encodeURIComponent(options.missingProbe.column)}`)
      ) {
        return new Response(JSON.stringify({ code: 'PGRST204', message: 'schema cache mismatch' }), {
          status: 400,
          headers: { 'content-type': 'application/json' },
        });
      }

      return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
}

async function readiness() {
  const { getSchemaReadiness } = await import('~/lib/qhub/schema-check.server');
  return getSchemaReadiness(ENV, { force: true });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Gate 04 metadata assurance', () => {
  it('rejects a Gate 03-only schema with no Gate 04 verifier', async () => {
    installFetch({ rpcStatus: 404 });

    const report = await readiness();
    expect(report.ready).toBe(false);
    expect(report.missing.some((item) => item.identifier?.includes('qhub_verify_governance_schema'))).toBe(true);
  });

  it('rejects a stale Gate 03 verifier version', async () => {
    installFetch({ version: '2026-07-25.gate03' });

    const report = await readiness();
    expect(report.ready).toBe(false);
    expect(report.error).toContain('stale');
  });

  it('fails closed for a missing Gate 04 table probe', async () => {
    installFetch({ missingProbe: { table: 'qhub_enforcement_plans', column: 'enforcement_plan_hash' } });

    const report = await readiness();
    expect(report.ready).toBe(false);
    expect(report.missing.some((item) => item.table === 'qhub_enforcement_plans')).toBe(true);
  });

  it('fails closed for a missing Gate 04 column probe', async () => {
    installFetch({ missingProbe: { table: 'qhub_control_evaluations', column: 'action_request_id' } });

    const report = await readiness();
    expect(report.ready).toBe(false);
    expect(report.missing.some((item) => item.column === 'action_request_id')).toBe(true);
  });

  it.each([
    ['constraint.action_request_unique', 'CONSTRAINT', 'CONSTRAINT_MISSING_OR_MISMATCH'],
    ['index.active_plan_unique', 'INDEX', 'INDEX_MISSING_OR_MISMATCH'],
    ['index.evaluation_idempotency', 'INDEX', 'INDEX_MISSING_OR_MISMATCH'],
    ['rls.control_evaluations', 'RLS_ENABLED', 'RLS_DISABLED'],
    ['policy.control_evaluations_service_only', 'RLS_POLICY', 'RLS_POLICY_MISSING_OR_MISMATCH'],
    ['function.atomic_claim', 'FUNCTION', 'FUNCTION_MISSING_OR_EXPOSED'],
    ['function.atomic_approval_consumption', 'FUNCTION', 'FUNCTION_MISSING_OR_EXPOSED'],
  ] as const)('fails closed when %s is mismatched', async (identifier, category, reason) => {
    const checks = baselineChecks.map((check) =>
      check.identifier === identifier ? { ...check, ready: false, reason_code: reason } : check,
    );
    installFetch({ checks });

    const report = await readiness();
    expect(report.ready).toBe(false);
    expect(
      report.missing.some(
        (item) => item.identifier === identifier && item.category === category && item.detail === reason,
      ),
    ).toBe(true);
  });

  it('accepts only a current, internally consistent Gate 04 contract', async () => {
    installFetch();

    const report = await readiness();
    expect(report.ready).toBe(true);
    expect(report.expectedSchemaVersion).toBe('2026-07-26.gate04');
    expect(report.missing).toEqual([]);
    expect(REQUIRED_SCHEMA_OBJECTS.some((item) => item.table === 'qhub_control_approvals')).toBe(true);
  });

  it('diagnostic objects contain no SQL definitions, predicates, credentials, or customer data', async () => {
    installFetch();

    const report = await readiness();
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain('SUPABASE_SERVICE_ROLE_KEY');
    expect(serialized).not.toContain('CREATE POLICY');
    expect(serialized).not.toContain('pg_get_expr');
    expect(serialized).not.toContain('test-service-role-key');
    expect(serialized).not.toContain('customer');
  });
});
