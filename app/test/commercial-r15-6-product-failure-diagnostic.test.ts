/**
 * R15.6 read-only product-failure diagnostic addendum.
 *
 * Proves that diagnostic 19 calls the verifier once, preserves the exact ordered
 * failure array, fails closed on catalog/report drift, and contains no mutation.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const RELEASE = `${REPO}docs/release/r15-6-runtime-verifier/`;
const DIAGNOSTIC = readFileSync(`${RELEASE}19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql`, 'utf8');

const APPROVED_HASHES = {
  migration: '1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755',
  pre: '897ba790555879db5d722581e909b3ee836f97db0a5c692fe9a0c5c52a3e0a8a',
  patch: '911055870d867f9993f0ceb981e4d5b91d922bee798b559f26f3f4c100582ab0',
  post: '7585739ed47afe8dce360eb44899402325c9968cedd0f74f7d0c85e2122a09dd',
} as const;

interface DiagnosticRow {
  diagnostic_status: string;
  product_ready: boolean;
  product_version: string | null;
  failed_labels: string[] | null;
  failed_label_count: number | null;
  failed_labels_evidence: Array<{ ordinal: number; label: string }> | null;
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function executableStatement(sql: string): string {
  const match = sql.match(/WITH verifier_catalog[\s\S]*?FROM evidence;/);

  if (!match) {
    throw new Error('diagnostic SELECT statement not found');
  }

  return match[0];
}

function codeWithoutComments(sql: string): string {
  return sql.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

function codeWithoutSqlStrings(sql: string): string {
  return sql.replace(/'(?:''|[^'])*'/g, "''");
}

async function openWithReport(reportExpression: string): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema()
    RETURNS jsonb LANGUAGE plpgsql STABLE AS $fn$
    BEGIN
      RETURN ${reportExpression};
    END;
    $fn$;
  `);

  return db;
}

async function runDiagnostic(db: PGlite): Promise<DiagnosticRow> {
  await db.exec('BEGIN; SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;');

  try {
    const result = await db.query<DiagnosticRow>(executableStatement(DIAGNOSTIC));
    await db.exec('COMMIT;');

    return result.rows[0];
  } catch (error) {
    await db.exec('ROLLBACK;');
    throw error;
  }
}

describe('R15.6 diagnostic 19 — immutable artifact and read-only construction', () => {
  it('keeps every approved artifact byte-identical', () => {
    expect(sha256(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`)).toBe(
      APPROVED_HASHES.migration,
    );
    expect(sha256(`${RELEASE}16_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql`)).toBe(APPROVED_HASHES.pre);
    expect(sha256(`${RELEASE}17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql`)).toBe(APPROVED_HASHES.patch);
    expect(sha256(`${RELEASE}18_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql`)).toBe(APPROVED_HASHES.post);
  });

  it('uses one materialized verifier invocation inside an explicit read-only transaction', () => {
    const code = codeWithoutComments(DIAGNOSTIC);
    const executableCode = codeWithoutSqlStrings(code);
    const invocations = executableCode.match(/\bpublic\.qhub_verify_commercial_schema\s*\(\s*\)/g) ?? [];

    expect(invocations).toHaveLength(1);
    expect(code).toMatch(/^\s*BEGIN\s*;/i);
    expect(code).toMatch(/SET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+REPEATABLE\s+READ\s*,\s*READ\s+ONLY\s*;/i);
    expect(code).toMatch(/invocation\s+AS\s+MATERIALIZED/i);
    expect(code).toMatch(/COMMIT\s*;\s*$/i);

    const forbidden = /\b(ALTER|CREATE|DELETE|DROP|GRANT|INSERT|MERGE|REVOKE|TRUNCATE|UPDATE|EXECUTE|COPY|CALL)\b/i;
    expect(code).not.toMatch(forbidden);
    expect(code).not.toMatch(/\b(query_to_xml|dblink|lo_import|pg_read_file|pg_write_file)\b/i);
  });
});

describe('R15.6 diagnostic 19 — deterministic verifier report evidence', () => {
  const cases: Array<{
    name: string;
    report: string;
    ready: boolean;
    labels: string[];
  }> = [
    {
      name: 'empty',
      report: `jsonb_build_object('expected_version','2026-07-30.commercial-launch-r8','ready',true,'failed','[]'::jsonb)`,
      ready: true,
      labels: [],
    },
    {
      name: 'one label',
      report: `jsonb_build_object('expected_version','2026-07-30.commercial-launch-r8','ready',false,'failed',jsonb_build_array('row_immutable_identity'))`,
      ready: false,
      labels: ['row_immutable_identity'],
    },
    {
      name: 'multiple labels',
      report: `jsonb_build_object('expected_version','2026-07-30.commercial-launch-r8','ready',false,'failed',jsonb_build_array('z_last','a_first','trigger:qhub_usage_ledger'))`,
      ready: false,
      labels: ['z_last', 'a_first', 'trigger:qhub_usage_ledger'],
    },
  ];

  for (const testCase of cases) {
    it(`returns the exact ${testCase.name} failure array and ordered evidence`, async () => {
      const db = await openWithReport(testCase.report);

      try {
        const row = await runDiagnostic(db);
        expect(row).toMatchObject({
          diagnostic_status: 'R15_6_PRODUCT_REPORT_VALID',
          product_ready: testCase.ready,
          product_version: '2026-07-30.commercial-launch-r8',
          failed_labels: testCase.labels,
          failed_label_count: testCase.labels.length,
        });
        expect(row.failed_labels_evidence).toEqual(
          testCase.labels.map((label, index) => ({ ordinal: index + 1, label })),
        );
      } finally {
        await db.close();
      }
    });
  }

  it('materializes and invokes the verifier exactly once', async () => {
    const db = new PGlite();
    await db.exec(`
      CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema()
      RETURNS jsonb LANGUAGE plpgsql STABLE AS $fn$
      DECLARE calls integer := coalesce(nullif(current_setting('qhub.test_calls', true), ''), '0')::integer;
      BEGIN
        IF calls <> 0 THEN RAISE EXCEPTION 'verifier_invoked_more_than_once'; END IF;
        PERFORM set_config('qhub.test_calls', '1', true);
        RETURN jsonb_build_object(
          'expected_version','2026-07-30.commercial-launch-r8',
          'ready',false,
          'failed',jsonb_build_array('single_invocation_probe')
        );
      END;
      $fn$;
    `);

    try {
      const row = await runDiagnostic(db);
      expect(row.failed_labels).toEqual(['single_invocation_probe']);
      expect(row.failed_label_count).toBe(1);
    } finally {
      await db.close();
    }
  });

  it.each([
    ['missing failed field', `jsonb_build_object('expected_version','v','ready',false)`],
    ['non-array failed field', `jsonb_build_object('expected_version','v','ready',false,'failed','bad')`],
    ['non-string label', `jsonb_build_object('expected_version','v','ready',false,'failed',jsonb_build_array(7))`],
    [
      'inconsistent readiness',
      `jsonb_build_object('expected_version','v','ready',true,'failed',jsonb_build_array('failure'))`,
    ],
    ['unexpected field', `jsonb_build_object('expected_version','v','ready',true,'failed','[]'::jsonb,'extra',1)`],
  ])('fails closed for an unexpected report shape: %s', async (_name, report) => {
    const db = await openWithReport(report);

    try {
      const row = await runDiagnostic(db);
      expect(row).toEqual({
        diagnostic_status: 'VERIFIER_REPORT_INVALID',
        product_ready: false,
        product_version: null,
        failed_labels: null,
        failed_label_count: null,
        failed_labels_evidence: null,
      });
    } finally {
      await db.close();
    }
  });

  it('fails closed on an overload without invoking the zero-argument verifier', async () => {
    const db = new PGlite();
    await db.exec(`
      CREATE FUNCTION public.qhub_verify_commercial_schema()
      RETURNS jsonb LANGUAGE plpgsql STABLE AS $fn$
      BEGIN RAISE EXCEPTION 'zero_arg_verifier_must_not_run'; END;
      $fn$;
      CREATE FUNCTION public.qhub_verify_commercial_schema(value integer)
      RETURNS jsonb LANGUAGE sql STABLE AS $fn$ SELECT '{}'::jsonb $fn$;
    `);

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('VERIFIER_CONTRACT_INVALID');
      expect(row.product_ready).toBe(false);
      expect(row.failed_labels).toBeNull();
    } finally {
      await db.close();
    }
  });

  it('fails closed when the exact verifier is missing', async () => {
    const db = new PGlite();
    await expect(runDiagnostic(db)).rejects.toThrow(/qhub_verify_commercial_schema/i);
    await db.close();
  });
});
