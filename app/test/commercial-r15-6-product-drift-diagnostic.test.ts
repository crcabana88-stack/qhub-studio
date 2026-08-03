/**
 * R15.6 targeted product-drift diagnostic.
 *
 * Proves that Diagnostic 20 is a single-invocation, read-only, exact-report-
 * gated catalog diagnostic for only qhub_decide_review and qhub_row_immutable.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const RELEASE = `${REPO}docs/release/r15-6-runtime-verifier/`;
const DIAGNOSTIC = readFileSync(`${RELEASE}20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql`, 'utf8');

const EXPECTED_VERSION = '2026-07-30.commercial-launch-r8';
const EXPECTED_LABELS = [
  'decide_review_body_drift',
  'r7_ack_immutable_body_drift',
  'row_immutable_body_digest',
  'row_immutable_acl_cardinality',
  'row_immutable_acl_unexpected_grantee',
] as const;

const APPROVED_ARTIFACTS = {
  'supabase/migrations/20260729_commercial_launch_foundation.sql':
    '1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755',
  'docs/release/r15-2-verifier-patch/07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql':
    '1e67adf03601fcee0d7e30d4c9df4277c9fd9c75cb8c0d2c2f28dc8770c984db',
  'docs/release/r15-2-verifier-patch/08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql':
    '143759ba0e7633de01d8abd7c8625cc918d4c4b111023967b901989f8bc7a564',
  'docs/release/r15-3-body-restoration/10_PRE_RESTORE_LIVE_BODY_VERIFY.sql':
    '5b455b50cddd2524627faa22e0c74e3da6895ef10842c2286f378a928e964b37',
  'docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql':
    'a549863161a403f34b63261f3cde5b0d91abb901092031580916f34bf9df6529',
  'docs/release/r15-3-body-restoration/12_POST_RESTORE_BODY_VERIFY.sql':
    'b373b8589ec06bc2e2274b366f03cce99f1cc6d8bc5d9f3df36869297eb5332f',
  'docs/release/r15-5-runtime-verifier/14_LIVE_RUNTIME_VERIFIER_TRIGGER_ACL_PATCH.sql':
    'b4466c780013fdb7c728ca02a123352de1f3f46f9add1518af3b103242d9101a',
  'docs/release/r15-6-runtime-verifier/16_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql':
    '897ba790555879db5d722581e909b3ee836f97db0a5c692fe9a0c5c52a3e0a8a',
  'docs/release/r15-6-runtime-verifier/17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql':
    '911055870d867f9993f0ceb981e4d5b91d922bee798b559f26f3f4c100582ab0',
  'docs/release/r15-6-runtime-verifier/18_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql':
    '7585739ed47afe8dce360eb44899402325c9968cedd0f74f7d0c85e2122a09dd',
  'docs/release/r15-6-runtime-verifier/19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql':
    'dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa',
} as const;

interface FunctionEvidence {
  object_key: string;
  expected: {
    accepted_body_digests: string[];
    body_digest_method: string;
  };
  actual: {
    body_digest: string;
    identity: string;
  };
  metadata_match: boolean;
  body_digest_match: boolean;
  drift_classification: string;
}

interface AclEntry {
  ordinal: number;
  grantee_oid: number;
  grantee: string;
  grantor_oid: number;
  grantor: string;
  privilege: string;
  grantable: boolean;
  unexpected_grantee: boolean;
}

interface LabelCondition {
  label_order: number;
  label: string;
  implicated_object: string;
  verifier_condition: string;
  condition_failed: boolean;
}

interface DiagnosticRow {
  diagnostic_status: string;
  product_ready: boolean;
  product_version: string | null;
  failed_labels: string[] | null;
  failed_label_count: number | null;
  target_catalog_status: string;
  function_evidence: FunctionEvidence[] | null;
  row_immutable_acl_summary: Record<string, unknown> | null;
  row_immutable_direct_acl: AclEntry[] | null;
  unexpected_grantee_evidence: Array<Record<string, unknown>> | null;
  label_condition_evidence: LabelCondition[] | null;
  implicated_discrepancy_classes: string[] | null;
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function executableStatement(sql: string): string {
  const match = sql.match(/WITH constants[\s\S]*?CROSS JOIN acl_summary a;/);

  if (!match) {
    throw new Error('Diagnostic 20 SELECT statement not found');
  }

  return match[0];
}

function codeWithoutComments(sql: string): string {
  return sql.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

function codeWithoutSqlStrings(sql: string): string {
  return sql.replace(/'(?:''|[^'])*'/g, "''");
}

function reportSql(version = EXPECTED_VERSION, labels: readonly string[] = EXPECTED_LABELS): string {
  const encoded = JSON.stringify(labels).replace(/'/g, "''");

  return `jsonb_build_object(
    'expected_version', '${version.replace(/'/g, "''")}',
    'ready', false,
    'failed', '${encoded}'::jsonb
  )`;
}

async function installVerifier(db: PGlite, report: string): Promise<void> {
  await db.exec(`
    CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema()
    RETURNS jsonb LANGUAGE plpgsql STABLE AS $fn$
    DECLARE calls integer := coalesce(nullif(current_setting('qhub.r156_d20_calls', true), ''), '0')::integer;
    BEGIN
      IF calls <> 0 THEN RAISE EXCEPTION 'verifier_invoked_more_than_once'; END IF;
      PERFORM set_config('qhub.r156_d20_calls', '1', true);
      RETURN ${report};
    END;
    $fn$;
  `);
}

async function openFixture(options: { includeRow?: boolean; overloadRow?: boolean } = {}): Promise<PGlite> {
  const db = new PGlite();
  const includeRow = options.includeRow ?? true;

  await db.exec(`
    CREATE TABLE public.qhub_manual_review_requests (id uuid);
    CREATE TABLE public.qhub_acknowledgments (id uuid);
    CREATE ROLE service_role;

    CREATE FUNCTION public.qhub_decide_review(
      p_request_id uuid, p_actor text, p_is_staff boolean,
      p_decision text, p_reason text, p_policy_version text
    ) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    BEGIN
      RAISE EXCEPTION 'D20_DECIDE_BODY_MUST_NOT_EXECUTE_OR_APPEAR';
    END;
    $fn$;
  `);

  if (includeRow) {
    await db.exec(`
      CREATE FUNCTION public.qhub_row_immutable()
      RETURNS trigger LANGUAGE plpgsql AS $fn$
      BEGIN
        RAISE EXCEPTION 'D20_ROW_BODY_MUST_NOT_EXECUTE_OR_APPEAR';
      END;
      $fn$;
      REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO service_role;
    `);
  }

  if (options.overloadRow) {
    await db.exec(`
      CREATE FUNCTION public.qhub_row_immutable(value integer)
      RETURNS integer LANGUAGE sql AS $fn$ SELECT value $fn$;
    `);
  }

  await installVerifier(db, reportSql());

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

describe('R15.6 Diagnostic 20 - immutable scope and read-only construction', () => {
  it('keeps every accepted migration and historical release artifact byte-identical', () => {
    for (const [relativePath, digest] of Object.entries(APPROVED_ARTIFACTS)) {
      expect(sha256(`${REPO}${relativePath}`), relativePath).toBe(digest);
    }
  });

  it('uses one verifier invocation inside an explicit repeatable-read, read-only transaction', () => {
    const code = codeWithoutComments(DIAGNOSTIC);
    const executableCode = codeWithoutSqlStrings(code);
    const invocations = executableCode.match(/\bpublic\.qhub_verify_commercial_schema\s*\(\s*\)/g) ?? [];

    expect(invocations).toHaveLength(1);
    expect(code).toMatch(/^\s*BEGIN\s*;/i);
    expect(code).toMatch(/SET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+REPEATABLE\s+READ\s*,\s*READ\s+ONLY\s*;/i);
    expect(code).toMatch(/verifier_invocation\s+AS\s+MATERIALIZED/i);
    expect(code).toMatch(/COMMIT\s*;\s*$/i);
  });

  it('contains no mutation, dynamic SQL, temporary object, or implicated-function invocation', () => {
    const executableCode = codeWithoutSqlStrings(codeWithoutComments(DIAGNOSTIC));
    const forbidden = /\b(ALTER|CREATE|DELETE|DROP|GRANT|INSERT|MERGE|REVOKE|TRUNCATE|UPDATE|EXECUTE|COPY|CALL|DO)\b/i;

    expect(executableCode).not.toMatch(forbidden);
    expect(executableCode).not.toMatch(/\b(query_to_xml|dblink|lo_import|pg_read_file|pg_write_file)\b/i);
    expect(executableCode).not.toMatch(/\bpublic\.qhub_decide_review\s*\(/i);
    expect(executableCode).not.toMatch(/\bpublic\.qhub_row_immutable\s*\(/i);
  });

  it('queries only the commercial verifier and the two implicated function names', () => {
    const catalogNames = [...DIAGNOSTIC.matchAll(/p\.proname\s*=\s*'([^']+)'/g)].map((match) => match[1]);

    expect(new Set(catalogNames)).toEqual(
      new Set(['qhub_verify_commercial_schema', 'qhub_decide_review', 'qhub_row_immutable']),
    );
    expect(DIAGNOSTIC).not.toMatch(/pg_get_functiondef|prosrc\s+AS|jsonb_build_object\([^)]*prosrc/is);
  });
});

describe('R15.6 Diagnostic 20 - exact report gate and deterministic evidence', () => {
  it('returns deterministic evidence for the exact five-label report and invokes the verifier once', async () => {
    const db = await openFixture();

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('R15_6_TARGETED_DRIFT_EVIDENCE_READY');
      expect(row.product_version).toBe(EXPECTED_VERSION);
      expect(row.product_ready).toBe(false);
      expect(row.failed_labels).toEqual(EXPECTED_LABELS);
      expect(row.failed_label_count).toBe(5);
      expect(row.target_catalog_status).toBe('EXACT_TARGETS_IDENTIFIED');
      expect(row.implicated_discrepancy_classes).toEqual([
        'decide_review_body',
        'row_immutable_body',
        'row_immutable_direct_acl',
      ]);
    } finally {
      await db.close();
    }
  });

  it.each([
    ['changed version', '2026-07-30.commercial-launch-r7', EXPECTED_LABELS],
    ['changed label', EXPECTED_VERSION, [...EXPECTED_LABELS.slice(0, 4), 'row_immutable_acl_grant_option']],
    ['reordered labels', EXPECTED_VERSION, [EXPECTED_LABELS[1], EXPECTED_LABELS[0], ...EXPECTED_LABELS.slice(2)]],
  ])('withholds targeted evidence for %s', async (_name, version, labels) => {
    const db = await openFixture();
    await installVerifier(db, reportSql(version, labels));

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('VERSION_OR_ORDERED_LABEL_GATE_FAILED');
      expect(row.function_evidence).toBeNull();
      expect(row.row_immutable_direct_acl).toBeNull();
      expect(row.label_condition_evidence).toBeNull();
    } finally {
      await db.close();
    }
  });

  it('fails closed for an unexpected verifier report shape', async () => {
    const db = await openFixture();
    await installVerifier(
      db,
      `jsonb_build_object('expected_version','${EXPECTED_VERSION}','ready',false,'failed','bad')`,
    );

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('VERIFIER_REPORT_INVALID');
      expect(row.function_evidence).toBeNull();
    } finally {
      await db.close();
    }
  });

  it('maps every captured label to the exact verifier predicate in verifier order', async () => {
    const db = await openFixture();

    try {
      const row = await runDiagnostic(db);
      expect(row.label_condition_evidence).toEqual([
        {
          label_order: 1,
          label: 'decide_review_body_drift',
          implicated_object: 'public.qhub_decide_review(uuid,text,boolean,text,text,text)',
          verifier_condition: 'raw_md5_prosrc_not_in_expected_digest_set',
          condition_failed: true,
        },
        {
          label_order: 2,
          label: 'r7_ack_immutable_body_drift',
          implicated_object: 'public.qhub_row_immutable()',
          verifier_condition: 'raw_md5_prosrc_not_in_expected_digest_set',
          condition_failed: true,
        },
        {
          label_order: 3,
          label: 'row_immutable_body_digest',
          implicated_object: 'public.qhub_row_immutable()',
          verifier_condition: 'raw_md5_prosrc_not_in_expected_digest_set',
          condition_failed: true,
        },
        {
          label_order: 4,
          label: 'row_immutable_acl_cardinality',
          implicated_object: 'public.qhub_row_immutable()',
          verifier_condition: 'direct_acl_cardinality_is_distinct_from_1',
          condition_failed: true,
        },
        {
          label_order: 5,
          label: 'row_immutable_acl_unexpected_grantee',
          implicated_object: 'public.qhub_row_immutable()',
          verifier_condition: 'direct_acl_contains_grantee_other_than_function_owner',
          condition_failed: true,
        },
      ]);
    } finally {
      await db.close();
    }
  });

  it('reports deterministic expected and actual raw-prosrc digests without returning bodies', async () => {
    const db = await openFixture();

    try {
      const first = await runDiagnostic(db);
      const second = await runDiagnostic(db);
      const evidence = first.function_evidence ?? [];

      expect(evidence).toHaveLength(2);
      expect(evidence.map((entry) => entry.actual.body_digest)).toEqual(
        second.function_evidence?.map((entry) => entry.actual.body_digest),
      );
      expect(evidence[0].expected.accepted_body_digests).toEqual([
        '7e678f1e4bba0c540507cfe3743fbe54',
        'dac8abcd56d7fc804baac660059c14bf',
      ]);
      expect(evidence[1].expected.accepted_body_digests).toEqual([
        '41ae59dde9a471b580d28e2cb45984f5',
        '4936e3f58627dde5abc10d2b0ecf5b4f',
      ]);
      expect(
        evidence.every((entry) => entry.expected.body_digest_method === 'raw_md5_pg_proc_prosrc_no_normalization'),
      ).toBe(true);
      expect(JSON.stringify(first)).not.toContain('D20_DECIDE_BODY_MUST_NOT_EXECUTE_OR_APPEAR');
      expect(JSON.stringify(first)).not.toContain('D20_ROW_BODY_MUST_NOT_EXECUTE_OR_APPEAR');
    } finally {
      await db.close();
    }
  });

  it('returns every direct row-helper ACL field and isolates unexpected grantees', async () => {
    const db = await openFixture();

    try {
      const row = await runDiagnostic(db);
      const entries = row.row_immutable_direct_acl ?? [];
      const unexpected = entries.filter((entry) => entry.unexpected_grantee);

      expect(entries).toHaveLength(2);
      expect(
        entries.every(
          (entry) =>
            Object.keys(entry).sort().join(',') ===
            'grantable,grantee,grantee_oid,grantor,grantor_oid,ordinal,privilege,unexpected_grantee',
        ),
      ).toBe(true);
      expect(unexpected).toHaveLength(1);
      expect(unexpected[0]).toMatchObject({
        grantee: 'service_role',
        privilege: 'EXECUTE',
        grantable: false,
        unexpected_grantee: true,
      });
      expect(row.unexpected_grantee_evidence).toHaveLength(1);
    } finally {
      await db.close();
    }
  });

  it('distinguishes a missing implicated object and withholds evidence', async () => {
    const db = await openFixture({ includeRow: false });

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('IMPLICATED_OBJECT_MISSING');
      expect(row.target_catalog_status).toBe('IMPLICATED_OBJECT_MISSING');
      expect(row.function_evidence).toBeNull();
    } finally {
      await db.close();
    }
  });

  it('distinguishes an implicated overload and withholds evidence', async () => {
    const db = await openFixture({ overloadRow: true });

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('IMPLICATED_OBJECT_OVERLOADED');
      expect(row.target_catalog_status).toBe('IMPLICATED_OBJECT_OVERLOADED');
      expect(row.function_evidence).toBeNull();
    } finally {
      await db.close();
    }
  });

  it('fails closed when the commercial verifier is missing', async () => {
    const db = new PGlite();
    await expect(runDiagnostic(db)).rejects.toThrow(/qhub_verify_commercial_schema/i);
    await db.close();
  });

  it('fails closed when the commercial verifier is overloaded without invoking it', async () => {
    const db = await openFixture();
    await db.exec(`
      CREATE FUNCTION public.qhub_verify_commercial_schema(value integer)
      RETURNS jsonb LANGUAGE sql STABLE AS $fn$ SELECT '{}'::jsonb $fn$;
    `);

    try {
      const row = await runDiagnostic(db);
      expect(row.diagnostic_status).toBe('VERIFIER_CONTRACT_INVALID');
      expect(row.function_evidence).toBeNull();
    } finally {
      await db.close();
    }
  });
});
