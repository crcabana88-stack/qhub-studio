/**
 * R15.6 protected-function restoration package.
 *
 * Focused offline proof for PRE 21, PATCH 22, and POST 23.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R156 = REPO + 'docs/release/r15-6-runtime-verifier/';
const PRE = readFileSync(R156 + '21_PRE_PROTECTED_FUNCTION_RESTORATION.sql', 'utf8');
const PATCH = readFileSync(R156 + '22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql', 'utf8');
const POST = readFileSync(R156 + '23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql', 'utf8');
const MIGRATION = readFileSync(REPO + 'supabase/migrations/20260729_commercial_launch_foundation.sql', 'utf8');
const LIVE_VERIFIER = readFileSync(REPO + 'app/test/fixtures/r8-644b5c6-live-verifier.sql', 'utf8');
const R156_VERIFIER_PATCH = readFileSync(R156 + '17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql', 'utf8');
const AUTHORITATIVE_RESTORE = readFileSync(
  REPO + 'docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql',
  'utf8',
);

const EXISTING = {
  'supabase/migrations/20260729_commercial_launch_foundation.sql':
    '1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755',
  'docs/release/r15-6-runtime-verifier/19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql':
    'dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa',
  'docs/release/r15-6-runtime-verifier/20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql':
    '0626edb61d9f5ed916be881eb48af0dddac972c852472c8d18f2a8832ffd9047',
  'docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql':
    'a549863161a403f34b63261f3cde5b0d91abb901092031580916f34bf9df6529',
  'docs/release/r15-6-runtime-verifier/17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql':
    '911055870d867f9993f0ceb981e4d5b91d922bee798b559f26f3f4c100582ab0',
} as const;

const APPROVED = {
  decideLf: '7e678f1e4bba0c540507cfe3743fbe54',
  decideCrlf: 'dac8abcd56d7fc804baac660059c14bf',
  rowLf: '41ae59dde9a471b580d28e2cb45984f5',
  rowCrlf: '4936e3f58627dde5abc10d2b0ecf5b4f',
} as const;

const CP1252: Record<number, number> = {
  0x80: 0x20ac,
  0x82: 0x201a,
  0x83: 0x0192,
  0x84: 0x201e,
  0x85: 0x2026,
  0x86: 0x2020,
  0x87: 0x2021,
  0x88: 0x02c6,
  0x89: 0x2030,
  0x8a: 0x0160,
  0x8b: 0x2039,
  0x8c: 0x0152,
  0x8e: 0x017d,
  0x91: 0x2018,
  0x92: 0x2019,
  0x93: 0x201c,
  0x94: 0x201d,
  0x95: 0x2022,
  0x96: 0x2013,
  0x97: 0x2014,
  0x98: 0x02dc,
  0x99: 0x2122,
  0x9a: 0x0161,
  0x9b: 0x203a,
  0x9c: 0x0153,
  0x9e: 0x017e,
  0x9f: 0x0178,
};

const SUPABASE_DEFAULT_PRIVILEGES = `ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`;

const PRE_R154_MIGRATION = MIGRATION.replace(
  /REVOKE ALL PRIVILEGES ON FUNCTION public\.qhub_row_immutable\(\)[^\n]*\n/g,
  '',
).replace(/DO \$qhub_row_immutable_owner_grant\$[\s\S]*?\$qhub_row_immutable_owner_grant\$;\n/, '');

function mangle(value: string): string {
  let result = '';

  for (const byte of Buffer.from(value, 'utf8')) {
    result += String.fromCodePoint(CP1252[byte] ?? byte);
  }

  return result;
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function code(sql: string): string {
  return sql.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

function codeWithoutBodiesAndStrings(sql: string): string {
  return code(sql)
    .replace(/\$[A-Za-z0-9_]*\$[\s\S]*?\$[A-Za-z0-9_]*\$/g, '$$')
    .replace(/'(?:''|[^'])*'/g, "''");
}

function definition(sql: string, name: string): string {
  const start = sql.indexOf('CREATE OR REPLACE FUNCTION public.' + name);
  const end = sql.indexOf('\n$$;', start);

  if (start < 0 || end < 0) {
    throw new Error(name + ' definition missing');
  }

  return sql.slice(start, end + 4);
}

async function fixture(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    [
      'CREATE ROLE anon NOLOGIN;',
      'CREATE ROLE authenticated NOLOGIN;',
      'CREATE ROLE service_role NOLOGIN;',
      'CREATE TABLE public.qhub_manual_review_requests(id uuid);',
      'CREATE TABLE public.qhub_acknowledgments(id uuid);',
      'CREATE TABLE public.qhub_usage_ledger(id uuid);',
      'CREATE TABLE public.qhub_entitlement_audit(id uuid);',
      'CREATE FUNCTION public.qhub_decide_review(',
      ' p_request_id uuid,p_actor text,p_is_staff boolean,p_decision text,p_reason text,p_policy_version text',
      ') RETURNS jsonb LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE NOT LEAKPROOF',
      'COST 100 SECURITY DEFINER SET search_path=pg_catalog, public AS $$ BEGIN RETURN jsonb_build_object(',
      " 'ok',false); END; $$;",
      'REVOKE ALL ON FUNCTION public.qhub_decide_review(uuid,text,boolean,text,text,text) FROM PUBLIC,anon,authenticated;',
      'GRANT EXECUTE ON FUNCTION public.qhub_decide_review(uuid,text,boolean,text,text,text) TO service_role;',
      'CREATE FUNCTION public.qhub_row_immutable() RETURNS trigger LANGUAGE plpgsql VOLATILE',
      'CALLED ON NULL INPUT PARALLEL UNSAFE NOT LEAKPROOF COST 100 AS $$ BEGIN RAISE EXCEPTION',
      " 'immutable'; END; $$;",
      'GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon,authenticated,service_role;',
      'CREATE TRIGGER trg_qhub_acknowledgments_immutable BEFORE UPDATE OR DELETE ON public.qhub_acknowledgments',
      'FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();',
      'CREATE TRIGGER trg_qhub_usage_ledger_immutable BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger',
      'FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();',
      'CREATE TRIGGER trg_qhub_entitlement_audit_immutable BEFORE UPDATE OR DELETE ON public.qhub_entitlement_audit',
      'FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();',
    ].join('\n'),
  );

  return db;
}

async function liveR156DriftFixture(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );
  await db.exec(SUPABASE_DEFAULT_PRIVILEGES);
  await db.exec(mangle(PRE_R154_MIGRATION.replace(/\r?\n/g, '\r\n')));
  await db.exec(mangle(LIVE_VERIFIER.replace(/\r?\n/g, '\r\n')));
  await db.exec(R156_VERIFIER_PATCH);

  return db;
}

async function facts(db: PGlite): Promise<Array<{ proname: string; oid: number; digest: string; acl: string }>> {
  return (
    await db.query<{ proname: string; oid: number; digest: string; acl: string }>(
      'SELECT p.proname,p.oid,md5(p.prosrc) digest,p.proacl::text acl FROM pg_proc p ' +
        "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' " +
        "AND p.proname IN ('qhub_decide_review','qhub_row_immutable') ORDER BY p.proname",
    )
  ).rows;
}

describe('R15.6 protected restoration package — static authority', () => {
  it('keeps all previously approved artifacts byte-identical', () => {
    for (const [relative, digest] of Object.entries(EXISTING)) {
      expect(sha256(REPO + relative), relative).toBe(digest);
    }
  });

  it('makes PRE and POST repeatable-read, read-only, and mutation-free', () => {
    for (const sql of [PRE, POST]) {
      const executable = codeWithoutBodiesAndStrings(sql);
      expect(executable).toMatch(/^\s*BEGIN\s*;/i);
      expect(executable).toMatch(/SET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+REPEATABLE\s+READ\s*,\s*READ\s+ONLY/i);
      expect(executable).toMatch(/COMMIT\s*;\s*$/i);
      expect(executable).not.toMatch(/\b(CREATE|ALTER|DROP|TRUNCATE|INSERT|UPDATE|DELETE|MERGE|GRANT|REVOKE|COPY)\b/i);
    }
  });

  it('pins exact version, ordered labels, current digests, five ACL entries, metadata, owners, and triggers', () => {
    const ordered = [
      'decide_review_body_drift',
      'r7_ack_immutable_body_drift',
      'row_immutable_body_digest',
      'row_immutable_acl_cardinality',
      'row_immutable_acl_unexpected_grantee',
    ];
    let previous = -1;

    for (const label of ordered) {
      const at = PRE.indexOf("'" + label + "'");
      expect(at).toBeGreaterThan(previous);
      previous = at;
    }
    expect(PRE).toContain('2026-07-30.commercial-launch-r8');
    expect(PRE).toContain('9bc91d1671c5f65241ea22538c00d703');
    expect(PRE).toContain('583882c1a9b203e278b27d1080065c9e');

    for (const role of ['PUBLIC', 'anon', 'authenticated', 'postgres', 'service_role']) {
      expect(PRE).toContain(role);
    }
    expect(PRE).toContain('tg.tgtype=27');
    expect(PRE).toContain("tg.tgenabled='O'");
    expect(PRE).toContain('tg.tgconstraint=0');
    expect(PRE).toContain('SAFE_TO_APPLY_PROTECTED_FUNCTION_RESTORATION');
  });

  it('repeats every material safety gate in PATCH before either CREATE OR REPLACE', () => {
    const firstMutation = PATCH.indexOf('CREATE OR REPLACE FUNCTION public.qhub_decide_review');
    const gate = PATCH.slice(0, firstMutation);

    for (const token of [
      'verifier_exact_live_report',
      '9bc91d1671c5f65241ea22538c00d703',
      '583882c1a9b203e278b27d1080065c9e',
      'trigger_binding_cardinality',
      'unexpected_function_acl_state',
      'owner_reference_objects',
    ]) {
      expect(gate).toContain(token);
    }
  });

  it('contains exactly two approved function targets and only the authorized ACL mutation', () => {
    const targets = [...PATCH.matchAll(/CREATE OR REPLACE FUNCTION public\.([a-z0-9_]+)/g)].map((m) => m[1]);
    expect(targets).toEqual(['qhub_decide_review', 'qhub_row_immutable']);
    expect(code(PATCH)).not.toMatch(/\b(?:GRANT|REVOKE)[^;\n]*qhub_decide_review/i);
    expect(PATCH.match(/REVOKE ALL PRIVILEGES ON FUNCTION public\.qhub_row_immutable\(\)/g)).toHaveLength(4);
    expect(PATCH.match(/GRANT EXECUTE ON FUNCTION public\.qhub_row_immutable\(\)/g)).toHaveLength(1);
    expect(codeWithoutBodiesAndStrings(PATCH)).not.toMatch(
      /\b(INSERT|UPDATE|DELETE|MERGE|DROP|TRUNCATE|ALTER TABLE|CREATE TABLE|CREATE POLICY|ALTER POLICY|ALTER ROLE)\b/i,
    );
  });

  it('embeds the exact reviewed bodies and approved raw prosrc digests', () => {
    expect(definition(PATCH, 'qhub_decide_review')).toBe(definition(AUTHORITATIVE_RESTORE, 'qhub_decide_review'));
    expect(definition(PATCH, 'qhub_row_immutable')).toBe(definition(AUTHORITATIVE_RESTORE, 'qhub_row_immutable'));
    expect(PATCH).toContain(APPROVED.decideCrlf);
    expect(PATCH).toContain(APPROVED.rowCrlf);
  });

  it('has a final assertion before COMMIT and exposes complete POST closure evidence', () => {
    expect(PATCH.indexOf('R15_6_PROTECTED_FUNCTION_PATCH_FINAL_STOP')).toBeGreaterThan(
      PATCH.indexOf('CREATE OR REPLACE FUNCTION public.qhub_row_immutable'),
    );
    expect(PATCH.lastIndexOf('COMMIT;')).toBeGreaterThan(PATCH.indexOf('R15_6_PROTECTED_FUNCTION_PATCH_FINAL_STOP'));

    for (const field of [
      'product_ready',
      'product_version',
      'failed_labels',
      'function_evidence',
      'acl_evidence',
      'trigger_evidence',
      'unexpected_effective_executors',
      'R15_6_PROTECTED_FUNCTION_RESTORATION_VERIFIED',
    ]) {
      expect(POST).toContain(field);
    }
  });

  it('contains no migration bookkeeping, founder seed, Stripe, or secrets', () => {
    const all = [PRE, PATCH, POST].join('\n');
    expect(all).not.toMatch(/schema_migrations|migration_history|founder_seed|stripe/i);
    expect(all).not.toMatch(/service_role_key|access_token|refresh_token|authorization\s*:|password\s*=|sk_live_/i);
  });
});

describe('R15.6 protected restoration package — executable invariants', () => {
  it('accepts the exact observed start, restores only the approved contract, and POST closes READY', async () => {
    const db = await liveR156DriftFixture();

    try {
      const before = await facts(db);
      await expect(db.exec(PRE)).resolves.toBeDefined();
      expect(await facts(db)).toEqual(before);

      await expect(db.exec(PATCH)).resolves.toBeDefined();
      await expect(db.exec(POST)).resolves.toBeDefined();

      const report = await db.query<{ report: { ready: boolean; expected_version: string; failed: string[] } }>(
        'SELECT public.qhub_verify_commercial_schema() report',
      );
      expect(report.rows[0].report).toEqual({
        ready: true,
        expected_version: '2026-07-30.commercial-launch-r8',
        failed: [],
      });
    } finally {
      await db.close();
    }
  });

  it.each([
    [
      'body digest',
      "CREATE OR REPLACE FUNCTION public.qhub_row_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'different'; END $$;",
    ],
    ['ACL', 'REVOKE EXECUTE ON FUNCTION public.qhub_row_immutable() FROM service_role;'],
    ['owner', 'ALTER FUNCTION public.qhub_row_immutable() OWNER TO service_role;'],
    ['metadata', 'ALTER FUNCTION public.qhub_row_immutable() IMMUTABLE;'],
    [
      'trigger',
      'DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger; ' +
        'CREATE TRIGGER trg_qhub_usage_ledger_immutable BEFORE INSERT OR UPDATE OR DELETE ' +
        'ON public.qhub_usage_ledger FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();',
    ],
  ])('fails closed before mutation when the observed %s state changes', async (_case, mutation) => {
    const db = await liveR156DriftFixture();

    try {
      await db.exec(mutation);

      const before = await facts(db);
      let stopped = false;

      try {
        const results = await db.exec(PRE);
        stopped = results.some((result) =>
          result.rows.some((row) => (row as Record<string, unknown>).verdict === 'PROTECTED_FUNCTION_RESTORATION_STOP'),
        );
      } catch {
        stopped = true;

        try {
          await db.exec('ROLLBACK');
        } catch {
          // PRE already rolled back.
        }
      }
      expect(stopped).toBe(true);
      expect(await facts(db)).toEqual(before);
    } finally {
      await db.close();
    }
  });

  it('same-signature replacements preserve OIDs, dependencies, and qhub_decide_review ACL', async () => {
    const db = await fixture();

    try {
      const before = await facts(db);
      await db.exec(definition(PATCH, 'qhub_decide_review'));
      await db.exec(definition(PATCH, 'qhub_row_immutable'));

      const after = await facts(db);
      expect(after.map((x) => x.oid)).toEqual(before.map((x) => x.oid));
      expect(after[0].acl).toBe(before[0].acl);
      expect(after[0].digest).toBe(APPROVED.decideLf);
      expect(after[1].digest).toBe(APPROVED.rowLf);

      const triggerCount = await db.query<{ n: number }>(
        "SELECT count(*)::integer n FROM pg_trigger WHERE tgfoid=to_regprocedure('public.qhub_row_immutable()')",
      );
      expect(triggerCount.rows[0].n).toBe(3);
    } finally {
      await db.close();
    }
  });

  it('the authorized row-helper ACL transition ends owner-only', async () => {
    const db = await fixture();

    try {
      await db.exec(definition(PATCH, 'qhub_row_immutable'));
      await db.exec(
        [
          'REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM PUBLIC;',
          'REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM anon;',
          'REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM authenticated;',
          'REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM service_role;',
          'GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO postgres;',
        ].join('\n'),
      );

      const acl = await db.query<{ grantee: string; grantor: string; privilege: string; grantable: boolean }>(
        "SELECT CASE WHEN ae.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(ae.grantee) END grantee," +
          'pg_get_userbyid(ae.grantor) grantor,ae.privilege_type privilege,ae.is_grantable grantable ' +
          'FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) ae ' +
          "WHERE p.oid=to_regprocedure('public.qhub_row_immutable()')",
      );
      expect(acl.rows).toEqual([{ grantee: 'postgres', grantor: 'postgres', privilege: 'EXECUTE', grantable: false }]);
    } finally {
      await db.close();
    }
  });

  it('a failed final assertion rolls back both bodies and ACL', async () => {
    const db = await fixture();
    const before = await facts(db);

    try {
      const tx = [
        'BEGIN;',
        definition(PATCH, 'qhub_decide_review'),
        definition(PATCH, 'qhub_row_immutable'),
        'REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM PUBLIC,anon,authenticated,service_role;',
        "DO $$ BEGIN RAISE EXCEPTION 'forced_final_assertion'; END $$;",
        'COMMIT;',
      ].join('\n');
      await expect(db.exec(tx)).rejects.toThrow(/forced_final_assertion/);

      try {
        await db.exec('ROLLBACK');
      } catch {
        /* already rolled back */
      }
      expect(await facts(db)).toEqual(before);
    } finally {
      await db.close();
    }
  });
});
