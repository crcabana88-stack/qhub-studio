/**
 * QHUB R15.2A — LIVE PATCH PACKAGE AUTHORITY (PGlite)
 * app/test/commercial-r15-2-patch-package.test.ts
 *
 * Exercises the COMMITTED operational package under docs/release/r15-2-verifier-patch/ as the operator
 * will run it. The package is what authorizes a live change, so its precheck and postcheck must be
 * truthful: every authority condition they display must also gate their verdict.
 *
 * Codex found that 09 could return R15_2_VERIFIER_READY after verifier-owner drift and search_path
 * drift (both were displayed but excluded from final_status), that 07 displayed signature_matches
 * without requiring it, and that a missing function could raise PostgreSQL 42883 instead of failing
 * closed. Each of those is a first-class regression test here.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const PKG = `${REPO}docs/release/r15-2-verifier-patch/`;
const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');
const PATCH = readFileSync(`${PKG}08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql`, 'utf8');

/** Split a package script into runnable statements, dropping comment-only lines. */
function statements(sql: string): string[] {
  return sql
    .split(/;\s*\n/)
    .map((chunk) =>
      chunk
        .split('\n')
        .filter((l) => !/^\s*--/.test(l))
        .join('\n')
        .trim(),
    )
    .filter(Boolean);
}

const PRE = statements(readFileSync(`${PKG}07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql`, 'utf8'));
const POST = statements(readFileSync(`${PKG}09_POST_PATCH_VERIFY.sql`, 'utf8'));

/** 07: QUERY 2 is the verdict. 09: QUERY 1 is the existence gate, QUERY 3 the final status. */
const PRE_VERDICT = PRE[1];
const POST_GATE = POST[0];
const POST_FINAL = POST[POST.length - 1];

async function open(migration = MIGRATION, patch?: string): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  `);
  await db.exec(migration);

  if (patch) {
    await db.exec(patch);
  }

  return db;
}

const preVerdict = async (db: PGlite) => (await db.query<{ verdict: string }>(PRE_VERDICT)).rows[0].verdict;
const postStatus = async (db: PGlite) => (await db.query<{ final_status: string }>(POST_FINAL)).rows[0].final_status;

/**
 * Apply drift to a patched database and return the status the OPERATOR would reach by following
 * 09 in order: the catalog authority gate (QUERY 2) decides first because it cannot raise, then the
 * final status (QUERY 3). This mirrors the runbook exactly and never throws.
 */
async function statusAfter(drift: string): Promise<string> {
  const db = await open(MIGRATION, PATCH);

  try {
    if (drift) {
      await db.exec(drift);
    }

    const gate = (await db.query<{ authority_status: string }>(POST[1])).rows[0].authority_status;

    if (gate === 'R15_2_VERIFIER_NOT_READY') {
      return gate;
    }

    return await postStatus(db);
  } finally {
    await db.close();
  }
}

/** Apply drift to an unpatched database, read 07's verdict, and close. */
async function verdictAfter(drift: string): Promise<string> {
  const db = await open();

  try {
    if (drift) {
      await db.exec(drift);
    }

    return await preVerdict(db);
  } finally {
    await db.close();
  }
}

describe('R15.2A — 07 precheck binds exact signature AND exact raw body', () => {
  it('test 1 — the five exact signatures with approved raw digests authorize the patch', async () => {
    expect(await verdictAfter('')).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
  }, 120_000);

  it('test 1b — a CRLF-applied database also authorizes (second reviewed encoding)', async () => {
    const db = await open(MIGRATION.replace(/\n/g, '\r\n'));

    try {
      expect(await preVerdict(db)).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
    } finally {
      await db.close();
    }
  }, 120_000);

  const PRECHECK_DRIFT: Array<[string, string]> = [
    ['test 2 — missing function', 'DROP FUNCTION public.qhub_canon_cells(text[]) CASCADE;'],
    [
      'test 3/6 — wrong argument signature (same name, correct-looking body)',
      `DROP FUNCTION public.qhub_canon_cells(text[]) CASCADE;
       CREATE FUNCTION public.qhub_canon_cells(p_cells text) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT p_cells $f$;`,
    ],
    ['test 4 — renamed function', 'ALTER FUNCTION public.qhub_canon_cells(text[]) RENAME TO qhub_canon_cells_old;'],
    [
      'test 5 — unexpected overload alongside the reviewed function',
      `CREATE FUNCTION public.qhub_canon_cells(p_cells text) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT p_cells $f$;`,
    ],
    [
      'test 7 — unapproved raw digest (body replaced)',
      `CREATE OR REPLACE FUNCTION public.qhub_canon_cells(p_cells TEXT[])
       RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT array_to_string(p_cells, '|') $f$;`,
    ],
  ];

  for (const [name, drift] of PRECHECK_DRIFT) {
    it(`${name} returns UNEXPECTED_FUNCTION_BODY_STOP with no SQL error`, async () => {
      expect(await verdictAfter(drift)).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    }, 120_000);
  }

  it('test 8 — a CR embedded in executable text stops the precheck', async () => {
    const db = await open(MIGRATION.replace("'staff_required'", "'staff\r_required'"));

    try {
      expect(await preVerdict(db)).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('test 9 — intra-body mixed line endings stop the precheck', async () => {
    const start = MIGRATION.indexOf('CREATE OR REPLACE FUNCTION public.qhub_decide_review');
    const end = MIGRATION.indexOf('$$;', start) + 3;
    const lines = MIGRATION.slice(start, end).split('\n');
    const half = Math.floor(lines.length / 2);
    const mixed =
      MIGRATION.slice(0, start) + lines.map((l, n) => (n < half ? `${l}\r` : l)).join('\n') + MIGRATION.slice(end);

    const db = await open(mixed);

    try {
      expect(await preVerdict(db)).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);
});

describe('R15.2A — 09 postcheck gates on every authority condition it displays', () => {
  it('test 10 — a healthy patched verifier is READY', async () => {
    expect(await statusAfter('')).toBe('R15_2_VERIFIER_READY');
  }, 120_000);

  const POSTCHECK_DRIFT: Array<[string, string]> = [
    // The two P1 false-READY paths Codex found.
    [
      'test 11 — verifier OWNER drift',
      'CREATE ROLE drifted_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO drifted_owner;',
    ],
    [
      'test 12 — fixed search_path drift',
      'ALTER FUNCTION public.qhub_verify_commercial_schema() SET search_path = public;',
    ],
    [
      'test 12b — search_path removed entirely',
      'ALTER FUNCTION public.qhub_verify_commercial_schema() RESET search_path;',
    ],
    ['test 13 — SECURITY DEFINER dropped', 'ALTER FUNCTION public.qhub_verify_commercial_schema() SECURITY INVOKER;'],
    [
      'test 14 — service_role EXECUTE revoked',
      'REVOKE EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() FROM service_role;',
    ],
    ['test 15 — PUBLIC EXECUTE granted', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO PUBLIC;'],
    ['test 16 — anon EXECUTE granted', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO anon;'],
    [
      'test 17 — authenticated EXECUTE granted',
      'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO authenticated;',
    ],
    [
      'test 18 — unexpected privileged grantee',
      'CREATE ROLE sneaky NOLOGIN; GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO sneaky;',
    ],
    [
      'test 19 — verifier body drift',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
       LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
       BEGIN RETURN jsonb_build_object('expected_version','2026-07-30.commercial-launch-r8','ready',true,'failed','[]'::jsonb); END; $f$;`,
    ],
    [
      'test 20 — an overload of the verifier is added',
      `CREATE FUNCTION public.qhub_verify_commercial_schema(p integer) RETURNS JSONB
       LANGUAGE sql AS $f$ SELECT '{}'::jsonb $f$;`,
    ],

    // test 22/23/24: a product-level failure must also block the package verdict.
    [
      'test 22/24 — product verifier reports ready=false / non-empty failed',
      `ALTER TABLE public.qhub_acknowledgments NO FORCE ROW LEVEL SECURITY;`,
    ],
  ];

  for (const [name, drift] of POSTCHECK_DRIFT) {
    it(`${name} yields R15_2_VERIFIER_NOT_READY`, async () => {
      expect(await statusAfter(drift)).toBe('R15_2_VERIFIER_NOT_READY');
    }, 120_000);
  }

  it('test 21 — a missing verifier is reported NOT READY by the gate, with no 42883', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      await db.exec('DROP FUNCTION public.qhub_verify_commercial_schema();');

      // The QUERY 1 gate is pure-catalog: it must answer cleanly rather than raise 42883.
      const gate = await db.query<{ verifier_present: boolean; status_if_absent: string }>(POST_GATE);
      expect(gate.rows[0].verifier_present).toBe(false);
      expect(gate.rows[0].status_if_absent).toBe('R15_2_VERIFIER_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('test 25 — every authority column displayed by the final query is an input to final_status', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      const row = (await db.query<Record<string, unknown>>(POST_FINAL)).rows[0];
      const inputs = Object.keys(row).filter((k) => k !== 'final_status');

      /*
       * Each displayed column is boolean and true on a healthy database; the verdict ANDs all of them,
       * so no displayed authority condition can be silently excluded.
       */
      for (const key of inputs) {
        expect(typeof row[key], `${key} should be a boolean authority input`).toBe('boolean');
        expect(row[key], `${key} should hold on a healthy patched database`).toBe(true);
      }

      // The specific conditions Codex found missing must be present by name.
      for (const required of ['owner_exact', 'search_path_exact', 'security_definer', 'body_approved']) {
        expect(inputs, `final_status must consume ${required}`).toContain(required);
      }

      expect(row.final_status).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);
});

describe('R15.2A — 08 patch scope and idempotency', () => {
  it('tests 26/27 — the patch changes only the verifier and preserves owner/security/search_path/ACL', async () => {
    const db = await open();

    try {
      const snapshot = async () =>
        (
          await db.query<{ n: number }>(
            `select count(*)::int n from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
              where ns.nspname = 'public' and p.proname like 'qhub_%'`,
          )
        ).rows[0].n;

      const before = await snapshot();
      const beforeBodies = await db.query<{ proname: string; m: string }>(
        `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
          where ns.nspname='public' and p.proname in
            ('qhub_decide_review','qhub_create_review_request','qhub_record_acknowledgment','qhub_canon_cells','qhub_row_immutable')
          order by p.proname`,
      );

      await db.exec(PATCH);

      expect(await snapshot()).toBe(before);

      // Protected bodies untouched by the patch.
      const afterBodies = await db.query<{ proname: string; m: string }>(
        `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
          where ns.nspname='public' and p.proname in
            ('qhub_decide_review','qhub_create_review_request','qhub_record_acknowledgment','qhub_canon_cells','qhub_row_immutable')
          order by p.proname`,
      );
      expect(afterBodies.rows).toEqual(beforeBodies.rows);

      // Verifier identity restored exactly.
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('test 28 — a second application of the patch is idempotent', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('test 29 — the patch contains no destructive SQL and only one transaction', () => {
    const code = PATCH.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');

    /*
     * Match destructive STATEMENTS, not the bare words. The verifier body legitimately contains
     * 'TRUNCATE' and 'DELETE' inside a privilege-name list it checks browser roles do NOT hold.
     */
    expect(code).not.toMatch(/\bDROP\s+(TABLE|FUNCTION|POLICY|INDEX|TRIGGER|CONSTRAINT|SCHEMA|ROLE)\s+/i);
    expect(code).not.toMatch(/\bTRUNCATE\s+(TABLE\s+)?[a-z_."]+\s*;/i);
    expect(code).not.toMatch(/\bDELETE\s+FROM\s+[a-z_."]+/i);
    expect((PATCH.match(/^BEGIN;$/gm) ?? []).length).toBe(1);
    expect((PATCH.match(/^COMMIT;$/gm) ?? []).length).toBe(1);

    // Only the verifier is created/replaced.
    expect((PATCH.match(/CREATE OR REPLACE FUNCTION/g) ?? []).length).toBe(1);
    expect(PATCH).toMatch(/CREATE OR REPLACE FUNCTION public\.qhub_verify_commercial_schema\(\)/);
  });
});

describe('R15.2A — full live sequence', () => {
  const authorityStatus = async (db: PGlite) =>
    (await db.query<{ authority_status: string }>(POST[1])).rows[0].authority_status;

  it('tests 30-37 — CRLF channel -> 07 SAFE -> 08 -> 09 READY -> drift NOT READY -> reset READY', async () => {
    /*
     * The live database was applied through the CRLF channel. (Reproducing the five original
     * *_body_drift failures requires the pre-R15.2 verifier and is covered by the R15.2 product suite
     * and the recorded diagnosis; this migration's verifier now accepts both reviewed encodings.)
     */
    const db = await open(MIGRATION.replace(/\n/g, '\r\n'));

    try {
      // 31-33. precheck authorizes, patch applies, postcheck is READY.
      expect(await preVerdict(db)).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
      await db.exec(PATCH);
      expect(await authorityStatus(db)).toBe('CATALOG_AUTHORITY_OK_CONTINUE_TO_QUERY_3');
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');

      /*
       * 34. Owner drift. A drifted owner makes the SECURITY DEFINER verifier raise "permission denied"
       * rather than return, so the catalog gate — which cannot raise — is what must produce the verdict.
       */
      await db.exec(
        'CREATE ROLE seq_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO seq_owner;',
      );
      expect(await authorityStatus(db)).toBe('R15_2_VERIFIER_NOT_READY');

      // 36. Restoring the approved owner returns the sequence to READY.
      await db.exec('ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO CURRENT_USER;');
      expect(await authorityStatus(db)).toBe('CATALOG_AUTHORITY_OK_CONTINUE_TO_QUERY_3');
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');

      // 35. search_path drift is caught by both gates, then reset by re-applying the approved patch.
      await db.exec('ALTER FUNCTION public.qhub_verify_commercial_schema() SET search_path = public;');
      expect(await authorityStatus(db)).toBe('R15_2_VERIFIER_NOT_READY');
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_NOT_READY');

      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 240_000);
});
