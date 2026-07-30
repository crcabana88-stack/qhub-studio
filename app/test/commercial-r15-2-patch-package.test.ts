/**
 * QHUB R15.2B — ATOMIC LIVE PATCH AUTHORIZATION (PGlite)
 * app/test/commercial-r15-2-patch-package.test.ts
 *
 * Exercises the COMMITTED operational package under docs/release/r15-2-verifier-patch/ exactly as the
 * operator runs it: each file pasted and executed IN FULL, as one unit.
 *
 * Findings this suite locks down:
 *   R15.2A  09 displayed owner and search_path but excluded them from final_status (false READY).
 *   R15.2B  P1-A a pre-existing `service_role EXECUTE WITH GRANT OPTION` survived CREATE OR REPLACE and
 *                the old REVOKE/GRANT sequence, and the postcheck never inspected is_grantable.
 *           P1-B catalog gating and verifier execution lived in separate statements, so an unreviewed
 *                body could still be executed by the later statement.
 *           P2   07 ended with an unconditional verifier invocation that raised 42883 when the file was
 *                run in full after a missing-function STOP.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const PKG = `${REPO}docs/release/r15-2-verifier-patch/`;
const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');
const PRE = readFileSync(`${PKG}07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql`, 'utf8');
const PATCH = readFileSync(`${PKG}08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql`, 'utf8');
const POST = readFileSync(`${PKG}09_POST_PATCH_VERIFY.sql`, 'utf8');

/** The single authoritative statement of a package file (everything except BEGIN/SET/COMMIT). */
function finalStatement(sql: string): string {
  const parts = sql
    .split(/;\s*\n/)
    .map((chunk) =>
      chunk
        .split('\n')
        .filter((l) => !/^\s*--/.test(l))
        .join('\n')
        .trim(),
    )
    .filter(Boolean)
    .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION)/i.test(s));

  return parts[parts.length - 1];
}

const PRE_VERDICT = finalStatement(PRE);
const POST_FINAL = finalStatement(POST);

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

/** Run 07 IN FULL (as the operator does) and return its verdict. */
async function runPreInFull(db: PGlite): Promise<string> {
  await db.exec(PRE);

  return (await db.query<{ verdict: string }>(PRE_VERDICT)).rows[0].verdict;
}

/** Run 09 IN FULL and return its single authoritative row. */
async function runPostInFull(db: PGlite): Promise<Record<string, unknown>> {
  await db.exec(POST);

  return (await db.query<Record<string, unknown>>(POST_FINAL)).rows[0];
}

const postStatus = async (db: PGlite) => (await runPostInFull(db)).final_status as string;

async function verdictAfter(drift: string, migration = MIGRATION): Promise<string> {
  const db = await open(migration);

  try {
    if (drift) {
      await db.exec(drift);
    }

    return await runPreInFull(db);
  } finally {
    await db.close();
  }
}

async function statusAfter(drift: string): Promise<string> {
  const db = await open(MIGRATION, PATCH);

  try {
    if (drift) {
      await db.exec(drift);
    }

    return await postStatus(db);
  } finally {
    await db.close();
  }
}

/** Direct ACL facts for the verifier, used to prove 08's reset. */
async function verifierAcl(db: PGlite) {
  return (
    await db.query<{ role_name: string; privilege_type: string; is_grantable: boolean }>(
      `select pg_get_userbyid(ae.grantee) role_name, ae.privilege_type, ae.is_grantable
         from pg_proc p, aclexplode(p.proacl) ae
        where p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
        order by 1, 2`,
    )
  ).rows;
}

// ─── 07 precheck ────────────────────────────────────────────────────────────────

describe('R15.2B — 07 is safe to run in full and binds identity + raw body', () => {
  it('test 1 — healthy LF state authorizes', async () => {
    expect(await verdictAfter('')).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
  }, 120_000);

  it('test 1b — healthy CRLF state authorizes', async () => {
    expect(await verdictAfter('', MIGRATION.replace(/\n/g, '\r\n'))).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
  }, 120_000);

  const DRIFT: Array<[string, string]> = [
    ['test 2 — missing function', 'DROP FUNCTION public.qhub_canon_cells(text[]) CASCADE;'],
    ['test 3 — renamed function', 'ALTER FUNCTION public.qhub_canon_cells(text[]) RENAME TO qhub_canon_cells_old;'],
    [
      'test 4 — wrong argument signature',
      `DROP FUNCTION public.qhub_canon_cells(text[]) CASCADE;
       CREATE FUNCTION public.qhub_canon_cells(p_cells text) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT p_cells $f$;`,
    ],
    [
      'test 5 — unexpected overload',
      `CREATE FUNCTION public.qhub_canon_cells(p_cells text) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT p_cells $f$;`,
    ],
    [
      'test 6 — unapproved raw digest',
      `CREATE OR REPLACE FUNCTION public.qhub_canon_cells(p_cells TEXT[])
       RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$ SELECT array_to_string(p_cells, '|') $f$;`,
    ],
  ];

  for (const [name, drift] of DRIFT) {
    it(`${name} STOPs with no SQL error`, async () => {
      expect(await verdictAfter(drift)).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    }, 120_000);
  }

  it('test 7 — embedded executable CR STOPs', async () => {
    expect(await verdictAfter('', MIGRATION.replace("'staff_required'", "'staff\r_required'"))).toBe(
      'UNEXPECTED_FUNCTION_BODY_STOP',
    );
  }, 120_000);

  it('test 8 — intra-body mixed line endings STOP', async () => {
    const start = MIGRATION.indexOf('CREATE OR REPLACE FUNCTION public.qhub_decide_review');
    const end = MIGRATION.indexOf('$$;', start) + 3;
    const lines = MIGRATION.slice(start, end).split('\n');
    const half = Math.floor(lines.length / 2);
    const mixed =
      MIGRATION.slice(0, start) + lines.map((l, n) => (n < half ? `${l}\r` : l)).join('\n') + MIGRATION.slice(end);

    expect(await verdictAfter('', mixed)).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
  }, 120_000);

  it('test 9 — running the WHOLE file is safe even with the verifier missing (no 42883)', async () => {
    const db = await open();

    try {
      await db.exec('DROP FUNCTION public.qhub_verify_commercial_schema();');
      await db.exec('DROP FUNCTION public.qhub_canon_cells(text[]) CASCADE;');

      // Executing the entire file must not raise; the verdict must still be STOP.
      await expect(db.exec(PRE)).resolves.toBeDefined();
      expect((await db.query<{ verdict: string }>(PRE_VERDICT)).rows[0].verdict).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('07 never invokes a function (catalog-only)', () => {
    const code = PRE.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    expect(code).not.toMatch(/FROM\s+public\.qhub_verify_commercial_schema\(\)/i);
    expect(code).not.toMatch(/SELECT\s+public\.qhub_\w+\s*\(/i);
    expect(code).not.toMatch(/::regprocedure/);
  });
});

// ─── 08 exact authority reset ───────────────────────────────────────────────────

describe('R15.2B — 08 resets exact owner, security, search_path and ACL', () => {
  it('test 14 — a pre-existing service_role WITH GRANT OPTION is removed', async () => {
    const db = await open();

    try {
      await db.exec(
        'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role WITH GRANT OPTION;',
      );
      expect((await verifierAcl(db)).some((r) => r.role_name === 'service_role' && r.is_grantable)).toBe(true);

      await db.exec(PATCH);

      const acl = await verifierAcl(db);
      const svc = acl.filter((r) => r.role_name === 'service_role' && r.privilege_type === 'EXECUTE');
      expect(svc).toHaveLength(1);
      expect(svc[0].is_grantable, 'grant option must be stripped').toBe(false);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  const RESET_CASES: Array<[string, string]> = [
    [
      'test 11 — wrong owner restored',
      'CREATE ROLE wrong_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO wrong_owner;',
    ],
    [
      'test 12 — wrong security mode restored',
      'ALTER FUNCTION public.qhub_verify_commercial_schema() SECURITY INVOKER;',
    ],
    [
      'test 13 — wrong search_path restored',
      'ALTER FUNCTION public.qhub_verify_commercial_schema() SET search_path = public;',
    ],
    ['test 15a — PUBLIC grant removed', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO PUBLIC;'],
    ['test 15b — anon grant removed', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO anon;'],
    [
      'test 15c — authenticated grant removed',
      'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO authenticated;',
    ],
    [
      'test 16 — unexpected grantee removed',
      'CREATE ROLE sneaky NOLOGIN; GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO sneaky;',
    ],
  ];

  for (const [name, drift] of RESET_CASES) {
    it(`${name} by re-applying 08`, async () => {
      const db = await open(MIGRATION, PATCH);

      try {
        await db.exec(drift);
        expect(await postStatus(db), 'drift must first be detected').toBe('R15_2_VERIFIER_NOT_READY');

        await db.exec(PATCH);
        expect(await postStatus(db), 'the patch must restore the exact authority state').toBe('R15_2_VERIFIER_READY');
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('test 17 — service_role holds EXECUTE without grant option after a clean apply', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      const acl = await verifierAcl(db);
      const svc = acl.filter((r) => r.role_name === 'service_role' && r.privilege_type === 'EXECUTE');
      expect(svc).toHaveLength(1);
      expect(svc[0].is_grantable).toBe(false);
      expect(acl.some((r) => ['anon', 'authenticated'].includes(r.role_name))).toBe(false);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('test 18 — a second application is idempotent', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('tests 19/20 — verifier only, one transaction, no destructive SQL', async () => {
    const code = PATCH.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    expect(code).not.toMatch(/\bDROP\s+(TABLE|FUNCTION|POLICY|INDEX|TRIGGER|CONSTRAINT|SCHEMA|ROLE)\s+/i);
    expect(code).not.toMatch(/\bTRUNCATE\s+(TABLE\s+)?[a-z_."]+\s*;/i);
    expect(code).not.toMatch(/\bDELETE\s+FROM\s+[a-z_."]+/i);
    expect((PATCH.match(/^BEGIN;$/gm) ?? []).length).toBe(1);
    expect((PATCH.match(/^COMMIT;$/gm) ?? []).length).toBe(1);
    expect((PATCH.match(/CREATE OR REPLACE FUNCTION/g) ?? []).length).toBe(1);

    const db = await open();

    try {
      const bodies = async () =>
        (
          await db.query<{ proname: string; m: string }>(
            `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
              where ns.nspname='public' and p.proname in
                ('qhub_decide_review','qhub_create_review_request','qhub_record_acknowledgment',
                 'qhub_canon_cells','qhub_row_immutable') order by p.proname`,
          )
        ).rows;

      const before = await bodies();
      await db.exec(PATCH);
      expect(await bodies()).toEqual(before);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── 09 single-snapshot postcheck ───────────────────────────────────────────────

describe('R15.2B — 09 is one snapshot, one statement, and gates the verifier call', () => {
  it('test 21 — healthy state is READY', async () => {
    expect(await statusAfter('')).toBe('R15_2_VERIFIER_READY');
  }, 120_000);

  const POST_DRIFT: Array<[string, string]> = [
    [
      'test 22 — owner drift',
      'CREATE ROLE d_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO d_owner;',
    ],
    ['test 23 — search_path drift', 'ALTER FUNCTION public.qhub_verify_commercial_schema() SET search_path = public;'],
    ['test 23b — search_path removed', 'ALTER FUNCTION public.qhub_verify_commercial_schema() RESET search_path;'],
    ['test 24 — security-mode drift', 'ALTER FUNCTION public.qhub_verify_commercial_schema() SECURITY INVOKER;'],
    [
      'test 25 — service_role EXECUTE revoked',
      'REVOKE EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() FROM service_role;',
    ],
    [
      'test 26 — service_role grant option added',
      'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role WITH GRANT OPTION;',
    ],
    ['test 27 — PUBLIC grant', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO PUBLIC;'],
    ['test 28 — anon grant', 'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO anon;'],
    [
      'test 29 — authenticated grant',
      'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO authenticated;',
    ],
    [
      'test 30 — unexpected grantee',
      'CREATE ROLE extra NOLOGIN; GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO extra;',
    ],
    [
      'test 31 — unexpected grant option',
      'CREATE ROLE go_role NOLOGIN; GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO go_role WITH GRANT OPTION;',
    ],
    [
      'test 32 — verifier body drift',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
       LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
       BEGIN RETURN jsonb_build_object('expected_version','2026-07-30.commercial-launch-r8','ready',true,'failed','[]'::jsonb); END; $f$;`,
    ],
    [
      'test 33 — overload added',
      `CREATE FUNCTION public.qhub_verify_commercial_schema(p integer) RETURNS JSONB LANGUAGE sql AS $f$ SELECT '{}'::jsonb $f$;`,
    ],
    [
      'tests 35/37 — product verifier reports a failure',
      'ALTER TABLE public.qhub_acknowledgments NO FORCE ROW LEVEL SECURITY;',
    ],
  ];

  for (const [name, drift] of POST_DRIFT) {
    it(`${name} yields R15_2_VERIFIER_NOT_READY`, async () => {
      expect(await statusAfter(drift)).toBe('R15_2_VERIFIER_NOT_READY');
    }, 120_000);
  }

  it('test 34 — a missing verifier yields NOT READY with no 42883, running the file in full', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      await db.exec('DROP FUNCTION public.qhub_verify_commercial_schema();');

      await expect(db.exec(POST)).resolves.toBeDefined();

      const row = (await db.query<Record<string, unknown>>(POST_FINAL)).rows[0];
      expect(row.verifier_present).toBe(false);
      expect(row.authority_ok).toBe(false);
      expect(row.final_status).toBe('R15_2_VERIFIER_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  /*
   * test 38 — THE ATOMICITY PROOF. Install a verifier body that raises if executed, then break catalog
   * authority. 09 must return NOT READY without the sentinel ever running.
   */
  it('test 38 — an unreviewed verifier body is NEVER executed when authority fails', async () => {
    const db = await open(MIGRATION, PATCH);

    try {
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN
          RAISE EXCEPTION 'SHOULD_NOT_EXECUTE_UNREVIEWED_VERIFIER';
        END; $f$;
      `);

      // The body itself is already unapproved; also break owner so authority fails on two counts.
      await db.exec(
        'CREATE ROLE sentinel_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO sentinel_owner;',
      );

      // Running the whole file must NOT surface the sentinel exception.
      await expect(db.exec(POST)).resolves.toBeDefined();

      const row = (await db.query<Record<string, unknown>>(POST_FINAL)).rows[0];
      expect(row.authority_ok).toBe(false);
      expect(row.body_approved).toBe(false);
      expect(row.owner_exact).toBe(false);

      // Proof of non-execution: the guarded product columns are NULL, not an error and not a value.
      expect(row.product_ready).toBeNull();
      expect(row.product_version).toBeNull();
      expect(row.product_failed_count).toBeNull();
      expect(row.final_status).toBe('R15_2_VERIFIER_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('tests 39/40 — one authoritative statement, and every displayed check feeds final_status', async () => {
    // 09 has exactly one result-producing statement (plus BEGIN / SET TRANSACTION / COMMIT).
    const resultStatements = POST.split(/;\s*\n/)
      .map((c) =>
        c
          .split('\n')
          .filter((l) => !/^\s*--/.test(l))
          .join('\n')
          .trim(),
      )
      .filter(Boolean)
      .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION)/i.test(s));
    expect(resultStatements).toHaveLength(1);

    // The transaction is explicitly REPEATABLE READ + READ ONLY (one snapshot).
    expect(POST).toMatch(/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;/);

    const db = await open(MIGRATION, PATCH);

    try {
      const row = await runPostInFull(db);
      const booleans = Object.entries(row).filter(([, v]) => typeof v === 'boolean');

      // Every boolean condition displayed holds on a healthy database, and the verdict ANDs them.
      for (const [k, v] of booleans) {
        expect(v, `${k} should hold on a healthy patched database`).toBe(true);
      }

      for (const required of [
        'owner_exact',
        'search_path_exact',
        'security_definer',
        'service_role_execute',
        'service_role_no_grant_option',
        'public_denied',
        'anon_denied',
        'authenticated_denied',
        'no_unexpected_grantee',
        'no_unexpected_grant_option',
        'body_approved',
        'authority_ok',
      ]) {
        expect(Object.keys(row), `final_status must consume ${required}`).toContain(required);
      }

      expect(row.final_status).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── live sequence ──────────────────────────────────────────────────────────────

describe('R15.2B — full live sequence', () => {
  it('tests 41-52 — CRLF -> 07 -> 08 -> 09 -> grant-option drift -> 08 -> 09 -> owner drift -> 08 -> 09', async () => {
    const db = await open(MIGRATION.replace(/\n/g, '\r\n'));

    try {
      // 42-44
      expect(await runPreInFull(db)).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');
      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');

      // 45-46 idempotent re-apply
      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');

      // 47-49 grant-option injection is detected, then repaired by 08
      await db.exec(
        'GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role WITH GRANT OPTION;',
      );
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_NOT_READY');
      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');

      // 50-51 owner drift is detected without executing the verifier, then repaired by 08
      await db.exec(
        'CREATE ROLE seq_owner NOLOGIN; ALTER FUNCTION public.qhub_verify_commercial_schema() OWNER TO seq_owner;',
      );

      const drifted = await runPostInFull(db);
      expect(drifted.owner_exact).toBe(false);
      expect(drifted.product_ready, 'the verifier must not have been invoked').toBeNull();
      expect(drifted.final_status).toBe('R15_2_VERIFIER_NOT_READY');

      await db.exec(PATCH);
      expect(await postStatus(db)).toBe('R15_2_VERIFIER_READY');
    } finally {
      await db.close();
    }
  }, 300_000);
});
