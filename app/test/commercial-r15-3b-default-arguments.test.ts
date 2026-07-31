/**
 * QHUB R15.3B — DEFAULT-ARGUMENT / CALLABLE-INTERFACE CONTRACT CLOSURE (PGlite)
 * app/test/commercial-r15-3b-default-arguments.test.ts
 *
 * Drives the COMMITTED package under docs/release/r15-3-body-restoration/ exactly as the operator runs
 * it, focused on the CALLABLE INTERFACE. Body encoding lives in
 * commercial-r15-3-body-restoration.test.ts; semantic attributes in
 * commercial-r15-3a-function-attributes.test.ts.
 *
 * THE DEFECT THIS SUITE LOCKS DOWN (independently reproduced before it was fixed):
 *   pg_get_function_identity_arguments() deliberately EXCLUDES argument defaults. Adding
 *   `p_policy_version TEXT DEFAULT NULL` therefore leaves BOTH the identity arguments AND the raw
 *   prosrc digest completely unchanged — while creating a NEW callable arity. Verified directly: with
 *   the reviewed body intact and one default added, postcheck 12 returned
 *   R15_3_REVIEWED_BODIES_RESTORED while
 *       SELECT public.qhub_decide_review(uuid, text, boolean, text, text)
 *   SUCCEEDED — a five-argument call into a SECURITY DEFINER decision RPC with p_policy_version
 *   silently NULL.
 *
 * A PostgreSQL property that shapes the fix: defaults CANNOT be removed through CREATE OR REPLACE
 * ("cannot remove parameter defaults from existing function"), so the patch could not repair this even
 * if it wanted to. It refuses instead, and the drift survives as escalation evidence.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R3 = `${REPO}docs/release/r15-3-body-restoration/`;

const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');
const PRE10 = readFileSync(`${R3}10_PRE_RESTORE_LIVE_BODY_VERIFY.sql`, 'utf8');
const RESTORE11 = readFileSync(`${R3}11_RESTORE_REVIEWED_PROTECTED_BODIES.sql`, 'utf8');
const POST12 = readFileSync(`${R3}12_POST_RESTORE_BODY_VERIFY.sql`, 'utf8');

const SIG = 'public.qhub_decide_review(uuid,text,boolean,text,text,text)';
const REVIEWED_LF = '7e678f1e4bba0c540507cfe3743fbe54';
const MOJIBAKE = '9bc91d1671c5f65241ea22538c00d703';
const REVIEWED_ARGS =
  'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text';
const BASE5 = 'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text';

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

function mangle(s: string): string {
  let out = '';

  for (const b of Buffer.from(s, 'utf8')) {
    out += String.fromCodePoint(CP1252[b] ?? b);
  }

  return out;
}

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
    .filter(Boolean)
    .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION)/i.test(s));
}

const PRE_DETAIL = statements(PRE10)[0];
const PRE_VERDICT = statements(PRE10).at(-1)!;
const POST_FINAL = statements(POST12).at(-1)!;

async function open(sql: string): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  `);
  await db.exec(sql);

  return db;
}

/** Live state: the reviewed migration applied through the mangling channel. */
const openLiveLike = () => open(mangle(MIGRATION.replace(/\r?\n/g, '\r\n')));

/** A database whose bodies are already the reviewed LF text. */
const openReviewed = () => open(MIGRATION);

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

/** Re-declare qhub_decide_review keeping its CURRENT body verbatim, with a custom argument list. */
async function redeclare(db: PGlite, argList: string): Promise<void> {
  const body = (await db.query<{ prosrc: string }>(`select prosrc from pg_proc where oid = to_regprocedure($1)`, [SIG]))
    .rows[0].prosrc;

  await db.query(`create or replace function public.qhub_decide_review(${argList})
    returns jsonb language plpgsql volatile called on null input parallel unsafe not leakproof cost 100
    security definer set search_path = pg_catalog, public as $q$${body}$q$;`);
}

const iface = async (db: PGlite) =>
  (
    await db.query<Record<string, unknown>>(
      `select md5(prosrc) m, pronargdefaults, (proargdefaults is null) defaults_null,
              pg_get_function_identity_arguments(oid) ident_args, pg_get_function_arguments(oid) full_args
         from pg_proc where oid = to_regprocedure($1)`,
      [SIG],
    )
  ).rows[0];

const preRun = async (db: PGlite) => {
  await db.exec(PRE10);

  return {
    detail: (await db.query<Record<string, unknown>>(PRE_DETAIL)).rows,
    verdict: (await db.query<{ verdict: string }>(PRE_VERDICT)).rows[0].verdict,
  };
};

const postRun = async (db: PGlite) => {
  await db.exec(POST12);

  return (await db.query<Record<string, unknown>>(POST_FINAL)).rows;
};

/** Every default variant the brief requires, all leaving prosrc byte-identical. */
const DEFAULT_VARIANTS: Array<[string, string]> = [
  ['one trailing DEFAULT NULL', `${BASE5}, p_policy_version text DEFAULT NULL`],
  [
    'two trailing DEFAULTs',
    `p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text DEFAULT 'r', p_policy_version text DEFAULT NULL`,
  ],
  ['empty-string DEFAULT', `${BASE5}, p_policy_version text DEFAULT ''`],
  ['literal DEFAULT', `${BASE5}, p_policy_version text DEFAULT 'v1'`],
  ['expression DEFAULT', `${BASE5}, p_policy_version text DEFAULT (current_setting('server_version'))`],
];

// ─── the reviewed callable-interface contract ──────────────────────────────────

describe('R15.3B — the reviewed callable interface has no argument defaults', () => {
  it('b1 — both targets: pronargdefaults = 0 and proargdefaults IS NULL', async () => {
    const db = await openLiveLike();

    try {
      const rows = (
        await db.query<Record<string, unknown>>(
          `select p.proname, p.pronargs, p.pronargdefaults, (p.proargdefaults is null) defaults_null,
                  pg_get_function_arguments(p.oid) full_args, (p.proargmodes is null) modes_null,
                  (p.proallargtypes is null) allargtypes_null, p.provariadic
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable') order by 1`,
        )
      ).rows;

      expect(rows).toEqual([
        {
          proname: 'qhub_decide_review',
          pronargs: 6,
          pronargdefaults: 0,
          defaults_null: true,
          full_args: REVIEWED_ARGS,
          modes_null: true,
          allargtypes_null: true,
          provariadic: 0,
        },
        {
          proname: 'qhub_row_immutable',
          pronargs: 0,
          pronargdefaults: 0,
          defaults_null: true,
          full_args: '',
          modes_null: true,
          allargtypes_null: true,
          provariadic: 0,
        },
      ]);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b2 — a default leaves identity arguments AND the body digest untouched (why identity is not enough)', async () => {
    const db = await openReviewed();

    try {
      const before = await iface(db);
      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);

      const after = await iface(db);

      expect(after.m, 'prosrc digest is unchanged').toBe(before.m);
      expect(after.m).toBe(REVIEWED_LF);
      expect(after.ident_args, 'identity arguments are unchanged').toBe(REVIEWED_ARGS);
      expect(after.pronargdefaults, 'but a default now exists').toBe(1);
      expect(after.full_args).toContain('DEFAULT');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b3 — the added default creates a genuinely callable shorter arity', async () => {
    const db = await openReviewed();

    try {
      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);

      const r = await db.query<{ j: Record<string, unknown> }>(
        `select public.qhub_decide_review('00000000-0000-0000-0000-000000000001'::uuid,'a',false,'APPROVED','r') j`,
      );
      expect(r.rows[0].j, 'a 5-argument call into the SECURITY DEFINER RPC succeeds').toEqual({
        ok: false,
        reason: 'staff_required',
      });
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b4 — PostgreSQL forbids removing defaults via CREATE OR REPLACE (so the patch cannot repair them)', async () => {
    const db = await openReviewed();

    try {
      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);
      await expect(redeclare(db, REVIEWED_ARGS)).rejects.toThrow(/cannot remove parameter defaults/i);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── precheck 10 ───────────────────────────────────────────────────────────────

describe('R15.3B — 10 STOPs on every default-argument drift', () => {
  for (const [label, args] of DEFAULT_VARIANTS) {
    it(`b5 — ${label} => UNEXPECTED_LIVE_BODY_STOP`, async () => {
      const db = await openLiveLike();

      try {
        await redeclare(db, args);

        // the live body is still byte-identical to the diagnosed mojibake
        expect((await iface(db)).m).toBe(MOJIBAKE);

        const { detail, verdict } = await preRun(db);
        expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

        const row = detail.find((r) => r.proname === 'qhub_decide_review')!;
        expect(row.no_arg_defaults).toBe(false);
        expect(row.no_default_expressions).toBe(false);
        expect(row.full_arguments_ok).toBe(false);
        expect(row.no_alternate_arity).toBe(false);
        expect(row.signature_ok, 'identity arguments alone would have passed').toBe(true);
        expect(row.restorable).toBe(false);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('b6 — a non-IN argument mode (INOUT) STOPs and flags argmodes', async () => {
    const db = await openLiveLike();

    try {
      /*
       * INOUT keeps the same INPUT types, so the function still resolves at the reviewed
       * signature — but proargmodes becomes non-NULL, which is a callable-interface change.
       */
      await db.exec(`DROP FUNCTION public.qhub_decide_review(uuid, text, boolean, text, text, text);
        CREATE FUNCTION public.qhub_decide_review(
          p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text,
          INOUT p_policy_version text) LANGUAGE sql AS $f$ SELECT p_policy_version $f$;`);

      const { detail, verdict } = await preRun(db);
      expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

      const row = detail.find((r) => r.proname === 'qhub_decide_review')!;
      expect(row.argmodes_plain_in).toBe(false);
      expect(row.restorable).toBe(false);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b7 — one healthy function and one drifted function still STOPs', async () => {
    const db = await openLiveLike();

    try {
      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);

      const { detail, verdict } = await preRun(db);
      expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');
      expect(detail.find((r) => r.proname === 'qhub_row_immutable')!.attributes_ok).toBe(true);
      expect(detail.find((r) => r.proname === 'qhub_decide_review')!.attributes_ok).toBe(false);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b8 — removing the default (DROP + recreate) restores SAFE', async () => {
    const db = await openLiveLike();

    try {
      const body = (
        await db.query<{ prosrc: string }>(`select prosrc from pg_proc where oid = to_regprocedure($1)`, [SIG])
      ).rows[0].prosrc;

      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);
      expect((await preRun(db)).verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

      // defaults cannot be dropped by CREATE OR REPLACE, so the only route back is DROP + recreate
      await db.exec(`DROP FUNCTION public.qhub_decide_review(uuid, text, boolean, text, text, text);`);
      await db.query(`create or replace function public.qhub_decide_review(${REVIEWED_ARGS})
        returns jsonb language plpgsql volatile called on null input parallel unsafe not leakproof cost 100
        security definer set search_path = pg_catalog, public as $q$${body}$q$;`);
      await db.exec(`ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT)
                       OWNER TO postgres;
                     REVOKE ALL ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT)
                       FROM PUBLIC, anon, authenticated;
                     GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT)
                       TO service_role;`);

      expect((await preRun(db)).verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── patch 11 ──────────────────────────────────────────────────────────────────

describe('R15.3B — 11 refuses deterministically and never repairs a default', () => {
  it('b9 — raises unexpected_function_default_argument_state before any change', async () => {
    const db = await openLiveLike();

    try {
      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);

      const before = await iface(db);

      await expect(db.exec(RESTORE11)).rejects.toThrow(/unexpected_function_default_argument_state/);
      await rollback(db);

      const after = await iface(db);
      expect(after, 'the drift must survive as escalation evidence').toEqual(before);
      expect(after.pronargdefaults).toBe(1);
      expect(after.m, 'no partial restoration').toBe(MOJIBAKE);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b10 — the other function is not partially restored either', async () => {
    const db = await openLiveLike();

    try {
      const immutBefore = (
        await db.query<{ m: string }>(`select md5(prosrc) m from pg_proc where oid = to_regprocedure($1)`, [
          'public.qhub_row_immutable()',
        ])
      ).rows[0].m;

      await redeclare(db, `${BASE5}, p_policy_version text DEFAULT NULL`);
      await expect(db.exec(RESTORE11)).rejects.toThrow(/unexpected_function_default_argument_state/);
      await rollback(db);

      const immutAfter = (
        await db.query<{ m: string }>(`select md5(prosrc) m from pg_proc where oid = to_regprocedure($1)`, [
          'public.qhub_row_immutable()',
        ])
      ).rows[0].m;
      expect(immutAfter, 'both functions roll back together').toBe(immutBefore);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('b11 — the healthy path is unaffected and stays idempotent', async () => {
    const db = await openLiveLike();

    try {
      expect((await preRun(db)).verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
      await db.exec(RESTORE11);
      await db.exec(RESTORE11);

      const rows = await postRun(db);
      expect(rows[0].final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
      expect((await iface(db)).pronargdefaults).toBe(0);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── postcheck 12 ──────────────────────────────────────────────────────────────

describe('R15.3B — 12 refuses a correct reviewed body that carries a default', () => {
  for (const [label, args] of DEFAULT_VARIANTS) {
    it(`b12 — reviewed body + ${label} => R15_3_BODY_RESTORE_NOT_READY`, async () => {
      const db = await openReviewed();

      try {
        await redeclare(db, args);
        expect((await iface(db)).m, 'the body is exactly the reviewed text').toBe(REVIEWED_LF);

        const rows = await postRun(db);
        const row = rows.find((r) => r.proname === 'qhub_decide_review')!;

        expect(row.body_reviewed, 'the body passes — only the interface fails').toBe(true);
        expect(row.mojibake_cleared).toBe(true);
        expect(row.signature_exact, 'identity arguments alone would have passed').toBe(true);
        expect(row.no_arg_defaults).toBe(false);
        expect(row.no_default_expressions).toBe(false);
        expect(row.full_arguments_exact).toBe(false);
        expect(row.no_alternate_arity).toBe(false);
        expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('b13 — healthy restoration certifies the whole callable interface', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);

      const rows = await postRun(db);

      for (const row of rows) {
        for (const required of [
          'full_arguments_exact',
          'nargs_exact',
          'no_arg_defaults',
          'no_default_expressions',
          'argnames_exact',
          'argmodes_plain_in',
          'no_out_or_table_args',
          'argtypes_exact',
          'no_alternate_arity',
        ]) {
          expect(Object.keys(row), `final_status must consume ${required}`).toContain(required);
          expect(row[required], `${row.proname}.${required} should hold`).toBe(true);
        }
      }

      expect(rows[0].final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
    } finally {
      await db.close();
    }
  }, 120_000);
});
