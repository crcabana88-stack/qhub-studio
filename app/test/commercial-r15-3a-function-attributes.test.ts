/**
 * QHUB R15.3A — FUNCTION-ATTRIBUTE AUTHORITY CLOSURE (PGlite)
 * app/test/commercial-r15-3a-function-attributes.test.ts
 *
 * Drives the COMMITTED package under docs/release/r15-3-body-restoration/ exactly as the operator runs
 * it, focused on the SEMANTIC ATTRIBUTE contract rather than the body encoding (that lives in
 * commercial-r15-3-body-restoration.test.ts).
 *
 * THE DEFECT THIS SUITE LOCKS DOWN (independently reproduced before it was fixed):
 *   CREATE OR REPLACE FUNCTION does NOT preserve omitted attribute clauses — it RESETS volatility,
 *   strictness, parallel safety, leakproof and cost to their defaults. Verified directly:
 *   IMMUTABLE/STRICT/PARALLEL SAFE/COST 42 became VOLATILE/CALLED ON NULL INPUT/PARALLEL UNSAFE/COST 100.
 *   The reviewed values for both targets ARE those defaults, so before R15.3A a live function altered to
 *   STRICT PARALLEL SAFE passed precheck 10, was silently normalised by 11, and 12 reported RESTORED —
 *   destroying the evidence that someone had altered a SECURITY DEFINER decision function.
 *
 * The fix is refusal, not repair: 10 STOPs, 11 raises before touching anything, and the drift survives
 * as escalation evidence.
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

const DR = 'public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT)';
const RI = 'public.qhub_row_immutable()';

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

/** The legacy PowerShell ANSI channel — regenerates the exact live mojibake state. */
function mangle(s: string): string {
  let out = '';

  for (const b of Buffer.from(s, 'utf8')) {
    out += String.fromCodePoint(CP1252[b] ?? b);
  }

  return out;
}

/** Result-producing statements of a package file, in order (BEGIN/SET/COMMIT removed). */
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

/** A database in the exact state of live: reviewed migration applied through the mangling channel. */
async function openLiveLike(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  `);
  await db.exec(mangle(MIGRATION.replace(/\r?\n/g, '\r\n')));

  return db;
}

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

async function preRun(db: PGlite) {
  await db.exec(PRE10);

  return {
    detail: (await db.query<Record<string, unknown>>(PRE_DETAIL)).rows,
    verdict: (await db.query<{ verdict: string }>(PRE_VERDICT)).rows[0].verdict,
  };
}

async function postRun(db: PGlite) {
  await db.exec(POST12);

  return (await db.query<Record<string, unknown>>(POST_FINAL)).rows;
}

const attrs = async (db: PGlite, sig: string) =>
  (
    await db.query<Record<string, unknown>>(
      `select p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.procost, p.prorows,
              p.proretset, p.prosecdef, p.proconfig::text cfg
         from pg_proc p where p.oid = to_regprocedure($1)`,
      [sig],
    )
  ).rows[0];

// ─── the reviewed attribute contract ────────────────────────────────────────────

describe('R15.3A — the reviewed attribute contract is exactly what the package pins', () => {
  it('a1 — CREATE OR REPLACE resets omitted attributes (the root cause)', async () => {
    const db = new PGlite();

    try {
      await db.exec(
        `CREATE FUNCTION public.probe() RETURNS int LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE COST 42 AS $$ SELECT 1 $$;`,
      );

      const before = (
        await db.query<Record<string, unknown>>(
          `select provolatile, proisstrict, proparallel, procost from pg_proc where proname='probe'`,
        )
      ).rows[0];
      expect(before).toEqual({ provolatile: 'i', proisstrict: true, proparallel: 's', procost: 42 });

      await db.exec(`CREATE OR REPLACE FUNCTION public.probe() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;`);

      const after = (
        await db.query<Record<string, unknown>>(
          `select provolatile, proisstrict, proparallel, procost from pg_proc where proname='probe'`,
        )
      ).rows[0];
      expect(after, 'omitted clauses are RESET, not preserved').toEqual({
        provolatile: 'v',
        proisstrict: false,
        proparallel: 'u',
        procost: 100,
      });
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a2 — both targets carry the exact reviewed attribute values', async () => {
    const db = await openLiveLike();

    try {
      const want = {
        provolatile: 'v',
        proisstrict: false,
        proparallel: 'u',
        proleakproof: false,
        procost: 100,
        prorows: 0,
        proretset: false,
      };

      expect(await attrs(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)')).toEqual({
        ...want,
        prosecdef: true,
        cfg: '{"search_path=pg_catalog, public"}',
      });
      expect(await attrs(db, 'public.qhub_row_immutable()')).toEqual({ ...want, prosecdef: false, cfg: null });
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a3 — after restoration the attributes are still exactly reviewed', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      expect(await attrs(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)')).toEqual({
        provolatile: 'v',
        proisstrict: false,
        proparallel: 'u',
        proleakproof: false,
        procost: 100,
        prorows: 0,
        proretset: false,
        prosecdef: true,
        cfg: '{"search_path=pg_catalog, public"}',
      });
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── precheck 10 binds every semantic attribute ────────────────────────────────

const ATTRIBUTE_DRIFT: Array<[string, string, string]> = [
  ['a4 — STRICT added (decide_review)', `ALTER FUNCTION ${DR} STRICT;`, 'strictness_ok'],
  ['a5 — STRICT added (row_immutable)', `ALTER FUNCTION ${RI} STRICT;`, 'strictness_ok'],
  ['a6 — PARALLEL SAFE (decide_review)', `ALTER FUNCTION ${DR} PARALLEL SAFE;`, 'parallel_ok'],
  ['a7 — PARALLEL RESTRICTED (decide_review)', `ALTER FUNCTION ${DR} PARALLEL RESTRICTED;`, 'parallel_ok'],
  ['a8 — PARALLEL SAFE (row_immutable)', `ALTER FUNCTION ${RI} PARALLEL SAFE;`, 'parallel_ok'],
  ['a9 — IMMUTABLE (decide_review)', `ALTER FUNCTION ${DR} IMMUTABLE;`, 'volatility_ok'],
  ['a10 — STABLE (decide_review)', `ALTER FUNCTION ${DR} STABLE;`, 'volatility_ok'],
  ['a11 — STABLE (row_immutable)', `ALTER FUNCTION ${RI} STABLE;`, 'volatility_ok'],
  ['a12 — LEAKPROOF added (decide_review)', `ALTER FUNCTION ${DR} LEAKPROOF;`, 'leakproof_ok'],
  ['a13 — LEAKPROOF added (row_immutable)', `ALTER FUNCTION ${RI} LEAKPROOF;`, 'leakproof_ok'],
  ['a14 — COST changed (decide_review)', `ALTER FUNCTION ${DR} COST 500;`, 'cost_ok'],
  ['a15 — COST changed (row_immutable)', `ALTER FUNCTION ${RI} COST 7;`, 'cost_ok'],
  ['a16 — SECURITY mode changed', `ALTER FUNCTION ${DR} SECURITY INVOKER;`, 'security_ok'],
  ['a17 — search_path changed', `ALTER FUNCTION ${DR} SET search_path = public;`, 'search_path_ok'],
  ['a18 — search_path removed', `ALTER FUNCTION ${DR} RESET search_path;`, 'search_path_ok'],
  ['a19 — owner changed', `CREATE ROLE r15_3a_wrong NOLOGIN; ALTER FUNCTION ${DR} OWNER TO r15_3a_wrong;`, 'owner_ok'],
  ['a20 — anon granted EXECUTE', `GRANT EXECUTE ON FUNCTION ${DR} TO anon;`, 'acl_ok'],
  [
    'a21 — service_role WITH GRANT OPTION',
    `GRANT EXECUTE ON FUNCTION ${DR} TO service_role WITH GRANT OPTION;`,
    'acl_ok',
  ],
  ['a22 — a grant applied to row_immutable', `REVOKE ALL ON FUNCTION ${RI} FROM PUBLIC;`, 'acl_ok'],
];

describe('R15.3A — 10 STOPs on every semantic attribute drift', () => {
  for (const [name, drift, flag] of ATTRIBUTE_DRIFT) {
    it(`${name} => UNEXPECTED_LIVE_BODY_STOP`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);

        const { detail, verdict } = await preRun(db);
        expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

        // the specific attribute flag must be the one that failed
        expect(
          detail.some((r) => r[flag] === false),
          `${flag} must be false somewhere`,
        ).toBe(true);
        expect(detail.some((r) => r.restorable === false)).toBe(true);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('a23 — an overload STOPs', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(
        `CREATE FUNCTION public.qhub_decide_review(p_probe integer) RETURNS JSONB LANGUAGE sql AS $f$ SELECT '{}'::jsonb $f$;`,
      );
      expect((await preRun(db)).verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a24 — a language / return-type / set-returning change STOPs and flags those bindings', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`DROP FUNCTION ${DR};
        CREATE FUNCTION public.qhub_decide_review(
          p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
        ) RETURNS SETOF text LANGUAGE sql AS $f$ SELECT 'x'::text $f$;`);

      const { detail, verdict } = await preRun(db);
      expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

      const row = detail.find((r) => r.proname === 'qhub_decide_review')!;
      expect(row.language_ok).toBe(false);
      expect(row.rettype_ok).toBe(false);
      expect(row.retset_ok).toBe(false);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a25 — restating a reviewed value is NOT drift (no false STOP)', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`ALTER FUNCTION ${DR} CALLED ON NULL INPUT;
                     ALTER FUNCTION ${DR} PARALLEL UNSAFE;
                     ALTER FUNCTION ${DR} VOLATILE;
                     ALTER FUNCTION ${DR} COST 100;`);
      expect((await preRun(db)).verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a26 — the healthy live-like state still authorizes, with every attribute flag true', async () => {
    const db = await openLiveLike();

    try {
      const { detail, verdict } = await preRun(db);
      expect(verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
      expect(detail).toHaveLength(2);

      for (const row of detail) {
        for (const [k, v] of Object.entries(row)) {
          if (
            typeof v === 'boolean' &&
            k !== 'already_reviewed' &&
            k !== 'live_strict' &&
            k !== 'live_leakproof' &&
            k !== 'live_retset'
          ) {
            expect(v, `${row.proname}.${k} should hold`).toBe(true);
          }
        }
        expect(row.no_support_function).toBe(true);
        expect(row.no_transforms).toBe(true);
      }
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── the Codex exploit, end to end ─────────────────────────────────────────────

describe('R15.3A — the reproduced exploit is refused, not silently repaired', () => {
  it('a27 — mojibake body + STRICT + PARALLEL SAFE: 10 STOPs, 11 refuses, drift survives as evidence', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`ALTER FUNCTION ${DR} STRICT; ALTER FUNCTION ${DR} PARALLEL SAFE;`);

      // 10 must STOP (before R15.3A this returned SAFE)
      expect((await preRun(db)).verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

      // 11 must refuse BEFORE changing anything
      await expect(db.exec(RESTORE11)).rejects.toThrow(/R15\.3 PRE:.*(strictness|parallel) drifted/s);
      await rollback(db);

      // the drift must SURVIVE — silently normalising it would destroy the evidence
      const after = await attrs(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)');
      expect(after.proisstrict, 'the tampering must remain visible').toBe(true);
      expect(after.proparallel).toBe('s');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a28 — 11 rolls BOTH functions back when the post-gate fails', async () => {
    const db = await openLiveLike();

    try {
      const snap = async () =>
        (
          await db.query<{ proname: string; m: string }>(
            `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace n on n.oid=p.pronamespace
              where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable') order by 1`,
          )
        ).rows;
      const before = await snap();

      // A mangled transfer of 11 itself: the post-gate must catch it and roll everything back.
      await expect(db.exec(mangle(RESTORE11))).rejects.toThrow(/R15\.3/);
      await rollback(db);

      expect(await snap(), 'both functions revert together').toEqual(before);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('a29 — 11 is idempotent under a healthy contract', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(RESTORE11);
      expect((await postRun(db))[0].final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── postcheck 12 certifies the complete contract ──────────────────────────────

describe('R15.3A — 12 refuses a correct body with drifted attributes', () => {
  const POST_DRIFT: Array<[string, string, string]> = [
    ['a30 — restored body + STRICT', `ALTER FUNCTION ${DR} STRICT;`, 'strictness_exact'],
    ['a31 — restored body + PARALLEL SAFE', `ALTER FUNCTION ${DR} PARALLEL SAFE;`, 'parallel_safety_exact'],
    ['a32 — restored body + PARALLEL RESTRICTED', `ALTER FUNCTION ${DR} PARALLEL RESTRICTED;`, 'parallel_safety_exact'],
    ['a33 — restored body + IMMUTABLE', `ALTER FUNCTION ${DR} IMMUTABLE;`, 'volatility_exact'],
    ['a34 — restored body + STABLE', `ALTER FUNCTION ${DR} STABLE;`, 'volatility_exact'],
    ['a35 — restored body + LEAKPROOF', `ALTER FUNCTION ${DR} LEAKPROOF;`, 'leakproof_exact'],
    ['a36 — restored body + COST 500', `ALTER FUNCTION ${DR} COST 500;`, 'cost_exact'],
    ['a37 — row_immutable + STRICT', `ALTER FUNCTION ${RI} STRICT;`, 'strictness_exact'],
    ['a38 — row_immutable + PARALLEL SAFE', `ALTER FUNCTION ${RI} PARALLEL SAFE;`, 'parallel_safety_exact'],
    ['a39 — row_immutable + STABLE', `ALTER FUNCTION ${RI} STABLE;`, 'volatility_exact'],
    ['a40 — row_immutable + LEAKPROOF', `ALTER FUNCTION ${RI} LEAKPROOF;`, 'leakproof_exact'],
    ['a41 — row_immutable + COST 7', `ALTER FUNCTION ${RI} COST 7;`, 'cost_exact'],
  ];

  for (const [name, drift, flag] of POST_DRIFT) {
    it(`${name} => R15_3_BODY_RESTORE_NOT_READY`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(RESTORE11);
        await db.exec(drift);

        const rows = await postRun(db);
        expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
        expect(
          rows.some((r) => r[flag] === false),
          `${flag} must fail`,
        ).toBe(true);

        // the body itself is still correct — proving the attribute check is what refused
        expect(rows.every((r) => r.body_reviewed === true)).toBe(true);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('a42 — healthy restoration certifies every attribute and returns RESTORED', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);

      const rows = await postRun(db);
      expect(rows).toHaveLength(2);

      for (const row of rows) {
        for (const [k, v] of Object.entries(row)) {
          if (typeof v === 'boolean' && !k.startsWith('live_') && !k.startsWith('restored_as_')) {
            expect(v, `${row.proname}.${k} should hold`).toBe(true);
          }
        }
        expect(row.final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
      }

      // every attribute certification the brief requires is present in the output
      for (const required of [
        'language_exact',
        'prokind_exact',
        'rettype_exact',
        'volatility_exact',
        'strictness_exact',
        'parallel_safety_exact',
        'leakproof_exact',
        'retset_exact',
        'cost_exact',
        'rows_exact',
        'variadic_exact',
        'no_support_function',
        'no_transforms',
        'owner_exact',
        'security_mode_exact',
        'search_path_exact',
        'acl_exact',
        'effective_acl_ok',
        'body_reviewed',
        'mojibake_cleared',
      ]) {
        expect(Object.keys(rows[0]), `final_status must consume ${required}`).toContain(required);
      }
    } finally {
      await db.close();
    }
  }, 120_000);
});
