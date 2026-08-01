/**
 * QHUB R15.6 — RUNTIME VERIFIER SEMANTIC + AUTHORITY EXACTNESS CLOSURE (PGlite)
 * app/test/commercial-r15-6-semantic-authority.test.ts
 *
 * THE FOUR P1s THIS SUITE LOCKS DOWN (each reproduced against the committed
 * R15.5 build before anything was changed):
 *   P1-1  ALTER FUNCTION qhub_row_immutable() IMMUTABLE STRICT PARALLEL SAFE
 *         LEAKPROOF COST 42 → the runtime verifier still returned ready=true.
 *   P1-2  a trigger broadened to BEFORE INSERT OR UPDATE OR DELETE (tgtype 31)
 *         still returned ready=true — bit containment, not equality.
 *   P1-3  PRE 13 still said SAFE after the verifier's own owner ACL row was
 *         revoked (live ACL {service_role=X/postgres}).
 *   P1-4  PATCH 14 silently repaired a SECURITY INVOKER start instead of
 *         stopping before replacement.
 *
 * R15.6 binds the COMPLETE derived pg_proc contract for the helper (labels
 * row_immutable_identity / _callable_interface / _semantic_attributes /
 * _execution_metadata / _body_digest), requires tgtype EXACTLY 27, gives 16/18
 * the exact normalized two-row verifier ACL (owner row mandatory, grantors
 * bound, no grant option anywhere) plus the exact semantic/callable contract,
 * and makes 17 fail with a deterministic exception BEFORE replacement on every
 * unexplained authority/interface/body state.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R6 = `${REPO}docs/release/r15-6-runtime-verifier/`;

const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');
const LIVE_VERIFIER_644 = readFileSync(`${REPO}app/test/fixtures/r8-644b5c6-live-verifier.sql`, 'utf8');
const PRE13 = readFileSync(`${R6}16_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql`, 'utf8');
const PATCH14 = readFileSync(`${R6}17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql`, 'utf8');
const POST15 = readFileSync(`${R6}18_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql`, 'utf8');

const RI = 'public.qhub_row_immutable()';
const VF = 'public.qhub_verify_commercial_schema()';
const LIVE_START = 'a35d8320d4a9804725a95f76534fe5a2';
const NEW_LF = '1c6f85b4cb410dc4ca307ed22ee1de47';
const NEW_CRLF = '42b43aaa01a770dc7d4a2a0d2f7f33b6';

/** The 80 labels of the committed R15.5 verifier (596b69f) — the preservation floor. */
const R15_5_LABELS_SHA_SOURCE = 'committed migration at 596b69f5969a93be81d9a3b9c2383ec533d4d730';
const NEW_LABELS = [...MIGRATION.matchAll(/v_failed \|\| \(?'([a-z0-9_:]+)'/g)].map((m) => m[1]);

const SUPABASE_DEFAULT_PRIVILEGES = `ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`;

const PRE_R154_MIGRATION = MIGRATION.replace(
  /REVOKE ALL PRIVILEGES ON FUNCTION public\.qhub_row_immutable\(\)[^\n]*\n/g,
  '',
).replace(/DO \$qhub_row_immutable_owner_grant\$[\s\S]*?\$qhub_row_immutable_owner_grant\$;\n/, '');

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

function lastStatement(sql: string): string {
  return sql
    .split(/;\s*\n/)
    .map((c) =>
      c
        .split('\n')
        .filter((l) => !/^\s*--/.test(l))
        .join('\n')
        .trim(),
    )
    .filter(Boolean)
    .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION)/i.test(s))
    .at(-1)!;
}

const V13 = lastStatement(PRE13);
const V15 = lastStatement(POST15);

async function open(sql: string, supa = true): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );

  if (supa) {
    await db.exec(SUPABASE_DEFAULT_PRIVILEGES);
  }

  await db.exec(sql);

  return db;
}

async function openLiveLike(): Promise<PGlite> {
  const db = await open(mangle(PRE_R154_MIGRATION.replace(/\r?\n/g, '\r\n')), true);
  await db.exec(mangle(LIVE_VERIFIER_644.replace(/\r?\n/g, '\r\n')));

  return db;
}

const verify = async (db: PGlite) =>
  (await db.query<{ j: { ready: boolean; failed: string[] } }>(`select public.qhub_verify_commercial_schema() j`))
    .rows[0].j;

const vstate = async (db: PGlite) =>
  (
    await db.query<{ prosecdef: boolean; m: string; a: string | null; c: string | null }>(
      `select prosecdef, md5(prosrc) m, proacl::text a, proconfig::text c
         from pg_proc where oid = to_regprocedure('${VF}')`,
    )
  ).rows[0];

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

// ─── §3 — the complete row-helper semantic/callable contract ───────────────────

describe('R15.6 — the runtime verifier binds the complete reviewed helper contract', () => {
  it('s0 — healthy install: ready=true, failed=[] in BOTH environments, and the reviewed values ARE the catalog values', async () => {
    for (const supa of [false, true]) {
      const db = await open(MIGRATION, supa);

      try {
        const v = await verify(db);
        expect(v).toMatchObject({ ready: true, failed: [] });

        const r = (
          await db.query<Record<string, unknown>>(
            `SELECT p.provolatile, p.proisstrict, p.proparallel, p.proleakproof,
                    p.procost, p.prorows, p.prosupport::oid s, p.probin IS NULL bn,
                    p.prosqlbody IS NULL sn, p.proacl::text acl,
                    (SELECT array_agg(tg.tgtype ORDER BY tg.tgname) FROM pg_trigger tg
                      WHERE tg.tgfoid = p.oid AND NOT tg.tgisinternal)::text trigs
               FROM pg_proc p WHERE p.oid = to_regprocedure('${RI}')`,
          )
        ).rows[0];
        expect(r).toMatchObject({
          provolatile: 'v',
          proisstrict: false,
          proparallel: 'u',
          proleakproof: false,
          procost: 100,
          prorows: 0,
          s: 0,
          bn: true,
          sn: true,
          acl: '{postgres=X/postgres}',
          trigs: '{27,27,27}',
        });
      } finally {
        await db.close();
      }
    }
  }, 240_000);

  // P1-1 exact reproduction vector, now closed, plus the full semantic matrix.
  const SEMANTIC_MATRIX: Array<[string, string, string]> = [
    [
      's1 — the exact P1-1 vector (IMMUTABLE STRICT PARALLEL SAFE LEAKPROOF COST 42)',
      `ALTER FUNCTION ${RI} IMMUTABLE STRICT PARALLEL SAFE LEAKPROOF COST 42;`,
      'row_immutable_semantic_attributes',
    ],
    ['s2 — VOLATILE → STABLE', `ALTER FUNCTION ${RI} STABLE;`, 'row_immutable_semantic_attributes'],
    ['s3 — VOLATILE → IMMUTABLE', `ALTER FUNCTION ${RI} IMMUTABLE;`, 'row_immutable_semantic_attributes'],
    ['s4 — CALLED ON NULL INPUT → STRICT', `ALTER FUNCTION ${RI} STRICT;`, 'row_immutable_semantic_attributes'],
    ['s5 — PARALLEL UNSAFE → SAFE', `ALTER FUNCTION ${RI} PARALLEL SAFE;`, 'row_immutable_semantic_attributes'],
    [
      's6 — PARALLEL UNSAFE → RESTRICTED',
      `ALTER FUNCTION ${RI} PARALLEL RESTRICTED;`,
      'row_immutable_semantic_attributes',
    ],
    ['s7 — LEAKPROOF', `ALTER FUNCTION ${RI} LEAKPROOF;`, 'row_immutable_semantic_attributes'],
    ['s8 — cost drift', `ALTER FUNCTION ${RI} COST 42;`, 'row_immutable_semantic_attributes'],
    ['s9 — SECURITY DEFINER', `ALTER FUNCTION ${RI} SECURITY DEFINER;`, 'row_immutable_identity'],
    ['s10 — proconfig drift', `ALTER FUNCTION ${RI} SET search_path = public;`, 'row_immutable_identity'],
    [
      's11 — owner drift',
      `CREATE ROLE r156_o NOLOGIN; ALTER FUNCTION ${RI} OWNER TO r156_o;`,
      'row_immutable_identity',
    ],
    [
      's12 — body drift (prosrc)',
      `CREATE OR REPLACE FUNCTION public.qhub_row_immutable() RETURNS trigger
       LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;`,
      'row_immutable_body_digest',
    ],
    [
      's13 — overload added (callable-interface exactness)',
      `CREATE FUNCTION public.qhub_row_immutable(x int) RETURNS int LANGUAGE sql AS $s$SELECT 1$s$;`,
      'row_immutable_callable_interface',
    ],
  ];

  for (const [name, drift, label] of SEMANTIC_MATRIX) {
    it(`${name} => ready=false with ${label}`, async () => {
      const db = await open(MIGRATION, true);

      try {
        await db.exec(drift);

        const v = await verify(db);
        expect(v.ready).toBe(false);
        expect(v.failed).toContain(label);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('s14 — language/probin drift (internal-language replacement) => callable_interface + body_digest', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`DROP FUNCTION ${RI} CASCADE;
        CREATE FUNCTION public.qhub_row_immutable() RETURNS trigger
          LANGUAGE internal AS $n$suppress_redundant_updates_trigger$n$;`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('row_immutable_callable_interface');
      expect(v.failed).toContain('row_immutable_body_digest');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('s15 — dropped entirely: EVERY row_immutable label fires (fail-closed), no SQL error', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`DROP FUNCTION ${RI} CASCADE;`);

      const v = await verify(db);
      expect(v.ready).toBe(false);

      for (const l of [
        'row_immutable_identity',
        'row_immutable_callable_interface',
        'row_immutable_semantic_attributes',
        'row_immutable_execution_metadata',
        'row_immutable_body_digest',
        'row_immutable_acl_cardinality',
        'row_immutable_acl_owner_entry',
        'row_immutable_trigger_missing:qhub_usage_ledger',
      ]) {
        expect(v.failed).toContain(l);
      }
    } finally {
      await db.close();
    }
  }, 120_000);

  it('s16 — recovery restores ready=true and repeated invocation is stable', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`ALTER FUNCTION ${RI} IMMUTABLE STRICT LEAKPROOF COST 42;`);
      expect((await verify(db)).ready).toBe(false);

      await db.exec(`ALTER FUNCTION ${RI} VOLATILE CALLED ON NULL INPUT NOT LEAKPROOF COST 100;`);

      const a = await verify(db);
      const b = await verify(db);
      expect(a).toMatchObject({ ready: true, failed: [] });
      expect(b).toEqual(a);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── §4 — exact trigger event/timing bits ──────────────────────────────────────

describe('R15.6 — trigger checks require tgtype EXACTLY 27, not bit containment', () => {
  const T = `DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;
    CREATE TRIGGER trg_qhub_usage_ledger_immutable `;
  const TB = 'row_immutable_trigger_binding:qhub_usage_ledger';

  const TRIGGER_MATRIX: Array<[string, string, string]> = [
    [
      't1 — the exact P1-2 vector: BEFORE INSERT OR UPDATE OR DELETE (tgtype 31)',
      `${T}BEFORE INSERT OR UPDATE OR DELETE ON public.qhub_usage_ledger
         FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't2 — UPDATE only',
      `${T}BEFORE UPDATE ON public.qhub_usage_ledger
       FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't3 — DELETE only',
      `${T}BEFORE DELETE ON public.qhub_usage_ledger
       FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't4 — AFTER instead of BEFORE',
      `${T}AFTER UPDATE OR DELETE ON public.qhub_usage_ledger
       FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't5 — statement-level instead of row-level',
      `${T}BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger
       FOR EACH STATEMENT EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't6 — extra TRUNCATE event',
      `${T}BEFORE UPDATE OR DELETE OR TRUNCATE ON public.qhub_usage_ledger
       FOR EACH STATEMENT EXECUTE FUNCTION public.qhub_row_immutable();`,
      TB,
    ],
    [
      't7 — rebound to a different function',
      `CREATE FUNCTION public.r156_noop() RETURNS trigger
       LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
       ${T}BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger
         FOR EACH ROW EXECUTE FUNCTION public.r156_noop();`,
      TB,
    ],
    [
      't8 — renamed away',
      `ALTER TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger
       RENAME TO some_other_trigger;`,
      'row_immutable_trigger_missing:qhub_usage_ledger',
    ],
    [
      't9 — disabled',
      `ALTER TABLE public.qhub_usage_ledger
       DISABLE TRIGGER trg_qhub_usage_ledger_immutable;`,
      'row_immutable_trigger_disabled:qhub_usage_ledger',
    ],
  ];

  for (const [name, drift, label] of TRIGGER_MATRIX) {
    it(`${name} => ready=false with ${label}`, async () => {
      const db = await open(MIGRATION, true);

      try {
        await db.exec(drift);

        const v = await verify(db);
        expect(v.ready).toBe(false);
        expect(v.failed).toContain(label);
      } finally {
        await db.close();
      }
    }, 120_000);
  }
});

// ─── §5 — PRE 16 exact verifier start-state authority ─────────────────────────

describe('R15.6 — PRE 16 authorizes only the complete exact verifier contract', () => {
  it('a0 — untouched live-like start AND patched final state are both SAFE', async () => {
    const db = await openLiveLike();

    try {
      expect((await vstate(db)).m).toBe(LIVE_START);
      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH');

      await db.exec(PATCH14);
      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH');
    } finally {
      await db.close();
    }
  }, 240_000);

  const PRE_STOPS: Array<[string, string]> = [
    ['a1 — the exact P1-3 vector: missing owner ACL row', `REVOKE EXECUTE ON FUNCTION ${VF} FROM postgres;`],
    ['a2 — missing service_role ACL row', `REVOKE EXECUTE ON FUNCTION ${VF} FROM service_role;`],
    ['a3 — owner grant option', `GRANT EXECUTE ON FUNCTION ${VF} TO postgres WITH GRANT OPTION;`],
    ['a4 — service_role grant option', `GRANT EXECUTE ON FUNCTION ${VF} TO service_role WITH GRANT OPTION;`],
    ['a5 — PUBLIC grant', `GRANT EXECUTE ON FUNCTION ${VF} TO PUBLIC;`],
    ['a6 — anon grant', `GRANT EXECUTE ON FUNCTION ${VF} TO anon;`],
    ['a7 — authenticated grant', `GRANT EXECUTE ON FUNCTION ${VF} TO authenticated;`],
    ['a8 — unexpected grantee', `CREATE ROLE r156_x NOLOGIN; GRANT EXECUTE ON FUNCTION ${VF} TO r156_x;`],
    ['a9 — SECURITY INVOKER', `ALTER FUNCTION ${VF} SECURITY INVOKER;`],
    ['a10 — wrong owner', `CREATE ROLE r156_w NOLOGIN; ALTER FUNCTION ${VF} OWNER TO r156_w;`],
    ['a11 — wrong search_path', `ALTER FUNCTION ${VF} SET search_path = public;`],
    ['a12 — semantic drift (COST 42)', `ALTER FUNCTION ${VF} COST 42;`],
    ['a13 — semantic drift (IMMUTABLE)', `ALTER FUNCTION ${VF} IMMUTABLE;`],
    [
      'a14 — unknown body',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
       LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
       AS $f$ BEGIN RETURN '{}'::jsonb; END $f$;`,
    ],
    [
      'a15 — overload',
      `CREATE FUNCTION public.qhub_verify_commercial_schema(x int) RETURNS int
       LANGUAGE sql AS $s$SELECT 1$s$;`,
    ],
  ];

  for (const [name, drift] of PRE_STOPS) {
    it(`${name} => UNEXPECTED_RUNTIME_VERIFIER_STOP`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);
        await db.exec(PRE13);
        expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('UNEXPECTED_RUNTIME_VERIFIER_STOP');
      } finally {
        await db.close();
      }
    }, 120_000);
  }
});

// ─── §6 — PATCH 17 fails BEFORE replacement, never repairs, evidence intact ───

describe('R15.6 — PATCH 17 refuses every unexplained start state before replacement', () => {
  const PATCH_STOPS: Array<[string, string, RegExp]> = [
    [
      'p1 — the exact P1-4 vector: SECURITY INVOKER start',
      `ALTER FUNCTION ${VF} SECURITY INVOKER;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'p2 — missing owner ACL row',
      `REVOKE EXECUTE ON FUNCTION ${VF} FROM postgres;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'p3 — wrong search_path',
      `ALTER FUNCTION ${VF} SET search_path = public;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'p4 — wrong owner',
      `CREATE ROLE r156_w2 NOLOGIN; ALTER FUNCTION ${VF} OWNER TO r156_w2;`,
      /unexpected_runtime_verifier_authority|unexpected_effective_verifier_executor/,
    ],
    [
      'p5 — grant option on service_role',
      `GRANT EXECUTE ON FUNCTION ${VF} TO service_role WITH GRANT OPTION;`,
      /unexpected_runtime_verifier_authority/,
    ],
    ['p6 — semantic drift', `ALTER FUNCTION ${VF} COST 42;`, /unexpected_runtime_verifier_interface/],
    [
      'p7 — unknown body',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
       LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
       AS $f$ BEGIN RETURN '{}'::jsonb; END $f$;`,
      /unexpected_runtime_verifier_state/,
    ],
    [
      'p8 — membership-derived effective executor (R15.2C gate preserved)',
      `CREATE ROLE r156_m NOLOGIN; GRANT service_role TO r156_m;`,
      /unexpected_effective_verifier_executor/,
    ],
  ];

  for (const [name, drift, rx] of PATCH_STOPS) {
    it(`${name} => deterministic STOP, no replacement, evidence intact`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);

        const before = await vstate(db);

        await expect(db.exec(PATCH14)).rejects.toThrow(rx);
        await rollback(db);

        /*
         * The unexplained start state survives untouched as evidence: same body,
         * same security mode, same ACL, same proconfig — nothing was normalized.
         */
        expect(await vstate(db)).toEqual(before);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('p9 — PATCH 17 is idempotent and POST remains closed until helper restoration', async () => {
    const db = await openLiveLike();

    try {
      /*
       * 11's body restoration is exercised by the R15.5 suite; here 14 runs from
       * the untouched live-like start (the verifier patch is independent of it).
       */
      await db.exec(PATCH14);
      expect((await vstate(db)).m).toBe(NEW_LF);

      await db.exec(POST15);

      const r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.final_status).toBe('R15_6_VERIFIER_NOT_READY');
      expect(r.body_approved).toBe(true);

      /*
       * NOT READY is correct here: the helper body is still mojibake (11 has not
       * run in this test), proving the new row_immutable_body_digest check reaches
       * the product verdict. The R15.5 suite proves the READY path after 11.
       */
      expect(r.product_ready).toBe('false');

      await db.exec(PATCH14);
      expect((await vstate(db)).m).toBe(NEW_LF);
    } finally {
      await db.close();
    }
  }, 240_000);
});

// ─── §7 — POST 18 complete final certification ────────────────────────────────

describe('R15.6 — POST 18 certifies the complete final verifier authority', () => {
  const POST_FAILS: Array<[string, string]> = [
    ['f1 — verifier missing owner ACL row', `REVOKE EXECUTE ON FUNCTION ${VF} FROM postgres;`],
    ['f2 — verifier SECURITY INVOKER', `ALTER FUNCTION ${VF} SECURITY INVOKER;`],
    ['f3 — verifier wrong search_path', `ALTER FUNCTION ${VF} SET search_path = public;`],
    ['f4 — verifier semantic drift', `ALTER FUNCTION ${VF} COST 42;`],
    ['f5 — verifier grant option', `GRANT EXECUTE ON FUNCTION ${VF} TO service_role WITH GRANT OPTION;`],
    ['f6 — unexpected effective executor', `CREATE ROLE r156_e NOLOGIN; GRANT service_role TO r156_e;`],
  ];

  for (const [name, drift] of POST_FAILS) {
    it(`${name} => R15_6_VERIFIER_NOT_READY`, async () => {
      const db = await open(MIGRATION, true);

      try {
        await db.exec(drift);
        await db.exec(POST15);
        expect((await db.query<Record<string, unknown>>(V15)).rows[0].final_status).toBe('R15_6_VERIFIER_NOT_READY');
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('f7 — helper semantic drift and extra INSERT event each fail POST 18 through the product verdict', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(POST15);
      expect((await db.query<Record<string, unknown>>(V15)).rows[0].final_status).toBe('R15_6_VERIFIER_READY');

      await db.exec(`ALTER FUNCTION ${RI} COST 42;`);
      await db.exec(POST15);

      let r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.final_status).toBe('R15_6_VERIFIER_NOT_READY');
      expect(r.product_ready).toBe('false');

      await db.exec(`ALTER FUNCTION ${RI} COST 100;`);
      await db.exec(`DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;
        CREATE TRIGGER trg_qhub_usage_ledger_immutable BEFORE INSERT OR UPDATE OR DELETE
          ON public.qhub_usage_ledger FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();`);
      await db.exec(POST15);
      r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.final_status).toBe('R15_6_VERIFIER_NOT_READY');
      expect(r.product_ready).toBe('false');
    } finally {
      await db.close();
    }
  }, 240_000);

  it('f8 — verification performs no mutation: ACL and body identical before/after', async () => {
    const db = await open(MIGRATION, true);

    try {
      const before = await vstate(db);
      await db.exec(POST15);
      await db.query(V15);
      expect(await vstate(db)).toEqual(before);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── §8 — wrong-grantor coverage ──────────────────────────────────────────────

describe('R15.6 — wrong-grantor ACL coverage', () => {
  it('g1 — LIVE MUTATION (verifier): a service_role row granted by a non-owner via SET ROLE STOPs PRE 16', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`CREATE ROLE r156_g NOLOGIN;
        GRANT EXECUTE ON FUNCTION ${VF} TO r156_g WITH GRANT OPTION;
        SET ROLE r156_g;
        GRANT EXECUTE ON FUNCTION ${VF} TO service_role;
        RESET ROLE;`);

      /*
       * PostgreSQL keeps (grantee, grantor) pairs distinct: service_role now has
       * BOTH an owner-granted and an r156_g-granted row.
       */
      expect((await vstate(db)).a).toContain('service_role=X/r156_g');

      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('UNEXPECTED_RUNTIME_VERIFIER_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('g2 — CATALOG FIXTURE (verifier): equal-cardinality ACL whose ONLY defect is a wrong grantor STOPs PRE 16', async () => {
    const db = await openLiveLike();

    try {
      /*
       * Direct catalog write builds the state SQL GRANT cannot reach: exactly two
       * rows, correct grantees, but the service_role row granted by a non-owner.
       * This isolates the grantor equality predicate from the cardinality check.
       */
      await db.exec(`CREATE ROLE r156_h NOLOGIN;
        UPDATE pg_proc
           SET proacl = ('{postgres=X/postgres,service_role=X/r156_h}')::aclitem[]
         WHERE oid = to_regprocedure('${VF}');`);
      expect((await vstate(db)).a).toBe('{postgres=X/postgres,service_role=X/r156_h}');

      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('UNEXPECTED_RUNTIME_VERIFIER_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('g3 — CATALOG FIXTURE (helper): a one-row owner ACL granted by a non-owner is NOT READY via the owner-entry predicate', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`CREATE ROLE r156_i NOLOGIN;
        UPDATE pg_proc SET proacl = ('{postgres=X/r156_i}')::aclitem[]
         WHERE oid = to_regprocedure('${RI}');`);

      const v = await verify(db);
      expect(v.ready).toBe(false);

      /*
       * Cardinality is 1 and the grantee IS the owner — the ONLY defect is the
       * grantor, so this proves row_immutable_acl_owner_entry binds ae.grantor.
       */
      expect(v.failed).toContain('row_immutable_acl_owner_entry');
      expect(v.failed).not.toContain('row_immutable_acl_cardinality');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('g4 — LIVE MUTATION (helper): a grant issued BY a non-owner role via SET ROLE is NOT READY', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`CREATE ROLE r156_j NOLOGIN; CREATE ROLE r156_k NOLOGIN;
        GRANT EXECUTE ON FUNCTION ${RI} TO r156_j WITH GRANT OPTION;
        SET ROLE r156_j;
        GRANT EXECUTE ON FUNCTION ${RI} TO r156_k;
        RESET ROLE;`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('row_immutable_acl_unexpected_grantee');
      expect(v.failed).toContain('row_immutable_acl_grant_option');
      expect(v.failed).toContain('row_immutable_acl_cardinality');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── §9 — every prior label preserved, none verdict-dead ──────────────────────

describe('R15.6 — label inventory preservation', () => {
  it('l1 — the 84-label inventory is a strict superset of the committed R15.5 inventory (80), zero removed or renamed', () => {
    /*
     * The R15.5 floor: every label the committed verifier could emit
     * (source of truth: ${R15_5_LABELS_SHA_SOURCE}).
     */
    const R15_5_FLOOR = [
      'row_immutable_identity',
      'row_immutable_acl_cardinality',
      'row_immutable_acl_owner_entry',
      'row_immutable_acl_unexpected_grantee',
      'row_immutable_acl_grant_option',
      'row_immutable_trigger_missing:',
      'row_immutable_trigger_binding:',
      'row_immutable_trigger_disabled:',
      'r7_ack_immutable_trigger',
      'r7_ack_immutable_body_drift',
      'decide_review_body_drift',
    ];
    const set = new Set(NEW_LABELS);
    expect(set.size).toBe(84);

    for (const l of R15_5_FLOOR) {
      expect(set.has(l), `label ${l} must survive`).toBe(true);
    }

    for (const l of [
      'row_immutable_callable_interface',
      'row_immutable_semantic_attributes',
      'row_immutable_execution_metadata',
      'row_immutable_body_digest',
    ]) {
      expect(set.has(l), `new label ${l}`).toBe(true);
    }
  });

  it('l2 — no label is verdict-dead: every label expression appends to v_failed, which alone decides ready', () => {
    // Every emit site is an append to v_failed…
    const emits = MIGRATION.match(/v_failed := v_failed \|\|/g) ?? [];
    expect(emits.length, `floor source: ${R15_5_LABELS_SHA_SOURCE}`).toBeGreaterThanOrEqual(84);

    // …and the verdict is derived from v_failed alone.
    expect(MIGRATION).toContain(`'ready', (cardinality(v_failed) = 0)`);
    expect(MIGRATION).toContain(`'failed', to_jsonb(v_failed)`);
  });

  it('l3 — 13, 14 and 15 all pin exactly the reviewed final LF and CRLF digests plus the documented live start', () => {
    for (const [name, sql] of [
      ['13', PRE13],
      ['14', PATCH14],
      ['15', POST15],
    ] as const) {
      expect(sql, `${name} must pin the reviewed LF digest`).toContain(NEW_LF);
      expect(sql, `${name} must pin the reviewed CRLF digest`).toContain(NEW_CRLF);
    }

    /*
     * The live-start digest belongs in the start-state gates (13 and 14), and the
     * known-mojibake digests are never blessed anywhere in the package.
     */
    expect(PRE13).toContain(LIVE_START);
    expect(PATCH14).toContain(LIVE_START);

    for (const mojibake of ['9bc91d1671c5f65241ea22538c00d703', '583882c1a9b203e278b27d1080065c9e']) {
      for (const sql of [PRE13, PATCH14, POST15]) {
        expect(sql).not.toContain(mojibake);
      }
    }
  });
});
