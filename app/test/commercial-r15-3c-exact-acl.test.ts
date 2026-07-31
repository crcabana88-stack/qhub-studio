/**
 * QHUB R15.3C — EXACT DIRECT-ACL CONTRACT CLOSURE (PGlite)
 * app/test/commercial-r15-3c-exact-acl.test.ts
 *
 * Drives the COMMITTED package under docs/release/r15-3-body-restoration/ exactly as the operator runs
 * it, focused on the DIRECT ACL. Body encoding lives in commercial-r15-3-body-restoration.test.ts,
 * semantic attributes in commercial-r15-3a-function-attributes.test.ts, and the callable interface in
 * commercial-r15-3b-default-arguments.test.ts.
 *
 * THE DEFECT THIS SUITE LOCKS DOWN (independently reproduced before it was fixed):
 *   The reviewed ACL for qhub_decide_review is EXACTLY {postgres=X/postgres,service_role=X/postgres}.
 *   The package required service_role EXECUTE and rejected unexpected grantees, but never required the
 *   OWNER's own EXECUTE entry. Revoking it leaves {service_role=X/postgres}, and the package returned
 *   PRE SAFE and POST RESTORED.
 *
 * Severity, stated precisely: the owner retains EXECUTE through inherent ownership rights even without
 * the ACL row, so this is contract-integrity drift rather than an immediate privilege escalation. It is
 * still drift — someone revoked from the owner — and it must neither be accepted nor silently repaired.
 *
 * RESPONSIBILITY SPLIT (§7 audit). R15.3 owns the DIRECT ACL of the two restored functions, exactly.
 * R15.2C owns the verifier's own direct ACL reset and its EFFECTIVE (inherited) privilege contract.
 * Owner inherent execution, an explicit owner ACL row, a service_role grant, inherited privilege via
 * role membership, and superuser inherent privilege are five distinct things and are not conflated.
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

/**
 * Supabase ships these default privileges on schema public; plain PostgreSQL/PGlite does
 * not. Modeling the live database therefore requires them — without them the trigger
 * helper ends up with proacl IS NULL instead of the five rows live actually has.
 */
const SUPABASE_DEFAULT_PRIVILEGES = `ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`;

/**
 * The migration as it stood BEFORE R15.4 added the explicit trigger ACL. The live
 * database was created from that version, so a live-like fixture must apply it.
 */
const PRE_R154_MIGRATION = MIGRATION.replace(
  /REVOKE ALL PRIVILEGES ON FUNCTION public\.qhub_row_immutable\(\)[^\n]*\n/g,
  '',
).replace(/DO \$qhub_row_immutable_owner_grant\$[\s\S]*?\$qhub_row_immutable_owner_grant\$;\n/, '');

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
  await db.exec(SUPABASE_DEFAULT_PRIVILEGES);
  await db.exec(sql);

  return db;
}

const openLiveLike = () => open(mangle(PRE_R154_MIGRATION.replace(/\r?\n/g, '\r\n')));
const openReviewed = () => open(MIGRATION);

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

/** Normalized ACL rows, the way the package compares them. */
const aclRows = async (db: PGlite, sig: string) =>
  (
    await db.query<{ grantee: string; privilege_type: string; grantor: string; is_grantable: boolean }>(
      `select pg_get_userbyid(ae.grantee) grantee, ae.privilege_type, pg_get_userbyid(ae.grantor) grantor,
              ae.is_grantable
         from pg_proc p, aclexplode(p.proacl) ae
        where p.oid = to_regprocedure($1)
        order by 1, 2`,
      [sig],
    )
  ).rows;

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

// ─── the reviewed ACL contract ─────────────────────────────────────────────────

describe('R15.3C — the reviewed direct-ACL contract, derived not assumed', () => {
  it('c1 — qhub_decide_review has EXACTLY the owner and service_role EXECUTE entries', async () => {
    const db = await openLiveLike();

    try {
      expect(await aclRows(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)')).toEqual([
        { grantee: 'postgres', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'service_role', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
      ]);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('c2 — qhub_row_immutable carries the five-row Supabase-default ACL on a live-like database', async () => {
    const db = await openLiveLike();

    try {
      const acl = (
        await db.query<{ acl: string | null }>(`select proacl::text acl from pg_proc where oid = to_regprocedure($1)`, [
          'public.qhub_row_immutable()',
        ])
      ).rows[0];

      /*
       * R15.4: Supabase's ALTER DEFAULT PRIVILEGES produce these five rows from the
       * pre-R15.4 migration. This is the documented starting state 10 authorizes.
       */
      expect(acl.acl).not.toBeNull();
      expect(await aclRows(db, 'public.qhub_row_immutable()')).toEqual([
        { grantee: 'anon', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'authenticated', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'postgres', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'service_role', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'unknown (OID=0)', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
      ]);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('c3 — removing the owner entry leaves a set every weaker check accepts', async () => {
    const db = await openReviewed();

    try {
      await db.exec(`REVOKE EXECUTE ON FUNCTION ${DR} FROM postgres;`);

      const rows = await aclRows(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)');
      expect(rows).toEqual([
        { grantee: 'service_role', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
      ]);

      /*
       * service_role is still present and there is still no unexpected grantee — which is
       * precisely why "service_role present + no unexpected grantee" was not sufficient.
       */
      expect(rows.some((r) => r.grantee === 'service_role')).toBe(true);
      expect(rows.some((r) => !['postgres', 'service_role'].includes(r.grantee))).toBe(false);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('c4 — the owner keeps EXECUTE by inherent ownership even without the ACL row', async () => {
    const db = await openReviewed();

    try {
      await db.exec(`REVOKE EXECUTE ON FUNCTION ${DR} FROM postgres;`);

      const e = (
        await db.query<{ e: boolean }>(`select has_function_privilege('postgres', to_regprocedure($1), 'EXECUTE') e`, [
          'public.qhub_decide_review(uuid,text,boolean,text,text,text)',
        ])
      ).rows[0].e;

      /*
       * Contract-integrity drift, not immediate escalation — stated precisely so the
       * severity is not overclaimed.
       */
      expect(e).toBe(true);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── the adversarial matrix ────────────────────────────────────────────────────

const ACL_DRIFT: Array<[string, string, string]> = [
  ['c5 — owner EXECUTE removed', `REVOKE EXECUTE ON FUNCTION ${DR} FROM postgres;`, 'acl_expected_rows_present'],
  [
    'c6 — service_role EXECUTE removed',
    `REVOKE EXECUTE ON FUNCTION ${DR} FROM service_role;`,
    'acl_expected_rows_present',
  ],
  [
    'c7 — service_role WITH GRANT OPTION',
    `GRANT EXECUTE ON FUNCTION ${DR} TO service_role WITH GRANT OPTION;`,
    'acl_expected_rows_present',
  ],
  [
    'c8 — owner grant-option added',
    `GRANT EXECUTE ON FUNCTION ${DR} TO postgres WITH GRANT OPTION;`,
    'acl_expected_rows_present',
  ],
  ['c9 — PUBLIC EXECUTE', `GRANT EXECUTE ON FUNCTION ${DR} TO PUBLIC;`, 'acl_no_unexpected_entry'],
  ['c10 — anon EXECUTE', `GRANT EXECUTE ON FUNCTION ${DR} TO anon;`, 'acl_no_unexpected_entry'],
  ['c11 — authenticated EXECUTE', `GRANT EXECUTE ON FUNCTION ${DR} TO authenticated;`, 'acl_no_unexpected_entry'],
  [
    'c12 — unexpected direct grantee',
    `CREATE ROLE r15_3c_extra NOLOGIN; GRANT EXECUTE ON FUNCTION ${DR} TO r15_3c_extra;`,
    'acl_no_unexpected_entry',
  ],
  [
    /*
     * service_role already holds EXECUTE in the documented five-row start state, so
     * re-granting it is a no-op. A genuinely unexpected sixth grantee is the drift.
     */
    'c13 — row_immutable given an unexpected sixth grantee',
    `CREATE ROLE r154_extra NOLOGIN; GRANT EXECUTE ON FUNCTION ${RI} TO r154_extra;`,
    'acl_cardinality_exact',
  ],
  [
    /*
     * Real drift in BOTH states — the five-row start set and the owner-only final set
     * each contain the owner row. (Revoking PUBLIC is a no-op after normalization.)
     */
    'c14 — row_immutable owner EXECUTE removed',
    `REVOKE EXECUTE ON FUNCTION ${RI} FROM postgres;`,
    'acl_cardinality_exact',
  ],
];

describe('R15.3C — 10 STOPs on every direct-ACL drift', () => {
  for (const [name, drift, flag] of ACL_DRIFT) {
    it(`${name} => UNEXPECTED_LIVE_BODY_STOP`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);

        const { detail, verdict } = await preRun(db);
        expect(verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');
        expect(
          detail.some((r) => r[flag] === false),
          `${flag} must fail`,
        ).toBe(true);
        expect(detail.some((r) => r.restorable === false)).toBe(true);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('c15 — the healthy reviewed ACL still authorizes', async () => {
    const db = await openLiveLike();

    try {
      const { detail, verdict } = await preRun(db);
      expect(verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');

      for (const row of detail) {
        expect(row.acl_cardinality_exact).toBe(true);
        expect(row.acl_expected_rows_present).toBe(true);
        expect(row.acl_expected_rows_present).toBe(true);
        expect(row.acl_no_unexpected_entry).toBe(true);
      }
    } finally {
      await db.close();
    }
  }, 120_000);

  it('c16 — set equality is order-independent (re-granting the same rights is not drift)', async () => {
    const db = await openLiveLike();

    try {
      // Re-issuing the identical grants rewrites the ACL array without changing the set.
      await db.exec(`GRANT EXECUTE ON FUNCTION ${DR} TO service_role;
                     GRANT EXECUTE ON FUNCTION ${DR} TO postgres;`);
      expect((await preRun(db)).verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── patch 11 ──────────────────────────────────────────────────────────────────

describe('R15.3C — 11 refuses on ACL drift and never repairs it', () => {
  for (const [name, drift] of ACL_DRIFT) {
    it(`${name} => 11 raises unexpected_function_acl_state and changes nothing`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);

        const snapshot = async () =>
          JSON.stringify(
            (
              await db.query<Record<string, unknown>>(
                `select p.proname, md5(p.prosrc) m, coalesce(p.proacl::text,'(NULL)') acl
                   from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                  where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable')
                  order by 1`,
              )
            ).rows,
          );
        const before = await snapshot();

        await expect(db.exec(RESTORE11)).rejects.toThrow(/unexpected_function_(acl_state|state)/);
        await rollback(db);

        expect(await snapshot(), 'drift intact, neither function partially restored').toBe(before);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('c17 — 11 contains no ACL repair path for drift (only the reviewed restatement)', () => {
    const code = RESTORE11.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    const grants = code.split('\n').filter((l) => /^\s*(GRANT|REVOKE)\b/i.test(l));

    /*
     * R15.4: exactly six statements — the two reviewed qhub_decide_review statements,
     * plus the four REVOKEs that normalize the trigger helper from the documented
     * five-row Supabase-default ACL to the reviewed owner-only contract. The owner
     * GRANT is issued through a catalog-derived DO block, never a literal role name.
     * Anything beyond this exact set would be an unreviewed ACL repair path.
     */
    expect(grants).toHaveLength(6);
    expect(grants.filter((g) => /qhub_decide_review/.test(g))).toHaveLength(2);

    const triggerAcl = grants.filter((g) => /qhub_row_immutable/.test(g));
    expect(triggerAcl).toHaveLength(4);

    for (const g of triggerAcl) {
      expect(g, 'the trigger ACL is only ever revoked in plain statements').toMatch(/^\s*REVOKE\b/);
    }

    for (const role of ['PUBLIC', 'anon', 'authenticated', 'service_role']) {
      expect(triggerAcl.some((g) => g.includes(role))).toBe(true);
    }
    expect(code).not.toMatch(/\bDROP\s+FUNCTION\b/i);
  });

  it('c18 — healthy path remains idempotent under the exact reviewed ACL', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(RESTORE11);

      expect((await postRun(db))[0].final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
      expect(await aclRows(db, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)')).toEqual([
        { grantee: 'postgres', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
        { grantee: 'service_role', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false },
      ]);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── postcheck 12 ──────────────────────────────────────────────────────────────

describe('R15.3C — 12 refuses a correct reviewed body with drifted ACL', () => {
  for (const [name, drift, flag] of ACL_DRIFT) {
    it(`${name} => R15_3_BODY_RESTORE_NOT_READY`, async () => {
      const db = await openReviewed();

      try {
        await db.exec(drift);

        const rows = await postRun(db);
        expect(
          rows.every((r) => r.body_reviewed === true),
          'the body passes — only the ACL fails',
        ).toBe(true);
        expect(
          rows.some((r) => r[flag] === false),
          `${flag} must fail`,
        ).toBe(true);
        expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('c19 — exact reviewed ACL certifies RESTORED, and every ACL flag feeds the verdict', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);

      const rows = await postRun(db);

      for (const row of rows) {
        for (const required of [
          'acl_cardinality_exact',
          'acl_expected_rows_present',
          'acl_expected_rows_present',
          'acl_no_unexpected_entry',
          'effective_acl_ok',
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
