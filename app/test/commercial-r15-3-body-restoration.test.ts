/**
 * QHUB R15.3 — ENCODING-SAFE PROTECTED-BODY RESTORATION (PGlite)
 * app/test/commercial-r15-3-body-restoration.test.ts
 *
 * Drives the COMMITTED package under docs/release/r15-3-body-restoration/ exactly as the operator runs
 * it: each file executed IN FULL, as one unit.
 *
 * The defect being repaired. The 2026-07-30 manual apply passed the migration through a Windows
 * PowerShell clipboard command lacking `-Encoding UTF8`; PowerShell 5.1 `Get-Content` decoded the
 * BOM-less UTF-8 file as Windows-1252 and re-encoded it mangled (§ -> Â§, — -> â€", → -> â†'). Only
 * qhub_decide_review and qhub_row_immutable contain non-ASCII, and only inside comments — so their
 * executable text stayed byte-identical while their RAW digests did not, which is why R15.2C's 07
 * correctly returned UNEXPECTED_FUNCTION_BODY_STOP.
 *
 * `mangle()` below reproduces that channel exactly: it regenerates the real live digests
 * 9bc91d1671c5f65241ea22538c00d703 and 583882c1a9b203e278b27d1080065c9e observed on the live database.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R3 = `${REPO}docs/release/r15-3-body-restoration/`;
const R2C = `${REPO}docs/release/r15-2-verifier-patch/`;

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
const PRE07 = readFileSync(`${R2C}07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql`, 'utf8');
const PATCH08 = readFileSync(`${R2C}08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql`, 'utf8');
const POST09 = readFileSync(`${R2C}09_POST_PATCH_VERIFY.sql`, 'utf8');

/** Digests observed on the live database on 2026-07-31, and the reviewed digests they must become. */
const LIVE_MOJIBAKE = {
  qhub_decide_review: '9bc91d1671c5f65241ea22538c00d703',
  qhub_row_immutable: '583882c1a9b203e278b27d1080065c9e',
} as const;
const REVIEWED_LF = {
  qhub_decide_review: '7e678f1e4bba0c540507cfe3743fbe54',
  qhub_row_immutable: '41ae59dde9a471b580d28e2cb45984f5',
} as const;
const REVIEWED_CRLF = {
  qhub_decide_review: 'dac8abcd56d7fc804baac660059c14bf',
  qhub_row_immutable: '4936e3f58627dde5abc10d2b0ecf5b4f',
} as const;

/** Windows-1252 high range; the rest of 0xA0..0xFF maps to the same code point. */
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

/** Reproduces the legacy PowerShell ANSI channel: UTF-8 bytes decoded as cp1252, re-encoded as UTF-8. */
function mangle(s: string): string {
  let out = '';

  for (const b of Buffer.from(s, 'utf8')) {
    out += String.fromCodePoint(CP1252[b] ?? b);
  }

  return out;
}

const toCrlf = (s: string) => s.replace(/\r?\n/g, '\r\n');

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

const V10 = finalStatement(PRE10);
const V12 = finalStatement(POST12);
const V07 = finalStatement(PRE07);
const V09 = finalStatement(POST09);

async function open(migration: string): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
    `);
  await db.exec(SUPABASE_DEFAULT_PRIVILEGES);
  await db.exec(migration);

  return db;
}

/** A database in the exact state of live: the reviewed migration applied through the mangling channel. */
const openLiveLike = () => open(mangle(toCrlf(PRE_R154_MIGRATION)));

async function bodyDigests(db: PGlite): Promise<Record<string, string>> {
  const rows = (
    await db.query<{ proname: string; m: string }>(
      `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable') order by 1`,
    )
  ).rows;

  return Object.fromEntries(rows.map((r) => [r.proname, r.m]));
}

const verdict10 = async (db: PGlite) => {
  await db.exec(PRE10);

  return (await db.query<{ verdict: string }>(V10)).rows[0].verdict;
};

const rows12 = async (db: PGlite) => {
  await db.exec(POST12);

  return (await db.query<Record<string, unknown>>(V12)).rows;
};

const status12 = async (db: PGlite) => (await rows12(db))[0].final_status as string;

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

// ─── the mangling channel is a faithful reproduction of live ────────────────────

describe('R15.3 — the legacy PowerShell ANSI channel is reproduced exactly', () => {
  it('r1 — mangling the reviewed migration regenerates the REAL live digests', async () => {
    const db = await openLiveLike();

    try {
      expect(await bodyDigests(db)).toEqual(LIVE_MOJIBAKE);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r2 — a UTF-8-safe transfer preserves §, — and → and yields an approved digest', async () => {
    for (const [enc, sql, want] of [
      ['LF', MIGRATION, REVIEWED_LF],
      ['CRLF', toCrlf(MIGRATION), REVIEWED_CRLF],
    ] as const) {
      const db = await open(sql);

      try {
        expect(await bodyDigests(db), `${enc} transfer must be approved`).toEqual(want);
      } finally {
        await db.close();
      }
    }
  }, 240_000);

  it('r3 — the mangled text really does differ only inside comments', () => {
    // Every mangled character comes from § — → …, which appear only in comment text.
    const changed = [...MIGRATION].filter((c) => c.codePointAt(0)! > 127);
    expect(changed.length).toBeGreaterThan(0);
    expect(mangle(MIGRATION)).not.toEqual(MIGRATION);

    // and the transform is deterministic
    expect(mangle(MIGRATION)).toEqual(mangle(MIGRATION));
  });
});

// ─── 10 pre-restore gate ────────────────────────────────────────────────────────

describe('R15.3 — 10 authorizes only the exact diagnosed state', () => {
  it('r4 — live-like mojibake state authorizes', async () => {
    const db = await openLiveLike();

    try {
      expect(await verdict10(db)).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r5 — an ALREADY-reviewed body STOPs (nothing to restore)', async () => {
    for (const sql of [MIGRATION, toCrlf(MIGRATION)]) {
      const db = await open(sql);

      try {
        expect(await verdict10(db)).toBe('UNEXPECTED_LIVE_BODY_STOP');
      } finally {
        await db.close();
      }
    }
  }, 240_000);

  const DRIFT: Array<[string, string]> = [
    [
      'r6 — a THIRD unknown body STOPs (unexplained drift is not repairable here)',
      `CREATE OR REPLACE FUNCTION public.qhub_row_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $f$
       BEGIN RAISE EXCEPTION 'nope'; END; $f$;`,
    ],
    [
      'r7 — owner drift STOPs',
      `CREATE ROLE r15_3_wrong NOLOGIN;
       ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) OWNER TO r15_3_wrong;`,
    ],
    [
      'r8 — security-mode drift STOPs',
      'ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) SECURITY INVOKER;',
    ],
    [
      'r9 — search_path drift STOPs',
      'ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) SET search_path = public;',
    ],
    [
      /*
       * A trigger function cannot take declared arguments, so the overload is added to the other
       * protected function — which is the realistic shape of this drift anyway.
       */
      'r10 — an unexpected overload STOPs',
      `CREATE FUNCTION public.qhub_decide_review(p_probe integer) RETURNS JSONB LANGUAGE sql AS $f$ SELECT '{}'::jsonb $f$;`,
    ],
    [
      'r11 — a missing function STOPs cleanly (no 42883)',
      'DROP FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT);',
    ],
  ];

  for (const [name, drift] of DRIFT) {
    it(
      name,
      async () => {
        const db = await openLiveLike();

        try {
          await db.exec(drift);
          await expect(db.exec(PRE10)).resolves.toBeDefined();
          expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');
        } finally {
          await db.close();
        }
      },
      120_000,
    );
  }

  it('r12 — 10 never invokes a function and uses no normalization', () => {
    const code = PRE10.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    expect(code).not.toMatch(/::regprocedure/);
    expect(code).not.toMatch(/SELECT\s+public\.qhub_\w+\s*\(/i);
    expect(code).not.toMatch(/\b(regexp_replace|translate|btrim)\s*\(/i);

    // md5() must always be applied to the RAW prosrc
    expect(code).not.toMatch(/md5\s*\(\s*replace/i);
  });
});

// ─── 11 restoration ─────────────────────────────────────────────────────────────

describe('R15.3 — 11 restores exactly the two reviewed bodies and nothing else', () => {
  it('r13 — restores both bodies to an approved digest', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      expect(await bodyDigests(db)).toEqual(REVIEWED_LF);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r14 — a second application is idempotent', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(RESTORE11);
      expect(await bodyDigests(db)).toEqual(REVIEWED_LF);
      expect(await status12(db)).toBe('R15_3_REVIEWED_BODIES_RESTORED');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r15 — a mangled transfer of 11 ITSELF raises and rolls the whole thing back', async () => {
    const db = await openLiveLike();

    try {
      const before = await bodyDigests(db);
      await expect(db.exec(mangle(RESTORE11))).rejects.toThrow(/R15\.3 POST/);
      await rollback(db);
      expect(await bodyDigests(db), 'no partial restoration may survive').toEqual(before);
      expect(before).toEqual(LIVE_MOJIBAKE);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r16 — 11 refuses to run against an unknown third body', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`CREATE OR REPLACE FUNCTION public.qhub_row_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $f$
                     BEGIN RAISE EXCEPTION 'unknown'; END; $f$;`);
      await expect(db.exec(RESTORE11)).rejects.toThrow(/unexpected_function_state.*UNKNOWN body/s);
      await rollback(db);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r17 — 11 alters no other object, mutates no data, and creates no overload', async () => {
    const db = await openLiveLike();

    try {
      const snapshot = async () =>
        (
          await db.query<{ proname: string; m: string }>(
            `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace n on n.oid = p.pronamespace
              where n.nspname='public' and p.proname like 'qhub@_%' escape '@'
                and p.proname not in ('qhub_decide_review','qhub_row_immutable') order by 1`,
          )
        ).rows;
      const others = await snapshot();
      const rels = async () =>
        (await db.query<{ n: number }>(`select count(*)::int n from pg_class where relname like 'qhub@_%' escape '@'`))
          .rows[0].n;
      const relsBefore = await rels();
      const policiesBefore = (
        await db.query<{ n: number }>(`select count(*)::int n from pg_policies where schemaname='public'`)
      ).rows[0].n;

      await db.exec(RESTORE11);

      expect(await snapshot(), 'no other function body may change').toEqual(others);
      expect(await rels()).toBe(relsBefore);
      expect(
        (await db.query<{ n: number }>(`select count(*)::int n from pg_policies where schemaname='public'`)).rows[0].n,
      ).toBe(policiesBefore);

      for (const fn of ['qhub_decide_review', 'qhub_row_immutable']) {
        const n = (
          await db.query<{ n: number }>(
            `select count(*)::int n from pg_proc p join pg_namespace ns on ns.oid=p.pronamespace
              where ns.nspname='public' and p.proname=$1`,
            [fn],
          )
        ).rows[0].n;
        expect(n, `${fn} must have exactly one definition`).toBe(1);
      }
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r18 — 11 normalizes qhub_row_immutable to the owner-only ACL and pins decide_review exactly', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);

      const acl = (
        await db.query<{ proname: string; acl: string | null }>(
          `select p.proname, p.proacl::text acl from pg_proc p join pg_namespace n on n.oid=p.pronamespace
            where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable') order by 1`,
        )
      ).rows;

      const immut = acl.find((r) => r.proname === 'qhub_row_immutable');
      expect(immut?.acl, 'R15.4: normalized from the 5-row Supabase default to owner-only').toContain('postgres=X');
      expect(immut?.acl).not.toContain('anon=');
      expect(immut?.acl).not.toContain('authenticated=');

      const decide = acl.find((r) => r.proname === 'qhub_decide_review');
      expect(decide?.acl).toContain('service_role=X');
      expect(decide?.acl).not.toContain('anon=');
      expect(decide?.acl).not.toContain('authenticated=');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r19 — statically: one transaction, two replacements, no destructive statement', () => {
    const code = RESTORE11.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    expect((RESTORE11.match(/^BEGIN;$/gm) ?? []).length).toBe(1);
    expect((RESTORE11.match(/^COMMIT;$/gm) ?? []).length).toBe(1);
    expect((code.match(/CREATE OR REPLACE FUNCTION/g) ?? []).length).toBe(2);
    expect(code).not.toMatch(/\bDROP\s+(TABLE|FUNCTION|POLICY|INDEX|TRIGGER|CONSTRAINT|SCHEMA|ROLE)\s+/i);
    expect(code).not.toMatch(/\bTRUNCATE\s+(TABLE\s+)?[a-z_."]+\s*;/i);
    expect(code).not.toMatch(/\bDELETE\s+FROM\s+public\./i);

    // never touches cluster role membership
    expect(code).not.toMatch(/\bGRANT\s+service_role\s+TO\b/i);
    expect(code).not.toMatch(/\bREVOKE\s+service_role\s+FROM\b/i);
  });
});

// ─── 12 post-restore verification ───────────────────────────────────────────────

describe('R15.3 — 12 requires the exact reviewed state', () => {
  it('r20 — restored state is RESTORED, with both rows ok', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);

      const rows = await rows12(db);
      expect(rows).toHaveLength(2);

      for (const r of rows) {
        expect(r.function_ok, `${r.proname} must pass`).toBe(true);
        expect(r.body_reviewed).toBe(true);
        expect(r.mojibake_cleared).toBe(true);
        expect(r.final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
      }
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r21 — 12 REJECTS the mojibake bodies that 10 accepts', async () => {
    const db = await openLiveLike();

    try {
      expect(await verdict10(db), '10 accepts the diagnosed state').toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');

      const rows = await rows12(db);
      expect(rows.every((r) => r.mojibake_cleared === false)).toBe(true);
      expect(rows[0].final_status, '12 must never accept a mojibake body').toBe('R15_3_BODY_RESTORE_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  const POST_DRIFT: Array<[string, string]> = [
    [
      'r22 — owner drift',
      `CREATE ROLE r15_3_d NOLOGIN;
       ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) OWNER TO r15_3_d;`,
    ],
    [
      'r23 — security-mode drift',
      'ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) SECURITY INVOKER;',
    ],
    [
      'r24 — search_path drift',
      'ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) SET search_path = public;',
    ],
    [
      'r25 — anon granted EXECUTE on decide_review',
      'GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) TO anon;',
    ],
    [
      'r26 — service_role WITH GRANT OPTION on decide_review',
      'GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) TO service_role WITH GRANT OPTION;',
    ],
    [
      'r27 — inherited effective EXECUTE on decide_review',
      'CREATE ROLE r15_3_inh NOLOGIN; GRANT service_role TO r15_3_inh;',
    ],
    [
      'r28 — a grant applied to qhub_row_immutable (its reviewed ACL is owner-only)',
      'GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;',
    ],
    [
      'r29 — an unexpected overload',
      `CREATE FUNCTION public.qhub_decide_review(p int) RETURNS JSONB LANGUAGE sql AS $f$ SELECT '{}'::jsonb $f$;`,
    ],
    ['r30 — a missing function', 'DROP FUNCTION public.qhub_row_immutable() CASCADE;'],
    [
      'r31 — one comment character changed',
      `CREATE OR REPLACE FUNCTION public.qhub_row_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $f$
       BEGIN -- x
         RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
       END; $f$;`,
    ],
  ];

  for (const [name, drift] of POST_DRIFT) {
    it(`${name} yields R15_3_BODY_RESTORE_NOT_READY`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(RESTORE11);
        await db.exec(drift);
        await expect(db.exec(POST12)).resolves.toBeDefined();

        const rows = (await db.query<Record<string, unknown>>(V12)).rows;
        expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('r32 — an embedded CR inside executable text is rejected', async () => {
    const db = await open(mangle(toCrlf(MIGRATION.replace("'staff_required'", "'staff\r_required'"))));

    try {
      await db.exec(RESTORE11).catch(() => undefined);
      await rollback(db);

      const rows = await rows12(db);
      expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r33 — no third digest is ever accepted by 12', () => {
    const code = POST12.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])--[^\n]*/g, '$1');
    const digests = [...new Set(code.match(/'[0-9a-f]{32}'/g) ?? [])];
    const approved = [
      ...Object.values(REVIEWED_LF),
      ...Object.values(REVIEWED_CRLF),
      ...Object.values(LIVE_MOJIBAKE),
    ].map((d) => `'${d}'`);
    expect(digests.sort()).toEqual([...approved].sort());
    expect(code).not.toMatch(/\b(regexp_replace|translate|btrim)\s*\(/i);
    expect(code).not.toMatch(/md5\s*\(\s*replace/i);
  });
});

// ─── behavioral regression ──────────────────────────────────────────────────────

describe('R15.3 — restored bodies behave exactly like the reviewed bodies', () => {
  it('r34 — decide_review and row_immutable behave identically before and after restoration', async () => {
    const reviewed = await open(MIGRATION);
    const restored = await openLiveLike();

    try {
      await restored.exec(RESTORE11);

      const probe = async (db: PGlite, sql: string) => {
        try {
          return JSON.stringify((await db.query(sql)).rows);
        } catch (e) {
          return `ERR:${String((e as Error).message).split('\n')[0]}`;
        }
      };

      const seed = `insert into public.qhub_acknowledgments
                      (org_id, project_id, user_id, ack_type, ack_version, required_version, status)
                    values ('o1','11111111-1111-1111-1111-111111111111','u1','terms','v1','v1','ACTIVE')
                    on conflict do nothing;`;
      await reviewed.exec(seed);
      await restored.exec(seed);

      const CASES: Array<[string, string]> = [
        [
          'non-staff actor',
          `select public.qhub_decide_review('00000000-0000-0000-0000-000000000001'::uuid,'a',false,'APPROVED','r','v') j`,
        ],
        [
          'unknown request',
          `select public.qhub_decide_review('00000000-0000-0000-0000-000000000001'::uuid,'a',true,'APPROVED','r','v') j`,
        ],
        [
          'invalid decision token',
          `select public.qhub_decide_review('00000000-0000-0000-0000-000000000001'::uuid,'a',true,'BOGUS','r','v') j`,
        ],
        [
          'prohibited use / stale declaration path',
          `select public.qhub_decide_review('00000000-0000-0000-0000-000000000002'::uuid,'a',true,'REJECTED','r','stale') j`,
        ],
        ['duplicate audit prevention (audit row count)', `select count(*)::int n from public.qhub_entitlement_audit`],
        [
          'zero mutation on failure (review row count)',
          `select count(*)::int n from public.qhub_manual_review_requests`,
        ],
        [
          'protected-field mutation',
          `update public.qhub_acknowledgments set user_id='u2' where user_id='u1' returning 1`,
        ],
        [
          'unauthorized field change',
          `update public.qhub_acknowledgments set org_id='o2' where user_id='u1' returning 1`,
        ],
        [
          'timestamp-only change',
          `update public.qhub_acknowledgments set acknowledged_at=now() where user_id='u1' returning 1`,
        ],
        ['direct DELETE', `delete from public.qhub_acknowledgments where user_id='u1' returning 1`],
        [
          'allowed ACTIVE->REVOKED',
          `update public.qhub_acknowledgments set status='REVOKED', revoked_at=now() where user_id='u1' returning status`,
        ],
        [
          'reverse REVOKED->ACTIVE',
          `update public.qhub_acknowledgments set status='ACTIVE', revoked_at=null where user_id='u1' returning status`,
        ],
      ];

      for (const [label, sql] of CASES) {
        expect(await probe(restored, sql), `${label} must behave identically`).toBe(await probe(reviewed, sql));
      }
    } finally {
      await reviewed.close();
      await restored.close();
    }
  }, 300_000);
});

// ─── live-sequence simulation, all the way to R15_2_VERIFIER_READY ──────────────

describe('R15.3 — full live sequence reaches R15_2_VERIFIER_READY', () => {
  it('r35 — mojibake -> 10 -> 11 -> 12 -> 07 -> 08 -> 09 READY, with idempotent re-runs', async () => {
    const db = await openLiveLike();

    try {
      expect(await bodyDigests(db)).toEqual(LIVE_MOJIBAKE);
      expect(await verdict10(db)).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');

      await db.exec(RESTORE11);
      expect(await status12(db)).toBe('R15_3_REVIEWED_BODIES_RESTORED');

      await db.exec(RESTORE11);
      expect(await status12(db), 'idempotent').toBe('R15_3_REVIEWED_BODIES_RESTORED');

      expect(await verdict10(db), 'already restored is a STOP for 10').toBe('UNEXPECTED_LIVE_BODY_STOP');

      await db.exec(PRE07);
      expect((await db.query<{ verdict: string }>(V07)).rows[0].verdict).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');

      await db.exec(PATCH08);
      await db.exec(POST09);

      const r = (await db.query<Record<string, unknown>>(V09)).rows[0];
      expect(r.final_status).toBe('R15_2_VERIFIER_READY');
      expect(r.product_ready).toBe('true');
      expect(r.product_failed_count).toBe('0');
      expect(r.product_version).toBe('2026-07-30.commercial-launch-r8');
    } finally {
      await db.close();
    }
  }, 300_000);

  it('r36 — without the restoration, R15.2C still correctly refuses', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(PRE07);
      expect((await db.query<{ verdict: string }>(V07)).rows[0].verdict).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);
});
