/**
 * QHUB R15.5 — RUNTIME VERIFIER TRIGGER-ACL CLOSURE (PGlite)
 * app/test/commercial-r15-5-runtime-verifier.test.ts
 *
 * THE P1 THIS SUITE LOCKS DOWN (reproduced before anything was changed):
 *   On a clean R15.4 install the runtime verifier returned ready=true. After
 *   GRANT EXECUTE ON public.qhub_row_immutable() TO anon it STILL returned ready=true,
 *   failed=[] — the verifier had no checks for the trigger helper's ACL or its trigger
 *   attachments, so drift against the reviewed owner-only contract was a false READY.
 *
 * The R15.5 verifier adds stable labels for the helper's identity, its exact one-row
 * owner-only ACL, and the three immutability triggers (attached + enabled + bound to
 * exactly this function). This suite drives the false-READY matrix, the trigger-drift
 * matrix, recovery, and the full final live sequence 10→11→12→13→14→15.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R3 = `${REPO}docs/release/r15-3-body-restoration/`;
const R5 = `${REPO}docs/release/r15-5-runtime-verifier/`;

const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');

/** The exact verifier the live database runs: commit 644b5c6's, extracted verbatim. */
const LIVE_VERIFIER_644 = readFileSync(`${REPO}app/test/fixtures/r8-644b5c6-live-verifier.sql`, 'utf8');
const PRE10 = readFileSync(`${R3}10_PRE_RESTORE_LIVE_BODY_VERIFY.sql`, 'utf8');
const RESTORE11 = readFileSync(`${R3}11_RESTORE_REVIEWED_PROTECTED_BODIES.sql`, 'utf8');
const POST12 = readFileSync(`${R3}12_POST_RESTORE_BODY_VERIFY.sql`, 'utf8');
const PRE13 = readFileSync(`${R5}13_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql`, 'utf8');
const PATCH14 = readFileSync(`${R5}14_LIVE_RUNTIME_VERIFIER_TRIGGER_ACL_PATCH.sql`, 'utf8');
const POST15 = readFileSync(`${R5}15_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql`, 'utf8');

const RI = 'public.qhub_row_immutable()';
const LIVE_START = 'a35d8320d4a9804725a95f76534fe5a2';
const NEW_LF = '83c8cd60a96e44e6cb8d66db93daf403';

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

const V10 = lastStatement(PRE10);
const V12 = lastStatement(POST12);
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

/**
 * The live database, faithfully: Supabase defaults + the pre-R15.4 migration through the
 * mojibake channel, then the verifier replaced with commit 644b5c6's (also mangled) —
 * because the live verifier predates every R15.x verifier change.
 */
async function openLiveLike(): Promise<PGlite> {
  const db = await open(mangle(PRE_R154_MIGRATION.replace(/\r?\n/g, '\r\n')), true);
  await db.exec(mangle(LIVE_VERIFIER_644.replace(/\r?\n/g, '\r\n')));

  return db;
}

const verify = async (db: PGlite) =>
  (
    await db.query<{ j: { ready: boolean; failed: string[]; expected_version: string } }>(
      `select public.qhub_verify_commercial_schema() j`,
    )
  ).rows[0].j;

const verifierMd5 = async (db: PGlite) =>
  (
    await db.query<{ m: string }>(
      `select md5(prosrc) m from pg_proc where oid = to_regprocedure('public.qhub_verify_commercial_schema()')`,
    )
  ).rows[0].m;

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

// ─── the false-READY matrix ────────────────────────────────────────────────────

describe('R15.5 — the runtime verifier now catches trigger-helper ACL drift', () => {
  it('v1 — healthy R15.5 install: ready=true, failed=[] (both environments)', async () => {
    for (const supa of [false, true]) {
      const db = await open(MIGRATION, supa);

      try {
        const v = await verify(db);
        expect(v.ready).toBe(true);
        expect(v.failed).toEqual([]);
      } finally {
        await db.close();
      }
    }
  }, 240_000);

  const ACL_MATRIX: Array<[string, string, string[]]> = [
    [
      'v2 — anon EXECUTE (the exact Codex P1)',
      `GRANT EXECUTE ON FUNCTION ${RI} TO anon;`,
      ['row_immutable_acl_cardinality', 'row_immutable_acl_unexpected_grantee'],
    ],
    [
      'v3 — authenticated EXECUTE',
      `GRANT EXECUTE ON FUNCTION ${RI} TO authenticated;`,
      ['row_immutable_acl_unexpected_grantee'],
    ],
    [
      'v4 — service_role EXECUTE',
      `GRANT EXECUTE ON FUNCTION ${RI} TO service_role;`,
      ['row_immutable_acl_unexpected_grantee'],
    ],
    ['v5 — PUBLIC EXECUTE', `GRANT EXECUTE ON FUNCTION ${RI} TO PUBLIC;`, ['row_immutable_acl_unexpected_grantee']],
    [
      'v6 — owner row removed',
      `REVOKE EXECUTE ON FUNCTION ${RI} FROM postgres;`,
      ['row_immutable_acl_cardinality', 'row_immutable_acl_owner_entry'],
    ],
    [
      'v7 — owner WITH GRANT OPTION',
      `GRANT EXECUTE ON FUNCTION ${RI} TO postgres WITH GRANT OPTION;`,
      ['row_immutable_acl_owner_entry', 'row_immutable_acl_grant_option'],
    ],
    [
      'v8 — unexpected direct grantee',
      `CREATE ROLE r155_t NOLOGIN; GRANT EXECUTE ON FUNCTION ${RI} TO r155_t;`,
      ['row_immutable_acl_unexpected_grantee'],
    ],
  ];

  for (const [name, drift, labels] of ACL_MATRIX) {
    it(`${name} => ready=false with exact labels`, async () => {
      const db = await open(MIGRATION, true);

      try {
        await db.exec(drift);

        const v = await verify(db);
        expect(v.ready).toBe(false);

        for (const l of labels) {
          expect(v.failed).toContain(l);
        }
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  const TRIGGER_MATRIX: Array<[string, string, string[]]> = [
    [
      'v9 — trigger detached',
      `DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;`,
      ['row_immutable_trigger_missing:qhub_usage_ledger'],
    ],
    [
      'v10 — trigger disabled',
      `ALTER TABLE public.qhub_entitlement_audit DISABLE TRIGGER trg_qhub_entitlement_audit_immutable;`,
      ['row_immutable_trigger_disabled:qhub_entitlement_audit'],
    ],
    [
      'v11 — trigger rebound to a different function',
      `CREATE FUNCTION public.r155_noop() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
       DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;
       CREATE TRIGGER trg_qhub_usage_ledger_immutable BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger
         FOR EACH ROW EXECUTE FUNCTION public.r155_noop();`,
      ['row_immutable_trigger_binding:qhub_usage_ledger'],
    ],
    [
      'v12 — trigger renamed (a count-only check would pass; the exact-name binding does not)',
      `ALTER TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger RENAME TO some_other_trigger;`,
      ['row_immutable_trigger_missing:qhub_usage_ledger'],
    ],
    [
      'v13 — an unrelated decoy trigger does not satisfy the reviewed binding',
      `DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;
       CREATE FUNCTION public.r155_noop2() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
       CREATE TRIGGER decoy_trigger BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger
         FOR EACH ROW EXECUTE FUNCTION public.r155_noop2();`,
      ['row_immutable_trigger_missing:qhub_usage_ledger'],
    ],
  ];

  for (const [name, drift, labels] of TRIGGER_MATRIX) {
    it(`${name} => ready=false with exact labels`, async () => {
      const db = await open(MIGRATION, true);

      try {
        await db.exec(drift);

        const v = await verify(db);
        expect(v.ready).toBe(false);

        for (const l of labels) {
          expect(v.failed).toContain(l);
        }
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('v14 — recovery restores ready=true, repeated invocation is stable, and verification mutates nothing', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`GRANT EXECUTE ON FUNCTION ${RI} TO anon;`);
      expect((await verify(db)).ready).toBe(false);

      await db.exec(`REVOKE EXECUTE ON FUNCTION ${RI} FROM anon;`);

      const a = await verify(db);
      const b = await verify(db);
      expect(a).toEqual({ ready: true, failed: [], expected_version: '2026-07-30.commercial-launch-r8' });
      expect(b).toEqual(a);

      const acl = (
        await db.query<{ a: string }>(`select proacl::text a from pg_proc where oid = to_regprocedure($1)`, [RI])
      ).rows[0].a;
      expect(acl, 'verification must not mutate the ACL').toBe('{postgres=X/postgres}');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('v15 — deterministic failed-label ordering across invocations', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(`GRANT EXECUTE ON FUNCTION ${RI} TO anon;
                     DROP TRIGGER trg_qhub_usage_ledger_immutable ON public.qhub_usage_ledger;`);

      const a = await verify(db);
      const b = await verify(db);
      expect(a.failed).toEqual(b.failed);
      expect(a.failed.length).toBeGreaterThanOrEqual(3);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── the package: 13 / 14 / 15 ─────────────────────────────────────────────────

describe('R15.5 — the live package authorizes and installs the new verifier', () => {
  it('p1 — the live-like fixture reproduces the EXACT documented live verifier digest', async () => {
    const db = await openLiveLike();

    try {
      expect(await verifierMd5(db)).toBe(LIVE_START);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('p2 — 13 authorizes the documented live state and the patched state, and STOPs an unknown verifier', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH');

      // an unknown verifier body is an unexplained state -> STOP
      await db.exec(`CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN jsonb_build_object('ready', true, 'failed', '[]'::jsonb, 'expected_version', '2026-07-30.commercial-launch-r8'); END $f$;`);
      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('UNEXPECTED_RUNTIME_VERIFIER_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('p3 — 14 refuses an unexplained live verifier and leaves it intact', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(`CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN '{}'::jsonb; END $f$;`);

      const before = await verifierMd5(db);

      await expect(db.exec(PATCH14)).rejects.toThrow(/unexpected_runtime_verifier_state/);
      await rollback(db);
      expect(await verifierMd5(db), 'the unexplained verifier survives as evidence').toBe(before);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('p4 — a mangled transfer of 14 itself rolls the whole transaction back', async () => {
    const db = await openLiveLike();

    try {
      // run the R15.4 restoration first so only the verifier transfer is at fault
      await db.exec(RESTORE11);

      await expect(db.exec(mangle(PATCH14))).rejects.toThrow(/R15\.5 POST|unexpected_runtime_verifier_state/);
      await rollback(db);
      expect(await verifierMd5(db), 'the live verifier is untouched').toBe(LIVE_START);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('p5 — membership-derived effective executor still aborts 14 (R15.2C gate preserved)', async () => {
    const db = await openLiveLike();

    try {
      await db.exec('CREATE ROLE r155_m NOLOGIN; GRANT service_role TO r155_m;');
      await expect(db.exec(PATCH14)).rejects.toThrow(/unexpected_effective_verifier_executor/);
      await rollback(db);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('p6 — THE FULL FINAL SEQUENCE: 10 → 11 → 12 → 13 → 14 → 15 = R15_5_VERIFIER_READY', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(PRE10);
      expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');

      await db.exec(RESTORE11);
      await db.exec(POST12);
      expect((await db.query<Record<string, unknown>>(V12)).rows[0].final_status).toBe(
        'R15_3_REVIEWED_BODIES_RESTORED',
      );

      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH');

      await db.exec(PATCH14);
      expect(await verifierMd5(db)).toBe(NEW_LF);

      await db.exec(POST15);

      const r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.final_status).toBe('R15_5_VERIFIER_READY');
      expect(r.product_ready).toBe('true');
      expect(r.product_failed_count).toBe('0');
      expect(r.product_version).toBe('2026-07-30.commercial-launch-r8');

      // idempotency of 14 under the final state
      await db.exec(PATCH14);
      await db.exec(POST15);
      expect((await db.query<Record<string, unknown>>(V15)).rows[0].final_status).toBe('R15_5_VERIFIER_READY');

      // and 13 accepts the final state
      await db.exec(PRE13);
      expect((await db.query<{ verdict: string }>(V13)).rows[0].verdict).toBe('SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH');
    } finally {
      await db.close();
    }
  }, 300_000);

  it('p7 — THE CLOSURE PROOF: after the full sequence, the P1 grant now fails 15', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(PATCH14);

      await db.exec(POST15);
      expect((await db.query<Record<string, unknown>>(V15)).rows[0].final_status).toBe('R15_5_VERIFIER_READY');

      // The exact Codex P1 mutation — now caught by the PRODUCT verifier at runtime.
      await db.exec(`GRANT EXECUTE ON FUNCTION ${RI} TO anon;`);

      await db.exec(POST15);

      const r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.final_status).toBe('R15_5_VERIFIER_NOT_READY');
      expect(r.product_ready).toBe('false');
      expect(Number(r.product_failed_count)).toBeGreaterThanOrEqual(2);
    } finally {
      await db.close();
    }
  }, 300_000);

  it('p8 — 15 retains the R15.2C non-execution guarantee for an unauthorized verifier body', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(PATCH14);

      await db.exec(`CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS JSONB
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RAISE EXCEPTION 'SHOULD_NOT_EXECUTE_UNREVIEWED_VERIFIER'; END $f$;`);

      await expect(db.exec(POST15)).resolves.toBeDefined();

      const r = (await db.query<Record<string, unknown>>(V15)).rows[0];
      expect(r.body_approved).toBe(false);
      expect(r.product_ready, 'the sentinel was never invoked').toBeNull();
      expect(r.final_status).toBe('R15_5_VERIFIER_NOT_READY');
    } finally {
      await db.close();
    }
  }, 120_000);
});
