/**
 * QHUB R15.6 — MIGRATION-HISTORY RECONCILIATION PACKAGE (PGlite, fully offline)
 * app/test/commercial-r15-6-migration-history.test.ts
 *
 * Verifies docs/release/r15-6-migration-history/ (25 PRE / 26 RECORD / 27 POST):
 * the package records EXACTLY one history row (20260729,
 * commercial_launch_foundation) — values derived through the pinned CLI's own
 * filename-parse contract — refuses every conflicting/ambiguous/not-READY
 * state, is idempotent on an already-correct entry, mutates nothing but the
 * history row, and keeps all package hashes and cross-references consistent.
 *
 * The history-table fixture is created with the EXACT DDL the pinned
 * supabase@2.110.0 CLI embeds (extracted verbatim offline from the installed
 * binary — see MIGRATION_HISTORY_MECHANISM_ANALYSIS.md §2).
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const DIR = `${REPO}docs/release/r15-6-migration-history/`;

const MIGRATION_PATH = `${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`;
const MIGRATION = readFileSync(MIGRATION_PATH, 'utf8');
const PRE25 = readFileSync(`${DIR}25_PRE_MIGRATION_HISTORY_VERIFY.sql`, 'utf8');
const REC26 = readFileSync(`${DIR}26_MIGRATION_HISTORY_RECORD.sql`, 'utf8');
const POST27 = readFileSync(`${DIR}27_POST_MIGRATION_HISTORY_VERIFY.sql`, 'utf8');
const RUNBOOK = readFileSync(`${DIR}R15_6_MIGRATION_HISTORY_RUNBOOK.md`, 'utf8');
const ANALYSIS = readFileSync(`${DIR}MIGRATION_HISTORY_MECHANISM_ANALYSIS.md`, 'utf8');

const VERSION = '20260729';
const NAME = 'commercial_launch_foundation';

/** The exact CLI 2.110.0 DDL, extracted verbatim from the installed binary. */
const CLI_DDL = `CREATE SCHEMA IF NOT EXISTS supabase_migrations;
CREATE TABLE IF NOT EXISTS supabase_migrations.schema_migrations (version text NOT NULL PRIMARY KEY);
ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS statements text[];
ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS name text;`;

const NEIGHBORS = `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES
 ('20260723','qhub_applications'),('20260725','gate03_policy'),
 ('20260726','gate04_enforcement'),('20260727','agent_framework_foundation');`;

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

const V25 = lastStatement(PRE25);
const V27 = lastStatement(POST27);
const A26 = lastStatement(REC26);

async function fresh(withHistory = true): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );
  await db.exec(`ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`);
  await db.exec(MIGRATION);

  if (withHistory) {
    await db.exec(CLI_DDL);
    await db.exec(NEIGHBORS);
  }

  return db;
}

const row = async (db: PGlite, sql: string) => (await db.query<Record<string, unknown>>(sql)).rows[0];

const histRows = async (db: PGlite) =>
  (
    await db.query<{ s: string }>(
      `select version || '=' || coalesce(name, '(null)') s
       from supabase_migrations.schema_migrations order by version`,
    )
  ).rows
    .map((r) => r.s)
    .join('|');

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

// ─── static contracts ─────────────────────────────────────────────────────────

describe('R15.6 history package — static contracts', () => {
  it('st1 — PRE and POST are read-only: READ ONLY transactions and no mutating statement', () => {
    for (const [name, sql] of [
      ['25', PRE25],
      ['27', POST27],
    ] as const) {
      expect(sql, `${name} must set READ ONLY`).toMatch(/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY/);
      expect(sql, `${name} must not INSERT`).not.toMatch(/^\s*INSERT/im);
      expect(sql, `${name} must not UPDATE`).not.toMatch(/^\s*UPDATE/im);
      expect(sql, `${name} must not DELETE`).not.toMatch(/^\s*DELETE/im);
      expect(sql, `${name} must not CREATE/ALTER/DROP`).not.toMatch(/^\s*(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE)/im);
    }
  });

  it('st2 — 26 mutates ONLY migration history: exactly one target INSERT plus the pg_temp audit', () => {
    const withoutComments = REC26.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');

    // The only INSERT targets are the history table and the temp audit table.
    const inserts = withoutComments.match(/INSERT INTO\s+([a-z0-9_.]+)/gi) ?? [];
    expect(inserts.map((s) => s.replace(/INSERT INTO\s+/i, '').toLowerCase()).sort()).toEqual([
      'r15_6_history_audit',
      'r15_6_history_audit',
      'supabase_migrations.schema_migrations',
    ]);

    // No UPDATE/DELETE/TRUNCATE anywhere; the only CREATE is the TEMP audit table.
    expect(withoutComments).not.toMatch(/\b(UPDATE|DELETE|TRUNCATE)\b/i);

    const creates = withoutComments.match(/^\s*CREATE\s+\w+(\s+\w+)?/gim) ?? [];
    expect(creates.map((s) => s.trim())).toEqual(['CREATE TEMP TABLE']);

    // Never the CLI's overwriting upsert, and no re-execution of migration DDL.
    expect(withoutComments).not.toMatch(/ON CONFLICT/i);
    expect(withoutComments).not.toMatch(/CREATE (TABLE|POLICY|FUNCTION|TRIGGER|INDEX|SCHEMA)/i);
    expect(withoutComments).not.toMatch(/\b(GRANT|REVOKE)\b/i);
  });

  it('st3 — exact derived version and name literals are used everywhere', () => {
    for (const [name, sql] of [
      ['25', PRE25],
      ['26', REC26],
      ['27', POST27],
    ] as const) {
      expect(sql, `${name} version literal`).toContain(`'${VERSION}'`);
      expect(sql, `${name} name literal`).toContain(`'${NAME}'`);
    }

    expect(REC26).toContain(
      `INSERT INTO supabase_migrations.schema_migrations (version, name)
    VALUES ('${VERSION}', '${NAME}');`,
    );
  });

  it('st4 — no founder/entitlement/billing/stripe surface in any executable text', () => {
    /*
     * The words legitimately appear in the artifacts' own prohibition comments;
     * the assertion is that no EXECUTABLE text touches those surfaces.
     */
    const executable = [PRE25, REC26, POST27]
      .map((sql) =>
        sql
          .split('\n')
          .filter((l) => !/^\s*--/.test(l))
          .join('\n'),
      )
      .join('\n');
    expect(executable).not.toMatch(/founder|entitlement|stripe|billing|seed/i);
  });

  it('st5 — all package hashes and cross-references are consistent', () => {
    const sha = (buf: Buffer | string) => createHash('sha256').update(buf).digest('hex');

    // The six upstream authoritative artifacts still hash to the approved values.
    const upstream: Array<[string, string]> = [
      [
        'supabase/migrations/20260729_commercial_launch_foundation.sql',
        '1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755',
      ],
      [
        'docs/release/r15-6-runtime-verifier/19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql',
        'dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa',
      ],
      [
        'docs/release/r15-6-runtime-verifier/20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql',
        '0626edb61d9f5ed916be881eb48af0dddac972c852472c8d18f2a8832ffd9047',
      ],
      [
        'docs/release/r15-6-runtime-verifier/21_PRE_PROTECTED_FUNCTION_RESTORATION.sql',
        '9a4bbcae4bdba6e78355d89ae91e98b31d3b2192c66c88e7455a4a17a769cff1',
      ],
      [
        'docs/release/r15-6-runtime-verifier/22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql',
        'f0062b2dd1b59deb768c78f54155a69515a4e28bdf6f714aed8c1e9277d00303',
      ],
      [
        'docs/release/r15-6-runtime-verifier/23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql',
        '9ff28bc78b4083064e5794925922866eba22b392c3c51daa05b6ca4ebead6f0f',
      ],
    ];

    for (const [rel, expected] of upstream) {
      expect(sha(readFileSync(`${REPO}${rel}`)), rel).toBe(expected);
    }

    // The runbook's hash table matches the actual package artifacts.
    const packaged: Array<[string, string]> = [
      ['25_PRE_MIGRATION_HISTORY_VERIFY.sql', sha(readFileSync(`${DIR}25_PRE_MIGRATION_HISTORY_VERIFY.sql`))],
      ['26_MIGRATION_HISTORY_RECORD.sql', sha(readFileSync(`${DIR}26_MIGRATION_HISTORY_RECORD.sql`))],
      ['27_POST_MIGRATION_HISTORY_VERIFY.sql', sha(readFileSync(`${DIR}27_POST_MIGRATION_HISTORY_VERIFY.sql`))],
    ];

    for (const [file, actual] of packaged) {
      expect(RUNBOOK, `runbook must pin the current hash of ${file}`).toContain(actual);
    }

    /*
     * Cross-references: analysis pins the migration identity; runbook pins the
     * approved starting commit and both prior evidence commits.
     */
    expect(ANALYSIS).toContain('1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755');
    expect(ANALYSIS).toContain('125,186');
    expect(RUNBOOK).toContain('5a88cbf54b4c3cdf7ce17d57b46c495ff8861b44');
    expect(RUNBOOK).toContain('39f3ee077876fe94549e0c34eb073dba609e5559');
  });

  it('st6 — the migration file identity the values were derived from is intact', () => {
    const buf = readFileSync(MIGRATION_PATH);
    expect(buf.length).toBe(125186);

    const m = /^([0-9]+)_(.*)\.sql$/.exec('20260729_commercial_launch_foundation.sql')!;
    expect(m[1]).toBe(VERSION);
    expect(m[2]).toBe(NAME);
  });
});

// ─── PRE 25 ───────────────────────────────────────────────────────────────────

describe('R15.6 history package — PRE 25 verdicts', () => {
  const CASES: Array<[string, string | null, string]> = [
    ['target absent (happy path)', null, 'SAFE_TO_RECORD_MIGRATION_HISTORY'],
    [
      'already recorded exactly',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', '${NAME}');`,
      'ALREADY_RECORDED_EXACTLY',
    ],
    [
      'version under a different name',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', 'something_else');`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
    [
      'partial/legacy row (NULL name)',
      `INSERT INTO supabase_migrations.schema_migrations (version) VALUES ('${VERSION}');`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
    [
      'name under a different version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260728', '${NAME}');`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
    [
      'a version newer than the target',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260801', 'mystery');`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
    [
      'product verifier not READY (helper anon grant)',
      `GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
    [
      'verifier body replaced (even one that fakes ready)',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
         LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
         AS $f$ BEGIN RETURN jsonb_build_object('ready', true, 'failed', '[]'::jsonb,
           'expected_version', '2026-07-30.commercial-launch-r8'); END $f$;`,
      'UNEXPECTED_MIGRATION_HISTORY_STOP',
    ],
  ];

  for (const [name, setup, want] of CASES) {
    it(`p-${name} => ${want}`, async () => {
      const db = await fresh();

      try {
        if (setup) {
          await db.exec(setup);
        }

        await db.exec(PRE25);
        expect((await row(db, V25)).verdict).toBe(want);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('p-history table entirely absent => STOP verdict, never a SQL error', async () => {
    const db = await fresh(false);

    try {
      await db.exec(PRE25);
      expect((await row(db, V25)).verdict).toBe('UNEXPECTED_MIGRATION_HISTORY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── RECORD 26 ────────────────────────────────────────────────────────────────

describe('R15.6 history package — RECORD 26', () => {
  it('r1 — records exactly (20260729, commercial_launch_foundation) with NULL statements, then is idempotent', async () => {
    const db = await fresh();

    try {
      await db.exec(REC26);

      const a = await row(db, A26);
      expect(a.action).toBe('RECORDED_NOW');
      expect(a.history_version).toBe(VERSION);
      expect(a.history_name).toBe(NAME);
      expect(a.history_statements_cardinality).toBe('null');
      expect(String(a.rows_for_version)).toBe('1');

      await db.exec(REC26);

      const b = await row(db, A26);
      expect(b.action).toBe('ALREADY_RECORDED_EXACTLY');
      expect(String(b.rows_for_version)).toBe('1');
    } finally {
      await db.close();
    }
  }, 240_000);

  const FAILS: Array<[string, string, RegExp]> = [
    [
      'version under a different name',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', 'something_else');`,
      /migration_history_conflict/,
    ],
    [
      'partial/legacy row (NULL name)',
      `INSERT INTO supabase_migrations.schema_migrations (version) VALUES ('${VERSION}');`,
      /migration_history_conflict/,
    ],
    [
      'name under a different version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260728', '${NAME}');`,
      /migration_history_conflict/,
    ],
    [
      'a version newer than the target',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260801', 'mystery');`,
      /migration_history_conflict/,
    ],
    [
      'product verifier not READY',
      `GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;`,
      /migration_history_product_not_ready/,
    ],
    [
      'unknown verifier body',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
         LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
         AS $f$ BEGIN RETURN '{}'::jsonb; END $f$;`,
      /unexpected_runtime_verifier_state/,
    ],
    [
      'verifier SECURITY INVOKER',
      `ALTER FUNCTION public.qhub_verify_commercial_schema() SECURITY INVOKER;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'history shape drift (statements column missing)',
      `ALTER TABLE supabase_migrations.schema_migrations DROP COLUMN statements;`,
      /unexpected_migration_history_shape/,
    ],
    [
      'history shape drift (unexpected mandatory column)',
      `ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN must_have text NOT NULL DEFAULT 'x';
       ALTER TABLE supabase_migrations.schema_migrations ALTER COLUMN must_have DROP DEFAULT;`,
      /unexpected_migration_history_shape/,
    ],
  ];

  for (const [name, setup, rx] of FAILS) {
    it(`r-fail — ${name} => deterministic STOP, history untouched`, async () => {
      const db = await fresh();

      try {
        await db.exec(setup);

        const before = await histRows(db);

        await expect(db.exec(REC26)).rejects.toThrow(rx);
        await rollback(db);

        expect(await histRows(db)).toBe(before);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('r2 — history table absent => unexpected_migration_history_shape (it is never created here)', async () => {
    const db = await fresh(false);

    try {
      await expect(db.exec(REC26)).rejects.toThrow(/unexpected_migration_history_shape/);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r3 — mutation scope: nothing but the single history row changes', async () => {
    const db = await fresh();

    try {
      const snapshot = async () => ({
        fns: (
          await db.query<{ s: string }>(
            `select p.proname || ':' || md5(p.prosrc) || ':' || coalesce(p.proacl::text, '-') s
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' order by 1`,
          )
        ).rows
          .map((r) => r.s)
          .join('|'),
        triggers: (
          await db.query<{ t: string }>(
            `select tgname || ':' || tgtype::text || ':' || tgenabled::text t
             from pg_trigger where not tgisinternal order by 1`,
          )
        ).rows
          .map((r) => r.t)
          .join('|'),
        policies: (await row(db, `select count(*) c from pg_policies`)).c,
        appRows: (
          await row(db, `select coalesce(sum(n_live_tup), 0) c from pg_stat_user_tables where schemaname = 'public'`)
        ).c,
      });

      const before = await snapshot();
      const historyBefore = await histRows(db);

      await db.exec(REC26);

      expect(await snapshot()).toEqual(before);
      expect(await histRows(db)).toBe(`${historyBefore}|${VERSION}=${NAME}`);
    } finally {
      await db.close();
    }
  }, 240_000);
});

// ─── POST 27 ──────────────────────────────────────────────────────────────────

describe('R15.6 history package — POST 27', () => {
  it('q1 — after 26: MIGRATION_20260729_HISTORY_RECONCILED with READY product', async () => {
    const db = await fresh();

    try {
      await db.exec(REC26);
      await db.exec(POST27);

      const r = await row(db, V27);
      expect(r.final_status).toBe('MIGRATION_20260729_HISTORY_RECONCILED');
      expect(r.product_ready).toBe('true');
      expect(r.product_version).toBe('2026-07-30.commercial-launch-r8');
      expect(r.product_failed_count).toBe('0');
      expect(r.target_row_detail).toBe(`${VERSION}=${NAME}`);
    } finally {
      await db.close();
    }
  }, 240_000);

  const FAILS: Array<[string, string]> = [
    ['history row deleted', `DELETE FROM supabase_migrations.schema_migrations WHERE version = '${VERSION}';`],
    [
      'history name mutated',
      `UPDATE supabase_migrations.schema_migrations SET name = 'x' WHERE version = '${VERSION}';`,
    ],
    [
      'name duplicated under another version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260730', '${NAME}');`,
    ],
    ['product no longer READY', `GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;`],
  ];

  for (const [name, drift] of FAILS) {
    it(`q-fail — ${name} => MIGRATION_HISTORY_NOT_RECONCILED`, async () => {
      const db = await fresh();

      try {
        await db.exec(REC26);
        await db.exec(drift);
        await db.exec(POST27);

        expect((await row(db, V27)).final_status).toBe('MIGRATION_HISTORY_NOT_RECONCILED');
      } finally {
        await db.close();
      }
    }, 240_000);
  }
});
