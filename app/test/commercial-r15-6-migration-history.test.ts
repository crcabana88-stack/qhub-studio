/**
 * QHUB R15.6 — MIGRATION-HISTORY RECONCILIATION PACKAGE, CORRECTED (PGlite)
 * app/test/commercial-r15-6-migration-history.test.ts
 *
 * Verifies the corrected docs/release/r15-6-migration-history/ package
 * (25 PRE / 26 RECORD / 27 POST) against the independent review findings:
 *   P1-1 RECORD serializes via LOCK TABLE ... SHARE ROW EXCLUSIVE and re-checks
 *        everything post-lock (two-session proof lives in
 *        commercial-r15-6-history-concurrency.test.ts against real PostgreSQL).
 *   P1-2 RECORD enforces the complete pinned verifier-authority contract inside
 *        the mutation transaction.
 *   P1-3 the complete pinned CLI table contract and mutation boundary are
 *        enforced by PRE, RECORD and POST alike.
 *   P2-1 the row is complete: statements is the exact CLI-derived array
 *        (fixture app/test/fixtures/r8-20260729-cli-statements.json — 89
 *        elements, 124,959 bytes, canonical digest
 *        7b28ccf3ba7cae3e29c17bc5c3be60b6).
 *   P2-2/3 the temp audit table is created inside the transaction, without
 *        IF NOT EXISTS; same-session reruns fail closed; exactly one row.
 *
 * The history-table fixture uses the EXACT DDL the pinned supabase@2.110.0 CLI
 * embeds (extracted verbatim from the installed binary, sha256
 * 14814afa6fe59081eb9f24709fc077226bf89bc25cf77ee3bcb19565f3ef8899).
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
const STATEMENTS: string[] = JSON.parse(
  readFileSync(`${REPO}app/test/fixtures/r8-20260729-cli-statements.json`, 'utf8'),
);

const VERSION = '20260729';
const NAME = 'commercial_launch_foundation';
const STMT_COUNT = 89;
const STMT_DIGEST = '7b28ccf3ba7cae3e29c17bc5c3be60b6';
const STMT_BYTES = 124959;

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
    .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION|SET LOCAL)/i.test(s))
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

/** Insert the exact target row (including the fixture statements) directly. */
async function insertExactRow(db: PGlite): Promise<void> {
  await db.query(
    `INSERT INTO supabase_migrations.schema_migrations (version, name, statements)
     VALUES ($1, $2, $3)`,
    [VERSION, NAME, STATEMENTS],
  );
}

const row = async (db: PGlite, sql: string) => (await db.query<Record<string, unknown>>(sql)).rows[0];

const histRows = async (db: PGlite) =>
  (
    await db.query<{ s: string }>(
      `select version || '=' || coalesce(name, '(null)') || ':' || coalesce(cardinality(statements)::text, 'null') s
         from supabase_migrations.schema_migrations order by version`,
    )
  ).rows
    .map((r) => r.s)
    .join('|');

/** Shape-agnostic byte-identity fingerprint (survives dropped/added columns). */
const histFingerprint = async (db: PGlite) =>
  (
    await db.query<{ f: string }>(
      `select coalesce(md5(string_agg(to_jsonb(m.*)::text, '|' order by m.version)), 'empty') f
         from supabase_migrations.schema_migrations m`,
    )
  ).rows[0].f;

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

async function dropAudit(db: PGlite): Promise<void> {
  await db.exec('DROP TABLE IF EXISTS pg_temp.r15_6_migration_history_audit;');
}

// ─── fixture integrity ────────────────────────────────────────────────────────

describe('R15.6 history package — CLI statements fixture', () => {
  it('fx1 — cardinality, per-element bytes, total bytes and canonical digest match the pinned CLI derivation', () => {
    expect(STATEMENTS.length).toBe(STMT_COUNT);

    const total = STATEMENTS.reduce((a, s) => a + Buffer.byteLength(s), 0);
    expect(total).toBe(STMT_BYTES);

    const h = createHash('md5');

    for (const s of STATEMENTS) {
      h.update(`${Buffer.byteLength(s)}:`);
      h.update(s);
    }

    expect(h.digest('hex')).toBe(STMT_DIGEST);
  });

  it('fx2 — every statement is a verbatim, in-order substring of the committed migration', () => {
    let pos = 0;

    for (const s of STATEMENTS) {
      const i = MIGRATION.indexOf(s, pos);
      expect(i, 'statement must appear in order').toBeGreaterThanOrEqual(0);
      pos = i + s.length;
    }
  });

  it('fx3 — the base64 payload embedded in 26 decodes to exactly the fixture, element by element', () => {
    const embedded = [...REC26.matchAll(/pg_catalog\.decode\('([A-Za-z0-9+/=]+)', 'base64'\)/g)].map((m) =>
      Buffer.from(m[1], 'base64').toString('utf8'),
    );
    expect(embedded.length).toBe(STMT_COUNT);
    expect(embedded).toEqual(STATEMENTS);
  });

  it('fx4 — 26 pins the exact cardinality, digest and byte constants', () => {
    expect(REC26).toContain(`c_stmt_count  CONSTANT int    := ${STMT_COUNT};`);
    expect(REC26).toContain(`c_stmt_digest CONSTANT text   := '${STMT_DIGEST}';`);
    expect(REC26).toContain(`c_stmt_bytes  CONSTANT bigint := ${STMT_BYTES};`);
  });
});

// ─── static contracts ─────────────────────────────────────────────────────────

describe('R15.6 history package — static contracts', () => {
  it('st1 — PRE and POST are read-only: READ ONLY transactions and no mutating or temporary statement', () => {
    for (const [name, sql] of [
      ['25', PRE25],
      ['27', POST27],
    ] as const) {
      expect(sql, `${name} must set READ ONLY`).toMatch(/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY/);
      expect(sql, `${name} must not INSERT`).not.toMatch(/^\s*INSERT/im);
      expect(sql, `${name} must not UPDATE`).not.toMatch(/^\s*UPDATE/im);
      expect(sql, `${name} must not DELETE`).not.toMatch(/^\s*DELETE/im);
      expect(sql, `${name} must not CREATE/ALTER/DROP/LOCK`).not.toMatch(
        /^\s*(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|LOCK)\b/im,
      );
    }
  });

  it('st2 — 26 durable writes are exactly one history INSERT; temp DDL is in-transaction without IF NOT EXISTS', () => {
    const exec = REC26.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');

    const inserts = (exec.match(/INSERT INTO\s+([a-z0-9_.]+)/gi) ?? []).map((s) =>
      s.replace(/INSERT INTO\s+/i, '').toLowerCase(),
    );
    expect(inserts.sort()).toEqual(['pg_temp.r15_6_migration_history_audit', 'supabase_migrations.schema_migrations']);

    expect(exec).not.toMatch(/\b(UPDATE|DELETE|TRUNCATE)\b/i);
    expect(exec).not.toMatch(/ON CONFLICT/i);
    expect(exec).not.toMatch(/^\s*(GRANT|REVOKE)\b/im);

    /*
     * No dynamic-SQL path: no plpgsql EXECUTE statement anywhere. (The string
     * literal 'EXECUTE' inside privilege comparisons is data, not code.)
     */
    expect(exec).not.toMatch(/^\s*EXECUTE\b/im);
    expect(exec).not.toMatch(/EXECUTE\s+(format|'|\$|v_|c_)/i);
    expect(exec).not.toMatch(/IF NOT EXISTS/i);

    const creates = (exec.match(/^\s*CREATE\s+\w+(\s+\w+)?/gim) ?? []).map((s) => s.trim());
    expect(creates).toEqual(['CREATE TEMP TABLE']);

    // The temp DDL sits after BEGIN (inside the explicit transaction).
    expect(exec.indexOf('BEGIN;')).toBeGreaterThanOrEqual(0);
    expect(exec.indexOf('CREATE TEMP TABLE')).toBeGreaterThan(exec.indexOf('BEGIN;'));
    expect(exec.indexOf('CREATE TEMP TABLE')).toBeLessThan(exec.indexOf('COMMIT;'));

    // Lock precedes every gate and the insert; restricted search_path is set.
    expect(exec).toMatch(/LOCK TABLE supabase_migrations\.schema_migrations IN SHARE ROW EXCLUSIVE MODE;/);
    expect(exec).toMatch(/SET LOCAL search_path = pg_catalog;/);
    expect(exec).toMatch(/SET TRANSACTION ISOLATION LEVEL READ COMMITTED;/);
  });

  it('st3 — exact derived literals and the complete-row INSERT shape', () => {
    for (const [name, sql] of [
      ['25', PRE25],
      ['26', REC26],
      ['27', POST27],
    ] as const) {
      expect(sql, `${name} version literal`).toContain(`'${VERSION}'`);
      expect(sql, `${name} name literal`).toContain(`'${NAME}'`);
      expect(sql, `${name} statements digest`).toContain(STMT_DIGEST);
    }

    expect(REC26).toContain('INSERT INTO supabase_migrations.schema_migrations (version, name, statements)');
    expect(REC26).toContain('VALUES (c_version, c_name, v_statements);');
  });

  it('st4 — no founder/entitlement/billing/stripe surface in any executable text', () => {
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

    for (const file of [
      '25_PRE_MIGRATION_HISTORY_VERIFY.sql',
      '26_MIGRATION_HISTORY_RECORD.sql',
      '27_POST_MIGRATION_HISTORY_VERIFY.sql',
    ]) {
      expect(RUNBOOK, `runbook must pin the current hash of ${file}`).toContain(sha(readFileSync(`${DIR}${file}`)));
    }

    // Fixture digest is pinned by runbook and analysis; CLI binary identity too.
    expect(RUNBOOK).toContain(STMT_DIGEST);
    expect(ANALYSIS).toContain(STMT_DIGEST);
    expect(ANALYSIS).toContain('14814afa6fe59081eb9f24709fc077226bf89bc25cf77ee3bcb19565f3ef8899');
    expect(RUNBOOK).toContain('5c36883eed44b877733768649c805ef2c64f0c7f');
  });

  it('st6 — the migration identity the values were derived from is intact', () => {
    const buf = readFileSync(MIGRATION_PATH);
    expect(buf.length).toBe(125186);

    const m = /^([0-9]+)_(.*)\.sql$/.exec('20260729_commercial_launch_foundation.sql')!;
    expect(m[1]).toBe(VERSION);
    expect(m[2]).toBe(NAME);
  });
});

// ─── PRE 25 ───────────────────────────────────────────────────────────────────

describe('R15.6 history package — PRE 25 verdicts', () => {
  it('p0 — happy path SAFE; exact recorded row ALREADY', async () => {
    const db = await fresh();

    try {
      await db.exec(PRE25);
      expect((await row(db, V25)).verdict).toBe('SAFE_TO_RECORD_MIGRATION_HISTORY');

      await insertExactRow(db);
      await db.exec(PRE25);
      expect((await row(db, V25)).verdict).toBe('ALREADY_RECORDED_EXACTLY');
    } finally {
      await db.close();
    }
  }, 240_000);

  const STOPS: Array<[string, string]> = [
    [
      'version under a different name',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', 'something_else');`,
    ],
    [
      'partial/legacy row (NULL name)',
      `INSERT INTO supabase_migrations.schema_migrations (version) VALUES ('${VERSION}');`,
    ],
    [
      'target row with NULL statements',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', '${NAME}');`,
    ],
    [
      'name under a different version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260728', '${NAME}');`,
    ],
    [
      'a version newer than the target',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260801', 'mystery');`,
    ],
    [
      'a malformed version sorting BEFORE the target',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('0x20260101', 'weird');`,
    ],
    [
      'a malformed version sorting AFTER the target',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('9zzz', 'weird');`,
    ],
    ['an extra optional column', `ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN extra text;`],
    [
      'an unexpected default on name',
      `ALTER TABLE supabase_migrations.schema_migrations ALTER COLUMN name SET DEFAULT 'x';`,
    ],
    ['an unexpected additional index', `CREATE INDEX sneaky_idx ON supabase_migrations.schema_migrations (name);`],
    [
      'an unexpected additional unique constraint',
      `ALTER TABLE supabase_migrations.schema_migrations ADD CONSTRAINT sneaky_u UNIQUE (name);`,
    ],
    [
      'an unexpected trigger',
      `CREATE FUNCTION public.r156h_noop() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
       CREATE TRIGGER sneaky_trg BEFORE INSERT ON supabase_migrations.schema_migrations
         FOR EACH ROW EXECUTE FUNCTION public.r156h_noop();`,
    ],
    [
      'an unexpected rewrite rule',
      `CREATE RULE sneaky_rule AS ON DELETE TO supabase_migrations.schema_migrations DO INSTEAD NOTHING;`,
    ],
    ['row-level security enabled', `ALTER TABLE supabase_migrations.schema_migrations ENABLE ROW LEVEL SECURITY;`],
    [
      'an unexpected policy',
      `ALTER TABLE supabase_migrations.schema_migrations ENABLE ROW LEVEL SECURITY;
       CREATE POLICY sneaky_pol ON supabase_migrations.schema_migrations FOR SELECT USING (true);`,
    ],
    [
      'product verifier not READY (helper anon grant)',
      `GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;`,
    ],
    [
      'verifier body replaced (even one that fakes ready)',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
         LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
         AS $f$ BEGIN RETURN jsonb_build_object('ready', true, 'failed', '[]'::jsonb,
           'expected_version', '2026-07-30.commercial-launch-r8'); END $f$;`,
    ],
  ];

  for (const [name, setup] of STOPS) {
    it(`p-${name} => UNEXPECTED_MIGRATION_HISTORY_STOP`, async () => {
      const db = await fresh();

      try {
        await db.exec(setup);
        await db.exec(PRE25);
        expect((await row(db, V25)).verdict).toBe('UNEXPECTED_MIGRATION_HISTORY_STOP');
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
  it('r1 — records the COMPLETE row (version, name, exact statements); same-session rerun rejected; fresh-session rerun no-ops', async () => {
    const db = await fresh();

    try {
      await db.exec(REC26);

      const a = await row(db, A26);
      expect(a.action).toBe('RECORDED_NOW');
      expect(a.history_version).toBe(VERSION);
      expect(a.history_name).toBe(NAME);
      expect(a.statements_cardinality).toBe(STMT_COUNT);
      expect(a.statements_digest).toBe(STMT_DIGEST);
      expect(String(a.statements_total_bytes)).toBe(String(STMT_BYTES));
      expect(String(a.rows_for_version)).toBe('1');

      const stored = (
        await db.query<{ statements: string[] }>(
          `select statements from supabase_migrations.schema_migrations where version = $1`,
          [VERSION],
        )
      ).rows[0].statements;
      expect(stored).toEqual(STATEMENTS);

      /*
       * Same-session rerun: the in-transaction CREATE TEMP TABLE (no IF NOT
       * EXISTS) fails closed before any gate.
       */
      await expect(db.exec(REC26)).rejects.toThrow(/already exists/i);
      await rollback(db);
      expect(await histRows(db)).toContain(`${VERSION}=${NAME}:${STMT_COUNT}`);

      // Fresh session (simulated by dropping the session-temp audit): clean no-op.
      await dropAudit(db);
      await db.exec(REC26);

      const b = await row(db, A26);
      expect(b.action).toBe('ALREADY_RECORDED_EXACTLY');
      expect(String(b.rows_for_version)).toBe('1');
    } finally {
      await db.close();
    }
  }, 300_000);

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
      'target row with NULL statements (never updated)',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('${VERSION}', '${NAME}');`,
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
      'a malformed recorded version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('2026x729', 'weird');`,
      /migration_history_conflict/,
    ],
    [
      'product verifier not READY',
      `GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO anon;`,
      /migration_history_product_not_ready/,
    ],
    [
      'unknown verifier body (fake ready)',
      `CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema() RETURNS jsonb
         LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
         AS $f$ BEGIN RETURN jsonb_build_object('ready', true, 'failed', '[]'::jsonb,
           'expected_version', '2026-07-30.commercial-launch-r8'); END $f$;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'verifier SECURITY INVOKER',
      `ALTER FUNCTION public.qhub_verify_commercial_schema() SECURITY INVOKER;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'verifier wrong volatility',
      `ALTER FUNCTION public.qhub_verify_commercial_schema() VOLATILE;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'verifier unexpected effective executor (membership)',
      `CREATE ROLE r156h_m NOLOGIN; GRANT service_role TO r156h_m;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'verifier unexpected direct grantee',
      `CREATE ROLE r156h_g NOLOGIN; GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO r156h_g;`,
      /unexpected_runtime_verifier_authority/,
    ],
    [
      'shape: statements column missing',
      `ALTER TABLE supabase_migrations.schema_migrations DROP COLUMN statements;`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: extra optional column',
      `ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN extra text;`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected default',
      `ALTER TABLE supabase_migrations.schema_migrations ALTER COLUMN name SET DEFAULT 'x';`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected additional index',
      `CREATE INDEX sneaky_idx ON supabase_migrations.schema_migrations (name);`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected unique constraint',
      `ALTER TABLE supabase_migrations.schema_migrations ADD CONSTRAINT sneaky_u UNIQUE (name);`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected trigger',
      `CREATE FUNCTION public.r156h_noop2() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
       CREATE TRIGGER sneaky_trg BEFORE INSERT ON supabase_migrations.schema_migrations
         FOR EACH ROW EXECUTE FUNCTION public.r156h_noop2();`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected rewrite rule',
      `CREATE RULE sneaky_rule AS ON DELETE TO supabase_migrations.schema_migrations DO INSTEAD NOTHING;`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: RLS enabled',
      `ALTER TABLE supabase_migrations.schema_migrations ENABLE ROW LEVEL SECURITY;`,
      /unexpected_migration_history_shape/,
    ],
    [
      'shape: unexpected policy',
      `ALTER TABLE supabase_migrations.schema_migrations ENABLE ROW LEVEL SECURITY;
       CREATE POLICY sneaky_pol ON supabase_migrations.schema_migrations FOR SELECT USING (true);`,
      /unexpected_migration_history_shape/,
    ],
  ];

  for (const [name, setup, rx] of FAILS) {
    it(`r-fail — ${name} => deterministic STOP, durable state byte-identical`, async () => {
      const db = await fresh();

      try {
        await db.exec(setup);

        const before = await histFingerprint(db);

        await expect(db.exec(REC26)).rejects.toThrow(rx);
        await rollback(db);

        expect(await histFingerprint(db)).toBe(before);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('r2 — history table absent => unexpected_migration_history_shape (never created here)', async () => {
    const db = await fresh(false);

    try {
      await expect(db.exec(REC26)).rejects.toThrow(/unexpected_migration_history_shape/);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r3 — corrupted embedded payload => migration_history_payload_integrity before any gate', async () => {
    const db = await fresh();

    try {
      /*
       * Flip the first base64 element's payload to another VALID base64 string
       * of the same shape — the digest gate must refuse it.
       */
      const m = /pg_catalog\.decode\('([A-Za-z0-9+/=]+)', 'base64'\)/.exec(REC26)!;
      const corrupted = REC26.replace(m[1], Buffer.from('corrupted statement', 'utf8').toString('base64'));
      expect(corrupted).not.toBe(REC26);

      await expect(db.exec(corrupted)).rejects.toThrow(/migration_history_payload_integrity/);
      await rollback(db);
      expect(await histRows(db)).not.toContain(VERSION);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r4 — pg_temp cannot shadow the target: a temp schema_migrations is ignored and untouched', async () => {
    const db = await fresh();

    try {
      await db.exec(`CREATE TEMP TABLE schema_migrations (version text, name text, statements text[]);`);
      await db.exec(REC26);

      expect((await row(db, A26)).action).toBe('RECORDED_NOW');
      expect(await histRows(db)).toContain(`${VERSION}=${NAME}:${STMT_COUNT}`);

      const temp = await row(db, `select count(*) c from pg_temp.schema_migrations`);
      expect(String(temp.c)).toBe('0');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('r5 — mutation scope: nothing but the single history row changes', async () => {
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
      expect(await histRows(db)).toBe(`${historyBefore}|${VERSION}=${NAME}:${STMT_COUNT}`);
    } finally {
      await db.close();
    }
  }, 300_000);
});

// ─── POST 27 ──────────────────────────────────────────────────────────────────

describe('R15.6 history package — POST 27', () => {
  it('q1 — after 26: MIGRATION_20260729_HISTORY_RECONCILED with READY product and exact statements', async () => {
    const db = await fresh();

    try {
      await db.exec(REC26);
      await db.exec(POST27);

      const r = await row(db, V27);
      expect(r.final_status).toBe('MIGRATION_20260729_HISTORY_RECONCILED');
      expect(r.product_ready).toBe('true');
      expect(r.product_version).toBe('2026-07-30.commercial-launch-r8');
      expect(r.product_failed_count).toBe('0');
      expect(r.target_exact_rows).toBe('1');
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
      'statements nulled out',
      `UPDATE supabase_migrations.schema_migrations SET statements = NULL WHERE version = '${VERSION}';`,
    ],
    [
      'statements truncated (one element removed)',
      `UPDATE supabase_migrations.schema_migrations SET statements = statements[1:88] WHERE version = '${VERSION}';`,
    ],
    [
      'one statement modified',
      `UPDATE supabase_migrations.schema_migrations SET statements[1] = statements[1] || ' ' WHERE version = '${VERSION}';`,
    ],
    [
      'name duplicated under another version',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260730', '${NAME}');`,
    ],
    [
      'a newer version recorded',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260801', 'mystery');`,
    ],
    [
      'a malformed version recorded',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('2026x729', 'weird');`,
    ],
    [
      'statements column dropped (table-contract drift)',
      `ALTER TABLE supabase_migrations.schema_migrations DROP COLUMN statements;`,
    ],
    [
      'extra optional column added (table-contract drift)',
      `ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN extra text;`,
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
