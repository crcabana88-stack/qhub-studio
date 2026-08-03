/**
 * QHUB R15.6 — MIGRATION-HISTORY EFFECTIVE-ROLE COVERAGE (REAL POSTGRESQL)
 * app/test/commercial-r15-6-history-effective-roles.test.ts
 *
 * Third-review P1: PRE 25 / RECORD 26 / POST 27 previously enforced effective
 * privileges only for the three hard-coded roles anon / authenticated /
 * service_role. Any other access path — a custom LOGIN role inheriting
 * pg_read_all_data, an authenticator-style role inheriting pg_write_all_data —
 * appeared only in informational evidence and produced reproducible false
 * successes (SAFE / RECORDED_NOW / RECONCILED), reproduced on PostgreSQL 16
 * before the fix.
 *
 * The corrected mandatory predicate is catalog-derived and NAME-INDEPENDENT:
 *   candidate = role that is NOT superuser, NOT the pinned owner, and is either
 *               rolcanlogin (any connection identity, whatever its name) or one
 *               of the required platform roles anon/authenticated/service_role
 *               (checked even though they are NOLOGIN);
 *   violation = the candidate can assume ANY role — itself, or any role reached
 *               by transitive membership regardless of INHERIT (pg_has_role
 *               ..., 'MEMBER') — that holds schema USAGE/CREATE or table
 *               SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER.
 * Membership closure rather than inheritance alone is required because a
 * NOINHERIT login reports FALSE from has_table_privilege yet can still SET ROLE
 * to a privileged role — established here from real behavior (case 13), not
 * assumption. Dormant predefined pg_* roles are never candidates, so their mere
 * existence never fails the healthy state (case 11).
 *
 * These tests REQUIRE real PostgreSQL: PGlite cannot host multi-role catalog
 * behavior faithfully enough, and source-text assertions cannot prove it at all.
 * When the harness is absent the suite SKIPS loudly — a skip is not a pass.
 *   QHUB_SCRATCH_PG_BIN   directory containing psql.exe
 *   QHUB_SCRATCH_PG_PORT  port (default 54329)
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const DIR = `${REPO}docs/release/r15-6-migration-history/`;
const PRE25 = `${DIR}25_PRE_MIGRATION_HISTORY_VERIFY.sql`;
const REC26 = `${DIR}26_MIGRATION_HISTORY_RECORD.sql`;
const POST27 = `${DIR}27_POST_MIGRATION_HISTORY_VERIFY.sql`;
const MIGRATION = `${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`;

const PG_BIN =
  process.env.QHUB_SCRATCH_PG_BIN ??
  'C:/Users/ccaba/AppData/Local/Temp/claude/C--Users-ccaba-qhub-studio/2af3a231-f755-4857-b22e-7cfdcdf5792d/scratchpad/pg/pgsql/bin';
const PORT = process.env.QHUB_SCRATCH_PG_PORT ?? '54329';
const PSQL = `${PG_BIN}/psql.exe`;
const ARGS = ['-h', '127.0.0.1', '-p', PORT, '-U', 'scratch', '-X', '-A', '-t'];
const DB = 'effroles_vitest';
const TBL = 'supabase_migrations.schema_migrations';

function harnessAvailable(): boolean {
  if (!existsSync(PSQL)) {
    return false;
  }

  try {
    execFileSync(PSQL, [...ARGS, '-d', 'postgres', '-c', 'SELECT 1;'], { encoding: 'utf8', timeout: 4000 });

    return true;
  } catch {
    return false;
  }
}

const HAVE_PG = harnessAvailable();

if (!HAVE_PG) {
  console.warn(
    '[commercial-r15-6-history-effective-roles] SKIPPED: no local scratch PostgreSQL harness ' +
      `(looked for ${PSQL} on port ${PORT}). The effective-role coverage proofs must be executed ` +
      'wherever the harness exists — a skip is not a pass.',
  );
}

const run = (sql: string, db = DB) =>
  execFileSync(PSQL, [...ARGS, '-d', db, '-v', 'ON_ERROR_STOP=1', '-c', sql], { encoding: 'utf8', timeout: 120000 });

function runFile(path: string): string {
  try {
    return execFileSync(PSQL, [...ARGS, '-d', DB, '-v', 'ON_ERROR_STOP=1', '-f', path], {
      encoding: 'utf8',
      timeout: 180000,
    });
  } catch (e) {
    const err = e as { stderr?: string; message?: string };

    return `ERR:${String(err.stderr ?? err.message)}`;
  }
}

function resetHistory(): void {
  run(`DROP SCHEMA IF EXISTS supabase_migrations CASCADE;
    CREATE SCHEMA supabase_migrations;
    CREATE TABLE ${TBL} (version text NOT NULL PRIMARY KEY);
    ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS statements text[];
    ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS name text;
    INSERT INTO ${TBL} (version, name) VALUES
     ('20260723','qhub_applications'),('20260725','gate03_policy'),
     ('20260726','gate04_enforcement'),('20260727','agent_framework_foundation');`);
}

const fingerprint = () =>
  run(`SELECT coalesce(md5(string_agg(to_jsonb(m.*)::text, '|' ORDER BY m.version)), 'empty') FROM ${TBL} m;`).trim();

const preVerdict = () =>
  /UNEXPECTED_MIGRATION_HISTORY_STOP|SAFE_TO_RECORD_MIGRATION_HISTORY|ALREADY_RECORDED_EXACTLY/.exec(
    runFile(PRE25),
  )?.[0] ?? 'NO_VERDICT';

const postVerdict = () =>
  /MIGRATION_20260729_HISTORY_RECONCILED|MIGRATION_HISTORY_NOT_RECONCILED/.exec(runFile(POST27))?.[0] ?? 'NO_VERDICT';

describe.skipIf(!HAVE_PG)('R15.6 — mandatory effective-role coverage on real PostgreSQL', () => {
  beforeAll(() => {
    for (const role of ['anon NOLOGIN', 'authenticated NOLOGIN', 'service_role NOLOGIN BYPASSRLS']) {
      try {
        run(`CREATE ROLE ${role};`, 'postgres');
      } catch {
        /* exists */
      }
    }

    try {
      run(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`, 'postgres');
    } catch {
      /* n/a */
    }

    run(`CREATE DATABASE ${DB};`, 'postgres');
    run(`ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`);
    execFileSync(PSQL, [...ARGS, '-d', DB, '-v', 'ON_ERROR_STOP=1', '-f', MIGRATION], {
      encoding: 'utf8',
      timeout: 300000,
    });
  }, 600_000);

  it('e0 — healthy state: PRE SAFE, RECORD records, POST reconciled (dormant predefined roles present)', () => {
    resetHistory();
    expect(preVerdict()).toBe('SAFE_TO_RECORD_MIGRATION_HISTORY');
    expect(runFile(REC26)).toMatch(/RECORDED_NOW/);
    expect(postVerdict()).toBe('MIGRATION_20260729_HISTORY_RECONCILED');

    // Case 11 — predefined capability roles exist but no login can assume them.
    expect(run(`SELECT count(*) FROM pg_roles WHERE rolname IN ('pg_read_all_data','pg_write_all_data');`).trim()).toBe(
      '2',
    );
    resetHistory();
    expect(preVerdict()).toBe('SAFE_TO_RECORD_MIGRATION_HISTORY');
  }, 300_000);

  const UNAUTHORIZED: Array<[string, string, string]> = [
    [
      'case 1 — custom_app LOGIN inheriting pg_read_all_data',
      `CREATE ROLE custom_app LOGIN; GRANT pg_read_all_data TO custom_app;`,
      `DROP ROLE custom_app;`,
    ],
    [
      'case 2 — arbitrarily named LOGIN inheriting pg_write_all_data',
      `CREATE ROLE zz_arbitrary LOGIN; GRANT pg_write_all_data TO zz_arbitrary;`,
      `DROP ROLE zz_arbitrary;`,
    ],
    [
      'case 3 — authenticator-style LOGIN inheriting pg_read_all_data',
      `CREATE ROLE authenticator LOGIN; GRANT pg_read_all_data TO authenticator;`,
      `DROP ROLE authenticator;`,
    ],
    [
      'case 4 — authenticator-style LOGIN inheriting pg_write_all_data',
      `CREATE ROLE authenticator LOGIN; GRANT pg_write_all_data TO authenticator;`,
      `DROP ROLE authenticator;`,
    ],
    [
      'case 5 — LOGIN inheriting a custom NOLOGIN role with direct SELECT',
      `CREATE ROLE capr NOLOGIN; GRANT USAGE ON SCHEMA supabase_migrations TO capr;
       GRANT SELECT ON ${TBL} TO capr; CREATE ROLE appl LOGIN; GRANT capr TO appl;`,
      `DROP ROLE appl; DROP ROLE capr;`,
    ],
    [
      'case 6 — LOGIN inheriting a custom NOLOGIN role with direct INSERT',
      `CREATE ROLE capw NOLOGIN; GRANT INSERT ON ${TBL} TO capw; CREATE ROLE appw LOGIN; GRANT capw TO appw;`,
      `DROP ROLE appw; DROP ROLE capw;`,
    ],
    [
      'case 7 — transitive membership LOGIN -> role A -> role B with access',
      `CREATE ROLE bb NOLOGIN; GRANT SELECT ON ${TBL} TO bb; CREATE ROLE aa NOLOGIN; GRANT bb TO aa;
       CREATE ROLE tl LOGIN; GRANT aa TO tl;`,
      `DROP ROLE tl; DROP ROLE aa; DROP ROLE bb;`,
    ],
    [
      'case 8 — LOGIN with direct schema USAGE and table SELECT',
      `CREATE ROLE dl LOGIN; GRANT USAGE ON SCHEMA supabase_migrations TO dl; GRANT SELECT ON ${TBL} TO dl;`,
      `DROP ROLE dl;`,
    ],
    ['case 9a — LOGIN with direct INSERT', `CREATE ROLE d1 LOGIN; GRANT INSERT ON ${TBL} TO d1;`, `DROP ROLE d1;`],
    ['case 9b — LOGIN with direct UPDATE', `CREATE ROLE d2 LOGIN; GRANT UPDATE ON ${TBL} TO d2;`, `DROP ROLE d2;`],
    ['case 9c — LOGIN with direct DELETE', `CREATE ROLE d3 LOGIN; GRANT DELETE ON ${TBL} TO d3;`, `DROP ROLE d3;`],
    ['case 9d — LOGIN with direct TRUNCATE', `CREATE ROLE d4 LOGIN; GRANT TRUNCATE ON ${TBL} TO d4;`, `DROP ROLE d4;`],
    [
      'case 9e — LOGIN with direct REFERENCES',
      `CREATE ROLE d5 LOGIN; GRANT REFERENCES ON ${TBL} TO d5;`,
      `DROP ROLE d5;`,
    ],
    ['case 9f — LOGIN with direct TRIGGER', `CREATE ROLE d6 LOGIN; GRANT TRIGGER ON ${TBL} TO d6;`, `DROP ROLE d6;`],
    [
      'case 10 — role created long after the scripts were authored (name-independent discovery)',
      `CREATE ROLE brand_new_2026 LOGIN; GRANT pg_read_all_data TO brand_new_2026;`,
      `DROP ROLE brand_new_2026;`,
    ],
    [
      'case 13 — NOINHERIT LOGIN that can SET ROLE to a privileged role',
      `CREATE ROLE nicap NOLOGIN; GRANT SELECT ON ${TBL} TO nicap;
       CREATE ROLE nilog LOGIN NOINHERIT; GRANT nicap TO nilog;`,
      `DROP ROLE nilog; DROP ROLE nicap;`,
    ],
    [
      'case 14 — anon granted access through a custom capability role',
      `CREATE ROLE anoncap NOLOGIN; GRANT SELECT ON ${TBL} TO anoncap; GRANT anoncap TO anon;`,
      `REVOKE anoncap FROM anon; DROP ROLE anoncap;`,
    ],
  ];

  for (const [label, setup, teardown] of UNAUTHORIZED) {
    it(`${label} => PRE STOP, RECORD refuses before any DML, POST NOT_RECONCILED`, () => {
      resetHistory();
      run(setup);

      try {
        expect(preVerdict(), 'PRE must not authorize').toBe('UNEXPECTED_MIGRATION_HISTORY_STOP');

        const before = fingerprint();
        const rec = runFile(REC26);
        expect(rec, 'RECORD must raise the privilege failure').toMatch(
          /unauthorized effective access path|unexpected_migration_history_privilege/,
        );
        expect(rec).not.toMatch(/RECORDED_NOW/);
        expect(fingerprint(), 'durable history must be byte-identical').toBe(before);

        // Seed the exact-looking target row so POST is judged on privilege, not absence.
        run(`INSERT INTO ${TBL} (version, name, statements)
             SELECT '20260729', 'commercial_launch_foundation', ARRAY['x']
              WHERE NOT EXISTS (SELECT 1 FROM ${TBL} WHERE version = '20260729');`);
        expect(postVerdict(), 'POST must not certify').toBe('MIGRATION_HISTORY_NOT_RECONCILED');
      } finally {
        resetHistory();
        run(teardown);
      }
    }, 300_000);
  }

  it('e-noinherit — establishes the real semantics the predicate is built on', () => {
    resetHistory();
    run(`CREATE ROLE ni_cap NOLOGIN; GRANT SELECT ON ${TBL} TO ni_cap;
         CREATE ROLE ni_login LOGIN NOINHERIT; GRANT ni_cap TO ni_login;`);

    try {
      // Inheritance-only view says "no access"...
      expect(run(`SELECT has_table_privilege('ni_login', '${TBL}', 'SELECT');`).trim()).toBe('f');

      // ...but the role can SET ROLE to the privileged role, so membership closure says "access".
      expect(run(`SELECT pg_has_role('ni_login', 'ni_cap', 'MEMBER');`).trim()).toBe('t');
      expect(preVerdict()).toBe('UNEXPECTED_MIGRATION_HISTORY_STOP');
    } finally {
      resetHistory();
      run(`DROP ROLE ni_login; DROP ROLE ni_cap;`);
    }
  }, 300_000);

  it('e-owner — the pinned owner and superusers remain the only permitted authority paths', () => {
    resetHistory();

    /*
     * The owner of the history objects is the contract owner and is excluded by
     * identity (not by name); superusers are excluded as inherent platform
     * administrators. With only those present, the healthy state verifies.
     */
    expect(
      run(`SELECT pg_get_userbyid(relowner) = current_user FROM pg_class WHERE oid = '${TBL}'::regclass;`).trim(),
    ).toBe('t');
    expect(preVerdict()).toBe('SAFE_TO_RECORD_MIGRATION_HISTORY');
  }, 300_000);
});
