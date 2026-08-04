/**
 * QHUB R15.6 — MIGRATION-HISTORY RECORD: REAL-POSTGRESQL CONCURRENCY PROOFS
 * app/test/commercial-r15-6-history-concurrency.test.ts
 *
 * Proves, with TWO INDEPENDENT SESSIONS against a real PostgreSQL 16 server,
 * that 26_MIGRATION_HISTORY_RECORD.sql's LOCK TABLE ... SHARE ROW EXCLUSIVE
 * serializes every relevant writer (review P1-1):
 *   * SHARE ROW EXCLUSIVE is self-conflicting (two RECORD runs serialize)
 *   * it blocks ROW EXCLUSIVE writers (any INSERT/UPDATE/DELETE, i.e. any
 *     concurrent CLI repair or raw SQL)
 *   * conflicts committed WHILE RECORD waits for the lock are seen by the
 *     post-lock recheck and refused (wrong-name / same-name-other-version /
 *     newer-version / malformed-version races)
 *   * of two concurrent RECORD runs, exactly one records; the other no-ops
 *
 * HARNESS: requires a local scratch PostgreSQL (localhost only) prepared per
 * docs/release/r15-6-migration-history/MIGRATION_HISTORY_MECHANISM_ANALYSIS.md.
 * Configure with env vars (defaults match the validation environment):
 *   QHUB_SCRATCH_PG_BIN   directory containing psql.exe
 *   QHUB_SCRATCH_PG_PORT  port (default 54329)
 * When the harness is unavailable the suite SKIPS — loudly. A skip is NOT a
 * pass of the concurrency contract; the proofs must be run wherever the
 * harness exists (they were run and recorded for the committed package).
 * PGlite cannot host these tests: it is single-connection by construction.
 */

import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { acquireClusterLock, releaseClusterLock } from './helpers/pg-cluster-lock';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const P26 = `${REPO}docs/release/r15-6-migration-history/26_MIGRATION_HISTORY_RECORD.sql`;
const MIGRATION = `${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`;

const PG_BIN =
  process.env.QHUB_SCRATCH_PG_BIN ??
  'C:/Users/ccaba/AppData/Local/Temp/claude/C--Users-ccaba-qhub-studio/2af3a231-f755-4857-b22e-7cfdcdf5792d/scratchpad/pg/pgsql/bin';
const PORT = process.env.QHUB_SCRATCH_PG_PORT ?? '54329';
const PSQL = `${PG_BIN}/psql.exe`;
const ARGS = ['-h', '127.0.0.1', '-p', PORT, '-U', 'scratch', '-X', '-A', '-t'];
const DB = 'conctest_vitest';

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
    '[commercial-r15-6-history-concurrency] SKIPPED: no local scratch PostgreSQL harness ' +
      `(looked for ${PSQL} on port ${PORT}). The SHARE ROW EXCLUSIVE serialization proofs ` +
      'must be executed wherever the harness exists — a skip is not a pass.',
  );
}

const run = (db: string, sql: string) =>
  execFileSync(PSQL, [...ARGS, '-d', db, '-v', 'ON_ERROR_STOP=1', '-c', sql], { encoding: 'utf8', timeout: 120000 });
const runFile = (db: string, f: string) =>
  execFileSync(PSQL, [...ARGS, '-d', db, '-v', 'ON_ERROR_STOP=1', '-f', f], { encoding: 'utf8', timeout: 120000 });

class Session {
  buf = '';
  private _p: ChildProcess;

  constructor(db: string) {
    this._p = spawn(PSQL, [...ARGS, '-d', db, '-v', 'ON_ERROR_STOP=0'], { stdio: ['pipe', 'pipe', 'pipe'] });
    this._p.stdout!.on('data', (d) => {
      this.buf += d.toString();
    });
    this._p.stderr!.on('data', (d) => {
      this.buf += d.toString();
    });
  }

  send(sql: string): void {
    this._p.stdin!.write(`${sql}\n`);
  }

  async waitFor(marker: string, ms = 20000): Promise<void> {
    const t0 = Date.now();

    while (!this.buf.includes(marker)) {
      if (Date.now() - t0 > ms) {
        throw new Error(`timeout waiting for ${marker}; tail: ${this.buf.slice(-300)}`);
      }

      await new Promise((r) => setTimeout(r, 50));
    }
  }

  async idleHas(marker: string, ms: number): Promise<boolean> {
    await new Promise((r) => setTimeout(r, ms));

    return this.buf.includes(marker);
  }

  end(): void {
    try {
      this._p.stdin!.end();
    } catch {
      /* already closed */
    }

    try {
      this._p.kill();
    } catch {
      /* already dead */
    }
  }
}

function resetHistory(): void {
  run(
    DB,
    `DROP SCHEMA IF EXISTS supabase_migrations CASCADE;
    CREATE SCHEMA supabase_migrations;
    CREATE TABLE supabase_migrations.schema_migrations (version text NOT NULL PRIMARY KEY);
    ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS statements text[];
    ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS name text;
    INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES
     ('20260723','qhub_applications'),('20260725','gate03_policy'),
     ('20260726','gate04_enforcement'),('20260727','agent_framework_foundation');`,
  );
}

const histDump = () =>
  run(
    DB,
    `SELECT version || '=' || coalesce(name, '(null)') || ':' || coalesce(cardinality(statements)::text, 'null')
             FROM supabase_migrations.schema_migrations ORDER BY version;`,
  ).trim();

describe.skipIf(!HAVE_PG)('R15.6 RECORD — SHARE ROW EXCLUSIVE serialization on real PostgreSQL', () => {
  beforeAll(async () => {
    /*
     * Roles are cluster-scoped: RECORD 26's privilege gate would otherwise see
     * a sibling real-PG suite's fixture roles and refuse for an unrelated reason.
     */
    await acquireClusterLock();

    for (const role of ['anon NOLOGIN', 'authenticated NOLOGIN', 'service_role NOLOGIN BYPASSRLS']) {
      try {
        run('postgres', `CREATE ROLE ${role};`);
      } catch {
        /* exists */
      }
    }

    try {
      run('postgres', `DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`);
    } catch {
      /* n/a */
    }
    run('postgres', `CREATE DATABASE ${DB};`);
    run(
      DB,
      `ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`,
    );
    runFile(DB, MIGRATION);
  }, 300_000);

  afterAll(() => {
    try {
      run('postgres', `DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`);
    } catch {
      /* n/a */
    }

    releaseClusterLock();
  }, 300_000);

  it('c1 — SRE self-conflicts: a second SHARE ROW EXCLUSIVE lock times out while the first is held', async () => {
    resetHistory();

    const a = new Session(DB);

    try {
      a.send(`BEGIN; LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE; SELECT 'A_LOCKED';`);
      await a.waitFor('A_LOCKED');

      const b = new Session(DB);

      try {
        b.send(`SET lock_timeout='1200ms';`);
        b.send(`BEGIN; LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE;`);
        await b.waitFor('canceling statement due to lock timeout', 10000);
      } finally {
        b.end();
      }
    } finally {
      a.send('ROLLBACK;');
      a.end();
    }
  }, 120_000);

  it('c2 — SRE blocks ROW EXCLUSIVE writers: a plain INSERT times out and leaves no row', async () => {
    resetHistory();

    const a = new Session(DB);

    try {
      a.send(`BEGIN; LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE; SELECT 'A_LOCKED';`);
      await a.waitFor('A_LOCKED');

      const c = new Session(DB);

      try {
        c.send(`SET statement_timeout='1200ms';`);
        c.send(`INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260888', 'x');`);
        await c.waitFor('canceling statement due to statement timeout', 10000);
      } finally {
        c.end();
      }
    } finally {
      a.send('ROLLBACK;');
      a.end();
    }

    expect(
      run(DB, `SELECT count(*) FROM supabase_migrations.schema_migrations WHERE version = '20260888';`).trim(),
    ).toBe('0');
  }, 120_000);

  const RACES: Array<[string, string, RegExp]> = [
    /*
     * R15.6.2 — a GRANT committed while 26 waits on the lock must be refused by
     * the post-lock privilege recheck. NOTE (empirically verified): GRANT does
     * NOT conflict with SHARE ROW EXCLUSIVE, so the guarantee here is
     * visibility, not serialization — 26 makes NO pre-lock authorization
     * decision, and its post-lock READ COMMITTED recheck sees every grant
     * committed up to lock acquisition. A grant committed after the recheck
     * cannot alter the recorded row and is refused by the mandatory POST 27
     * certification in its own snapshot.
     */
    [
      'anon SELECT granted during the wait',
      `GRANT SELECT ON supabase_migrations.schema_migrations TO anon;`,
      /unexpected_migration_history_privilege/,
    ],
    [
      'wrong-name target row committed during the wait',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260729', 'something_else');`,
      /migration_history_conflict/,
    ],
    [
      'same name under another version committed during the wait',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260728', 'commercial_launch_foundation');`,
      /migration_history_conflict/,
    ],
    [
      'newer version committed during the wait',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('20260801', 'mystery');`,
      /migration_history_conflict/,
    ],
    [
      'malformed version committed during the wait',
      `INSERT INTO supabase_migrations.schema_migrations (version, name) VALUES ('2026x729', 'weird');`,
      /migration_history_conflict/,
    ],
  ];

  for (const [label, conflictSql, refusalRx] of RACES) {
    it(`c3 — race: ${label} => 26 blocks, then its post-lock recheck refuses`, async () => {
      resetHistory();

      const a = new Session(DB);

      try {
        a.send(
          `BEGIN; LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE; SELECT 'A_LOCKED';`,
        );
        await a.waitFor('A_LOCKED');

        const b = new Session(DB);

        try {
          b.send(`\\i ${P26.replace(/\\/g, '/')}`);
          b.send(`SELECT 'B_FINISHED';`);

          // 26 must be blocked on the lock, not finished.
          expect(await b.idleHas('B_FINISHED', 1500)).toBe(false);

          // The conflicting state commits while 26 is still waiting.
          a.send(conflictSql);
          a.send(`COMMIT; SELECT 'A_DONE';`);
          await a.waitFor('A_DONE');

          await b.waitFor('B_FINISHED', 30000);
          expect(b.buf).toMatch(refusalRx);
        } finally {
          b.end();
        }
      } finally {
        a.end();
      }

      expect(histDump()).not.toContain('20260729=commercial_launch_foundation:89');
    }, 120_000);
  }

  it('c4 — two concurrent 26 runs: exactly one records; a subsequent fresh-session run no-ops', async () => {
    resetHistory();

    const a = new Session(DB);

    try {
      a.send(`BEGIN; LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE; SELECT 'A_LOCKED';`);
      await a.waitFor('A_LOCKED');

      const b = new Session(DB);

      try {
        b.send(`\\i ${P26.replace(/\\/g, '/')}`);
        b.send(`SELECT 'B_FINISHED';`);
        expect(await b.idleHas('B_FINISHED', 1500)).toBe(false);

        a.send(`ROLLBACK; SELECT 'A_DONE';`);
        await a.waitFor('A_DONE');

        await b.waitFor('B_FINISHED', 30000);
        expect(b.buf).toMatch(/RECORDED_NOW/);
      } finally {
        b.end();
      }
    } finally {
      a.end();
    }

    const second = runFile(DB, P26);
    expect(second).toMatch(/ALREADY_RECORDED_EXACTLY/);

    const hist = histDump();
    expect((hist.match(/20260729=commercial_launch_foundation:89/g) ?? []).length).toBe(1);
  }, 180_000);
});
