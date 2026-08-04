/**
 * Serializes the real-PostgreSQL suites against the single disposable cluster.
 *
 * PostgreSQL roles are CLUSTER-scoped, not database-scoped. A fixture role that
 * holds `pg_read_all_data` grants SELECT on every table in EVERY database of the
 * cluster — including the database a sibling suite is verifying at that moment.
 * Vitest runs test files in parallel workers, so two real-PG suites that each
 * create login roles will contaminate each other: the migration-history gate in
 * one suite correctly reports the other suite's roles as unauthorized access
 * paths, and its PRE/RECORD expectations fail for a reason that has nothing to
 * do with the code under test.
 *
 * The lock is a directory create, which is atomic on both Windows and POSIX and
 * survives across processes (a session-scoped PostgreSQL advisory lock would
 * not: every psql invocation is its own session). A lock left behind by a killed
 * worker is reclaimed once it is older than STALE_MS.
 *
 * Suites must acquire in `beforeAll` and release in `afterAll`.
 */

import { mkdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const LOCK_DIR = join(tmpdir(), 'qhub-real-pg-cluster.lock');
const WAIT_MS = 600_000;
const STALE_MS = 900_000;
const POLL_MS = 250;

export async function acquireClusterLock(): Promise<void> {
  const deadline = Date.now() + WAIT_MS;

  for (;;) {
    try {
      mkdirSync(LOCK_DIR);

      return;
    } catch {
      try {
        if (Date.now() - statSync(LOCK_DIR).mtimeMs > STALE_MS) {
          rmSync(LOCK_DIR, { recursive: true, force: true });
          continue;
        }
      } catch {
        // Released between the failed create and the stat — retry immediately.
        continue;
      }

      if (Date.now() > deadline) {
        throw new Error(`timed out after ${WAIT_MS}ms waiting for the real-PostgreSQL cluster lock`);
      }

      await new Promise((resolve) => {
        setTimeout(resolve, POLL_MS);
      });
    }
  }
}

export function releaseClusterLock(): void {
  try {
    rmSync(LOCK_DIR, { recursive: true, force: true });
  } catch {
    /* already released */
  }
}
