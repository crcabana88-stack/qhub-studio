/**
 * Serializes the real-PostgreSQL suites against the single disposable cluster.
 *
 * WHY. PostgreSQL roles are CLUSTER-scoped, not database-scoped. A fixture role
 * that holds `pg_read_all_data` grants SELECT on every table in EVERY database
 * of the cluster — including the database a sibling suite is verifying at that
 * moment. Vitest runs test files in parallel workers, so two real-PG suites
 * that each create login roles will contaminate each other: the
 * migration-history gate in one suite correctly reports the other suite's
 * roles as unauthorized access paths, and its expectations fail for a reason
 * unrelated to the code under test.
 *
 * DESIGN (corrected after independent review). The previous revision reaped
 * any lock whose mtime looked old. That is a race: a waiter could delete a
 * LIVE holder's lock, and the displaced holder's release could then delete the
 * successor's lock, permitting overlapping holders. This revision removes
 * automatic stale takeover entirely:
 *
 *   * Acquisition is a single atomic `mkdir` of a fixed, fully resolved
 *     directory under the OS temp dir. Exactly one process/worker can create
 *     it; everyone else polls.
 *   * The winner immediately records ownership metadata (a cryptographically
 *     unique token, pid, timestamp) inside the lock. If recording fails the
 *     winner removes its own directory and rethrows — it never holds an
 *     anonymous lock.
 *   * NOTHING ever deletes a lock it cannot prove it owns. Release re-reads
 *     the owner file and deletes only when the recorded token equals the token
 *     this instance created. A former owner therefore cannot delete a
 *     successor's lock, and a timed-out waiter deletes nothing at all.
 *   * A waiter that exceeds the bounded timeout throws an actionable error
 *     naming the exact lock path and the recorded ownership metadata, so a
 *     human can decide whether the holder is an orphan and remove it manually.
 *   * Only the fixed lock directory itself is ever removed — no broad,
 *     relative, or environment-derived path is ever deleted.
 *
 * Suites acquire in `beforeAll` and release in `afterAll` (vitest runs
 * `afterAll` even when `beforeAll` failed, and release is a safe no-op when
 * the lock was never acquired or is now owned by someone else).
 */

import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

interface OwnerRecord {
  token: string;
  pid: number;
  acquiredAt: string;
}

export interface DirectoryLockOptions {
  waitMs?: number;
  pollMs?: number;
}

export class DirectoryLock {
  private readonly _lockDir: string;

  private readonly _ownerFile: string;

  private readonly _waitMs: number;

  private readonly _pollMs: number;

  private _heldToken: string | null = null;

  constructor(lockDir: string, options: DirectoryLockOptions = {}) {
    this._lockDir = lockDir;
    this._ownerFile = join(lockDir, 'owner.json');
    this._waitMs = options.waitMs ?? 900_000;
    this._pollMs = options.pollMs ?? 250;
  }

  get path(): string {
    return this._lockDir;
  }

  /** True only while THIS instance verifiably owns the lock. */
  get held(): boolean {
    return this._heldToken !== null;
  }

  private _readOwner(): OwnerRecord | null {
    try {
      return JSON.parse(readFileSync(this._ownerFile, 'utf8')) as OwnerRecord;
    } catch {
      return null;
    }
  }

  async acquire(): Promise<void> {
    if (this._heldToken !== null) {
      throw new Error(`lock ${this._lockDir} is already held by this instance`);
    }

    const deadline = Date.now() + this._waitMs;

    for (;;) {
      try {
        mkdirSync(this._lockDir);
      } catch (e) {
        /*
         * Only EEXIST means "someone holds the lock" — anything else (missing
         * parent, permissions) is a real error and must surface immediately.
         */
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw e;
        }

        /*
         * Someone else holds it. Never reap — age proves nothing about
         * liveness. Wait for the owner to release, up to the bounded timeout.
         */
        if (Date.now() >= deadline) {
          const owner = this._readOwner();
          throw new Error(
            `timed out after ${this._waitMs}ms waiting for the PostgreSQL cluster lock at ` +
              `${this._lockDir} (held by: ${owner ? JSON.stringify(owner) : '(no readable owner metadata)'}). ` +
              'If the holding process is confirmed dead, remove that directory manually and retry.',
          );
        }

        await new Promise((resolve) => {
          setTimeout(resolve, this._pollMs);
        });
        continue;
      }

      const token = randomUUID();

      try {
        const record: OwnerRecord = { token, pid: process.pid, acquiredAt: new Date().toISOString() };
        writeFileSync(this._ownerFile, JSON.stringify(record));
      } catch (e) {
        // Never hold an anonymous lock: undo our own mkdir and surface the error.
        rmSync(this._lockDir, { recursive: true, force: true });
        throw e;
      }

      this._heldToken = token;

      return;
    }
  }

  /**
   * Deletes the lock only when this instance can PROVE ownership: the recorded
   * token must equal the token written at acquisition. Safe to call on normal
   * completion, on caught failure, and when the lock was never acquired.
   */
  release(): void {
    if (this._heldToken === null) {
      return;
    }

    const owner = this._readOwner();

    /*
     * Unreadable or foreign metadata means the lock is not verifiably ours
     * (e.g. it was externally removed and re-acquired by a successor): leave
     * it untouched. Ownership is surrendered either way.
     */
    if (owner === null || owner.token !== this._heldToken) {
      this._heldToken = null;

      return;
    }

    this._heldToken = null;
    rmSync(this._lockDir, { recursive: true, force: true });
  }
}

const clusterLock = new DirectoryLock(join(tmpdir(), 'qhub-real-pg-cluster.lock'));

export async function acquireClusterLock(): Promise<void> {
  await clusterLock.acquire();
}

export function releaseClusterLock(): void {
  clusterLock.release();
}
