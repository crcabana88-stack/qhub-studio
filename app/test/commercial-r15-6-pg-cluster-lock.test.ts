/**
 * QHUB R15.6.5 — adversarial validation of the cross-process cluster lock
 * app/test/commercial-r15-6-pg-cluster-lock.test.ts
 *
 * The independent review found a P2 ownership race in the previous lock: a
 * waiter could reap a LIVE holder's lock purely because its mtime looked old,
 * and the displaced holder could then delete the successor's lock, permitting
 * overlapping holders of the "exclusive" section. The corrected lock removes
 * automatic stale takeover entirely and verifies ownership by unique token
 * before any deletion. This suite attacks that design directly:
 *
 *   * simultaneous acquisition (in-process instances AND separate OS
 *     processes) admits exactly one holder;
 *   * a live owner whose timestamp looks ancient is NEVER reaped;
 *   * a timed-out waiter deletes nothing and reports the exact lock path and
 *     owner metadata;
 *   * a former owner cannot delete a successor's lock;
 *   * release works on normal completion and on caught failure, deletes only
 *     the lock directory itself, and leaves nothing behind.
 *
 * Pure filesystem suite — no PostgreSQL required.
 */

import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DirectoryLock } from './helpers/pg-cluster-lock';

const SCRATCH = join(tmpdir(), `qhub-lock-test-${process.pid}`);
let seq = 0;

function freshLockDir(): string {
  seq += 1;
  mkdirSync(SCRATCH, { recursive: true });

  return join(SCRATCH, `lock-${seq}`);
}

afterEach(() => {
  rmSync(SCRATCH, { recursive: true, force: true });
});

const sleep = (ms: number) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

describe('R15.6.5 — pg cluster lock: ownership and mutual exclusion', () => {
  it('l1 — two concurrent acquirers: exactly one enters the protected section at a time', async () => {
    const dir = freshLockDir();
    const a = new DirectoryLock(dir, { waitMs: 10_000, pollMs: 20 });
    const b = new DirectoryLock(dir, { waitMs: 10_000, pollMs: 20 });
    let inside = 0;
    let maxInside = 0;
    const overlaps: string[] = [];

    const worker = async (lock: DirectoryLock, name: string) => {
      await lock.acquire();
      inside += 1;
      maxInside = Math.max(maxInside, inside);

      if (inside > 1) {
        overlaps.push(name);
      }

      await sleep(120);
      inside -= 1;
      lock.release();
    };

    await Promise.all([worker(a, 'a'), worker(b, 'b')]);
    expect(maxInside, `overlapping holders: ${overlaps.join(',')}`).toBe(1);
    expect(existsSync(dir), 'no leftover lock after both released').toBe(false);
  });

  it('l2 — cross-process: two OS processes race the same atomic mkdir; exactly one wins', async () => {
    const dir = freshLockDir();
    mkdirSync(SCRATCH, { recursive: true });

    /*
     * Each child performs the lock's acquisition primitive (a single
     * non-recursive mkdir of the fully resolved path) once and reports the
     * outcome. Atomicity across processes is the OS guarantee the lock builds
     * on, so it is proven with real separate processes.
     */
    const script =
      `try { require('node:fs').mkdirSync(${JSON.stringify(dir)}); console.log('WON'); }` +
      ` catch { console.log('LOST'); }`;
    const runChild = () =>
      new Promise<string>((resolve, reject) => {
        execFile(process.execPath, ['-e', script], { timeout: 30_000 }, (err, stdout) => {
          if (err) {
            reject(err);
          } else {
            resolve(stdout.trim());
          }
        });
      });

    const results = await Promise.all([runChild(), runChild()]);
    expect(results.filter((r) => r === 'WON').length, `results: ${results.join(',')}`).toBe(1);
    expect(results.filter((r) => r === 'LOST').length).toBe(1);
  });

  it('l3 — a live owner with an ancient-looking timestamp is never reaped', async () => {
    const dir = freshLockDir();
    const owner = new DirectoryLock(dir, { waitMs: 10_000, pollMs: 20 });
    await owner.acquire();

    const ownerRecord = JSON.parse(readFileSync(join(dir, 'owner.json'), 'utf8')) as { token: string };

    // Backdate far beyond any conceivable staleness threshold.
    const ancient = (Date.now() - 7 * 24 * 3600 * 1000) / 1000;
    utimesSync(dir, ancient, ancient);
    utimesSync(join(dir, 'owner.json'), ancient, ancient);

    const waiter = new DirectoryLock(dir, { waitMs: 400, pollMs: 20 });
    await expect(waiter.acquire()).rejects.toThrow(/timed out/);

    // The live owner's lock is intact and still carries the owner's token.
    expect(existsSync(dir)).toBe(true);

    const after = JSON.parse(readFileSync(join(dir, 'owner.json'), 'utf8')) as { token: string };
    expect(after.token).toBe(ownerRecord.token);

    owner.release();
    expect(existsSync(dir)).toBe(false);
  });

  it('l4 — a timed-out waiter reports the exact lock path and owner metadata, and deletes nothing', async () => {
    const dir = freshLockDir();

    // A foreign (orphan-looking) lock created by some other process.
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'owner.json'), JSON.stringify({ token: 'foreign-token', pid: 424242, acquiredAt: 'x' }));

    const waiter = new DirectoryLock(dir, { waitMs: 300, pollMs: 20 });
    let message = '';

    try {
      await waiter.acquire();
    } catch (e) {
      message = (e as Error).message;
    }

    expect(message).toContain(dir);
    expect(message).toContain('foreign-token');
    expect(message).toContain('424242');
    expect(message).toMatch(/remove that directory manually/);

    // Nothing was deleted; release by the timed-out waiter is a no-op too.
    expect(existsSync(join(dir, 'owner.json'))).toBe(true);
    waiter.release();
    expect(existsSync(join(dir, 'owner.json'))).toBe(true);
  });

  it('l5 — a former owner cannot delete a successor lock', async () => {
    const dir = freshLockDir();
    const a = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await a.acquire();

    /*
     * Simulate the exact accident the review described: A's lock is removed
     * out from under it (the old mtime-reaper, a manual cleanup, a crash
     * handler), and B acquires legitimately.
     */
    rmSync(dir, { recursive: true, force: true });

    const b = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await b.acquire();

    const bToken = (JSON.parse(readFileSync(join(dir, 'owner.json'), 'utf8')) as { token: string }).token;

    // A's release must observe the foreign token and leave B's lock intact.
    a.release();
    expect(existsSync(dir), 'successor lock must survive the former owner release').toBe(true);

    const stillB = JSON.parse(readFileSync(join(dir, 'owner.json'), 'utf8')) as { token: string };
    expect(stillB.token).toBe(bToken);

    b.release();
    expect(existsSync(dir)).toBe(false);
  });

  it('l6 — normal release removes exactly the lock directory and nothing else', async () => {
    const dir = freshLockDir();
    mkdirSync(SCRATCH, { recursive: true });

    const sibling = join(SCRATCH, 'sibling-must-survive.txt');
    writeFileSync(sibling, 'untouched');

    const lock = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await lock.acquire();
    expect(lock.held).toBe(true);
    lock.release();

    expect(lock.held).toBe(false);
    expect(existsSync(dir)).toBe(false);
    expect(readFileSync(sibling, 'utf8'), 'narrow deletion target').toBe('untouched');
  });

  it('l7 — release on the caught-failure path frees the lock for the next acquirer', async () => {
    const dir = freshLockDir();
    const lock = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });

    try {
      await lock.acquire();
      throw new Error('simulated suite failure inside the protected section');
    } catch {
      lock.release();
    }

    expect(existsSync(dir)).toBe(false);

    const next = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await next.acquire();
    next.release();
    expect(existsSync(dir)).toBe(false);
  });

  it('l8 — double release and release-without-acquire are safe no-ops', async () => {
    const dir = freshLockDir();
    const never = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    never.release(); // never acquired — nothing to do, nothing thrown

    const a = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await a.acquire();
    a.release();

    const b = new DirectoryLock(dir, { waitMs: 5_000, pollMs: 20 });
    await b.acquire();

    // A releasing AGAIN after B acquired must not touch B's lock.
    a.release();
    expect(existsSync(dir)).toBe(true);
    b.release();
    expect(existsSync(dir)).toBe(false);
  });

  it('l9 — re-acquiring while already holding is rejected instead of deadlocking', async () => {
    const dir = freshLockDir();
    const lock = new DirectoryLock(dir, { waitMs: 500, pollMs: 20 });
    await lock.acquire();
    await expect(lock.acquire()).rejects.toThrow(/already held/);
    lock.release();
    expect(existsSync(dir)).toBe(false);
  });

  it('l10 — waiting acquirer proceeds as soon as the holder releases', async () => {
    const dir = freshLockDir();
    const a = new DirectoryLock(dir, { waitMs: 10_000, pollMs: 20 });
    const b = new DirectoryLock(dir, { waitMs: 10_000, pollMs: 20 });
    await a.acquire();

    const pending = b.acquire();
    await sleep(150);
    expect(b.held, 'b must still be waiting').toBe(false);

    a.release();
    await pending;
    expect(b.held).toBe(true);
    b.release();
    expect(existsSync(dir)).toBe(false);
  });
});
