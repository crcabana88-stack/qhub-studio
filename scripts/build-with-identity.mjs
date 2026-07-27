#!/usr/bin/env node
/**
 * QHUB verified production build — scripts/build-with-identity.mjs
 *
 * The ONLY sanctioned way to produce build/ for a Fly deploy. It:
 *   1. refuses a dirty TRACKED source tree (no uncommitted source shipped),
 *   2. deletes build/ and runs a clean production build,
 *   3. requires the build to exist,
 *   4. verifies the built server bundle contains the current code markers
 *      (so a stale build cannot ship),
 *   5. records a NON-SECRET build identity: source commit, artifact hash,
 *      lockfile hash — written to build/qhub-build-identity.json and printed as
 *      `BUILD_ENV=...` for the deploy step to inject as runtime env.
 *
 * Fails (exit 1) on any violation. No secrets are read or printed.
 */

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const sh = (cmd) => execSync(cmd, { cwd: ROOT, encoding: 'utf8' });
const die = (msg) => {
  console.error(`[build-with-identity] FAIL: ${msg}`);
  process.exit(1);
};

// Inline copies of the pure helpers (kept in sync with app/lib/qhub/build-identity.ts).
const REQUIRED_BUILD_MARKERS = [
  'canonicalAgentManifestString',
  'qhub_verify_agent_schema',
  'freeze_release',
  'bind_release',
  'AGENT_MANIFEST_NOT_IN_RELEASE',
  'qhub_verify_governance_schema',
  'qhub.runtime.langgraph',
];
function dirtySourcePaths(lines) {
  const excluded = /^(\.claude\/|\.pnpm-store\/|build\/|node_modules\/)/;

  return lines
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0 && !l.startsWith('?? '))
    .map((l) => l.slice(3))
    .filter((p) => p && !excluded.test(p));
}
function walk(dir) {
  const out = [];

  for (const name of readdirSync(dir)) {
    const p = join(dir, name);

    if (statSync(p).isDirectory()) {
      out.push(...walk(p));
    } else {
      out.push(p);
    }
  }

  return out;
}

// 1. Refuse a dirty tracked source tree.
const porcelain = sh('git status --porcelain').split(/\r?\n/);
const dirty = dirtySourcePaths(porcelain);

if (dirty.length > 0 && !process.env.QHUB_ALLOW_DIRTY_BUILD) {
  die(`uncommitted tracked source changes present — commit before building:\n  ${dirty.join('\n  ')}`);
}

const sourceCommit = sh('git rev-parse HEAD').trim();
const lockfileHash = createHash('sha256').update(readFileSync(join(ROOT, 'pnpm-lock.yaml'))).digest('hex');

// 2. Clean build.
console.log('[build-with-identity] removing build/ …');
rmSync(join(ROOT, 'build'), { recursive: true, force: true });
console.log('[build-with-identity] running production build …');
execSync('npx --no-install remix vite:build', { cwd: ROOT, stdio: 'inherit', env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=4096' } });

// 3. Require the build to exist.
const serverDir = join(ROOT, 'build', 'server');
const clientDir = join(ROOT, 'build', 'client');

if (!existsSync(serverDir) || !existsSync(clientDir)) {
  die('clean build did not produce build/server and build/client');
}

// 4. Verify current code markers are in the built server bundle.
const serverText = walk(serverDir)
  .filter((p) => p.endsWith('.js'))
  .map((p) => readFileSync(p, 'utf8'))
  .join('\n');
const missing = REQUIRED_BUILD_MARKERS.filter((m) => !serverText.includes(m));

if (missing.length > 0) {
  die(`built bundle is missing current code markers (stale build?): ${missing.join(', ')}`);
}

// 5. Compute artifact hash + write identity.
const files = [...walk(serverDir), ...walk(clientDir)]
  .map((p) => ({ path: relative(join(ROOT, 'build'), p).replace(/\\/g, '/'), sha256: createHash('sha256').update(readFileSync(p)).digest('hex') }))
  .filter((f) => f.path !== 'qhub-build-identity.json');
const artifactHash = createHash('sha256').update(files.map((f) => `${f.path} ${f.sha256}`).sort().join('\n')).digest('hex');
const builtAt = new Date().toISOString();

const identity = { source_commit: sourceCommit, built_at: builtAt, artifact_hash: artifactHash, lockfile_hash: lockfileHash, markers_ok: true };
writeFileSync(join(ROOT, 'build', 'qhub-build-identity.json'), JSON.stringify(identity, null, 2));

console.log('[build-with-identity] OK');
console.log(`  source_commit: ${sourceCommit}`);
console.log(`  artifact_hash: ${artifactHash}`);
console.log(`  lockfile_hash: ${lockfileHash}`);
console.log(`  markers_ok:    ${REQUIRED_BUILD_MARKERS.length}/${REQUIRED_BUILD_MARKERS.length}`);
// Machine-readable line the deploy step injects as runtime env (non-secret).
console.log(`BUILD_ENV=-e QHUB_BUILD_SOURCE_COMMIT=${sourceCommit} -e QHUB_BUILD_ARTIFACT_HASH=${artifactHash} -e QHUB_BUILD_AT=${builtAt}`);
