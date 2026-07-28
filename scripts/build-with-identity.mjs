#!/usr/bin/env node
/**
 * QHUB verified production build — scripts/build-with-identity.mjs
 *
 * The ONLY sanctioned way to produce build/ for a Fly deploy. It:
 *   1. refuses a dirty TRACKED source tree AND untracked files that could enter
 *      the source / Docker build context (only .claude/.pnpm-store/build/ allowed),
 *   2. deletes build/ and runs a clean production build,
 *   3. requires the build to exist,
 *   4. verifies the built server bundle contains the current code markers
 *      (so a stale build cannot ship),
 *   5. records a NON-SECRET build identity: source commit, artifact hash (via the
 *      SHARED canonical implementation), lockfile hash — written to
 *      build/qhub-build-identity.json and printed as `BUILD_ENV=...` for the
 *      deploy step to inject as the EXPECTED runtime identity (QHUB_BUILD_*).
 *
 * Fails (exit 1) on any violation. No secrets are read or printed.
 */

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalArtifactHash } from './lib/canonical-artifact-hash.mjs';

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
  'reconstructForResume',
];
const ALLOWLIST_UNTRACKED = /^(\.claude\/|\.pnpm-store\/|build\/|node_modules\/)/;

// Union of bundler/config discovery + Dockerfile COPY sources (incl. functions/).
const BUILD_RELEVANT_UNTRACKED =
  /^(app\/|functions\/|scripts\/|public\/|supabase\/|electron\/|package\.json|package-lock\.json|pnpm-lock\.yaml|tsconfig[^/]*\.json|vite\.config\.|vite-electron\.config\.|remix\.config\.|uno\.config\.|wrangler\.|postcss\.config\.|tailwind\.config\.|worker-configuration\.d\.ts|bindings\.sh|Dockerfile|fly\.toml|\.dockerignore|\.eslintrc|eslint\.config\.)/;

function dirtySourcePaths(lines) {
  return lines
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0 && !l.startsWith('?? '))
    .map((l) => l.slice(3))
    .filter((p) => p && !ALLOWLIST_UNTRACKED.test(p));
}

function untrackedBuildInputs(lines) {
  return lines
    .map((l) => l.trimEnd())
    .filter((l) => l.startsWith('?? '))
    .map((l) => l.slice(3))
    .filter((p) => p && !ALLOWLIST_UNTRACKED.test(p) && BUILD_RELEVANT_UNTRACKED.test(p));
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

// 1. Refuse a dirty tracked source tree AND untracked build-context files.
const porcelain = sh('git status --porcelain').split(/\r?\n/);
const dirty = dirtySourcePaths(porcelain);

if (dirty.length > 0 && !process.env.QHUB_ALLOW_DIRTY_BUILD) {
  die(`uncommitted tracked source changes present — commit before building:\n  ${dirty.join('\n  ')}`);
}

const untracked = untrackedBuildInputs(porcelain);

if (untracked.length > 0 && !process.env.QHUB_ALLOW_DIRTY_BUILD) {
  die(`untracked build-context files present — commit or remove before building:\n  ${untracked.join('\n  ')}`);
}

/*
 * 1b. Reject Vite-loaded .env files that are INVISIBLE to `git status` (ignored),
 *     at repo root or under functions/ — they can silently change the artifact.
 */
function viteLoadedEnvFiles(paths) {
  return paths
    .map((p) => p.replace(/\\/g, '/').trim())
    .filter((p) => p.length > 0)
    .filter((p) => {
      const base = p.split('/').pop() ?? '';

      if (base.endsWith('.example') || base.endsWith('.sample') || base.endsWith('.d.ts')) {
        return false;
      }

      return /^\.env(\.[A-Za-z0-9_-]+)*$/.test(base);
    });
}

/*
 * NON-TRACKED (ignored OR untracked) files are invisible to review yet Vite loads
 * them. Tracked .env templates are reviewable build inputs (part of source_commit)
 * and allowed; only non-tracked Vite env files at root or functions/ fail.
 */
let nonTracked = [];

try {
  nonTracked = [
    ...sh('git ls-files --others --ignored --exclude-standard').split(/\r?\n/),
    ...sh('git ls-files --others --exclude-standard').split(/\r?\n/),
  ];
} catch {
  nonTracked = [];
}

const loadedEnv = [...new Set(viteLoadedEnvFiles(nonTracked))].filter(
  (p) => !p.includes('/') || p.startsWith('functions/'),
);

if (loadedEnv.length > 0) {
  die(
    `non-tracked Vite-loaded .env file(s) present — a verified build must not read invisible env inputs:\n  ${loadedEnv.join('\n  ')}`,
  );
}

// 1c. Sanitized build environment: reject VITE_*/PUBLIC_*/QHUB_BUILD_* that would
//     inline into or alter the artifact (identity is injected at DEPLOY, not build).
const BUILD_ENV_ALLOWLIST = new Set(['NODE_OPTIONS', 'QHUB_ALLOW_DIRTY_BUILD']);
const badEnv = Object.keys(process.env).filter(
  (k) => (/^VITE_/.test(k) || /^PUBLIC_/.test(k) || /^QHUB_BUILD_/.test(k)) && !BUILD_ENV_ALLOWLIST.has(k),
);

if (badEnv.length > 0) {
  die(`unexpected build-time env vars present (would alter the artifact): ${badEnv.join(', ')}`);
}

const sourceCommit = sh('git rev-parse HEAD').trim();
const lockfileHash = createHash('sha256')
  .update(readFileSync(join(ROOT, 'pnpm-lock.yaml')))
  .digest('hex');

// 2. Clean build.
console.log('[build-with-identity] removing build/ …');
rmSync(join(ROOT, 'build'), { recursive: true, force: true });
console.log('[build-with-identity] running production build …');
execSync('npx --no-install remix vite:build', {
  cwd: ROOT,
  stdio: 'inherit',
  env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=4096' },
});

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

// 5. Compute artifact hash via the SHARED canonical implementation.
const files = [...walk(serverDir), ...walk(clientDir)].map((p) => {
  const buf = readFileSync(p);

  return {
    path: relative(join(ROOT, 'build'), p).replace(/\\/g, '/'),
    sha256: createHash('sha256').update(buf).digest('hex'),
    size: buf.length,
  };
});
const artifactHash = canonicalArtifactHash(files);
const builtAt = new Date().toISOString();

// Non-secret build-environment fingerprint (build provenance, not reproducibility).
const ua = process.env.npm_config_user_agent ?? '';
const pnpmVer = (ua.match(/pnpm\/([0-9.]+)/) ?? [, 'unknown'])[1];
const buildEnvironment = [
  `node=${process.version}`,
  `pnpm=${pnpmVer}`,
  `platform=${process.platform}`,
  `arch=${process.arch}`,
  `builder=remix-vite`,
  `manifest=artifact-manifest-1`,
].join(';');

const identity = {
  source_commit: sourceCommit,
  built_at: builtAt,
  artifact_hash: artifactHash,
  lockfile_hash: lockfileHash,
  build_environment: buildEnvironment,
  markers_ok: true,
};
writeFileSync(join(ROOT, 'build', 'qhub-build-identity.json'), JSON.stringify(identity, null, 2));

console.log('[build-with-identity] OK');
console.log(`  source_commit: ${sourceCommit}`);
console.log(`  artifact_hash: ${artifactHash}`);
console.log(`  lockfile_hash: ${lockfileHash}`);
console.log(`  markers_ok:    ${REQUIRED_BUILD_MARKERS.length}/${REQUIRED_BUILD_MARKERS.length}`);

console.log(`  build_environment: ${buildEnvironment}`);

// Machine-readable line the deploy step injects as the EXPECTED runtime identity.
console.log(
  `BUILD_ENV=-e QHUB_BUILD_SOURCE_COMMIT=${sourceCommit} -e QHUB_BUILD_ARTIFACT_HASH=${artifactHash} -e QHUB_BUILD_LOCKFILE_HASH=${lockfileHash} -e QHUB_BUILD_AT=${builtAt} -e "QHUB_BUILD_ENVIRONMENT=${buildEnvironment}"`,
);
