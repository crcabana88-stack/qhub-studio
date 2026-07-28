/**
 * QHUB Deployment integrity tests — app/test/build-identity.test.ts
 *
 * Proves the stale-build guard's logic and the runtime-to-image identity
 * comparison (source + artifact + lockfile), plus clean-build-input handling.
 */

import { describe, it, expect } from 'vitest';
import {
  REQUIRED_BUILD_MARKERS,
  missingMarkers,
  dirtySourcePaths,
  untrackedBuildInputs,
  viteLoadedEnvFiles,
  unexpectedBuildEnv,
  evaluateBuildIntegrity,
  type BuildIdentityTriple,
} from '~/lib/qhub/build-identity';

describe('deployment build integrity — markers', () => {
  it('flags a stale bundle that lacks a current source marker', () => {
    const staleBundle = 'function create(){} function version(){} qhub_verify_governance_schema';
    const missing = missingMarkers(staleBundle);
    expect(missing).toContain('freeze_release');
    expect(missing.length).toBeGreaterThan(0);
  });

  it('passes when every current marker is present', () => {
    expect(missingMarkers(REQUIRED_BUILD_MARKERS.join(' '))).toEqual([]);
  });

  it('requires the production no-replay reconstruction marker', () => {
    expect(REQUIRED_BUILD_MARKERS).toContain('reconstructForResume');
  });
});

describe('clean build inputs', () => {
  it('refuses a dirty tracked source tree', () => {
    const porcelain = [' M app/routes/api.agent.ts', 'A  app/lib/qhub/new.ts'];
    expect(dirtySourcePaths(porcelain)).toEqual(['app/routes/api.agent.ts', 'app/lib/qhub/new.ts']);
  });

  it('excludes untracked and known artifact dirs from the dirty (tracked) check', () => {
    const porcelain = ['?? scratch.mjs', ' M .claude/x', ' M .pnpm-store/y', ' M build/z.js', ' M app/real.ts'];
    expect(dirtySourcePaths(porcelain)).toEqual(['app/real.ts']);
  });

  it('rejects untracked build-relevant files across every category', () => {
    const porcelain = [
      '?? app/routes/api.evil.ts', // untracked route
      '?? functions/[[path]].ts', // Docker COPY functions/
      '?? scripts/sneaky.mjs', // untracked script
      '?? public/evil.js', // Docker COPY public/
      '?? supabase/migrations/evil.sql', // supabase
      '?? postcss.config.js', // PostCSS root config
      '?? tailwind.config.ts', // Tailwind root config
      '?? vite.config.ts', // bundler config
      '?? remix.config.js', // Remix config
      '?? wrangler.toml', // Wrangler config
      '?? tsconfig.build.json', // TS config
      '?? Dockerfile.bak', // Docker
      '?? fly.toml', // Fly
      '?? bindings.sh', // bindings
      '?? worker-configuration.d.ts', // worker types
      '?? .claude/notes.md', // allowed artifact
      '?? .pnpm-store/pkg', // allowed artifact
      '?? build/server/x.js', // build output
      '?? README.notes', // not build-relevant → ignored
    ];
    const flagged = untrackedBuildInputs(porcelain);

    for (const p of [
      'app/routes/api.evil.ts',
      'functions/[[path]].ts',
      'scripts/sneaky.mjs',
      'public/evil.js',
      'supabase/migrations/evil.sql',
      'postcss.config.js',
      'tailwind.config.ts',
      'vite.config.ts',
      'remix.config.js',
      'wrangler.toml',
      'tsconfig.build.json',
      'Dockerfile.bak',
      'fly.toml',
      'bindings.sh',
      'worker-configuration.d.ts',
    ]) {
      expect(flagged).toContain(p);
    }
    expect(flagged).not.toContain('README.notes');
  });

  it('untracked functions/** fails the build (Docker COPY source)', () => {
    expect(untrackedBuildInputs(['?? functions/hello.ts'])).toEqual(['functions/hello.ts']);
  });

  it('untracked postcss config fails the build', () => {
    expect(untrackedBuildInputs(['?? postcss.config.js'])).toEqual(['postcss.config.js']);
  });

  it('allows only the narrow untracked artifact allowlist', () => {
    const porcelain = ['?? .claude/', '?? .pnpm-store/', '?? build/server/x.js', '?? node_modules/x'];
    expect(untrackedBuildInputs(porcelain)).toEqual([]);
  });
});

describe('ignored Vite env files (invisible to git status)', () => {
  it('flags every Vite-loaded .env file at root and under functions/', () => {
    const flagged = viteLoadedEnvFiles([
      '.env',
      '.env.local',
      '.env.production',
      '.env.production.local',
      '.env.staging',
      '.env.staging.local',
      'functions/.env',
      '.env.example', // template, not loaded → ignored
      '.env.d.ts', // type file, not loaded → ignored
      'README.md', // unrelated
    ]);

    for (const p of [
      '.env',
      '.env.local',
      '.env.production',
      '.env.production.local',
      '.env.staging',
      'functions/.env',
    ]) {
      expect(flagged).toContain(p);
    }
    expect(flagged).not.toContain('.env.example');
    expect(flagged).not.toContain('.env.d.ts');
    expect(flagged).not.toContain('README.md');
  });

  it('.env.example alone does not affect the build', () => {
    expect(viteLoadedEnvFiles(['.env.example'])).toEqual([]);
  });
});

describe('sanitized build environment', () => {
  it('rejects unexpected VITE_*, PUBLIC_*, and build-time QHUB_BUILD_* variables', () => {
    const bad = unexpectedBuildEnv(['VITE_SECRET', 'PUBLIC_URL', 'QHUB_BUILD_SOURCE_COMMIT', 'PATH', 'NODE_OPTIONS']);
    expect(bad).toContain('VITE_SECRET');
    expect(bad).toContain('PUBLIC_URL');
    expect(bad).toContain('QHUB_BUILD_SOURCE_COMMIT');
    expect(bad).not.toContain('PATH');
    expect(bad).not.toContain('NODE_OPTIONS');
  });

  it('permits an empty/clean environment', () => {
    expect(unexpectedBuildEnv(['PATH', 'HOME', 'NODE_OPTIONS', 'QHUB_ALLOW_DIRTY_BUILD'])).toEqual([]);
  });
});

describe('runtime-to-image identity comparison (source + artifact + lockfile)', () => {
  const image: BuildIdentityTriple = {
    source_commit: 'abc',
    artifact_hash: 'art',
    lockfile_hash: 'lock',
    build_at: 't',
  };
  const expected: BuildIdentityTriple = {
    source_commit: 'abc',
    artifact_hash: 'art',
    lockfile_hash: 'lock',
    build_at: 't',
  };

  it('is ready when both identities are present and all three hashes match', () => {
    const r = evaluateBuildIntegrity(expected, image);
    expect(r.present).toBe(true);
    expect(r.ready).toBe(true);
    expect(r.mismatch_reason_codes).toEqual([]);
  });

  it('fails on a source-commit mismatch', () => {
    const r = evaluateBuildIntegrity({ ...expected, source_commit: 'WRONG' }, image);
    expect(r.ready).toBe(false);
    expect(r.mismatch_reason_codes).toContain('SOURCE_COMMIT_MISMATCH');
  });

  it('fails on an artifact-hash mismatch', () => {
    const r = evaluateBuildIntegrity({ ...expected, artifact_hash: 'WRONG' }, image);
    expect(r.ready).toBe(false);
    expect(r.mismatch_reason_codes).toContain('ARTIFACT_HASH_MISMATCH');
  });

  it('fails on a lockfile-hash mismatch', () => {
    const r = evaluateBuildIntegrity({ ...expected, lockfile_hash: 'WRONG' }, image);
    expect(r.ready).toBe(false);
    expect(r.mismatch_reason_codes).toContain('LOCKFILE_HASH_MISMATCH');
  });

  it('is not ready when the expected identity is absent', () => {
    const r = evaluateBuildIntegrity({ source_commit: null, artifact_hash: null, lockfile_hash: null }, image);
    expect(r.present).toBe(false);
    expect(r.ready).toBe(false);
    expect(r.mismatch_reason_codes).toContain('MISSING_EXPECTED_IDENTITY');
  });

  it('is not ready when the on-image identity is absent (never compares a value to itself)', () => {
    const r = evaluateBuildIntegrity(expected, { source_commit: null, artifact_hash: null, lockfile_hash: null });
    expect(r.present).toBe(false);
    expect(r.ready).toBe(false);
    expect(r.mismatch_reason_codes).toContain('MISSING_IMAGE_IDENTITY');
  });
});
