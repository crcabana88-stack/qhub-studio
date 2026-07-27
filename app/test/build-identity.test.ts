/**
 * QHUB Deployment integrity tests — app/test/build-identity.test.ts
 *
 * Proves the stale-build guard's logic: source changes cannot ship an old build,
 * missing markers fail, the artifact hash is deterministic and input-sensitive,
 * a dirty tracked source tree is refused, and known artifact dirs are excluded.
 */

import { describe, it, expect } from 'vitest';
import {
  REQUIRED_BUILD_MARKERS,
  computeArtifactHash,
  missingMarkers,
  dirtySourcePaths,
  compareBuildIdentity,
} from '~/lib/qhub/build-identity';

describe('deployment build integrity', () => {
  it('flags a stale bundle that lacks a current source marker (proof 1/4)', () => {
    // A bundle built BEFORE the freeze_release route existed.
    const staleBundle = 'function create(){} function version(){} qhub_verify_governance_schema';
    const missing = missingMarkers(staleBundle);
    expect(missing).toContain('freeze_release');
    expect(missing.length).toBeGreaterThan(0);
  });

  it('passes when every current marker is present (proof 4)', () => {
    const current = REQUIRED_BUILD_MARKERS.join(' ');
    expect(missingMarkers(current)).toEqual([]);
  });

  it('artifact hash is deterministic and input-sensitive (proof 6)', () => {
    const a = [
      { path: 'server/index.js', sha256: 'aa' },
      { path: 'client/app.js', sha256: 'bb' },
    ];
    const b = [
      { path: 'client/app.js', sha256: 'bb' },
      { path: 'server/index.js', sha256: 'aa' },
    ];

    // Order-independent (sorted), so identical inputs → identical hash.
    expect(computeArtifactHash(a)).toBe(computeArtifactHash(b));

    // A changed file → a changed artifact hash.
    expect(computeArtifactHash(a)).not.toBe(
      computeArtifactHash([
        { path: 'server/index.js', sha256: 'aa' },
        { path: 'client/app.js', sha256: 'CHANGED' },
      ]),
    );
  });

  it('refuses a dirty tracked source tree (proof 5)', () => {
    const porcelain = [' M app/routes/api.agent.ts', 'A  app/lib/qhub/new.ts'];
    expect(dirtySourcePaths(porcelain)).toEqual(['app/routes/api.agent.ts', 'app/lib/qhub/new.ts']);
  });

  it('excludes untracked files and known artifact dirs from the dirty check (proof 5)', () => {
    const porcelain = [
      '?? scratch.mjs', // untracked → ignored
      ' M .claude/worktrees/x', // excluded artifact
      ' M .pnpm-store/y', // excluded artifact
      ' M build/server/z.js', // build output
      ' M app/real-source.ts', // real tracked source → flagged
    ];
    expect(dirtySourcePaths(porcelain)).toEqual(['app/real-source.ts']);
  });

  it('a clean tracked tree yields no dirty source (proofs 2/3 precondition)', () => {
    expect(dirtySourcePaths(['?? .claude/', '?? .pnpm-store/'])).toEqual([]);
  });

  it('includes the LangGraph runtime-provider marker', () => {
    expect(REQUIRED_BUILD_MARKERS).toContain('qhub.runtime.langgraph');
  });
});

describe('release-integrity: reported identity vs on-image manifest', () => {
  const manifest = { source_commit: 'abc123', artifact_hash: 'hash-xyz' };

  it('passes when the reported identity matches the manifest', () => {
    const r = compareBuildIdentity({ source_commit: 'abc123', artifact_hash: 'hash-xyz', built_at: 't' }, manifest);
    expect(r.ok).toBe(true);
    expect(r.reasons).toEqual([]);
  });

  it('fails closed on a source-commit mismatch', () => {
    const r = compareBuildIdentity({ source_commit: 'WRONG', artifact_hash: 'hash-xyz', built_at: 't' }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toContain('SOURCE_COMMIT_MISMATCH');
  });

  it('fails closed on an artifact-hash mismatch', () => {
    const r = compareBuildIdentity({ source_commit: 'abc123', artifact_hash: 'TAMPERED', built_at: 't' }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toContain('ARTIFACT_HASH_MISMATCH');
  });

  it('fails closed when the reported identity is unavailable', () => {
    const r = compareBuildIdentity({ source_commit: null, artifact_hash: null, built_at: null }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toEqual(['IDENTITY_UNAVAILABLE']);
  });
});
