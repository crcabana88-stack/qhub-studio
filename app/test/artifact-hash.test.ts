/**
 * QHUB canonical artifact hash — app/test/artifact-hash.test.ts
 *
 * Exercises the SINGLE shared implementation used by build:verified so the tested
 * helper and the production build script are byte-for-byte equivalent.
 */

import { describe, it, expect } from 'vitest';

/*
 * The canonical hash lives in scripts/ so build:verified and this test share ONE
 * implementation; a relative import is required to reach the shared build helper.
 */
/* eslint-disable-next-line no-restricted-imports */
import {
  canonicalArtifactHash,
  canonicalRow,
  IDENTITY_MANIFEST_BASENAME,
} from '../../scripts/lib/canonical-artifact-hash.mjs';

const files = [
  { path: 'server/index.js', sha256: 'aa', size: 10 },
  { path: 'client/app.js', sha256: 'bb', size: 20 },
];

describe('canonical artifact hash (shared build + test implementation)', () => {
  it('is deterministic and order-independent', () => {
    expect(canonicalArtifactHash(files)).toBe(canonicalArtifactHash([...files].reverse()));
  });

  it('is sensitive to a changed file hash', () => {
    expect(canonicalArtifactHash(files)).not.toBe(
      canonicalArtifactHash([
        { path: 'server/index.js', sha256: 'aa', size: 10 },
        { path: 'client/app.js', sha256: 'CHANGED', size: 20 },
      ]),
    );
  });

  it('is sensitive to a changed file size', () => {
    expect(canonicalArtifactHash(files)).not.toBe(
      canonicalArtifactHash([
        { path: 'server/index.js', sha256: 'aa', size: 999 },
        { path: 'client/app.js', sha256: 'bb', size: 20 },
      ]),
    );
  });

  it('normalizes backslash paths to forward slashes', () => {
    expect(
      canonicalArtifactHash([
        { path: 'server\\index.js', sha256: 'aa', size: 10 },
        { path: 'client/app.js', sha256: 'bb', size: 20 },
      ]),
    ).toBe(canonicalArtifactHash(files));
  });

  it('excludes the identity manifest itself (no self-reference)', () => {
    const withManifest = [...files, { path: IDENTITY_MANIFEST_BASENAME, sha256: 'zz', size: 5 }];
    expect(canonicalArtifactHash(withManifest)).toBe(canonicalArtifactHash(files));
  });

  it('canonical row is compact key-sorted JSON of {path, sha256, size}', () => {
    expect(canonicalRow({ path: 'a/b.js', sha256: 'x', size: 3 })).toBe('{"path":"a/b.js","sha256":"x","size":3}');
  });
});
