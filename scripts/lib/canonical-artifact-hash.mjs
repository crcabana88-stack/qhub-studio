/**
 * QHUB canonical artifact hash — scripts/lib/canonical-artifact-hash.mjs
 *
 * The SINGLE canonical implementation of the deployed-artifact hash, shared by
 * `build:verified` (scripts/build-with-identity.mjs) and the tests, so the tested
 * helper and the production build script are byte-for-byte equivalent.
 *
 * Canonical input per file: an unambiguous JSON object with the normalized
 * forward-slash relative path, the file byte length, and the SHA-256 of the file
 * bytes. Rows are sorted by path and joined with newlines, then SHA-256'd.
 *
 * The identity manifest itself (`qhub-build-identity.json`) is EXCLUDED from the
 * hash to avoid self-reference (its content depends on the hash).
 */

import { createHash } from 'node:crypto';

export const IDENTITY_MANIFEST_BASENAME = 'qhub-build-identity.json';

/** Normalize a relative path to forward slashes. */
export function normalizeRelPath(p) {
  return String(p).replace(/\\/g, '/');
}

/** Canonical row for one file: {path, size, sha256} as compact, key-sorted JSON. */
export function canonicalRow(file) {
  const path = normalizeRelPath(file.path);

  return JSON.stringify({ path, sha256: file.sha256, size: file.size });
}

/**
 * Canonical artifact hash over `[{path, size, sha256}]`. The identity manifest is
 * excluded. Deterministic and order-independent (rows are sorted).
 */
export function canonicalArtifactHash(files) {
  const rows = files
    .filter((f) => normalizeRelPath(f.path).split('/').pop() !== IDENTITY_MANIFEST_BASENAME)
    .map(canonicalRow)
    .sort();

  return createHash('sha256').update(rows.join('\n')).digest('hex');
}
