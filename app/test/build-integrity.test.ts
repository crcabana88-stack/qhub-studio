/**
 * QHUB runtime build-integrity gate — app/test/build-integrity.test.ts
 *
 * Proves the production gate that reads QHUB_BUILD_* (expected) vs QHUB_IMAGE_*
 * (on-image) and decides allow / fail-closed per environment.
 */

import { describe, it, expect } from 'vitest';
import { assertBuildIntegrity, isEnforcedDeployEnv, readBuildIntegrity } from '~/lib/qhub/build-integrity.server';

const match = {
  QHUB_BUILD_SOURCE_COMMIT: 'c',
  QHUB_BUILD_ARTIFACT_HASH: 'a',
  QHUB_BUILD_LOCKFILE_HASH: 'l',
  QHUB_IMAGE_SOURCE_COMMIT: 'c',
  QHUB_IMAGE_ARTIFACT_HASH: 'a',
  QHUB_IMAGE_LOCKFILE_HASH: 'l',
};

describe('build integrity gate', () => {
  it('allows when the two identities match', () => {
    const g = assertBuildIntegrity({ ...match, QHUB_DEPLOY_ENV: 'staging' });
    expect(g.ok).toBe(true);
    expect(g.result.ready).toBe(true);
  });

  it('fails closed on a mismatch in any environment (present but different)', () => {
    const g = assertBuildIntegrity({ ...match, QHUB_IMAGE_ARTIFACT_HASH: 'DIFFERENT', QHUB_DEPLOY_ENV: 'local' });
    expect(g.ok).toBe(false);
    expect(g.result.mismatch_reason_codes).toContain('ARTIFACT_HASH_MISMATCH');
  });

  it('tolerates absent identity in local dev (UNAVAILABLE)', () => {
    expect(assertBuildIntegrity({ QHUB_DEPLOY_ENV: 'local' }).ok).toBe(true);
  });

  it('fails closed on absent identity in staging/production', () => {
    expect(assertBuildIntegrity({ QHUB_DEPLOY_ENV: 'staging' }).ok).toBe(false);
    expect(assertBuildIntegrity({ QHUB_DEPLOY_ENV: 'production' }).ok).toBe(false);
  });

  it('classifies enforced environments', () => {
    expect(isEnforcedDeployEnv({ QHUB_DEPLOY_ENV: 'staging' })).toBe(true);
    expect(isEnforcedDeployEnv({ QHUB_DEPLOY_ENV: 'production' })).toBe(true);
    expect(isEnforcedDeployEnv({ QHUB_DEPLOY_ENV: 'local' })).toBe(false);
    expect(isEnforcedDeployEnv({})).toBe(false);
  });

  it('reads both identity triples from the environment', () => {
    const r = readBuildIntegrity(match);
    expect(r.source_commit).toBe('c');
    expect(r.lockfile_hash).toBe('l');
  });
});
