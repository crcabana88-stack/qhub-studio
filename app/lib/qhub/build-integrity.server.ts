/**
 * QHUB runtime build-integrity check (SERVER)
 * app/lib/qhub/build-integrity.server.ts
 *
 * Reads the two INDEPENDENT identities from the runtime bindings and compares
 * them with the pure `evaluateBuildIntegrity`:
 *   - EXPECTED (deployment):  QHUB_BUILD_*  (injected at deploy time)
 *   - IMAGE (on-image):       QHUB_IMAGE_*  (read from build/qhub-build-identity.json
 *                                            by bindings.sh at container startup)
 *
 * Enforcement policy by environment:
 *   - ready                     → allow.
 *   - present but mismatched    → FAIL CLOSED everywhere (a real integrity breach).
 *   - identity absent           → local dev tolerates (UNAVAILABLE); staging /
 *                                 production FAIL CLOSED.
 */

import { evaluateBuildIntegrity, type BuildIdentityTriple, type BuildIntegrityResult } from './build-identity';

type Env = Record<string, string | undefined>;

function readEnv(env: Env, key: string): string | null {
  return env[key] ?? process.env[key] ?? null;
}

export function readBuildIntegrity(env: Env): BuildIntegrityResult {
  const expected: BuildIdentityTriple = {
    source_commit: readEnv(env, 'QHUB_BUILD_SOURCE_COMMIT'),
    artifact_hash: readEnv(env, 'QHUB_BUILD_ARTIFACT_HASH'),
    lockfile_hash: readEnv(env, 'QHUB_BUILD_LOCKFILE_HASH'),
    build_at: readEnv(env, 'QHUB_BUILD_AT'),
  };
  const image: BuildIdentityTriple = {
    source_commit: readEnv(env, 'QHUB_IMAGE_SOURCE_COMMIT'),
    artifact_hash: readEnv(env, 'QHUB_IMAGE_ARTIFACT_HASH'),
    lockfile_hash: readEnv(env, 'QHUB_IMAGE_LOCKFILE_HASH'),
    build_at: readEnv(env, 'QHUB_IMAGE_BUILD_AT'),
  };

  return evaluateBuildIntegrity(expected, image);
}

/** staging / production enforce; other environments (local dev) tolerate absence. */
export function isEnforcedDeployEnv(env: Env): boolean {
  const e = (readEnv(env, 'QHUB_DEPLOY_ENV') ?? '').toLowerCase();

  return e === 'staging' || e === 'production' || e === 'prod';
}

export interface BuildIntegrityGate {
  ok: boolean;
  result: BuildIntegrityResult;
  reason?: string;
}

/**
 * Gate used by the diagnostic route AND by Agent Run start/resume. Fail-closed
 * unless the identity is ready — or absent in a non-enforced (local dev) env.
 */
export function assertBuildIntegrity(env: Env): BuildIntegrityGate {
  const result = readBuildIntegrity(env);

  if (result.ready) {
    return { ok: true, result };
  }

  // Both present but mismatched → always a hard failure.
  if (result.present) {
    return { ok: false, result, reason: result.mismatch_reason_codes[0] ?? 'BUILD_IDENTITY_MISMATCH' };
  }

  // Identity absent: tolerate in local dev, fail closed in staging/production.
  if (isEnforcedDeployEnv(env)) {
    return { ok: false, result, reason: 'BUILD_IDENTITY_UNAVAILABLE' };
  }

  return { ok: true, result };
}
