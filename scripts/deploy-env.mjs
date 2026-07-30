/**
 * QHUB deployment-environment parser — scripts/deploy-env.mjs
 *
 * ONE canonical, fail-closed parser for QHUB_DEPLOY_ENV, shared by schema-smoke-check,
 * startup-preflight, and (mirrored + parity-tested) the runtime readiness module.
 *
 * Allowed environments are EXACTLY: local, test, staging, production (lowercase). Anything
 * missing, empty, unknown, misspelled, mixed-case, or malformed is a CONFIGURATION_ERROR
 * (kind === 'INVALID') — there is no fallback of unknown → local, and NODE_ENV alone never
 * determines deployment trust. staging/production are DEPLOYED (always require verifiers);
 * local/test are LOCAL (may use explicit test-only behavior).
 */

export const ALLOWED_DEPLOY_ENVS = ['local', 'test', 'staging', 'production'];

/**
 * @param {unknown} raw the QHUB_DEPLOY_ENV value
 * @returns {{ ok: boolean, kind: 'DEPLOYED'|'LOCAL'|'INVALID', env: string|null, code: string }}
 */
export function parseDeployEnv(raw) {
  const v = typeof raw === 'string' ? raw : '';

  if (!ALLOWED_DEPLOY_ENVS.includes(v)) {
    return { ok: false, kind: 'INVALID', env: null, code: 'deploy_env_invalid' };
  }

  const deployed = v === 'staging' || v === 'production';

  return { ok: true, kind: deployed ? 'DEPLOYED' : 'LOCAL', env: v, code: 'ok' };
}

export function isDeployedEnv(raw) {
  return parseDeployEnv(raw).kind === 'DEPLOYED';
}
