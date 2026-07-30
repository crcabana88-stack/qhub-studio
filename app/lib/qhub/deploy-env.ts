/**
 * QHUB deployment-environment parser (RUNTIME) — app/lib/qhub/deploy-env.ts
 *
 * The canonical, STRICT, fail-closed parser for QHUB_DEPLOY_ENV, used by runtime code and
 * tests. It is byte-for-byte behaviourally identical to scripts/deploy-env.mjs (the .mjs
 * copy the node deploy tooling imports); commercial-deploy-preflight.test.ts asserts exact
 * script/runtime parity across every valid and invalid input.
 *
 * Allowed environments are EXACTLY: local, test, staging, production. The value is matched
 * EXACTLY — no lowercasing, no trimming/padding tolerance, no default of unknown → local, and
 * NODE_ENV never determines deployment trust. Anything missing/empty/unknown/misspelled/
 * mixed-case/padded is INVALID (a CONFIGURATION_ERROR). staging/production are DEPLOYED (always
 * require verifiers); local/test are LOCAL (may use explicit test-only behaviour).
 */

export const ALLOWED_DEPLOY_ENVS = ['local', 'test', 'staging', 'production'] as const;

export type DeployEnvKind = 'DEPLOYED' | 'LOCAL' | 'INVALID';

export interface DeployEnvResult {
  ok: boolean;
  kind: DeployEnvKind;
  env: string | null;
  code: string;
}

export function parseDeployEnv(raw: unknown): DeployEnvResult {
  const v = typeof raw === 'string' ? raw : '';

  if (!(ALLOWED_DEPLOY_ENVS as readonly string[]).includes(v)) {
    return { ok: false, kind: 'INVALID', env: null, code: 'deploy_env_invalid' };
  }

  const deployed = v === 'staging' || v === 'production';

  return { ok: true, kind: deployed ? 'DEPLOYED' : 'LOCAL', env: v, code: 'ok' };
}

export function isDeployedEnv(raw: unknown): boolean {
  return parseDeployEnv(raw).kind === 'DEPLOYED';
}
