#!/usr/bin/env node
/**
 * QHUB startup preflight — scripts/startup-preflight.mjs
 *
 * Process-startup enforcement (layer B of the deployment preflight). Runs BEFORE the
 * server starts serving. In a DEPLOYED target (staging/production, or a Fly prod marker)
 * it runs the full schema verification (Gate 01–05 + Agent Foundation + Commercial R4)
 * via scripts/schema-smoke-check.mjs and PROPAGATES its exit code — so a NOT_READY /
 * UNAVAILABLE schema makes the process exit nonzero and the server starts in a closed,
 * non-serving state. It never silently continues on failure in staging/production.
 *
 * In a non-deployed local/test target the startup preflight is advisory (exit 0) — the
 * runtime commercial fail-closed service boundary still protects every commercial route —
 * so local development is not bricked by an intentionally-unapplied migration.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const smoke = join(here, 'schema-smoke-check.mjs');

const deployEnv = (process.env.QHUB_DEPLOY_ENV ?? '').toLowerCase();
const flyApp = (process.env.FLY_APP_NAME ?? '').toLowerCase();
const isDeployedTarget =
  deployEnv === 'staging' ||
  deployEnv === 'preview' ||
  deployEnv === 'production' ||
  deployEnv === 'prod' ||
  flyApp.includes('staging') ||
  flyApp.includes('prod');

if (!isDeployedTarget) {
  console.warn(
    `[startup-preflight] non-deployed target (QHUB_DEPLOY_ENV=${deployEnv || 'unset'}). ` +
      'Schema preflight is advisory here; the runtime commercial fail-closed boundary still applies.',
  );
  process.exit(0);
}

console.log(`[startup-preflight] deployed target (QHUB_DEPLOY_ENV=${deployEnv}). Running schema verification…`);

const res = spawnSync(process.execPath, [smoke], { stdio: 'inherit' });

if (res.status !== 0) {
  console.error(
    '[startup-preflight] FAIL: schema verification did not pass. The server will NOT start serving ' +
      'commercial traffic (fail-closed). Apply the pending migrations to this target and redeploy.',
  );
  process.exit(res.status === null ? 1 : res.status);
}

console.log('[startup-preflight] PASS: schema verified. Starting server.');
process.exit(0);
