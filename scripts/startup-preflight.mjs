#!/usr/bin/env node
/**
 * QHUB startup preflight — scripts/startup-preflight.mjs
 *
 * Process-startup enforcement (layer B of the deployment preflight). Runs BEFORE the
 * server serves. The deployment environment is parsed by the ONE shared fail-closed
 * parser (scripts/deploy-env.mjs):
 *
 *   - DEPLOYED (staging/production): runs the full schema verification (Gate 01–05 + Agent
 *     Foundation + Commercial R4) via schema-smoke-check.mjs and PROPAGATES its exit code,
 *     so a NOT_READY/UNAVAILABLE schema makes the process exit nonzero and the server starts
 *     in a closed, non-serving state. Never silently continues on failure.
 *   - INVALID (missing / empty / unknown / misspelled / mixed-case): CONFIGURATION_ERROR →
 *     exits nonzero. A misspelled environment can NEVER fail open into a serving state.
 *   - LOCAL (local/test): advisory (exit 0) — the runtime commercial fail-closed boundary
 *     still protects every commercial route, so local development is not bricked.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseDeployEnv } from './deploy-env.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const smoke = join(here, 'schema-smoke-check.mjs');

const parsed = parseDeployEnv(process.env.QHUB_DEPLOY_ENV);

if (parsed.kind === 'INVALID') {
  console.error(
    `[startup-preflight] FAIL (CONFIGURATION_ERROR / ${parsed.code}): QHUB_DEPLOY_ENV must be exactly ` +
      'one of local|test|staging|production. A missing/unknown/misspelled/mixed-case environment can never ' +
      'serve commercial traffic (fail-closed).',
  );
  process.exit(1);
}

if (parsed.kind === 'LOCAL') {
  console.warn(
    `[startup-preflight] non-deployed target (QHUB_DEPLOY_ENV=${parsed.env}). Schema preflight is advisory ` +
      'here; the runtime commercial fail-closed boundary still applies.',
  );
  process.exit(0);
}

console.log(`[startup-preflight] deployed target (QHUB_DEPLOY_ENV=${parsed.env}). Running schema verification…`);

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
