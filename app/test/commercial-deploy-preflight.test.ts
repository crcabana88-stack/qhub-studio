/**
 * QHUB Commercial Launch R5 — DEPLOYMENT PREFLIGHT (non-bypassable across repo paths)
 * app/test/commercial-deploy-preflight.test.ts
 *
 * Parses the repository-controlled deployment/start configurations (package.json, fly.toml,
 * Dockerfile) AND runs the startup preflight as a subprocess, proving that no
 * repository-supported path can serve commercial traffic without schema verification, and
 * that staging/production can never skip. All three verifier families (Gate, Agent,
 * Commercial) run through scripts/schema-smoke-check.mjs.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const read = (p: string) => readFileSync(`${ROOT}${p}`, 'utf8');

const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
const fly = read('fly.toml');
const dockerfile = read('Dockerfile');
const smoke = read('scripts/schema-smoke-check.mjs');

describe('repository deploy paths run schema verification', () => {
  it('the schema:check script runs the smoke verifier', () => {
    expect(pkg.scripts['schema:check']).toMatch(/schema-smoke-check\.mjs/);
  });

  it('package deploy wrappers run schema:check before shipping', () => {
    for (const s of ['deploy', 'pages:deploy']) {
      const cmd = pkg.scripts[s];
      expect(cmd, `${s} missing`).toBeDefined();
      expect(cmd.indexOf('schema:check')).toBeGreaterThanOrEqual(0);

      // schema:check precedes the actual deploy verb.
      expect(cmd.indexOf('schema:check')).toBeLessThan(cmd.indexOf('wrangler'));
    }
  });

  it('Fly runs a release-phase schema preflight (release_command)', () => {
    expect(fly).toMatch(/release_command\s*=\s*"[^"]*schema-smoke-check\.mjs"/);
  });

  it('the Docker CMD runs the startup preflight before serving, and scripts are in the image', () => {
    expect(dockerfile).toMatch(/COPY scripts \.\/scripts/);
    expect(dockerfile).toMatch(/startup-preflight\.mjs && pnpm run dockerstart/);
  });

  it('the smoke check runs ALL THREE verifier families (Gate + Agent + Commercial)', () => {
    expect(smoke).toMatch(/qhub_verify_governance_schema/);
    expect(smoke).toMatch(/qhub_verify_agent_schema/);
    expect(smoke).toMatch(/qhub_verify_commercial_schema/);
  });

  it('no deploy config hard-codes a staging/production skip', () => {
    for (const cfg of [fly, dockerfile, JSON.stringify(pkg.scripts)]) {
      expect(cfg).not.toMatch(/QHUB_SKIP_SCHEMA_CHECK\s*[=:]\s*["']?1/);
    }
  });
});

// ─── startup preflight subprocess behavior ──────────────────────────────────────

const STARTUP = fileURLToPath(new URL('../../scripts/startup-preflight.mjs', import.meta.url));

function runStartup(overrides: Record<string, string>): number {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    QHUB_DEPLOY_ENV: '',
    FLY_APP_NAME: '',
    NODE_ENV: '',
    SUPABASE_URL: '',
    SUPABASE_SERVICE_ROLE_KEY: '',
    ...overrides,
  };

  try {
    execFileSync('node', [STARTUP], { env: env as NodeJS.ProcessEnv, stdio: 'pipe', timeout: 30_000 });

    return 0;
  } catch (e) {
    return (e as { status?: number }).status ?? 1;
  }
}

describe('startup preflight is fail-closed on deployed targets', () => {
  it('staging startup with no verifiable schema exits nonzero (starts closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'staging' })).not.toBe(0);
  });

  it('production startup with no verifiable schema exits nonzero (starts closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'production' })).not.toBe(0);
  });

  it('a Fly staging app marker is treated as a deployed target and fails closed', () => {
    expect(runStartup({ FLY_APP_NAME: 'qhub-studio-staging' })).not.toBe(0);
  });

  it('a non-deployed local target is advisory and continues (runtime stays fail-closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'dev' })).toBe(0);
  });

  it('an unset/misspelled deploy environment does not become a deployed-target bypass', () => {
    /*
     * "stagng" (typo) is NOT a deployed target → advisory (exit 0). It cannot masquerade
     * as staging to skip, and it cannot serve commercial traffic (runtime stays closed).
     */
    expect(runStartup({ QHUB_DEPLOY_ENV: 'stagng' })).toBe(0);
  });
});
