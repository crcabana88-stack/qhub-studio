/**
 * QHUB Commercial Launch R6 — UNIVERSAL DEPLOYMENT PREFLIGHT + FAIL-CLOSED ENV ENUM
 * app/test/commercial-deploy-preflight.test.ts
 *
 * Parses EVERY repository-controlled deploy/preview path (package.json, fly.toml, Dockerfile,
 * GitHub Actions incl. the Cloudflare preview workflow) and proves each runs the schema
 * preflight; a new deploy workflow without preflight fails the inventory. Exercises the ONE
 * shared fail-closed deploy-env parser (scripts/deploy-env.mjs) and runs the startup preflight
 * as a subprocess: missing/unknown/misspelled/mixed-case env exits nonzero (no fail-open), and
 * staging/production can never skip.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseDeployEnv as parseRuntime, ALLOWED_DEPLOY_ENVS as ALLOWED_RUNTIME } from '~/lib/qhub/deploy-env';

/*
 * The .mjs copy of the parser lives under scripts/ (imported by the node deploy tooling),
 * so it is imported by relative path rather than the app `~/` alias.
 */
// eslint-disable-next-line no-restricted-imports
import { parseDeployEnv, ALLOWED_DEPLOY_ENVS } from '../../scripts/deploy-env.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const read = (p: string) => readFileSync(`${ROOT}${p}`, 'utf8');

const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
const fly = read('fly.toml');
const dockerfile = read('Dockerfile');
const smoke = read('scripts/schema-smoke-check.mjs');

// ─── deploy-env fail-closed parser ──────────────────────────────────────────────

describe('deploy-env parser is a fail-closed enum', () => {
  it('exposes exactly local|test|staging|production', () => {
    expect(ALLOWED_DEPLOY_ENVS).toEqual(['local', 'test', 'staging', 'production']);
  });

  it('classifies staging/production as DEPLOYED and local/test as LOCAL', () => {
    expect(parseDeployEnv('staging').kind).toBe('DEPLOYED');
    expect(parseDeployEnv('production').kind).toBe('DEPLOYED');
    expect(parseDeployEnv('local').kind).toBe('LOCAL');
    expect(parseDeployEnv('test').kind).toBe('LOCAL');
  });

  it('missing/empty/unknown/misspelled/mixed-case/padded is INVALID (never falls back to local)', () => {
    for (const bad of [
      undefined,
      '',
      'unknown',
      'stagng',
      'Staging',
      'PRODUCTION',
      'prod',
      'preview',
      ' local',
      'local ',
      'local\n',
    ]) {
      expect(parseDeployEnv(bad as never).kind, `${String(bad)}`).toBe('INVALID');
    }
  });

  it('the RUNTIME parser and the SCRIPT parser are byte-for-byte behaviourally identical', () => {
    expect([...ALLOWED_RUNTIME]).toEqual([...ALLOWED_DEPLOY_ENVS]);

    const inputs = [
      undefined,
      '',
      'local',
      'test',
      'staging',
      'production',
      'unknown',
      'stagng',
      'Staging',
      'PRODUCTION',
      'prod',
      'preview',
      ' local',
      'local ',
      'LOCAL',
      '  ',
      'staging\t',
    ];

    for (const inp of inputs) {
      const a = parseDeployEnv(inp as never);
      const b = parseRuntime(inp as never);
      expect({ kind: b.kind, env: b.env, ok: b.ok }, `runtime≠script for ${String(inp)}`).toEqual({
        kind: a.kind,
        env: a.env,
        ok: a.ok,
      });
    }
  });
});

// ─── repository deploy path inventory ───────────────────────────────────────────

describe('every repository deploy/preview path runs schema verification', () => {
  it('the schema:check script runs the smoke verifier', () => {
    expect(pkg.scripts['schema:check']).toMatch(/schema-smoke-check\.mjs/);
  });

  it('package deploy wrappers run schema:check before shipping', () => {
    for (const s of ['deploy', 'pages:deploy']) {
      const cmd = pkg.scripts[s];
      expect(cmd, `${s} missing`).toBeDefined();
      expect(cmd.indexOf('schema:check')).toBeGreaterThanOrEqual(0);
      expect(cmd.indexOf('schema:check')).toBeLessThan(cmd.indexOf('wrangler'));
    }
  });

  it('Fly runs a release-phase schema preflight', () => {
    expect(fly).toMatch(/release_command\s*=\s*"[^"]*schema-smoke-check\.mjs"/);
  });

  it('the Docker CMD runs the startup preflight before serving, scripts are in the image', () => {
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

  // A GitHub Actions job that DEPLOYS to a serving/preview target must run the preflight.
  const DEPLOY_ACTION = /cloudflare\/pages-action|pages\s+deploy|wrangler\s+deploy|fly(ctl)?\s+deploy|superfly\/flyctl/;
  const workflows = readdirSync(`${ROOT}.github/workflows/`).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));

  it('the Cloudflare preview workflow runs schema preflight before deploy', () => {
    const preview = read('.github/workflows/preview.yaml');
    expect(DEPLOY_ACTION.test(preview)).toBe(true);

    // preflight step precedes the deploy action.
    expect(preview.indexOf('schema-smoke-check.mjs')).toBeGreaterThanOrEqual(0);
    expect(preview.indexOf('schema-smoke-check.mjs')).toBeLessThan(preview.search(/cloudflare\/pages-action/));
  });

  it('every workflow with a serving/preview deploy action also runs a schema preflight', () => {
    const offenders: string[] = [];

    for (const w of workflows) {
      const src = read(`.github/workflows/${w}`);

      if (DEPLOY_ACTION.test(src) && !/schema-smoke-check\.mjs/.test(src)) {
        offenders.push(w);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('a new deploy workflow WITHOUT preflight is detected (fixture)', () => {
    const badWorkflow = `jobs:\n  deploy:\n    steps:\n      - uses: cloudflare/pages-action@v1\n`;
    expect(DEPLOY_ACTION.test(badWorkflow) && !/schema-smoke-check\.mjs/.test(badWorkflow)).toBe(true);
  });

  /*
   * Universal package-script inventory: EVERY npm script that PUBLISHES/DEPLOYS must chain a
   * preflight. Local dev/serve scripts (wrangler pages dev, remix vite:dev) are exempt; the
   * deployed serving path (dockerstart) runs the preflight from the Docker CMD, not the script.
   */
  const PKG_DEPLOY = /wrangler\s+(pages\s+)?deploy|pages\s+deploy|fly(ctl)?\s+deploy/;
  const PKG_PREFLIGHT = /schema:check|schema-smoke-check|startup-preflight/;

  it('every publishing/deploying package script chains a schema preflight', () => {
    const offenders = Object.entries(pkg.scripts).filter(([, cmd]) => PKG_DEPLOY.test(cmd) && !PKG_PREFLIGHT.test(cmd));
    expect(offenders.map(([n]) => n)).toEqual([]);
  });

  it('a new publishing package script WITHOUT preflight is detected (fixture)', () => {
    const bad = 'wrangler pages deploy build/client';
    expect(PKG_DEPLOY.test(bad) && !PKG_PREFLIGHT.test(bad)).toBe(true);
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

describe('startup preflight is fail-closed (enum-driven)', () => {
  it('staging startup with no verifiable schema exits nonzero (starts closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'staging' })).not.toBe(0);
  });

  it('production startup with no verifiable schema exits nonzero (starts closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'production' })).not.toBe(0);
  });

  it('a MISSING deploy environment exits nonzero (CONFIGURATION_ERROR — no fail-open)', () => {
    expect(runStartup({})).not.toBe(0);
  });

  it('a MISSPELLED deploy environment exits nonzero (no silent fail-open to advisory)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'stagng' })).not.toBe(0);
    expect(runStartup({ QHUB_DEPLOY_ENV: 'Staging' })).not.toBe(0); // mixed-case invalid
  });

  it('an explicit local/test environment is advisory and continues (runtime stays fail-closed)', () => {
    expect(runStartup({ QHUB_DEPLOY_ENV: 'local' })).toBe(0);
    expect(runStartup({ QHUB_DEPLOY_ENV: 'test' })).toBe(0);
  });
});
