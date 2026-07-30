/**
 * QHUB Commercial Launch R4 — PREDEPLOY BYPASS REMOVAL (executable)
 * app/test/commercial-predeploy-bypass.test.ts
 *
 * Runs the real scripts/schema-smoke-check.mjs as a subprocess with different env
 * combinations. Staging and production can NEVER skip the schema verifiers; only a
 * local test process (NODE_ENV=test + explicit flag + non-deployed target) may bypass,
 * and it exits BEFORE any DB probe.
 */

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const SCRIPT = fileURLToPath(new URL('../../scripts/schema-smoke-check.mjs', import.meta.url));

/** Run the smoke check with a controlled env; return { code, out }. */
function run(overrides: Record<string, string>): { code: number; out: string } {
  const env: Record<string, string> = {
    /*
     * Inherit the OS env (PATH, SystemRoot, etc. — needed for node to launch), then
     * neutralize any ambient deploy markers / creds so only `overrides` matter.
     */
    ...(process.env as Record<string, string>),
    QHUB_DEPLOY_ENV: '',
    FLY_APP_NAME: '',
    NODE_ENV: '',
    QHUB_SKIP_SCHEMA_CHECK: '',
    QHUB_LOCAL_TEST_SCHEMA_BYPASS: '',
    SUPABASE_URL: '',
    SUPABASE_SERVICE_ROLE_KEY: '',
    ...overrides,
  };

  try {
    const out = execFileSync('node', [SCRIPT], { env: env as NodeJS.ProcessEnv, stdio: 'pipe' }).toString();

    return { code: 0, out };
  } catch (e) {
    const err = e as { status?: number; stdout?: Buffer; stderr?: Buffer };

    return { code: err.status ?? 1, out: `${err.stdout ?? ''}${err.stderr ?? ''}` };
  }
}

describe('predeploy schema check has NO staging/production bypass', () => {
  it('a staging skip attempt exits nonzero', () => {
    const { code, out } = run({ QHUB_SKIP_SCHEMA_CHECK: '1', QHUB_DEPLOY_ENV: 'staging' });
    expect(code).not.toBe(0);
    expect(out).toMatch(/deployed-target-never-bypasses/);
  });

  it('a production skip attempt exits nonzero', () => {
    const { code } = run({ QHUB_SKIP_SCHEMA_CHECK: '1', QHUB_DEPLOY_ENV: 'production' });
    expect(code).not.toBe(0);
  });

  it('a misspelled deploy env is a CONFIGURATION_ERROR (nonzero), never a skip', () => {
    const { code, out } = run({ QHUB_LOCAL_TEST_SCHEMA_BYPASS: '1', NODE_ENV: 'test', QHUB_DEPLOY_ENV: 'stagng' });
    expect(code).not.toBe(0);
    expect(out).toMatch(/CONFIGURATION_ERROR|deploy_env_invalid/);
  });

  it('a MISSING deploy env is a CONFIGURATION_ERROR (nonzero)', () => {
    const { code } = run({ QHUB_LOCAL_TEST_SCHEMA_BYPASS: '1', NODE_ENV: 'test' });
    expect(code).not.toBe(0);
  });

  it('the legacy QHUB_SKIP_SCHEMA_CHECK alone (no test conditions) cannot skip', () => {
    const { code } = run({ QHUB_SKIP_SCHEMA_CHECK: '1', QHUB_DEPLOY_ENV: 'local' });
    expect(code).not.toBe(0);
  });

  it('a local test bypass (QHUB_DEPLOY_ENV=local + NODE_ENV=test + explicit flag) exits 0 before any probe', () => {
    const { code } = run({
      QHUB_LOCAL_TEST_SCHEMA_BYPASS: '1',
      NODE_ENV: 'test',
      QHUB_DEPLOY_ENV: 'local',
    });
    expect(code).toBe(0);
  });
});
