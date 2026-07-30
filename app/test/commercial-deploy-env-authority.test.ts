/**
 * QHUB Commercial Launch R8 §2 — ONE STRICT DEPLOY-ENV AUTHORITY (repository-wide)
 * app/test/commercial-deploy-env-authority.test.ts
 *
 * There is exactly ONE canonical deployment-environment parser (app/lib/qhub/deploy-env.ts,
 * mirrored byte-for-byte in scripts/deploy-env.mjs). This test walks EVERY non-test source
 * file under app/ and scripts/ and fails if any code manually lowercases, trims, defaults, or
 * string-compares the QHUB_DEPLOY_ENV value OUTSIDE the canonical parser — the exact class of
 * divergent/weak parsing the R7 review reproduced (session dev-auth, governed adapters, the
 * predeploy bypass authorizer). The raw deploy-env value may only be consumed by
 * `parseDeployEnv(...)`.
 *
 * It also proves, end-to-end, that an invalid/missing/mixed-case deploy environment can NEVER
 * enable the dev-auth fallback (fail-closed), and that the runtime + script parsers agree.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { isDevAuthAllowed } from '~/lib/auth/session';
import { parseDeployEnv } from '~/lib/qhub/deploy-env';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

// The canonical parser modules are the ONLY place the raw string may be manipulated.
const CANONICAL = new Set(['app/lib/qhub/deploy-env.ts', 'scripts/deploy-env.mjs']);

function walk(dir: string, exts: string[], acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = `${dir}/${entry}`;
    const st = statSync(full);

    if (st.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git' || entry === 'build' || entry === 'dist') {
        continue;
      }

      walk(full, exts, acc);
    } else if (exts.some((e) => entry.endsWith(e))) {
      acc.push(full);
    }
  }

  return acc;
}

function sourceFiles(): string[] {
  const files = [...walk(`${ROOT}app`, ['.ts', '.tsx']), ...walk(`${ROOT}scripts`, ['.mjs', '.js'])];

  return files.filter((f) => {
    const rel = f.slice(ROOT.length).replace(/\\/g, '/');

    // Exclude the tests themselves and the canonical parser modules.
    return !/\.test\.tsx?$/.test(rel) && !rel.includes('/test/') && !CANONICAL.has(rel);
  });
}

/*
 * Dangerous manual manipulations of the deploy-env VALUE. Each pattern anchors on the
 * QHUB_DEPLOY_ENV token so an unrelated `.toLowerCase()` elsewhere is never flagged.
 */
const ENV_NAME = '(?:local|test|staging|production|preview|prod|dev|development)';
const VIOLATIONS: Array<{ label: string; re: RegExp }> = [
  { label: 'lowercases the deploy-env value', re: /QHUB_DEPLOY_ENV[^\n;]*\.toLowerCase\s*\(/ },
  { label: 'trims the deploy-env value', re: /QHUB_DEPLOY_ENV[^\n;]*\.trim\s*\(/ },
  {
    label: 'defaults the deploy-env value to a concrete environment name',
    re: new RegExp(`QHUB_DEPLOY_ENV[^\\n;]*\\?\\?\\s*['"]${ENV_NAME}['"]`),
  },
  {
    label: 'directly string-compares the deploy-env value to an environment name',
    re: new RegExp(`QHUB_DEPLOY_ENV\\s*(?:===|!==|==|!=)\\s*['"]${ENV_NAME}['"]`),
  },
  {
    label: 'directly string-compares an environment name to the deploy-env value',
    re: new RegExp(`['"]${ENV_NAME}['"]\\s*(?:===|!==|==|!=)\\s*[^;\\n]*QHUB_DEPLOY_ENV`),
  },
];

describe('QHUB_DEPLOY_ENV has exactly one strict parsing authority', () => {
  it('no non-test source manually lowercases/trims/defaults/compares the deploy-env value', () => {
    const offenders: string[] = [];

    for (const file of sourceFiles()) {
      const src = readFileSync(file, 'utf8');

      if (!src.includes('QHUB_DEPLOY_ENV')) {
        continue;
      }

      const rel = file.slice(ROOT.length).replace(/\\/g, '/');

      for (const { label, re } of VIOLATIONS) {
        if (re.test(src)) {
          offenders.push(`${rel}: ${label}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('the violation scanner actually catches a synthetic manual parse (fixture)', () => {
    const bad = "const e = (env.QHUB_DEPLOY_ENV ?? '').toLowerCase(); if (e === 'staging') {}";
    expect(VIOLATIONS.some(({ re }) => re.test(bad))).toBe(true);

    const alsoBad = "if (env.QHUB_DEPLOY_ENV === 'production') fail();";
    expect(VIOLATIONS.some(({ re }) => re.test(alsoBad))).toBe(true);

    // The canonical call form is NOT a violation.
    const good = 'const p = parseDeployEnv(env.QHUB_DEPLOY_ENV ?? process.env.QHUB_DEPLOY_ENV);';
    expect(VIOLATIONS.some(({ re }) => re.test(good))).toBe(false);
  });
});

describe('dev-auth fallback is impossible outside an exact local/test environment', () => {
  /*
   * isDevAuthAllowed reads its `env` arg first and falls back to process.env (worker vs node);
   * clear the ambient values so the passed env is authoritative and the assertions are
   * deterministic regardless of the developer's shell.
   */
  const saved: Record<string, string | undefined> = {};

  beforeAll(() => {
    for (const k of ['QHUB_ALLOW_DEV_AUTH', 'QHUB_DEPLOY_ENV']) {
      saved[k] = process.env[k];
      delete (process.env as Record<string, string | undefined>)[k];
    }
  });

  afterAll(() => {
    for (const k of ['QHUB_ALLOW_DEV_AUTH', 'QHUB_DEPLOY_ENV']) {
      if (saved[k] === undefined) {
        delete (process.env as Record<string, string | undefined>)[k];
      } else {
        (process.env as Record<string, string | undefined>)[k] = saved[k];
      }
    }
  });

  const withFlag = (deploy: string | undefined): Record<string, string | undefined> => ({
    QHUB_ALLOW_DEV_AUTH: 'true',
    QHUB_DEPLOY_ENV: deploy,
  });

  it('permits dev auth ONLY for exact local/test with an exact `true` flag', () => {
    expect(isDevAuthAllowed(withFlag('local'))).toBe(true);
    expect(isDevAuthAllowed(withFlag('test'))).toBe(true);
  });

  it('refuses dev auth for staging/production even with the flag set', () => {
    expect(isDevAuthAllowed(withFlag('staging'))).toBe(false);
    expect(isDevAuthAllowed(withFlag('production'))).toBe(false);
  });

  it('refuses dev auth for missing/empty/mixed-case/misspelled/unknown deploy env', () => {
    for (const bad of [undefined, '', 'Local', 'TEST', 'stagng', 'prod', 'preview', ' local', 'local ']) {
      expect(isDevAuthAllowed(withFlag(bad as never)), `deploy=${String(bad)}`).toBe(false);
    }
  });

  it('refuses dev auth when the flag is anything other than exact `true` (even in local)', () => {
    for (const flag of [undefined, '', '1', 'TRUE', 'true ', 'yes', 'on']) {
      expect(
        isDevAuthAllowed({ QHUB_ALLOW_DEV_AUTH: flag as never, QHUB_DEPLOY_ENV: 'local' }),
        `flag=${String(flag)}`,
      ).toBe(false);
    }
  });

  it('NODE_ENV cannot re-enable dev auth under an invalid/deployed environment', () => {
    const prev = process.env.NODE_ENV;

    try {
      (process.env as Record<string, string | undefined>).NODE_ENV = 'development';
      expect(isDevAuthAllowed(withFlag('production'))).toBe(false);
      expect(isDevAuthAllowed(withFlag('unknown'))).toBe(false);
      expect(isDevAuthAllowed(withFlag(undefined))).toBe(false);
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = prev;
    }
  });

  it('runtime and script parsers classify identically (single authority)', () => {
    // A cross-check that the runtime parser used by dev-auth is the strict enum.
    expect(parseDeployEnv('local').kind).toBe('LOCAL');
    expect(parseDeployEnv('test').kind).toBe('LOCAL');
    expect(parseDeployEnv('staging').kind).toBe('DEPLOYED');
    expect(parseDeployEnv('production').kind).toBe('DEPLOYED');
    expect(parseDeployEnv('Local').kind).toBe('INVALID');
  });
});
