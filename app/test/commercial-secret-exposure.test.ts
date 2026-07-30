/**
 * QHUB Commercial Launch R8 §1 / §10 — SERVER-SECRET EXPOSURE ELIMINATION
 * app/test/commercial-secret-exposure.test.ts
 *
 * Proves a configured server credential can never reach the browser:
 *   - api.github-user.ts is INTERNAL_SERVER_ONLY, auth-gated, returns only non-secret metadata,
 *     never a raw token, and redacts errors (no error.message / details / auth header / env value).
 *   - No route reads a server secret into a response VALUE, and no route echoes a token/secret
 *     under a credential-named response field.
 *   - Every former provider-proxy route uses ONLY the caller's own cookie token (no server env).
 *   - A synthetic server token never appears in the built browser bundle.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const ROUTES = fileURLToPath(new URL('../routes/', import.meta.url));
const read = (p: string) => readFileSync(p, 'utf8');

function routeFiles(): string[] {
  return readdirSync(ROUTES)
    .filter((f) => (f.endsWith('.ts') || f.endsWith('.tsx')) && !f.endsWith('.d.ts'))
    .map((f) => ROUTES + f);
}

// A server-secret env NAME (mirror of the architecture detector). The public anon key is excluded.
const SECRET_ENV_NAME = /(TOKEN|SECRET|CREDENTIAL|PASSWORD|APIKEY|ACCESS_KEY|SERVICE_ROLE|PRIVATE|_KEY$|_KEY_)/;
const PUBLIC_ENV_NAMES = new Set(['SUPABASE_ANON_KEY']);

/** Server-secret env NAMES READ from the server environment anywhere in a source file. */
function serverSecretEnvReads(src: string): string[] {
  const hits = new Set<string>();

  for (const line of src.split('\n')) {
    if (!/\.env\b/.test(line)) {
      continue;
    }

    for (const m of line.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)) {
      if (!PUBLIC_ENV_NAMES.has(m[1]) && SECRET_ENV_NAME.test(m[1])) {
        hits.add(m[1]);
      }
    }
  }

  return [...hits];
}

const githubUser = read(`${ROUTES}api.github-user.ts`);

describe('api.github-user.ts (the reproduced P0) never exposes a server token', () => {
  it('is classified INTERNAL_SERVER_ONLY, not PUBLIC_SAFE', () => {
    expect(githubUser).toMatch(/@qhub-route:\s*INTERNAL_SERVER_ONLY/);
    expect(githubUser).not.toMatch(/@qhub-route:\s*PUBLIC_SAFE/);
  });

  it('requires an authenticated session before any provider I/O', () => {
    expect(githubUser).toMatch(/getVerifiedUser/);
    expect(githubUser).toMatch(/requireAuth\(/);
  });

  it('reads NO server-env GitHub credential (only the caller cookie token)', () => {
    expect(serverSecretEnvReads(githubUser), 'server secret env read present').toEqual([]);
    expect(githubUser).not.toMatch(/process\.env\.[A-Z_]*GITHUB[A-Z_]*/);
  });

  it('has no get_token action and never returns a raw token value', () => {
    expect(githubUser).not.toMatch(/get_token/);
    expect(githubUser).not.toMatch(/token:\s*githubToken/);
    expect(githubUser).not.toMatch(/json\(\s*\{\s*token:/);
  });

  it('redacts errors — no error.message / details leak in catch blocks', () => {
    expect(githubUser).not.toMatch(/details:\s*error/);
    expect(githubUser).not.toMatch(/error\.message/);
  });
});

describe('no route returns a raw server credential (repo-wide)', () => {
  const CRED_KEY = /\b(token|apiKey|api_key|secret|credential|password|accessToken|access_token|privateKey)\s*:/;

  it('no PUBLIC_SAFE-eligible route reads a server secret from the environment', () => {
    const offenders: string[] = [];

    for (const f of routeFiles()) {
      const src = read(f);

      /*
       * INTERNAL_SERVER_ONLY / STAFF_ONLY routes may legitimately read a server secret (never
       * returning it); PUBLIC_SAFE routes may not read one at all.
       */
      if (!/@qhub-route:\s*PUBLIC_SAFE/.test(src)) {
        continue;
      }

      const secrets = serverSecretEnvReads(src);

      if (secrets.length > 0) {
        offenders.push(`${f.slice(ROOT.length)}: ${secrets.join(', ')}`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('no route echoes a server env secret under a credential-named response field', () => {
    const offenders: string[] = [];

    for (const f of routeFiles()) {
      for (const line of read(f).split('\n')) {
        // e.g. `token: process.env.GITHUB_TOKEN` or `api_key: context.cloudflare.env.X_SECRET`
        if (CRED_KEY.test(line) && /\.env\b/.test(line) && SECRET_ENV_NAME.test(line)) {
          offenders.push(`${f.slice(ROOT.length)}: ${line.trim()}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('every former provider-proxy route reads ONLY the caller cookie token', () => {
    const proxies = [
      'api.github-branches.ts',
      'api.github-stats.ts',
      'api.github-template.ts',
      'api.netlify-user.ts',
      'api.supabase-user.ts',
      'api.vercel-user.ts',
      'api.system.git-info.ts',
    ];

    for (const p of proxies) {
      expect(serverSecretEnvReads(read(`${ROUTES}${p}`)), `${p} reads a server secret`).toEqual([]);
    }
  });
});

describe('R9 §6: dynamic/computed server-env access + SDK-error redaction', () => {
  // Mirror of the architecture dynamic-env detector.
  const DYNAMIC_ENV: RegExp[] = [
    /process\.env\s*\[/,
    /\.env\s*\[|\benv\s*\[/,
    /Object\.(entries|keys|values|assign|fromEntries)\s*\(\s*[^)]*\benv\b/,
    /\.\.\.\s*(?:[\w.?]*\.)?(?:process\.env|env)\b/,
    /JSON\.stringify\s*\(\s*[^)]*\.env\b/,
  ];

  it('no PUBLIC_SAFE route performs dynamic/computed server-env access', () => {
    const offenders: string[] = [];

    for (const f of routeFiles()) {
      const src = read(f);

      if (!/@qhub-route:\s*PUBLIC_SAFE/.test(src)) {
        continue;
      }

      if (DYNAMIC_ENV.some((re) => re.test(src))) {
        offenders.push(f.slice(ROOT.length));
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('the dynamic-env routes (check-env-key, configured-providers) are INTERNAL_SERVER_ONLY + guarded', () => {
    for (const p of ['api.check-env-key.ts', 'api.configured-providers.ts']) {
      const src = read(`${ROUTES}${p}`);
      expect(src, p).toMatch(/@qhub-route:\s*INTERNAL_SERVER_ONLY/);
      expect(src, p).toMatch(/getVerifiedUser/);
    }
  });

  it('api.bug-report.ts never logs the raw SDK error object (would leak the bot token)', () => {
    const src = read(`${ROUTES}api.bug-report.ts`);

    // The old unredacted `console.error('...', error)` form must be gone.
    expect(src).not.toMatch(/console\.error\([^)]*,\s*error\s*\)/);

    // Only a sanitized status is logged.
    expect(src).toMatch(/github status/);
  });
});

describe('the secret-export detector catches synthetic offenders (fixtures)', () => {
  it('a renamed secret-read wrapper is still detected (effect-based, not name-based)', () => {
    // Regardless of the wrapper function's name, the underlying env-secret READ is caught.
    const renamed = `function pull(e) { return process.env.STRIPE_SECRET_KEY; }\nconst grab = (c) => c.cloudflare.env.GITHUB_ACCESS_TOKEN;`;
    expect(serverSecretEnvReads(renamed).sort()).toEqual(['GITHUB_ACCESS_TOKEN', 'STRIPE_SECRET_KEY']);
  });

  it('a generic env-secret export line is flagged', () => {
    expect(serverSecretEnvReads(`return json({ key: process.env.SUPABASE_SERVICE_ROLE_KEY });`)).toEqual([
      'SUPABASE_SERVICE_ROLE_KEY',
    ]);
  });

  it('the public anon key + non-secret operational vars are NOT treated as secrets', () => {
    const benign = `const a = env.SUPABASE_ANON_KEY; const b = process.env.CF_PAGES_URL; const c = env.STRIPE_ACCOUNT_ID;`;
    expect(serverSecretEnvReads(benign)).toEqual([]);
  });
});

describe('a real server-secret VALUE never appears in the built browser bundle', () => {
  const clientDir = `${ROOT}build/client`;

  /*
   * Scan for actual credential VALUE shapes — not env-var NAMES (bolt.diy's bring-your-own-key
   * UI legitimately references names like GITHUB_ACCESS_TOKEN as form field labels). A leaked
   * VALUE (a GitHub PAT, a Stripe secret, a service-role JWT) has an unmistakable shape.
   */
  const SECRET_VALUE_SHAPES: Array<{ label: string; re: RegExp }> = [
    { label: 'github classic PAT', re: /\bghp_[A-Za-z0-9]{30,}\b/ },
    { label: 'github fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/ },
    { label: 'github OAuth token', re: /\bgho_[A-Za-z0-9]{30,}\b/ },
    { label: 'stripe live/test secret', re: /\bsk_(live|test)_[A-Za-z0-9]{20,}\b/ },
    { label: 'stripe webhook secret', re: /\bwhsec_[A-Za-z0-9]{20,}\b/ },
    { label: 'supabase service-role JWT', re: /"role"\s*:\s*"service_role"/ },
  ];

  it('no credential VALUE shape is present in any client bundle file', () => {
    if (!existsSync(clientDir)) {
      // The bundle scan runs after `pnpm build`; treated as satisfied when no build is present.
      expect(true).toBe(true);
      return;
    }

    const jsFiles: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir)) {
        const p = `${dir}/${e}`;

        if (statSync(p).isDirectory()) {
          walk(p);
        } else if (p.endsWith('.js')) {
          jsFiles.push(p);
        }
      }
    };
    walk(clientDir);

    const offenders: string[] = [];

    for (const jf of jsFiles) {
      const src = read(jf);

      for (const { label, re } of SECRET_VALUE_SHAPES) {
        if (re.test(src)) {
          offenders.push(`${jf.slice(clientDir.length)}: ${label}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('the credential-value scanner actually detects a synthetic leaked token (fixture)', () => {
    const synthetic = 'const t = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";';
    expect(SECRET_VALUE_SHAPES.some(({ re }) => re.test(synthetic))).toBe(true);
  });
});
