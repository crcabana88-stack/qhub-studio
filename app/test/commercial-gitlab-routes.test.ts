/**
 * QHUB Commercial Launch R15 — GitLab route closure adversarial suite
 * app/test/commercial-gitlab-routes.test.ts
 *
 * The two GitLab discovery routes previously accepted a caller-controlled `gitlabUrl` and a
 * browser-supplied token, then forwarded that token as `Authorization: Bearer …` to the selected host
 * (a synthetic probe reached https://attacker.invalid/api/v4/projects with the token attached). Both are
 * now DISABLED: a constant feature-disabled response, no body parsing, no destination, no credential,
 * no outbound request, no logging. These tests drive the EXACT route modules with a stubbed global fetch
 * and synthetic credentials only, and sweep the repository for any remaining route that combines a
 * caller-controlled origin with browser-token forwarding.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GITLAB_DISCOVERY_ENABLED, GITLAB_DISABLED_CODE } from '~/lib/qhub/gitlab-integration.server';
import * as gitlabBranches from '~/routes/api.gitlab-branches';
import * as gitlabProjects from '~/routes/api.gitlab-projects';

const APP = fileURLToPath(new URL('../', import.meta.url));
const SYNTHETIC_TOKEN = 'glpat-SYNTHETIC_R15_TOKEN_0123456789';

const ROUTES: Array<
  [string, { action: (...a: any[]) => Promise<Response>; loader: (...a: any[]) => Promise<Response> }]
> = [
  ['api.gitlab-projects.ts', gitlabProjects as any],
  ['api.gitlab-branches.ts', gitlabBranches as any],
];

/** Every hostile body shape the old routes would have turned into an upstream destination. */
const HOSTILE_BODIES: Array<[string, Record<string, unknown>]> = [
  ['test 1 — attacker.invalid host', { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://attacker.invalid', projectId: 1 }],
  ['test 8 — self-hosted GitLab', { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://gitlab.internal.corp', projectId: 1 }],
  ['test 9 — IP literal host', { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://169.254.169.254', projectId: 1 }],
  ['test 10 — protocol-relative', { token: SYNTHETIC_TOKEN, gitlabUrl: '//attacker.invalid', projectId: 1 }],
  ['test 11 — non-approved port', { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://gitlab.com:8080', projectId: 1 }],
  ['test 12 — redirect bait host', { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://redirector.invalid', projectId: 1 }],
  ['test 7 — default gitlab.com', { token: SYNTHETIC_TOKEN, projectId: 1 }],
];

let fetchSpy: ReturnType<typeof vi.fn>;
let logs: string[] = [];

beforeEach(() => {
  logs = [];
  fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
  vi.stubGlobal('fetch', fetchSpy);

  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
    });
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function post(body: unknown, headers: Record<string, string> = {}) {
  return new Request('https://app.local/api/gitlab', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

// ─── §8 tests 1-16 — the disabled routes cannot reach any destination ────────────

describe('R15 §8 — disabled GitLab routes reach no destination and forward no credential', () => {
  it('the feature flag is off and the disabled code is stable', () => {
    expect(GITLAB_DISCOVERY_ENABLED).toBe(false);
    expect(GITLAB_DISABLED_CODE).toBe('gitlab_integration_disabled');
  });

  // test 16: BOTH routes are covered by every case below.
  for (const [routeName, mod] of ROUTES) {
    describe(routeName, () => {
      for (const [label, body] of HOSTILE_BODIES) {
        it(`${label} → 410 disabled, ZERO outbound fetch (test 15)`, async () => {
          const res = await mod.action({ request: post(body) } as unknown as never);
          expect(res.status).toBe(410);
          expect(fetchSpy, 'a disabled route must make no outbound request').not.toHaveBeenCalled();

          const payload = (await res.json()) as { error: string; availability: string };
          expect(payload.error).toBe(GITLAB_DISABLED_CODE);
          expect(payload.availability).toBe('post_beta');
        });
      }

      it('tests 2/3 — browser Authorization / x-authorization headers are never forwarded', async () => {
        const res = await mod.action({
          request: post(
            { token: SYNTHETIC_TOKEN, gitlabUrl: 'https://attacker.invalid' },
            {
              authorization: `Bearer ${SYNTHETIC_TOKEN}`,
              'x-authorization': SYNTHETIC_TOKEN,
              cookie: `t=${SYNTHETIC_TOKEN}`,
            },
          ),
        } as unknown as never);
        expect(res.status).toBe(410);
        expect(fetchSpy).not.toHaveBeenCalled();
      });

      it('tests 5/6 — unauthenticated and unauthorized callers get the same disabled response, no fetch', async () => {
        // No session/authorization of any kind, and an "authorized-looking" caller: identical outcome.
        const anon = await mod.action({ request: post({ token: SYNTHETIC_TOKEN }) } as unknown as never);
        const authedLooking = await mod.action({
          request: post({ token: SYNTHETIC_TOKEN }, { cookie: 'sb-access-token=synthetic' }),
        } as unknown as never);
        expect(anon.status).toBe(410);
        expect(authedLooking.status).toBe(410);
        expect(fetchSpy).not.toHaveBeenCalled();
      });

      it('test 14 — no credential appears in the response body', async () => {
        const res = await mod.action({
          request: post({ token: SYNTHETIC_TOKEN, gitlabUrl: 'https://attacker.invalid' }),
        } as unknown as never);
        expect(await res.text()).not.toContain(SYNTHETIC_TOKEN);
      });

      it('test 13 — the synthetic token never appears in logs (nothing is logged at all)', async () => {
        await mod.action({
          request: post({ token: SYNTHETIC_TOKEN, gitlabUrl: 'https://attacker.invalid' }),
        } as unknown as never);
        expect(logs.join('\n')).not.toContain(SYNTHETIC_TOKEN);
        expect(logs).toEqual([]);
      });

      it('a GET (loader) is disabled identically and side-effect free', async () => {
        const res = await mod.loader({ request: new Request('https://app.local/api/gitlab') } as unknown as never);
        expect(res.status).toBe(410);
        expect(fetchSpy).not.toHaveBeenCalled();
      });
    });
  }

  // test 4 + test 7: the source itself no longer contains destination/credential construction.
  it('tests 4/7 — neither route source builds a bearer token or a caller-derived destination', () => {
    for (const [routeName] of ROUTES) {
      const src = readFileSync(`${APP}routes/${routeName}`, 'utf8');
      const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
      expect(code, `${routeName} still references a bearer token`).not.toMatch(/Bearer/);
      expect(code, `${routeName} still reads gitlabUrl`).not.toMatch(/gitlabUrl/);
      expect(code, `${routeName} still builds an Authorization header`).not.toMatch(/Authorization/);
      expect(code, `${routeName} still parses a request body`).not.toMatch(/request\.json\(/);
      expect(code, `${routeName} still performs a fetch`).not.toMatch(/\bfetch\s*\(/);
    }
  });
});

// ─── §8 test 17 — no live caller references remain ───────────────────────────────

describe('R15 §8 test 17 — the disabled routes have no live caller references', () => {
  function appFiles(dir: string): string[] {
    const out: string[] = [];

    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = `${dir}${e.name}`;

      if (e.isDirectory()) {
        out.push(...appFiles(`${p}/`));
      } else if (/\.(ts|tsx)$/.test(e.name) && !e.name.endsWith('.d.ts')) {
        out.push(p);
      }
    }

    return out;
  }

  it('no production module fetches /api/gitlab-projects or /api/gitlab-branches', () => {
    const callers: string[] = [];

    for (const file of appFiles(APP)) {
      const rel = file.slice(APP.length).replace(/\\/g, '/');

      // The route modules themselves and this test are not "callers".
      if (rel.startsWith('routes/api.gitlab-') || rel.startsWith('test/')) {
        continue;
      }

      const code = readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/(^|[^:])\/\/[^\n]*/g, '$1');

      if (/['"`]\/api\/gitlab-(projects|branches)['"`]/.test(code)) {
        callers.push(rel);
      }
    }

    expect(callers, `live caller references remain: ${callers.join(', ')}`).toEqual([]);
  });
});

// ─── §7 / §8 test 21 — targeted caller-host + browser-token sweep ────────────────

/**
 * A route is a MATCH when it fetches a URL whose ORIGIN is interpolated from a variable that is not a
 * literal https:// constant in the same file (i.e. caller-derived), AND it constructs an Authorization
 * header. A fixed-origin route (`const baseUrl = 'https://api.github.com'`) is correctly not a match.
 */
function callerHostWithTokenForwarding(src: string): boolean {
  const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

  if (!/Authorization/.test(code)) {
    return false;
  }

  // Identifiers assigned an absolute https:// string literal are constant origins.
  const constantOrigins = new Set<string>();

  for (const m of code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"`]https:\/\//g)) {
    constantOrigins.add(m[1]);
  }

  // A fetch whose template URL STARTS with an interpolation → the origin itself is variable.
  for (const m of code.matchAll(/fetch\(\s*`\$\{\s*([A-Za-z_$][\w$]*)/g)) {
    if (!constantOrigins.has(m[1])) {
      return true;
    }
  }

  return false;
}

describe('R15 §7 — targeted sweep: caller-controlled origin + browser-token forwarding', () => {
  it('the detector is not vacuous: it flags the OLD GitLab route shape', () => {
    const oldShape = `
      const { token, gitlabUrl = 'https://gitlab.com' } = body;
      const response = await fetch(\`\${gitlabUrl}/api/v4/projects\`, {
        headers: { Authorization: \`Bearer \${token}\` },
      });`;
    expect(callerHostWithTokenForwarding(oldShape)).toBe(true);
  });

  it('the detector does NOT flag a fixed-origin provider route (constant baseUrl)', () => {
    const fixed = `
      const baseUrl = 'https://api.github.com';
      const r = await fetch(\`\${baseUrl}/repos/\${repo}\`, { headers: { Authorization: \`Bearer \${token}\` } });`;
    expect(callerHostWithTokenForwarding(fixed)).toBe(false);
  });

  it('test 21 — NO production route combines a caller-controlled origin with token forwarding', () => {
    const matches: string[] = [];

    for (const name of readdirSync(`${APP}routes`)) {
      if (!/\.(ts|tsx)$/.test(name) || name.endsWith('.d.ts')) {
        continue;
      }

      if (callerHostWithTokenForwarding(readFileSync(`${APP}routes/${name}`, 'utf8'))) {
        matches.push(name);
      }
    }

    expect(matches, `caller-host + token-forwarding routes remain: ${matches.join(', ')}`).toEqual([]);
  });
});
