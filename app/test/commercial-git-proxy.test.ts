/**
 * QHUB Commercial Launch R13 — hardened git-proxy adversarial suite
 * app/test/commercial-git-proxy.test.ts
 *
 * Real in-memory route-level tests (synthetic credentials only) proving the relay: rejects
 * attacker-selected destinations before any fetch, never forwards inbound credentials, revalidates
 * redirects, requires authentication, enforces method/size limits, and NEVER logs headers/secrets.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  APPROVED_GIT_HOSTS,
  GitProxyError,
  handleGitProxy,
  resolveApprovedTarget,
  type GitProxyDeps,
} from '~/lib/qhub/git-proxy.server';

const SECRET = 'ghp_SYNTHETIC_secret_0123456789abcdef';
const BASE = 'https://app.local/api/git-proxy/';

interface FetchCall {
  url: string;
  headers: Record<string, string>;
  method: string;
}

/** A fetch that records calls and never touches the network. Optionally returns a redirect once. */
function mockFetch(opts: { redirectTo?: string; status?: number } = {}) {
  const calls: FetchCall[] = [];
  let served = false;

  const impl = (async (url: string | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    calls.push({ url: String(url), headers, method: init?.method ?? 'GET' });

    if (opts.redirectTo && !served) {
      served = true;
      return new Response(null, { status: 302, headers: { location: opts.redirectTo } });
    }

    return new Response('git-data', {
      status: opts.status ?? 200,
      headers: { 'content-type': 'application/x-git-upload-pack-advertisement', 'set-cookie': 'x=1' },
    });
  }) as unknown as typeof fetch;

  return { impl, calls };
}

const authedUser: GitProxyDeps['authenticate'] = async () => ({ userId: 'u1' });
const anonUser: GitProxyDeps['authenticate'] = async () => null;

function req(splatWithQuery: string, method = 'GET', headers: Record<string, string> = {}) {
  return new Request(`${BASE}${splatWithQuery}`, { method, headers });
}

/** Split a splat "host/path?query" into the params['*'] value + the request query. */
function proxyReq(splat: string, method = 'GET', headers: Record<string, string> = {}) {
  const [path, query] = splat.split('?');
  const request = new Request(`${BASE}${splat}`, {
    method,
    headers,
    body: method === 'POST' ? 'want abc' : undefined,
  });

  return { request, path, query };
}

let logs: string[] = [];

beforeEach(() => {
  logs = [];

  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      logs.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
    });
  }
});

afterEach(() => vi.restoreAllMocks());

// ─── §7 destination validation (rejected BEFORE any fetch) ──────────────────────

describe('R13 §7 — destination validation rejects attacker targets before fetch', () => {
  const rejects: Array<[string, string]> = [
    ['attacker hostname (test 1)', 'evil.com/x'],
    ['absolute URL in splat (test 2)', 'https://evil.com/x'],
    ['protocol-relative (test 3)', '//evil.com/x'],
    ['encoded traversal / host confusion (test 4)', 'github.com/%2e%2e/%2e%2e/evil'],
    ['IP literal (test 5)', '127.0.0.1/x'],
    ['non-approved port (test 6)', 'github.com:8080/x'],
  ];

  for (const [label, splat] of rejects) {
    it(`${label} → rejected, zero outbound fetch`, async () => {
      const { impl, calls } = mockFetch();
      const { request, path } = proxyReq(splat);
      const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
      expect(res.status).toBe(400);
      expect(calls.length, 'no outbound fetch on a rejected target').toBe(0);
    });
  }

  it('resolveApprovedTarget accepts only exact approved hosts', () => {
    expect(resolveApprovedTarget('github.com/o/r.git/info/refs').host).toBe('github.com');
    expect(() => resolveApprovedTarget('githubbcom.evil.com/x')).toThrow(GitProxyError);
    expect(() => resolveApprovedTarget('sub.github.com/x')).toThrow(GitProxyError); // no wildcard suffix
    expect(() => resolveApprovedTarget('user@github.com/x')).toThrow(GitProxyError); // userinfo

    for (const h of APPROVED_GIT_HOSTS) {
      expect(resolveApprovedTarget(`${h}/o/r.git/info/refs`).host).toBe(h);
    }
  });
});

// ─── §7 redirect + credential handling ───────────────────────────────────────────

describe('R13 §7 — redirect revalidation + credential stripping', () => {
  it('redirect to an unapproved host is rejected, not followed (test 7)', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://evil.com/steal' });
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack');
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.status).toBe(400);

    // Only the first (approved) fetch happened; the evil redirect target was never fetched.
    expect(calls.map((c) => new URL(c.url).hostname)).toEqual(['github.com']);
  });

  it('R14 §7 — a redirect from one approved origin to ANOTHER approved origin is rejected (github→gitlab)', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://gitlab.com/o/r.git/info/refs' });
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack');
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.status).toBe(400);

    // gitlab.com was never fetched — the relay stayed on the originating github.com origin.
    expect(calls.map((c) => new URL(c.url).hostname)).toEqual(['github.com']);
  });

  it('R14 §7 — a SAME-origin redirect on an approved host IS followed', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://github.com/o/r.git/git-upload-pack' });
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack');
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.status).toBe(200);
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual(['/o/r.git/info/refs', '/o/r.git/git-upload-pack']);
  });

  it('incoming authorization / x-authorization / cookie / api-key are NOT forwarded (tests 8-10)', async () => {
    const { impl, calls } = mockFetch();
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack', 'GET', {
      authorization: `Bearer ${SECRET}`,
      'x-authorization': SECRET,
      cookie: `session=${SECRET}`,
      'x-api-key': SECRET,
      accept: 'application/x-git-upload-pack-advertisement',
    });
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.status).toBe(200);

    const sent = calls[0].headers;
    expect(sent.authorization).toBeUndefined();
    expect(sent['x-authorization']).toBeUndefined();
    expect(sent.cookie).toBeUndefined();
    expect(sent['x-api-key']).toBeUndefined();

    // A benign, allowlisted header IS forwarded.
    expect(sent.accept).toBe('application/x-git-upload-pack-advertisement');
  });

  it('no upstream Authorization is ever attached (public clone; test 14 posture)', async () => {
    const { impl, calls } = mockFetch();
    const { request, path } = proxyReq('gitlab.com/o/r.git/info/refs?service=git-upload-pack');
    await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(calls[0].headers.authorization).toBeUndefined();
  });

  it('no upstream credential/set-cookie header is echoed back to the browser (test 15)', async () => {
    const { impl } = mockFetch();
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack');
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.headers.get('authorization')).toBeNull();
  });

  it('an approved relative provider path reaches ONLY the approved origin (test 13)', async () => {
    const { impl, calls } = mockFetch();
    const { request, path } = proxyReq('github.com/octocat/hello.git/info/refs?service=git-upload-pack');
    const res = await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });
    expect(res.status).toBe(200);
    expect(calls.length).toBe(1);
    expect(new URL(calls[0].url).origin).toBe('https://github.com');
    expect(new URL(calls[0].url).pathname).toBe('/octocat/hello.git/info/refs');
  });
});

// ─── §7 auth + limits + logging ──────────────────────────────────────────────────

describe('R13 §7 — auth boundary, limits, and zero sensitive logging', () => {
  it('an unauthenticated caller is rejected with zero outbound fetch (test 16, test 18)', async () => {
    const { impl, calls } = mockFetch();
    const { request, path } = proxyReq('github.com/o/r.git/info/refs');
    const res = await handleGitProxy(request, path, { authenticate: anonUser, fetchImpl: impl });
    expect(res.status).toBe(401);
    expect(calls.length).toBe(0);
  });

  it('method + size controls are enforced (test 17)', async () => {
    const { impl, calls } = mockFetch();

    // Disallowed method.
    const put = proxyReq('github.com/o/r.git', 'PUT');
    expect((await handleGitProxy(put.request, put.path, { authenticate: authedUser, fetchImpl: impl })).status).toBe(
      405,
    );

    // Oversized declared body.
    const big = new Request(`${BASE}github.com/o/r.git/git-upload-pack`, {
      method: 'POST',
      headers: { 'content-length': String(100 * 1024 * 1024) },
      body: 'x',
    });
    expect(
      (await handleGitProxy(big, 'github.com/o/r.git/git-upload-pack', { authenticate: authedUser, fetchImpl: impl }))
        .status,
    ).toBe(413);

    expect(calls.length, 'neither invalid request reached the network').toBe(0);
  });

  it('the synthetic credential and header objects NEVER appear in logs (tests 11, 12)', async () => {
    const { impl } = mockFetch();
    const { request, path } = proxyReq('github.com/o/r.git/info/refs?service=git-upload-pack', 'GET', {
      authorization: `Bearer ${SECRET}`,
      cookie: `s=${SECRET}`,
    });
    await handleGitProxy(request, path, { authenticate: authedUser, fetchImpl: impl });

    const joined = logs.join('\n');
    expect(joined).not.toContain(SECRET);
    expect(joined.toLowerCase()).not.toContain('authorization');
    expect(joined.toLowerCase()).not.toContain('cookie');

    // The hardened handler logs nothing at all for a normal request.
    expect(logs).toEqual([]);
  });

  it('OPTIONS preflight returns CORS without auth or fetch', async () => {
    const { impl, calls } = mockFetch();
    const res = await handleGitProxy(req('github.com/o/r.git', 'OPTIONS'), 'github.com/o/r.git', {
      authenticate: anonUser,
      fetchImpl: impl,
    });
    expect(res.status).toBe(204);
    expect(calls.length).toBe(0);
  });
});
