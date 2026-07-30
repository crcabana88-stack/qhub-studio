/**
 * QHUB Commercial Launch R14 — web-search SSRF adversarial suite
 * app/test/commercial-web-search.test.ts
 *
 * Exercises the shared SSRF validator/fetcher (safe-fetch.server) + the reclassified authenticated
 * web-search route. Synthetic data + mocked fetch only; proves every caller-controlled destination is
 * rejected BEFORE any outbound request, credentials are never forwarded, and nothing sensitive is logged.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { assertSafePublicUrl, safeFetch, SsrfError } from '~/lib/qhub/safe-fetch.server';
import { handleWebSearch, type WebSearchDeps } from '~/lib/qhub/web-search.server';

function mockFetch(
  opts: { redirectTo?: string; alwaysRedirect?: boolean; status?: number; contentType?: string; body?: string } = {},
) {
  const calls: Array<{ url: string; headers: Record<string, string>; method: string; hasSignal: boolean }> = [];
  let served = false;

  const impl = (async (url: string | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    calls.push({ url: String(url), headers, method: init?.method ?? 'GET', hasSignal: !!init?.signal });

    if (opts.redirectTo && (opts.alwaysRedirect || !served)) {
      served = true;
      return new Response(null, { status: 302, headers: { location: opts.redirectTo } });
    }

    return new Response(opts.body ?? '<title>ok</title>', {
      status: opts.status ?? 200,
      headers: { 'content-type': opts.contentType ?? 'text/html', 'set-cookie': 'x=1' },
    });
  }) as unknown as typeof fetch;

  return { impl, calls };
}

const authed: WebSearchDeps['authenticate'] = async () => ({ userId: 'u1' });
const anon: WebSearchDeps['authenticate'] = async () => null;

function post(body: unknown, headers: Record<string, string> = {}) {
  return new Request('https://app.local/api/web-search', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

let logs: string[] = [];

beforeEach(() => {
  logs = [];

  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      logs.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
    });
  }
});

afterEach(() => vi.restoreAllMocks());

// ─── §8 SSRF validation rejects every caller-controlled destination ─────────────

describe('R14 §8 — SSRF validator rejects unsafe targets', () => {
  const blocked: Array<[string, string]> = [
    ['test 1 — http IPv4-mapped loopback', 'http://[::ffff:127.0.0.1]/'],
    ['test 2 — https IPv4-mapped loopback', 'https://[::ffff:127.0.0.1]/'],
    ['test 3 — IPv4 loopback', 'https://127.0.0.1/'],
    ['test 4a — IPv4 private 10/8', 'https://10.0.0.5/'],
    ['test 4b — IPv4 private 192.168', 'https://192.168.1.1/'],
    ['test 4c — IPv4 private 172.16/12', 'https://172.16.9.9/'],
    ['test 5 — IPv4 link-local/metadata', 'https://169.254.169.254/'],
    ['test 6 — IPv6 loopback', 'https://[::1]/'],
    ['test 7a — IPv6 unique-local fc00', 'https://[fc00::1]/'],
    ['test 7b — IPv6 unique-local fd', 'https://[fd12:3456::1]/'],
    ['test 8 — IPv6 link-local', 'https://[fe80::1]/'],
    ['test 9a — decimal IPv4', 'https://2130706433/'],
    ['test 9b — hex IPv4', 'https://0x7f000001/'],
    ['test 9c — octal IPv4', 'https://0177.0.0.1/'],
    ['test 9d — shortened IPv4', 'https://127.1/'],
    ['test 10a — localhost', 'https://localhost/'],
    ['test 10b — LOCALHOST case', 'https://LOCALHOST/'],
    ['test 10c — *.localhost', 'https://foo.localhost/'],
    ['test 12 — protocol-relative', '//evil.example/'],
    ['test 13 — userinfo', 'https://user:pass@evil.example/'],
    ['test 14 — non-approved port', 'https://example.com:8080/'],
    ['scheme — non-https', 'http://example.com/'],
    ['single-label host', 'https://intranet/'],
    ['idn/punycode host', 'https://xn--e1afmkfd.example/'],
  ];

  for (const [label, url] of blocked) {
    it(`${label} → rejected`, async () => {
      await expect(assertSafePublicUrl(url)).rejects.toBeInstanceOf(SsrfError);
    });
  }

  it('a normal public HTTPS URL is accepted', async () => {
    await expect(assertSafePublicUrl('https://example.com/page')).resolves.toContain('https://example.com/');
  });

  it('test 11 — a DNS name resolving to a blocked IP is rejected via the injected resolver', async () => {
    const resolve = async () => ['203.0.113.9', '127.0.0.1']; // one public, one loopback
    await expect(assertSafePublicUrl('https://rebind.example/', { resolve })).rejects.toBeInstanceOf(SsrfError);

    // A resolver returning only public addresses passes.
    await expect(
      assertSafePublicUrl('https://ok.example/', { resolve: async () => ['93.184.216.34'] }),
    ).resolves.toContain('https://ok.example/');
  });
});

// ─── §8 fetch-level SSRF + redirect + credential handling ────────────────────────

describe('R14 §8 — safeFetch: zero fetch on rejection, redirect + credential controls', () => {
  it('test 20 — a rejected target performs ZERO outbound fetch', async () => {
    const { impl, calls } = mockFetch();
    await expect(safeFetch('https://127.0.0.1/', { fetchImpl: impl })).rejects.toBeInstanceOf(SsrfError);
    expect(calls.length).toBe(0);
  });

  it('test 15 — a redirect to a blocked IP (cross-origin) is rejected, not followed', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://127.0.0.1/internal' });
    await expect(safeFetch('https://example.com/', { fetchImpl: impl })).rejects.toBeInstanceOf(SsrfError);
    expect(calls.map((c) => new URL(c.url).hostname)).toEqual(['example.com']); // never hit 127.0.0.1
  });

  it('test 16 — a cross-origin redirect is rejected (same-origin only)', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://other.example/x' });
    await expect(safeFetch('https://example.com/', { fetchImpl: impl })).rejects.toBeInstanceOf(SsrfError);
    expect(calls.length).toBe(1);
  });

  it('a scheme-downgrade redirect (https→http) is rejected', async () => {
    const { impl } = mockFetch({ redirectTo: 'http://example.com/x' });
    await expect(safeFetch('https://example.com/', { fetchImpl: impl })).rejects.toBeInstanceOf(SsrfError);
  });

  it('a SAME-origin redirect is followed and re-validated', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://example.com/moved' });
    const res = await safeFetch('https://example.com/start', { fetchImpl: impl });
    expect(res.status).toBe(200);
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual(['/start', '/moved']);
  });

  it('test 17 — incoming authorization / cookie / api-key headers are stripped before fetch', async () => {
    const { impl, calls } = mockFetch();
    await safeFetch('https://example.com/', {
      fetchImpl: impl,
      headers: { authorization: 'Bearer S', cookie: 'sid=S', 'x-api-key': 'S', accept: 'text/html' },
    });
    expect(calls[0].headers.authorization).toBeUndefined();
    expect(calls[0].headers.cookie).toBeUndefined();
    expect(calls[0].headers['x-api-key']).toBeUndefined();
    expect(calls[0].headers.accept).toBe('text/html');
  });

  it('test 22 — method/timeout/redirect controls: an abort signal is set and the redirect cap holds', async () => {
    const { impl, calls } = mockFetch({ redirectTo: 'https://example.com/loop', alwaysRedirect: true });

    // Every hop carries an abort signal; the redirect cap bounds the number of hops (initial + 1).
    await expect(safeFetch('https://example.com/', { fetchImpl: impl, maxRedirects: 1 })).rejects.toBeInstanceOf(
      SsrfError,
    );
    expect(calls.every((c) => c.hasSignal)).toBe(true);
    expect(calls.length).toBe(2);
  });
});

// ─── §8 route-level auth + logging + zero-side-effect ────────────────────────────

describe('R14 §8 — web-search route: auth boundary, no forwarding, no sensitive logs', () => {
  const SECRET = 'ghp_SYNTHETIC_websearch_0123456789';

  it('test 18/19 — an unauthenticated caller is rejected with ZERO outbound fetch (no public fetch mode)', async () => {
    const { impl, calls } = mockFetch();
    const res = await handleWebSearch(post({ url: 'https://example.com/' }, { authorization: `Bearer ${SECRET}` }), {
      authenticate: anon,
      fetchImpl: impl,
    });
    expect(res.status).toBe(401);
    expect(calls.length).toBe(0);
  });

  it('an authenticated caller reaches an approved public page (scrapes title/content)', async () => {
    const { impl, calls } = mockFetch({ body: '<title>Hello</title><p>world</p>' });
    const res = await handleWebSearch(post({ url: 'https://example.com/a' }), {
      authenticate: authed,
      fetchImpl: impl,
    });
    expect(res.status).toBe(200);
    expect(calls.length).toBe(1);

    const data = (await res.json()) as { data: { title: string } };
    expect(data.data.title).toBe('Hello');
  });

  it('an authenticated caller with an SSRF url is rejected, ZERO outbound fetch (test 20)', async () => {
    const { impl, calls } = mockFetch();
    const res = await handleWebSearch(post({ url: 'https://[::ffff:169.254.169.254]/' }), {
      authenticate: authed,
      fetchImpl: impl,
    });
    expect(res.status).toBe(400);
    expect(calls.length).toBe(0);
  });

  it('test 21 — no sensitive header/token is ever logged; a non-POST is side-effect free', async () => {
    const { impl } = mockFetch();
    await handleWebSearch(
      post({ url: 'https://[::1]/' }, { authorization: `Bearer ${SECRET}`, cookie: `s=${SECRET}` }),
      {
        authenticate: authed,
        fetchImpl: impl,
      },
    );

    const joined = logs.join('\n');
    expect(joined).not.toContain(SECRET);
    expect(joined.toLowerCase()).not.toContain('authorization');
    expect(logs).toEqual([]);

    // OPTIONS is side-effect free (no auth, no fetch).
    const opt = await handleWebSearch(new Request('https://app.local/api/web-search', { method: 'OPTIONS' }), {
      authenticate: anon,
      fetchImpl: impl,
    });
    expect(opt.status).toBe(204);
  });

  it('test 22 (route) — a non-POST method is rejected', async () => {
    const { impl } = mockFetch();
    const res = await handleWebSearch(new Request('https://app.local/api/web-search', { method: 'GET' }), {
      authenticate: authed,
      fetchImpl: impl,
    });
    expect(res.status).toBe(405);
  });
});
