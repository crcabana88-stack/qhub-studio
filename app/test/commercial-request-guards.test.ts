/**
 * QHUB Commercial Launch R2 — request guards (CSRF, origin, rate, body)
 * app/test/commercial-request-guards.test.ts
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  configuredAppOrigin,
  appUrl,
  isSameOrigin,
  readBoundedJson,
  checkRateLimit,
  resetRateLimiter,
} from '~/lib/qhub/commercial/request-guards.server';

const ENV = { QHUB_APP_ORIGIN: 'https://app.qhub.example' };

beforeEach(() => resetRateLimiter());

describe('origin allowlist (no open redirect)', () => {
  it('resolves the configured origin only', () => {
    expect(configuredAppOrigin(ENV)).toBe('https://app.qhub.example');
    expect(configuredAppOrigin({})).toBeNull();
  });

  it('builds same-origin URLs from the configured origin', () => {
    expect(appUrl(ENV, '/build')).toBe('https://app.qhub.example/build');
    expect(appUrl(ENV, 'pricing')).toBe('https://app.qhub.example/pricing');
    expect(appUrl({}, '/build')).toBeNull();
  });
});

describe('CSRF same-origin', () => {
  it('accepts a matching Origin header', () => {
    const req = new Request('https://app.qhub.example/api/billing/checkout', {
      method: 'POST',
      headers: { origin: 'https://app.qhub.example' },
    });
    expect(isSameOrigin(req, ENV)).toBe(true);
  });

  it('rejects a foreign Origin header', () => {
    const req = new Request('https://app.qhub.example/api/billing/checkout', {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    });
    expect(isSameOrigin(req, ENV)).toBe(false);
  });

  it('rejects a request with no Origin/Referer when an origin is configured', () => {
    const req = new Request('https://app.qhub.example/x', { method: 'POST' });
    expect(isSameOrigin(req, ENV)).toBe(false);
  });

  it('passes in local dev when no origin is configured', () => {
    const req = new Request('http://localhost/x', { method: 'POST' });
    expect(isSameOrigin(req, {})).toBe(true);
  });
});

describe('bounded body', () => {
  it('parses a small JSON body', async () => {
    const req = new Request('https://x/y', { method: 'POST', body: JSON.stringify({ a: 1 }) });
    await expect(readBoundedJson<{ a: number }>(req, 1024)).resolves.toEqual({ a: 1 });
  });

  it('rejects an oversized body', async () => {
    const big = JSON.stringify({ a: 'x'.repeat(5000) });
    const req = new Request('https://x/y', { method: 'POST', body: big });
    await expect(readBoundedJson(req, 1024)).rejects.toThrow(/body_too_large/);
  });

  it('rejects invalid JSON', async () => {
    const req = new Request('https://x/y', { method: 'POST', body: 'not json' });
    await expect(readBoundedJson(req, 1024)).rejects.toThrow(/invalid_json/);
  });
});

describe('rate limiter', () => {
  it('allows up to max then blocks within the window', () => {
    const now = 1_000_000;

    for (let i = 0; i < 3; i++) {
      expect(checkRateLimit('k', 3, 60_000, now).allowed).toBe(true);
    }
    expect(checkRateLimit('k', 3, 60_000, now).allowed).toBe(false);
  });

  it('recovers after the window elapses', () => {
    const t0 = 2_000_000;

    for (let i = 0; i < 3; i++) {
      checkRateLimit('k2', 3, 60_000, t0);
    }
    expect(checkRateLimit('k2', 3, 60_000, t0).allowed).toBe(false);
    expect(checkRateLimit('k2', 3, 60_000, t0 + 61_000).allowed).toBe(true);
  });
});
