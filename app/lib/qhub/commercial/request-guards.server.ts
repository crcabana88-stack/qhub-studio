/**
 * QHUB Commercial Launch R2 — REQUEST GUARDS (SERVER)
 * app/lib/qhub/commercial/request-guards.server.ts
 *
 * CSRF (same-origin), rate limiting, bounded body reading, and a server-owned
 * origin allowlist for building redirect URLs (no open redirect, no trust in
 * forwarded host headers). The rate limiter and origin logic are pure/testable.
 */

// ─── Origin allowlist (no open redirect) ────────────────────────────────────────

/**
 * The single allowlisted application origin. Taken from QHUB_APP_ORIGIN — NEVER
 * from the request Host/forwarded headers. Returns null when unset.
 */
export function configuredAppOrigin(env: Record<string, string | undefined>): string | null {
  const raw = (env.QHUB_APP_ORIGIN ?? process.env.QHUB_APP_ORIGIN ?? '').trim();

  if (!raw) {
    return null;
  }

  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

/** Build a same-origin URL from the configured origin + a fixed path. */
export function appUrl(env: Record<string, string | undefined>, path: string): string | null {
  const origin = configuredAppOrigin(env);

  if (!origin) {
    return null;
  }

  const p = path.startsWith('/') ? path : `/${path}`;

  return `${origin}${p}`;
}

// ─── CSRF (same-origin for state-changing requests) ─────────────────────────────

/**
 * Verify the request Origin matches the configured app origin. When no app origin
 * is configured (local dev), the check passes. Returns true when allowed.
 */
export function isSameOrigin(request: Request, env: Record<string, string | undefined>): boolean {
  const configured = configuredAppOrigin(env);

  if (!configured) {
    return true; // local/dev without a configured origin
  }

  const origin = request.headers.get('origin');

  if (origin) {
    return origin === configured;
  }

  // Fall back to Referer origin when Origin is absent.
  const referer = request.headers.get('referer');

  if (referer) {
    try {
      return new URL(referer).origin === configured;
    } catch {
      return false;
    }
  }

  // No Origin/Referer on a state-changing request → reject.
  return false;
}

// ─── Bounded body ───────────────────────────────────────────────────────────────

const DEFAULT_MAX_BODY = 16 * 1024; // 16 KiB

/** Read a JSON body with a hard size cap. Throws 'body_too_large' / 'invalid_json'. */
export async function readBoundedJson<T = unknown>(request: Request, maxBytes = DEFAULT_MAX_BODY): Promise<T> {
  const len = Number(request.headers.get('content-length') ?? '0');

  if (len && len > maxBytes) {
    throw new Error('body_too_large');
  }

  const text = await request.text();

  if (text.length > maxBytes) {
    throw new Error('body_too_large');
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error('invalid_json');
  }
}

// ─── Rate limiter (in-memory sliding window) ────────────────────────────────────

const buckets = new Map<string, number[]>();

export interface RateResult {
  allowed: boolean;
  remaining: number;
}

/**
 * Sliding-window limiter. Best-effort per-isolate (sufficient as a basic abuse
 * control); the logic is deterministic and testable via an injected clock.
 */
export function checkRateLimit(key: string, max: number, windowMs: number, now: number = Date.now()): RateResult {
  const cutoff = now - windowMs;
  const hits = (buckets.get(key) ?? []).filter((t) => t > cutoff);

  if (hits.length >= max) {
    buckets.set(key, hits);
    return { allowed: false, remaining: 0 };
  }

  hits.push(now);
  buckets.set(key, hits);

  return { allowed: true, remaining: Math.max(0, max - hits.length) };
}

/** Test/maintenance helper — clears the limiter state. */
export function resetRateLimiter(): void {
  buckets.clear();
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
