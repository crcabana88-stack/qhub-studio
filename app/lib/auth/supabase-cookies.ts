/**
 * QHUB Studio — Supabase SSR cookie adapter
 * app/lib/auth/supabase-cookies.ts
 *
 * @supabase/ssr (>= 0.5) expects the getAll/setAll cookie interface. The older
 * get/set/remove interface does not correctly reassemble CHUNKED auth cookies
 * (Supabase splits the large OAuth session token into `<name>.0`, `<name>.1`…).
 * With get/set/remove the session is written but cannot be read back, so the
 * user bounces straight back to /login after a successful code exchange.
 *
 * These helpers implement the getAll/setAll contract against a raw Cookie
 * header (read) and a Headers object (write), so login, callback, and session
 * all share one correct implementation.
 */

export interface ParsedCookie {
  name: string;
  value: string;
}

/** Parse a raw `Cookie:` request header into name/value pairs. */
export function parseCookieHeader(header: string): ParsedCookie[] {
  if (!header) {
    return [];
  }

  return header
    .split(';')
    .map((pair) => {
      const eq = pair.indexOf('=');

      if (eq === -1) {
        return null;
      }

      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();

      if (!name) {
        return null;
      }

      return { name: decodeURIComponent(name), value: decodeURIComponent(value) };
    })
    .filter((c): c is ParsedCookie => c !== null);
}

/** Cookie attributes passed by @supabase/ssr in setAll. */
export interface SupabaseCookieOptions {
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: number | Date;
  sameSite?: boolean | 'lax' | 'strict' | 'none';
  httpOnly?: boolean;
  secure?: boolean;
}

/** Serialize one cookie to a Set-Cookie header value (always HttpOnly + Secure). */
export function serializeCookie(name: string, value: string, options: SupabaseCookieOptions = {}): string {
  const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];

  parts.push(`Path=${options.path ?? '/'}`);

  if (options.maxAge != null) {
    parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  }

  if (options.expires != null) {
    const expires = options.expires instanceof Date ? options.expires : new Date(options.expires);
    parts.push(`Expires=${expires.toUTCString()}`);
  }

  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }

  const sameSite = options.sameSite === undefined ? 'Lax' : normalizeSameSite(options.sameSite);
  parts.push(`SameSite=${sameSite}`);

  // Auth cookies are always HttpOnly (never read by client JS) and Secure
  // (served only over HTTPS in staging/production).
  parts.push('HttpOnly');
  parts.push('Secure');

  return parts.join('; ');
}

function normalizeSameSite(value: boolean | 'lax' | 'strict' | 'none'): string {
  if (value === true || value === 'strict') {
    return 'Strict';
  }

  if (value === 'none') {
    return 'None';
  }

  return 'Lax';
}

/**
 * Build the { getAll, setAll } object for createServerClient.
 * `cookieHeader` is the incoming request's Cookie header.
 * `responseHeaders` (optional) receives Set-Cookie entries; omit for read-only
 * flows (e.g. getSession) where nothing needs to be written back.
 */
export function createCookieMethods(cookieHeader: string, responseHeaders?: Headers) {
  return {
    getAll() {
      return parseCookieHeader(cookieHeader);
    },
    setAll(cookiesToSet: { name: string; value: string; options?: SupabaseCookieOptions }[]) {
      if (!responseHeaders) {
        return;
      }

      for (const { name, value, options } of cookiesToSet) {
        responseHeaders.append('Set-Cookie', serializeCookie(name, value, options));
      }
    },
  };
}
