/**
 * QHUB Studio — Session / Auth
 * app/lib/auth/session.ts
 *
 * Reads the authenticated user from the Supabase JWT cookie and
 * returns a typed session object used by Remix loaders and actions.
 *
 * SECURITY MODEL:
 *   QhubSession is the browser-facing session type. It deliberately
 *   does NOT include hmacSecret or any signing credentials.
 *   The HMAC secret is only accessible via getHmacSecret() which
 *   is a server-only call (reads from process.env / cloudflare env).
 *
 * Required env vars:
 *   SUPABASE_URL         e.g. https://xyzxyz.supabase.co
 *   SUPABASE_ANON_KEY    public anon key (safe to embed)
 *   QHUB_HMAC_SECRET     NEVER returned to browser — accessed via
 *                        app/lib/qhub/governance-secrets.server.ts only
 */

import { createServerClient } from '@supabase/ssr';
import { createCookieMethods } from '~/lib/auth/supabase-cookies';

/**
 * Browser-safe session type.
 * MUST NOT contain QHUB_HMAC_SECRET or any signing credentials.
 * All fields here may reach window.__remixContext via Remix SSR hydration.
 */
export interface QhubSession {
  userId: string;
  orgId: string;
  email: string;
  role: 'admin' | 'builder' | 'viewer';
}

/**
 * Extract the authenticated QHUB session from an incoming Request.
 * Returns null if unauthenticated.
 *
 * Usage in a Remix loader:
 *   const session = await getSession(request, env);
 *   if (!session) return redirect('/login');
 */
/**
 * Whether an unconfigured-Supabase dev fallback is permitted. Only true when
 * QHUB_ALLOW_DEV_AUTH is explicitly set AND the deploy environment is NOT a
 * staging/preview/production marker. This makes the dev fallback impossible in
 * staging/production (P1-10 fail-closed).
 */
export function isDevAuthAllowed(env: Record<string, string | undefined>): boolean {
  const flag = (env.QHUB_ALLOW_DEV_AUTH ?? process.env.QHUB_ALLOW_DEV_AUTH ?? '').toLowerCase();

  if (flag !== 'true' && flag !== '1') {
    return false;
  }

  const deployEnv = (env.QHUB_DEPLOY_ENV ?? process.env.QHUB_DEPLOY_ENV ?? '').toLowerCase();

  // Any recognized non-local marker forbids the fallback.
  return !['staging', 'preview', 'production', 'prod'].includes(deployEnv);
}

/** Signal returned when Supabase auth config is absent and no dev fallback is allowed. */
export type AuthConfigState = 'ok' | 'missing_config';

/**
 * Resolve ONLY the verified user identity (id + email) from the session token.
 * org_id and role from user_metadata are intentionally NOT trusted for
 * authorization — see requireCommercialContext for the authoritative resolution.
 * Returns 'missing_config' when Supabase is not configured and dev auth is not
 * allowed (fail closed), or null when unauthenticated.
 */
export async function getVerifiedUser(
  request: Request,
  env: Record<string, string | undefined>,
): Promise<{ userId: string; email: string } | null | 'missing_config'> {
  const supabaseUrl = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const supabaseAnonKey = env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

  if (!supabaseUrl || !supabaseAnonKey) {
    if (isDevAuthAllowed(env)) {
      const dev = devFallbackSession();
      return { userId: dev.userId, email: dev.email };
    }

    return 'missing_config';
  }

  const cookieHeader = request.headers.get('Cookie') ?? '';
  const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: createCookieMethods(cookieHeader),
  });

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return null;
  }

  return { userId: user.id, email: user.email ?? '' };
}

export async function getSession(
  request: Request,
  env: Record<string, string | undefined>,
): Promise<QhubSession | null> {
  const supabaseUrl = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const supabaseAnonKey = env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

  if (!supabaseUrl || !supabaseAnonKey) {
    // Fail closed in staging/production; only fall back when dev auth is allowed.
    if (isDevAuthAllowed(env)) {
      console.warn('[Auth] Supabase env vars missing — dev auth fallback (local only)');
      return devFallbackSession();
    }

    console.error('[Auth] Supabase env vars missing and dev auth not allowed — failing closed');

    return null;
  }

  const cookieHeader = request.headers.get('Cookie') ?? '';

  /*
   * Read-only: getSession only needs to READ the session. Chunked auth cookies
   * require the getAll interface to reassemble; no responseHeaders → setAll is a
   * no-op (any token refresh is re-persisted on the next write-capable request).
   */
  const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: createCookieMethods(cookieHeader),
  });

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return null;
  }

  // org_id and role are stored in user_metadata by the Supabase invite flow
  const orgId: string = (user.user_metadata?.org_id as string) ?? 'default';
  const role: QhubSession['role'] = (user.user_metadata?.role as QhubSession['role']) ?? 'builder';

  /*
   * hmacSecret is intentionally NOT included here.
   * Use getHmacSecret(env) in server actions/routes that need to sign events.
   */
  return {
    userId: user.id,
    orgId,
    email: user.email ?? '',
    role,
  };
}

/*
 * getHmacSecret has been moved to app/lib/qhub/governance-secrets.server.ts
 * Import from there to enforce the .server.ts module boundary.
 */

/** Dev-mode fallback when Supabase is not configured */
function devFallbackSession(): QhubSession {
  return {
    userId: 'dev-user',
    orgId: 'dev-org',
    email: 'dev@quantex-tech.com',
    role: 'admin',
  };
}
