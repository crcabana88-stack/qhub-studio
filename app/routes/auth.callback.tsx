// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Studio — Supabase OAuth Callback
 * app/routes/auth.callback.tsx
 *
 * Handles the redirect from Supabase after Google OAuth.
 * Exchanges the code for a session cookie, then redirects home.
 */

import type { LoaderFunctionArgs } from '@remix-run/cloudflare';
import { redirect } from '@remix-run/cloudflare';
import { createServerClient } from '@supabase/ssr';
import { createCookieMethods } from '~/lib/auth/supabase-cookies';

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const supabaseUrl = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const supabaseAnonKey = env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const next = url.searchParams.get('next') ?? '/';

  if (!code) {
    /*
     * Diagnostic: Supabase redirects back with ?error=... (no code) when the
     * redirect URL isn't allow-listed or the provider flow failed.
     */
    console.warn(
      '[Auth] callback missing code —',
      'error=',
      url.searchParams.get('error'),
      'error_code=',
      url.searchParams.get('error_code'),
      'error_description=',
      url.searchParams.get('error_description'),
    );
    return redirect('/login?error=no_code');
  }

  if (!supabaseUrl || !supabaseAnonKey) {
    // Dev mode — just redirect home
    return redirect(next);
  }

  const cookieHeader = request.headers.get('Cookie') ?? '';
  const responseHeaders = new Headers();

  const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: createCookieMethods(cookieHeader, responseHeaders),
  });

  const { error } = await supabase.auth.exchangeCodeForSession(code);

  if (error) {
    console.error('[Auth] exchangeCodeForSession error:', error.message);
    return redirect(`/login?error=${encodeURIComponent(error.message)}`, { headers: responseHeaders });
  }

  return redirect(next, { headers: responseHeaders });
}

export default function AuthCallback() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#0B0D10',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'rgba(255,255,255,0.5)',
        fontFamily: 'system-ui, sans-serif',
      }}
    >
      Signing you in…
    </div>
  );
}
