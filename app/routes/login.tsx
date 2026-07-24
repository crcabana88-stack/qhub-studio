/**
 * QHUB Studio — Login Page
 * app/routes/login.tsx
 *
 * Supabase Google OAuth sign-in with Quantex branding.
 * Unauthenticated users are redirected here by the root loader.
 */

import type { ActionFunctionArgs, LoaderFunctionArgs } from '@remix-run/cloudflare';
import { redirect } from '@remix-run/cloudflare';
import { Form, useActionData } from '@remix-run/react';
import { createServerClient } from '@supabase/ssr';
import { createCookieMethods } from '~/lib/auth/supabase-cookies';

// ── Server action: initiate Google OAuth ─────────────────────────────────────

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const supabaseUrl = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const supabaseAnonKey = env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

  if (!supabaseUrl || !supabaseAnonKey) {
    // Dev mode — skip auth and redirect home
    return redirect('/');
  }

  const cookieHeader = request.headers.get('Cookie') ?? '';
  const responseHeaders = new Headers();

  const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: createCookieMethods(cookieHeader, responseHeaders),
  });

  const siteUrl =
    env.SITE_URL ??
    process.env.SITE_URL ??
    (request.headers.get('Origin') || 'http://localhost:5173');

  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo: `${siteUrl}/auth/callback` },
  });

  if (error || !data.url) {
    return { error: error?.message ?? 'OAuth failed' };
  }

  return redirect(data.url, { headers: responseHeaders });
}

// ── Loader: if already authed, skip login ────────────────────────────────────

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const supabaseUrl = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';

  if (!supabaseUrl) {
    // Dev mode — always authenticated
    return redirect('/');
  }

  return null;
}

// ── UI ───────────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const actionData = useActionData<typeof action>();

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #0B0D10 0%, #0F1720 60%, #0B1623 100%)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: "'Inter', system-ui, sans-serif",
        color: '#fff',
      }}
    >
      {/* Logo */}
      <div style={{ marginBottom: 48, textAlign: 'center' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            marginBottom: 8,
            justifyContent: 'center',
          }}
        >
          {/* Three-signal mark */}
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="18" width="6" height="12" rx="1.5" fill="#1D9E75" />
            <rect x="13" y="10" width="6" height="20" rx="1.5" fill="#1D9E75" />
            <rect x="24" y="2" width="6" height="28" rx="1.5" fill="#1D9E75" />
          </svg>
          <span style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em', color: '#fff' }}>
            QHUB Studio
          </span>
        </div>
        <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)', letterSpacing: '0.06em' }}>
          by Quantex Technologies
        </span>
      </div>

      {/* Card */}
      <div
        style={{
          background: 'rgba(255,255,255,0.05)',
          border: '1px solid rgba(255,255,255,0.10)',
          borderRadius: 16,
          padding: '40px 48px',
          width: 400,
          backdropFilter: 'blur(12px)',
        }}
      >
        <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 8, marginTop: 0, color: '#fff' }}>
          Sign in to QHUB Studio
        </h1>
        <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.5)', marginBottom: 32, marginTop: 0 }}>
          Governed AI app builder. Every build tracked in the QHUB audit ledger.
        </p>

        {actionData?.error && (
          <div
            style={{
              background: 'rgba(239,68,68,0.15)',
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 8,
              padding: '12px 16px',
              marginBottom: 20,
              fontSize: 13,
              color: '#fca5a5',
            }}
          >
            {actionData.error}
          </div>
        )}

        <Form method="post">
          <button
            type="submit"
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 12,
              background: '#fff',
              color: '#111',
              border: 'none',
              borderRadius: 10,
              padding: '13px 24px',
              fontSize: 15,
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'opacity 0.15s',
            }}
            onMouseOver={(e) => ((e.currentTarget as HTMLButtonElement).style.opacity = '0.9')}
            onMouseOut={(e) => ((e.currentTarget as HTMLButtonElement).style.opacity = '1')}
          >
            {/* Google icon */}
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path
                d="M17.64 9.205c0-.639-.057-1.252-.164-1.841H9v3.481h4.844a4.14 4.14 0 01-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"
                fill="#4285F4"
              />
              <path
                d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z"
                fill="#34A853"
              />
              <path
                d="M3.964 10.71A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"
                fill="#FBBC05"
              />
              <path
                d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"
                fill="#EA4335"
              />
            </svg>
            Continue with Google
          </button>
        </Form>

        <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', textAlign: 'center', marginTop: 24, marginBottom: 0 }}>
          Access is limited to authorized Quantex organizations.
          <br />
          Contact{' '}
          <a href="mailto:carlos@quantex-tech.com" style={{ color: '#1D9E75', textDecoration: 'none' }}>
            carlos@quantex-tech.com
          </a>{' '}
          to request access.
        </p>
      </div>

      {/* Compliance badge */}
      <div
        style={{
          marginTop: 40,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontSize: 12,
          color: 'rgba(255,255,255,0.25)',
        }}
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#1D9E75',
            display: 'inline-block',
          }}
        />
        WORM audit ledger active · SOC 2 Type II in progress · FedRAMP Ready
      </div>
    </div>
  );
}
