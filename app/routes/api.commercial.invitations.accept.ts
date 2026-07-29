/**
 * QHUB Commercial Launch R3 — POST /api/commercial/invitations/accept
 * app/routes/api.commercial.invitations.accept.ts
 *
 * An authenticated user accepts an org invitation. Acceptance is transactional and
 * seat-capped by the org's plan (Builder Beta 1, Guided Builder 5): the guarded RPC
 * counts active seats under a lock, so concurrent acceptances can never exceed the
 * cap. The accepting user is NOT yet a member, so identity comes from the verified
 * token (not requireCommercialContext). CSRF/same-origin + rate limit apply.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getVerifiedUser } from '~/lib/auth/session';
import { acceptInvitation } from '~/lib/qhub/commercial/commercial-store.server';
import { checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  const user = await getVerifiedUser(request, env);

  if (user === 'missing_config') {
    return json({ ok: false, error: 'auth_not_configured' }, { status: 503 });
  }

  if (!user) {
    return json({ ok: false, error: 'unauthenticated' }, { status: 401 });
  }

  const rate = checkRateLimit(`invite_accept:${user.userId}`, 10, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  let body: { invitationId?: string; token?: string };

  try {
    body = await readBoundedJson(request, 2048);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!body.invitationId || !body.token) {
    return json({ ok: false, error: 'missing_invitation_or_token' }, { status: 400 });
  }

  // Hash the presented token the same way it was stored at invitation time.
  const tokenHash = await sha256Hex(body.token);

  /*
   * The RPC verifies email + token and derives the plan-based seat cap internally —
   * the caller supplies NO seat cap.
   */
  const result = await acceptInvitation(
    { invitationId: body.invitationId, userId: user.userId, userEmail: user.email, tokenHash },
    env,
  );

  const map: Record<string, number> = {
    SEAT_LIMIT: 409,
    INELIGIBLE: 402,
    EMAIL_MISMATCH: 403,
    TOKEN_MISMATCH: 403,
    INVALID: 400,
  };

  if (result !== 'ACCEPTED' && result !== 'ALREADY') {
    return json({ ok: false, error: result.toLowerCase() }, { status: map[result] ?? 400 });
  }

  return json({ ok: true, result });
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
