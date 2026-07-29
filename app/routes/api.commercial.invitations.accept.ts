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
import { acceptInvitation, getInvitationOrg } from '~/lib/qhub/commercial/commercial-store.server';
import { loadOrgEntitlements } from '~/lib/qhub/commercial/entitlements.server';
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

  let body: { invitationId?: string };

  try {
    body = await readBoundedJson(request, 2048);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!body.invitationId) {
    return json({ ok: false, error: 'missing_invitation' }, { status: 400 });
  }

  // Resolve the seat cap from the invitation's org plan (authoritative).
  const org = await getInvitationOrg(body.invitationId, env);

  if (!org) {
    return json({ ok: false, error: 'invalid_invitation' }, { status: 404 });
  }

  const resolved = await loadOrgEntitlements(org, env);
  const maxSeats = resolved.entitlements.seats;

  const result = await acceptInvitation({ invitationId: body.invitationId, userId: user.userId, maxSeats }, env);

  if (result === 'SEAT_LIMIT') {
    return json({ ok: false, error: 'seat_limit_reached' }, { status: 409 });
  }

  if (result === 'INVALID') {
    return json({ ok: false, error: 'invalid_invitation' }, { status: 400 });
  }

  return json({ ok: true, result });
}
