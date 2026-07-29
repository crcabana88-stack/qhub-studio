/**
 * QHUB Commercial Launch R3 — POST /api/internal/commercial/reviews/:requestId/decision
 * app/routes/api.internal.commercial.reviews.$requestId.decision.ts
 *
 * Quantex-STAFF-ONLY. A staff reviewer approves/rejects a pending request; the
 * actor is derived server-side from the authoritative staff context. The decision
 * atomically updates the request, the project's Governance Essentials disposition,
 * and captures the policy version. Prohibited categories are non-overridable.
 * CSRF/same-origin, rate limit, and a bounded reason apply.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { decideReviewRequest } from '~/lib/qhub/commercial/review.server';
import { checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context, params }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  const guard = await requireStaff(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;
  const rate = checkRateLimit(`review_decide:${ctx.userId}`, 60, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  let body: { decision?: 'approved' | 'rejected'; reason?: string; policyVersion?: string };

  try {
    body = await readBoundedJson(request, 8 * 1024);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!params.requestId || (body.decision !== 'approved' && body.decision !== 'rejected') || !body.reason?.trim()) {
    return json({ ok: false, error: 'invalid_decision' }, { status: 400 });
  }

  const result = await decideReviewRequest(
    ctx,
    {
      requestId: params.requestId,
      decision: body.decision,
      reason: body.reason,
      policyVersion: body.policyVersion ?? 'v1',
    },
    env,
  );

  if (!result.ok) {
    const status = result.error === 'staff_required' ? 403 : result.error === 'not_found' ? 404 : 409;
    return json({ ok: false, error: result.error }, { status });
  }

  return json({ ok: true });
}
