// @qhub-route: COMMERCIAL_READY
/**
 * QHUB Commercial Launch R3 — POST /api/commercial/reviews  (customer submit)
 * app/routes/api.commercial.reviews.ts
 *
 * A customer submits a review-eligible request for a project they own. Enforces:
 * authoritative membership + exact project ownership (requireCommercialProject),
 * REVIEW_REQUEST capability, prohibited-category rejection (in the service),
 * CSRF/same-origin, per-user+org rate limit, byte-bounded body, and exact
 * idempotency (via the request-hash unique constraint).
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialProject } from '~/lib/qhub/commercial/commercial-context.server';
import { requireCommercialReady } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { submitCustomerReview } from '~/lib/qhub/commercial/governance-essentials.server';
import { checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  /*
   * R9 §1: the browser may supply ONLY the project, a bounded reason, and an optional idempotency
   * key. It CANNOT supply the review category or any authoritative version/identity field — those
   * are all derived server-side by submitCustomerReview from the persisted Governance record and
   * the requester's authoritative acknowledgment.
   */
  let body: { projectId?: string; reason?: string; idempotencyKey?: string };

  try {
    body = await readBoundedJson(request, 8 * 1024);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!body.projectId || !body.reason) {
    return json({ ok: false, error: 'missing_fields' }, { status: 400 });
  }

  const guard = await requireCommercialProject(request, env, body.projectId, 'REVIEW_REQUEST');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  // Fail closed on schema readiness BEFORE any review write.
  const ready = await requireCommercialReady(env);

  if (!ready.ok) {
    return ready.response;
  }

  const rate = checkRateLimit(`review_submit:${ctx.orgId}:${ctx.userId}`, 10, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  const result = await submitCustomerReview(
    ctx,
    { projectId: body.projectId, reason: body.reason, idempotencyKey: body.idempotencyKey },
    ready.token,
    env,
  );

  if (!result.ok) {
    const status = result.error === 'prohibited_category' ? 403 : 400;
    return json({ ok: false, error: result.error }, { status });
  }

  return json({ ok: true, requestId: result.requestId, idempotent: result.idempotent });
}
