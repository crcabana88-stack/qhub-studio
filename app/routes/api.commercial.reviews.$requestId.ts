// @qhub-route: COMMERCIAL_READY
/**
 * QHUB Commercial Launch R3 — GET /api/commercial/reviews/:requestId  (customer view)
 * app/routes/api.commercial.reviews.$requestId.ts
 *
 * A customer views the status of their OWN review request. The request is fetched
 * scoped to the caller's authoritative org — cross-tenant reads return 404.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { getReviewRequestForOrg } from '~/lib/qhub/commercial/review.server';

export async function loader({ request, context, params }: LoaderFunctionArgs) {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const guard = await requireCommercialContext(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  if (!ctx.orgId || !params.requestId) {
    return json({ ok: false, error: 'not_found' }, { status: 404 });
  }

  const review = await getReviewRequestForOrg(params.requestId, ctx.orgId, env);

  if (!review) {
    return json({ ok: false, error: 'not_found' }, { status: 404 });
  }

  return json({ ok: true, review: { id: review.id, status: review.status, category: review.category } });
}
