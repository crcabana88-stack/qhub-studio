// @qhub-route: COMMERCIAL_READY
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
import { requireCommercialReady } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { currentReviewPolicyVersion } from '~/lib/qhub/commercial/governance-essentials';
import { getReviewDecisionMeta } from '~/lib/qhub/commercial/review.server';
import { decideReviewAtomic } from '~/lib/qhub/commercial/commercial-store.server';
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

  // Fail closed on schema readiness BEFORE any decision/governance/audit write.
  const ready = await requireCommercialReady(env);

  if (!ready.ok) {
    return ready.response;
  }

  const rate = checkRateLimit(`review_decide:${ctx.userId}`, 60, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  /*
   * NOTE: any `policyVersion` in the request body is IGNORED — the review policy version
   * is strictly server-derived. The browser can never choose or override it.
   */
  let body: { decision?: 'approved' | 'rejected'; reason?: string };

  try {
    body = await readBoundedJson(request, 8 * 1024);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!params.requestId || (body.decision !== 'approved' && body.decision !== 'rejected') || !body.reason?.trim()) {
    return json({ ok: false, error: 'invalid_decision' }, { status: 400 });
  }

  /*
   * SERVER-DERIVED policy version: load the version the request was evaluated under at
   * submission, and bind the decision to it. If the current policy has materially changed
   * since submission, require re-review (409) rather than silently re-versioning.
   */
  const meta = await getReviewDecisionMeta(params.requestId, env);

  if (!meta) {
    return json({ ok: false, error: 'not_found' }, { status: 404 });
  }

  const evaluatedVersion = meta.policyVersion ?? currentReviewPolicyVersion();

  if (evaluatedVersion !== currentReviewPolicyVersion()) {
    return json({ ok: false, error: 'policy_version_changed' }, { status: 409 });
  }

  /*
   * ONE atomic RPC: request + Governance Essentials + immutable audit, all-or-nothing.
   * The actor is the authoritative staff context; the policy version is SERVER-owned
   * (the evaluated-under version), never the browser's.
   */
  const result = await decideReviewAtomic(
    ready.token,
    {
      requestId: params.requestId,
      actor: ctx.userId,
      isStaff: ctx.isStaff,
      decision: body.decision,
      reason: body.reason,
      policyVersion: evaluatedVersion,
    },
    env,
  );

  if (!result.ok) {
    const status = result.reason === 'staff_required' ? 403 : result.reason === 'not_found' ? 404 : 409;
    return json({ ok: false, error: result.reason }, { status });
  }

  return json({ ok: true, policyVersion: evaluatedVersion });
}
