/**
 * QHUB Commercial Launch R3 — POST /api/commercial/projects
 * app/routes/api.commercial.projects.ts
 *
 * Create a commercial project, transactionally enforcing the plan project cap
 * (one active Guided project via the partial-unique index; Builder Beta five
 * active projects via the active-count check). CSRF + rate limit + bounded body.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { createCommercialProject } from '~/lib/qhub/commercial/commercial-service.server';
import { checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  const guard = await requireCommercialContext(request, env, 'PROJECT_CREATE');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  const rate = checkRateLimit(`project_create:${ctx.orgId}:${ctx.userId}`, 10, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  let body: { idempotencyKey?: string; requestHash?: string };

  try {
    body = await readBoundedJson(request, 2048);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  const idempotencyKey =
    typeof body.idempotencyKey === 'string' && body.idempotencyKey ? body.idempotencyKey : crypto.randomUUID();
  const requestHash = typeof body.requestHash === 'string' && body.requestHash ? body.requestHash : idempotencyKey;

  const created = await createCommercialProject(ctx, { idempotencyKey, requestHash }, env);

  if (!created.ok) {
    return json({ ok: false, error: created.reason }, { status: 409 });
  }

  return json({ ok: true, projectId: created.value.projectId, idempotent: created.value.idempotent });
}
