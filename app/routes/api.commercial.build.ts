/**
 * QHUB Commercial Launch R3 — POST /api/commercial/build
 * app/routes/api.commercial.build.ts
 *
 * The dedicated commercial build entry. It NEVER reaches the internal Studio. It
 * binds the request to an authoritative CommercialExecutionContext (verified
 * project ownership), then routes through invokeCommercialModel which re-checks
 * capability + Governance Essentials + credits BEFORE any model work. CSRF,
 * per-org rate limit, and a UTF-8 byte-bounded body apply.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialProject } from '~/lib/qhub/commercial/commercial-context.server';
import { requireCommercialReady } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { invokeCommercialModel, type CommercialBuildRequest } from '~/lib/qhub/commercial/commercial-service.server';
import { checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  let body: {
    projectId?: string;
    idempotencyKey?: string;
    model?: string;
    provider?: string;
    inputHash?: string;
    action?: string;
    template?: string;
    units?: number;
    governanceVersion?: string;
  };

  try {
    body = await readBoundedJson(request, 32 * 1024);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!body.projectId || !body.idempotencyKey) {
    return json({ ok: false, error: 'missing_project_or_key' }, { status: 400 });
  }

  // Authoritative context + verified project ownership + MODEL_INVOKE capability.
  const guard = await requireCommercialProject(request, env, body.projectId, 'MODEL_INVOKE');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  // Fail closed on schema readiness BEFORE any credit consumption or model invocation.
  const ready = await requireCommercialReady(env);

  if (!ready.ok) {
    return ready.response;
  }

  const rate = checkRateLimit(`build:${ctx.orgId}:${ctx.userId}`, 30, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  const req: CommercialBuildRequest = {
    model: body.model ?? 'default',
    provider: body.provider ?? 'default',
    inputHash: body.inputHash ?? '',
    action: body.action ?? 'BUILD',
    template: body.template ?? 'blank',
    units: Math.max(1, Math.floor(body.units ?? 1)),
    governanceVersion: body.governanceVersion ?? '1',
  };

  /*
   * The governed model runner. The real generation service is wrapped here; the
   * enforcement (context + governance + credit) has already happened in the service.
   */
  const outcome = await invokeCommercialModel(ctx, req, body.idempotencyKey, env, async () => {
    return { accepted: true, projectId: ctx.projectId };
  });

  if (!outcome.ok) {
    const status =
      outcome.reason === 'governance_gate_blocked' ? 409 : outcome.reason === 'insufficient_credits' ? 402 : 403;
    return json({ ok: false, error: outcome.reason }, { status });
  }

  return json({ ok: true, remaining: outcome.value.credit.remaining, ledgerId: outcome.value.credit.ledger_id });
}
