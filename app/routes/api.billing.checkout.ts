/**
 * QHUB Commercial Launch R2 — POST /api/billing/checkout
 * app/routes/api.billing.checkout.ts
 *
 * Creates a Stripe-hosted Checkout session. Authority: an authoritative
 * billing-admin membership (CHECKOUT capability) — never the browser. The org and
 * plan price are server-owned; success/cancel URLs are built from the configured
 * app origin (no open redirect, no forwarded-host trust). CSRF (same-origin), a
 * rate limit, and a bounded body apply. Fails closed (503) without billing config.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { createBillingProvider } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import { getSubscriptionSnapshot } from '~/lib/qhub/commercial/commercial-store.server';
import { appUrl, checkRateLimit, isSameOrigin, readBoundedJson } from '~/lib/qhub/commercial/request-guards.server';
import { isPaidPlan, type BillingInterval, type PlanId } from '~/lib/qhub/commercial/plans';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  // Billing-admin authority (server-authoritative membership role).
  const guard = await requireCommercialContext(request, env, 'CHECKOUT');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  if (!ctx.orgId) {
    return json({ ok: false, error: 'no_org_context' }, { status: 403 });
  }

  const rate = checkRateLimit(`checkout:${ctx.orgId}`, 5, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  let body: { planId?: PlanId; interval?: BillingInterval; includeSetupFee?: boolean };

  try {
    body = await readBoundedJson(request, 2048);
  } catch (e) {
    return json({ ok: false, error: e instanceof Error ? e.message : 'invalid_json' }, { status: 400 });
  }

  if (!body.planId || !isPaidPlan(body.planId)) {
    return json({ ok: false, error: 'invalid_plan' }, { status: 400 });
  }

  const interval: BillingInterval = body.interval === 'year' ? 'year' : 'month';
  const provider = createBillingProvider(env);

  if (!provider.isConfigured()) {
    return json({ ok: false, error: 'billing_not_configured', code: 'BILLING_NOT_CONFIGURED' }, { status: 503 });
  }

  // Server-owned redirect URLs from the configured origin only.
  const successUrl = appUrl(env, '/build?checkout=success');
  const cancelUrl = appUrl(env, '/pricing?checkout=cancelled');

  if (!successUrl || !cancelUrl) {
    return json({ ok: false, error: 'app_origin_not_configured' }, { status: 503 });
  }

  // Reuse the org's own provider customer if present (never a client value).
  let providerCustomerId: string | undefined;

  try {
    const snap = await getSubscriptionSnapshot(ctx.orgId, env);
    providerCustomerId = snap?.providerCustomerId;
  } catch {
    providerCustomerId = undefined;
  }

  const result = await provider.createCheckoutSession({
    orgId: ctx.orgId,
    userId: ctx.userId,
    customerEmail: ctx.email,
    planId: body.planId,
    interval,

    // Guided setup fee is enforced server-side and cannot be omitted by the browser.
    includeSetupFee: body.planId === 'guided_builder',
    successUrl,
    cancelUrl,
    providerCustomerId,
  });

  if (!result.ok) {
    return json({ ok: false, error: result.error, code: result.code }, { status: 502 });
  }

  return json({ url: result.value.url, sessionId: result.value.sessionId });
}
