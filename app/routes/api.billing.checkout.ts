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
import { requireCommercialReady } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { createCheckoutIntent, getSubscriptionSnapshot } from '~/lib/qhub/commercial/commercial-store.server';
import {
  appUrl,
  checkRateLimit,
  configuredAppOrigin,
  isSameOrigin,
  readBoundedJson,
} from '~/lib/qhub/commercial/request-guards.server';
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

  // Fail closed on schema readiness BEFORE any intent write or Stripe call.
  const ready = await requireCommercialReady(env);

  if (!ready.ok) {
    return ready.response;
  }

  const rate = checkRateLimit(`checkout:${ctx.orgId}`, 5, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  let body: { planId?: PlanId; interval?: BillingInterval; includeSetupFee?: boolean; idempotencyKey?: string };

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
  const origin = configuredAppOrigin(env);
  const successUrl = appUrl(env, '/build?checkout=success');
  const cancelUrl = appUrl(env, '/pricing?checkout=cancelled');

  if (!origin || !successUrl || !cancelUrl) {
    return json({ ok: false, error: 'app_origin_not_configured' }, { status: 503 });
  }

  // Resolve the EXACT server-configured prices for the plan (never client-supplied).
  const recurringPriceId = resolvePrice(env, body.planId, interval);
  const setupPriceId = body.planId === 'guided_builder' ? resolvePrice(env, body.planId, 'setup') : null;

  if (!recurringPriceId || (body.planId === 'guided_builder' && !setupPriceId)) {
    return json({ ok: false, error: 'price_not_configured' }, { status: 503 });
  }

  // Bind ALL authority into an immutable checkout intent BEFORE calling Stripe.
  const idempotencyKey =
    typeof body.idempotencyKey === 'string' && body.idempotencyKey ? body.idempotencyKey : crypto.randomUUID();
  const intent = await createCheckoutIntent(
    {
      orgId: ctx.orgId,
      requestedBy: ctx.userId,
      membershipId: `${ctx.userId}:${ctx.orgId}`,
      planId: body.planId,
      expectedRecurringPriceId: recurringPriceId,
      expectedSetupPriceId: setupPriceId,
      expectedMode: provider.expectedLivemode() ? 'live' : 'test',
      expectedAccount: env.STRIPE_ACCOUNT_ID ?? process.env.STRIPE_ACCOUNT_ID ?? null,
      expectedAppOrigin: origin,
      idempotencyKey,
      expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    },
    env,
  );

  if (!intent.ok) {
    return json({ ok: false, error: intent.reason }, { status: 409 });
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

    // ONLY the opaque intent id travels in Stripe metadata.
    checkoutIntentId: intent.intentId,
  });

  if (!result.ok) {
    return json({ ok: false, error: result.error, code: result.code }, { status: 502 });
  }

  return json({ url: result.value.url, sessionId: result.value.sessionId, intentId: intent.intentId });
}

/** Resolve a configured Stripe price id for a plan/interval from env (never client). */
function resolvePrice(
  env: Record<string, string | undefined>,
  planId: PlanId,
  kind: 'month' | 'year' | 'setup',
): string | null {
  const map: Record<string, string> = {
    'builder_beta:month': 'STRIPE_PRICE_BUILDER_BETA_MONTHLY',
    'builder_beta:year': 'STRIPE_PRICE_BUILDER_BETA_ANNUAL',
    'guided_builder:month': 'STRIPE_PRICE_GUIDED_BUILDER_MONTHLY',
    'guided_builder:setup': 'STRIPE_PRICE_GUIDED_BUILDER_SETUP',
  };
  const name = map[`${planId}:${kind}`];

  return name ? (env[name] ?? process.env[name] ?? null) : null;
}
