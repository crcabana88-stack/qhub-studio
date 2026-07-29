/**
 * QHUB Commercial Launch — POST /api/billing/checkout
 * app/routes/api.billing.checkout.ts
 *
 * Authenticated. Creates a Stripe-hosted Checkout session for a plan. QHub never
 * collects card details — the returned URL is Stripe-hosted. Fails closed (503)
 * when billing is not configured (no secret / no price id).
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { createBillingProvider } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import { getSubscriptionSnapshot } from '~/lib/qhub/commercial/commercial-store.server';
import { isPaidPlan, type BillingInterval, type PlanId } from '~/lib/qhub/commercial/plans';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ error: 'unauthorized' }, { status: 401 });
  }

  const body = (await request.json().catch(() => ({}))) as {
    planId?: PlanId;
    interval?: BillingInterval;
    includeSetupFee?: boolean;
  };

  if (!body.planId || !isPaidPlan(body.planId)) {
    return json({ error: 'invalid_plan' }, { status: 400 });
  }

  const interval: BillingInterval = body.interval === 'year' ? 'year' : 'month';
  const provider = createBillingProvider(env);

  if (!provider.isConfigured()) {
    return json({ error: 'billing_not_configured', code: 'BILLING_NOT_CONFIGURED' }, { status: 503 });
  }

  // Reuse an existing provider customer if we have one.
  let providerCustomerId: string | undefined;

  try {
    const snap = await getSubscriptionSnapshot(session.orgId, env);
    providerCustomerId = snap?.providerCustomerId;
  } catch {
    providerCustomerId = undefined;
  }

  const origin = new URL(request.url).origin;
  const result = await provider.createCheckoutSession({
    orgId: session.orgId,
    userId: session.userId,
    customerEmail: session.email,
    planId: body.planId,
    interval,
    includeSetupFee: !!body.includeSetupFee,
    successUrl: `${origin}/build?checkout=success`,
    cancelUrl: `${origin}/pricing?checkout=cancelled`,
    providerCustomerId,
  });

  if (!result.ok) {
    return json({ error: result.error, code: result.code }, { status: 502 });
  }

  return json({ url: result.value.url, sessionId: result.value.sessionId });
}
