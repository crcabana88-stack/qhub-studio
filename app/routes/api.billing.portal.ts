/**
 * QHUB Commercial Launch — POST /api/billing/portal
 * app/routes/api.billing.portal.ts
 *
 * Authenticated. Creates a Stripe-hosted Billing Portal session for the caller's
 * org, but ONLY for the org's own provider customer id (loaded server-side) — a
 * caller can never open another tenant's portal. Fails closed without config.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { createBillingProvider } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import { getSubscriptionSnapshot } from '~/lib/qhub/commercial/commercial-store.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ error: 'unauthorized' }, { status: 401 });
  }

  const provider = createBillingProvider(env);

  if (!provider.isConfigured()) {
    return json({ error: 'billing_not_configured', code: 'BILLING_NOT_CONFIGURED' }, { status: 503 });
  }

  // The customer id comes from the org's own durable record — never from the client.
  const snap = await getSubscriptionSnapshot(session.orgId, env).catch(() => null);

  if (!snap?.providerCustomerId) {
    return json({ error: 'no_billing_customer' }, { status: 400 });
  }

  const origin = new URL(request.url).origin;
  const result = await provider.createBillingPortalSession({
    providerCustomerId: snap.providerCustomerId,
    returnUrl: `${origin}/build`,
  });

  if (!result.ok) {
    return json({ error: result.error, code: result.code }, { status: 502 });
  }

  return json({ url: result.value.url });
}
