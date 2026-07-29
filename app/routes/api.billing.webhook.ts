/**
 * QHUB Commercial Launch — POST /api/billing/webhook
 * app/routes/api.billing.webhook.ts
 *
 * Stripe webhook receiver. NOT authenticated by session — authenticity comes from
 * the signed payload. Verifies the signature (fail closed without the secret),
 * dedupes by provider event id (replay protection), then applies the subscription
 * state change. Always returns 200 once verified+recorded so Stripe does not retry
 * a duplicate; verification/parse failures return 400 (or 503 when unconfigured).
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { createBillingProvider } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import {
  markWebhookProcessed,
  recordWebhookEventOnce,
  upsertBillingCustomer,
  upsertSubscription,
} from '~/lib/qhub/commercial/commercial-store.server';
import type { PlanId } from '~/lib/qhub/commercial/plans';
import type { SubscriptionStatus } from '~/lib/qhub/commercial/entitlements.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const provider = createBillingProvider(env);

  const rawBody = await request.text();
  const signature = request.headers.get('stripe-signature');
  const verified = await provider.verifyAndParseWebhook(rawBody, signature);

  if (!verified.ok) {
    const status = verified.code === 'NO_SECRET' ? 503 : 400;
    return json({ error: verified.error, code: verified.code }, { status });
  }

  const event = verified.event;

  // Replay protection: process each provider event id exactly once.
  const isNew = await recordWebhookEventOnce(
    { provider: provider.id, providerEventId: event.providerEventId, eventType: event.rawType },
    env,
  );

  if (!isNew) {
    return json({ received: true, duplicate: true });
  }

  // Apply state changes for the events we act on.
  if (
    event.orgId &&
    event.providerCustomerId &&
    (event.type === 'checkout.completed' || event.type === 'subscription.updated')
  ) {
    await upsertBillingCustomer(
      { orgId: event.orgId, provider: provider.id, providerCustomerId: event.providerCustomerId, email: '' },
      env,
    ).catch(() => undefined);
  }

  if (
    event.orgId &&
    (event.type === 'checkout.completed' ||
      event.type === 'subscription.updated' ||
      event.type === 'subscription.deleted' ||
      event.type === 'invoice.payment_failed')
  ) {
    const status: SubscriptionStatus =
      event.type === 'subscription.deleted'
        ? 'canceled'
        : event.type === 'invoice.payment_failed'
          ? 'past_due'
          : (event.status ?? 'active');

    await upsertSubscription(
      {
        orgId: event.orgId,
        planId: (event.planId as PlanId) ?? 'none',
        status,
        provider: provider.id,
        providerCustomerId: event.providerCustomerId,
        providerSubscriptionId: event.providerSubscriptionId,
        currentPeriodEnd: event.currentPeriodEnd,
      },
      env,
    );
  }

  await markWebhookProcessed({ provider: provider.id, providerEventId: event.providerEventId }, env);

  return json({ received: true });
}
