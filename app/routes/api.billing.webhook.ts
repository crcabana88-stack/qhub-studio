/**
 * QHUB Commercial Launch R2 — POST /api/billing/webhook
 * app/routes/api.billing.webhook.ts
 *
 * Recoverable Stripe webhook inbox. Authenticity comes from the signature over the
 * EXACT raw bytes (never a reserialized body). Flow:
 *   1. verify signature over raw bytes (mode + account bound; fail closed w/o secret)
 *   2. atomically CLAIM the event (state machine — duplicates are DUPLICATE, an
 *      in-flight one IN_PROGRESS, a fresh/retryable one CLAIMED)
 *   3. authoritatively RECONCILE by retrieving the current subscription from Stripe
 *      and validating account/livemode/customer/price/org mapping
 *   4. apply ONE atomic normalized mutation (out-of-order events are ignored)
 *   5. mark PROCESSED
 *
 * A transient (network/db) failure marks FAILED_RETRYABLE and returns 500 so Stripe
 * retries; a validation failure marks FAILED_PERMANENT and returns 200 (a bad event
 * must not be retried forever). No secrets or payment data are logged.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { createBillingProvider, planIdForConfiguredPrice } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import {
  applySubscriptionEvent,
  claimWebhookEvent,
  getOrgByCustomer,
  setWebhookState,
  upsertBillingCustomer,
} from '~/lib/qhub/commercial/commercial-store.server';
import type { NormalizedBillingEvent } from '~/lib/qhub/commercial/billing/billing-provider';
import type { SubscriptionStatus } from '~/lib/qhub/commercial/entitlements.server';

class PermanentError extends Error {}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const provider = createBillingProvider(env);

  // 1. Verify over EXACT raw bytes.
  const rawBody = await request.text();
  const signature = request.headers.get('stripe-signature');
  const verified = await provider.verifyAndParseWebhook(rawBody, signature);

  if (!verified.ok) {
    const status = verified.code === 'NO_SECRET' ? 503 : 400;
    return json({ ok: false, error: verified.error, code: verified.code }, { status });
  }

  const event = verified.event;

  // 2. Atomically claim (idempotency + state machine).
  const payloadHash = await sha256Hex(rawBody);
  const claim = await claimWebhookEvent(
    {
      provider: provider.id,
      providerEventId: event.providerEventId,
      eventType: event.rawType,
      livemode: event.livemode,
      account: event.stripeAccount ?? null,
      eventCreated: event.eventCreated,
      payloadHash,
      owner: crypto.randomUUID(), // this worker's lease owner
      leaseSeconds: 120,
    },
    env,
  );

  if (claim === 'DUPLICATE') {
    return json({ received: true, duplicate: true });
  }

  if (claim === 'IN_PROGRESS') {
    return json({ received: true, inProgress: true });
  }

  // 3 + 4. Reconcile + apply.
  try {
    await reconcileAndApply(event, provider, env);
    await setWebhookState({ provider: provider.id, providerEventId: event.providerEventId, state: 'PROCESSED' }, env);

    return json({ received: true });
  } catch (err) {
    if (err instanceof PermanentError) {
      await setWebhookState(
        {
          provider: provider.id,
          providerEventId: event.providerEventId,
          state: 'FAILED_PERMANENT',
          errorCode: err.message,
        },
        env,
      );

      // Acknowledge (200) — a permanently invalid event must not be retried forever.
      return json({ received: true, rejected: err.message });
    }

    // Transient: keep retryable so Stripe redelivers.
    await setWebhookState(
      {
        provider: provider.id,
        providerEventId: event.providerEventId,
        state: 'FAILED_RETRYABLE',
        errorCode: 'transient',
      },
      env,
    );

    return json({ ok: false, error: 'processing_failed' }, { status: 500 });
  }
}

async function reconcileAndApply(
  event: NormalizedBillingEvent,
  provider: ReturnType<typeof createBillingProvider>,
  env: Record<string, string | undefined>,
): Promise<void> {
  // Deletion / payment failure: no reactivation possible; apply a downgrade only.
  if (event.type === 'subscription.deleted' || event.type === 'invoice.payment_failed') {
    const status: SubscriptionStatus = event.type === 'subscription.deleted' ? 'canceled' : 'past_due';

    if (!event.providerCustomerId) {
      throw new PermanentError('missing_customer');
    }

    const org = await getOrgByCustomer(provider.id, event.providerCustomerId, env);

    if (!org) {
      throw new PermanentError('unknown_customer');
    }

    await applySubscriptionEvent(
      {
        orgId: org,
        planId: event.planId ?? 'none',
        status,
        provider: provider.id,
        providerCustomerId: event.providerCustomerId,
        providerSubscriptionId: event.providerSubscriptionId,
        eventCreated: event.eventCreated,
        livemode: event.livemode,
        stripeAccount: event.stripeAccount,
      },
      env,
    );

    return;
  }

  /*
   * checkout.completed / subscription.updated: NEVER trust event metadata alone —
   * retrieve and validate the authoritative subscription object from Stripe.
   */
  if (event.type === 'checkout.completed' || event.type === 'subscription.updated') {
    if (!event.providerSubscriptionId) {
      throw new PermanentError('missing_subscription');
    }

    const retrieved = await provider.retrieveSubscription(event.providerSubscriptionId);

    if (!retrieved.ok) {
      // Transient (network / Stripe error) — stay retryable.
      throw new Error(retrieved.error);
    }

    const sub = retrieved.value;

    // Mode binding.
    if (sub.livemode !== provider.expectedLivemode()) {
      throw new PermanentError('mode_mismatch');
    }

    // Customer must match the event's customer.
    if (event.providerCustomerId && sub.customerId !== event.providerCustomerId) {
      throw new PermanentError('customer_mismatch');
    }

    // The recurring price must be one of the server-configured prices.
    if (!sub.priceId || !provider.isConfiguredPrice(sub.priceId)) {
      throw new PermanentError('unknown_price');
    }

    const planId = planIdForConfiguredPrice(sub.priceId, env) ?? 'none';

    /*
     * Authoritative org: prefer the existing customer mapping; else bootstrap from
     * the subscription metadata (advisory), then require consistency thereafter.
     */
    const mappedOrg = await getOrgByCustomer(provider.id, sub.customerId, env);
    const metaOrg = sub.metadata.org_id ?? event.orgId;

    if (mappedOrg && metaOrg && mappedOrg !== metaOrg) {
      throw new PermanentError('org_customer_mismatch');
    }

    const org = mappedOrg ?? metaOrg;

    if (!org) {
      throw new PermanentError('unresolved_org');
    }

    if (!mappedOrg) {
      await upsertBillingCustomer(
        {
          orgId: org,
          provider: provider.id,
          providerCustomerId: sub.customerId,
          email: '',
          livemode: sub.livemode,
          stripeAccount: event.stripeAccount,
        },
        env,
      );
    }

    await applySubscriptionEvent(
      {
        orgId: org,
        planId,
        status: sub.status,
        provider: provider.id,
        providerCustomerId: sub.customerId,
        providerSubscriptionId: sub.id,
        providerPriceId: sub.priceId,
        currentPeriodEnd: sub.currentPeriodEnd ?? undefined,
        eventCreated: event.eventCreated,
        livemode: sub.livemode,
        stripeAccount: event.stripeAccount,
      },
      env,
    );

    return;
  }

  /*
   * invoice.paid / unknown: nothing to apply (paid does not itself reactivate —
   * subscription.updated carries the authoritative active state).
   */
}
