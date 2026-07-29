/*
 * @qhub-route: COMMERCIAL_READY
 * @qhub-boundary: SIGNATURE_AUTH — authenticated by the verified Stripe signature (raw-byte HMAC), not a user session.
 */
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
  requireCommercialReady,
  type CommercialReadyToken,
} from '~/lib/qhub/commercial/commercial-schema-check.server';
import {
  applySubscriptionEvent,
  claimWebhookEvent,
  getOrgByCustomer,
  reconcileCheckout,
  setWebhookState,
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

  /*
   * Fail closed on schema readiness AFTER the signature is verified but BEFORE any
   * claim or mutation. NOT READY → retryable (500), no claim, no state written, event
   * never marked PROCESSED or permanent, so Stripe redelivers once the schema is ready.
   */
  const ready = await requireCommercialReady(env, { webhook: true });

  if (!ready.ok) {
    return ready.response;
  }

  // 2. Atomically claim/reclaim the lease (idempotency + crash recovery).
  const owner = crypto.randomUUID(); // this worker's lease owner
  const payloadHash = await sha256Hex(rawBody);
  const claim = await claimWebhookEvent(
    ready.token,
    {
      provider: provider.id,
      providerEventId: event.providerEventId,
      eventType: event.rawType,
      livemode: event.livemode,
      account: event.stripeAccount ?? null,
      eventCreated: event.eventCreated,
      payloadHash,
      owner,
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

  /*
   * 3 + 4. Reconcile. checkout.completed goes through the ONE atomic reconciliation
   * RPC (which marks PROCESSED itself); other events mutate then mark PROCESSED via
   * the lease-bound transition.
   */
  try {
    const handledInRpc = await reconcileAndApply(event, provider, ready.token, env, owner);

    if (!handledInRpc) {
      await setWebhookState(
        ready.token,
        { provider: provider.id, providerEventId: event.providerEventId, owner, state: 'PROCESSED' },
        env,
      );
    }

    return json({ received: true });
  } catch (err) {
    if (err instanceof PermanentError) {
      await setWebhookState(
        ready.token,
        {
          provider: provider.id,
          providerEventId: event.providerEventId,
          owner,
          state: 'FAILED_PERMANENT',
          errorCode: err.message,
        },
        env,
      ).catch(() => undefined);

      // Acknowledge (200) — a permanently invalid event must not be retried forever.
      return json({ received: true, rejected: err.message });
    }

    // Transient: keep retryable so Stripe redelivers.
    await setWebhookState(
      ready.token,
      {
        provider: provider.id,
        providerEventId: event.providerEventId,
        owner,
        state: 'FAILED_RETRYABLE',
        errorCode: 'transient',
      },
      env,
    ).catch(() => undefined);

    return json({ ok: false, error: 'processing_failed' }, { status: 500 });
  }
}

async function reconcileAndApply(
  event: NormalizedBillingEvent,
  provider: ReturnType<typeof createBillingProvider>,
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
  owner: string,
): Promise<boolean> {
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
      token,
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

    return false;
  }

  /*
   * checkout.completed: the tenant comes ONLY from the opaque checkout intent. After
   * retrieving + validating the authoritative Stripe subscription and the Checkout
   * Session line items (for the Guided setup price), the ENTIRE reconciliation —
   * intent validation/consume, customer+subscription binding, normalized state, and
   * event PROCESSED — happens in ONE atomic RPC bound to this worker's lease.
   */
  if (event.type === 'checkout.completed') {
    if (!event.checkoutIntentId || !event.checkoutSessionId) {
      throw new PermanentError('missing_checkout_intent');
    }

    const sub = await retrieveValidSubscription(event, provider);

    // Independently confirm the Guided one-time setup price on the Session.
    const setupPriceId = env.STRIPE_PRICE_GUIDED_BUILDER_SETUP ?? process.env.STRIPE_PRICE_GUIDED_BUILDER_SETUP ?? '';
    const lines = await provider.retrieveCheckoutSessionPriceIds(event.checkoutSessionId);

    if (!lines.ok) {
      throw new Error(lines.error); // transient
    }

    const setupPresent = !!setupPriceId && lines.value.includes(setupPriceId);

    const result = await reconcileCheckout(
      token,
      {
        provider: provider.id,
        eventId: event.providerEventId,
        owner,
        intentId: event.checkoutIntentId,
        sessionId: event.checkoutSessionId,
        customerId: sub.customerId,
        subscriptionId: sub.id,
        recurringPrice: sub.priceId as string,
        setupPresent,
        mode: sub.livemode ? 'live' : 'test',
        account: event.stripeAccount ?? null,
        status: sub.status,
        currentPeriodEnd: sub.currentPeriodEnd,
        eventCreated: event.eventCreated,
      },
      env,
    );

    if (result.ok) {
      return true; // the RPC marked the event PROCESSED atomically
    }

    if (result.reason === 'lease_lost') {
      return true; // another worker owns this event — do not mutate
    }

    throw new PermanentError(result.reason ?? 'reconcile_failed');
  }

  /*
   * subscription.updated: reconcile an EXISTING authoritative customer→org mapping;
   * metadata never establishes the org here.
   */
  if (event.type === 'subscription.updated') {
    const sub = await retrieveValidSubscription(event, provider);
    const org = await getOrgByCustomer(provider.id, sub.customerId, env);

    if (!org) {
      throw new PermanentError('unknown_customer'); // no mapping → nothing to reconcile
    }

    await applySubscriptionEvent(
      token,
      {
        orgId: org,
        planId: (planIdForConfiguredPrice(sub.priceId as string, env) ?? 'none') as never,
        status: sub.status,
        provider: provider.id,
        providerCustomerId: sub.customerId,
        providerSubscriptionId: sub.id,
        providerPriceId: sub.priceId ?? undefined,
        currentPeriodEnd: sub.currentPeriodEnd ?? undefined,
        eventCreated: event.eventCreated,
        livemode: sub.livemode,
        stripeAccount: event.stripeAccount,
      },
      env,
    );

    return false;
  }

  /*
   * invoice.paid / unknown: nothing to apply (paid does not itself reactivate —
   * subscription.updated carries the authoritative active state).
   */
  return false;
}

/** Retrieve + validate the authoritative Stripe subscription (mode/customer/price). */
async function retrieveValidSubscription(
  event: NormalizedBillingEvent,
  provider: ReturnType<typeof createBillingProvider>,
) {
  if (!event.providerSubscriptionId) {
    throw new PermanentError('missing_subscription');
  }

  const retrieved = await provider.retrieveSubscription(event.providerSubscriptionId);

  if (!retrieved.ok) {
    throw new Error(retrieved.error); // transient — stay retryable
  }

  const sub = retrieved.value;

  if (sub.livemode !== provider.expectedLivemode()) {
    throw new PermanentError('mode_mismatch');
  }

  if (event.providerCustomerId && sub.customerId !== event.providerCustomerId) {
    throw new PermanentError('customer_mismatch');
  }

  if (!sub.priceId || !provider.isConfiguredPrice(sub.priceId)) {
    throw new PermanentError('unknown_price');
  }

  return sub;
}
