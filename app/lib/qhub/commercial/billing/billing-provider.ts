/**
 * QHUB Commercial Launch — BILLING PROVIDER INTERFACE (BROWSER-SAFE TYPES)
 * app/lib/qhub/commercial/billing/billing-provider.ts
 *
 * A replaceable billing-provider abstraction. Stripe is the first implementation
 * (billing/stripe-provider.server.ts). The provider owns ONLY payment mechanics —
 * checkout, subscription/invoice status, billing portal, webhook delivery. It must
 * NOT decide access to governance gates, projects, publishing, or connectors: that
 * is QHub's entitlement layer (entitlements.server.ts). This separation is a hard
 * architectural boundary.
 *
 * This file holds interface + DTO types only (no secrets, no I/O). Concrete
 * providers live in *.server.ts and fail closed when their secret is absent.
 */

import type { BillingInterval, PlanId } from '~/lib/qhub/commercial/plans';
import type { SubscriptionStatus } from '~/lib/qhub/commercial/entitlements.server';

// ─── Requests ───────────────────────────────────────────────────────────────────

export interface CreateCheckoutInput {
  orgId: string;
  userId: string;
  customerEmail: string;
  planId: Exclude<PlanId, 'none'>;
  interval: BillingInterval;

  /** Also charge the plan's one-time setup fee (Guided Builder). */
  includeSetupFee?: boolean;
  successUrl: string;
  cancelUrl: string;

  /** Optional existing provider customer id to reuse. */
  providerCustomerId?: string;

  /**
   * The opaque checkout-intent id. When set, it is the ONLY authority placed in
   * Stripe metadata (org/plan are never in metadata). The webhook loads + consumes
   * the intent to establish the tenant.
   */
  checkoutIntentId?: string;
}

export interface CreatePortalInput {
  providerCustomerId: string;
  returnUrl: string;
}

// ─── Results ────────────────────────────────────────────────────────────────────

export type BillingResult<T> = { ok: true; value: T } | { ok: false; error: string; code: string };

export interface CheckoutSession {
  sessionId: string;
  url: string;
}

export interface PortalSession {
  url: string;
}

// ─── Webhook ────────────────────────────────────────────────────────────────────

/** The provider-neutral event we care about after verifying a webhook. */
export type BillingEventType =
  | 'checkout.completed'
  | 'subscription.updated'
  | 'subscription.deleted'
  | 'invoice.payment_failed'
  | 'invoice.paid'
  | 'unknown';

export interface NormalizedBillingEvent {
  /** Provider event id — used for idempotent processing (replay protection). */
  providerEventId: string;
  type: BillingEventType;

  /** Raw provider event type string, for logging/audit. */
  rawType: string;
  providerCustomerId?: string;
  providerSubscriptionId?: string;
  providerPriceId?: string;
  orgId?: string;
  planId?: PlanId;
  status?: SubscriptionStatus;

  /** Seconds since epoch when the current period ends, if present. */
  currentPeriodEnd?: number;

  /** Stripe livemode flag — bound against the configured mode. */
  livemode: boolean;

  /** Stripe account id (Connect), when present. */
  stripeAccount?: string;

  /** event.created (seconds) — used to reject out-of-order updates. */
  eventCreated: number;

  /** The opaque checkout-intent id carried in metadata (checkout.completed). */
  checkoutIntentId?: string;
}

export type WebhookVerifyResult =
  | { ok: true; event: NormalizedBillingEvent }
  | {
      ok: false;
      error: string;
      code: 'NO_SECRET' | 'BAD_SIGNATURE' | 'STALE' | 'MALFORMED' | 'MODE_MISMATCH' | 'ACCOUNT_MISMATCH';
    };

/** The authoritative subscription object retrieved directly from the provider. */
export interface RetrievedSubscription {
  id: string;
  customerId: string;
  status: SubscriptionStatus;
  priceId: string | null;
  livemode: boolean;
  currentPeriodEnd: number | null;
  metadata: Record<string, string>;
}

// ─── Provider contract ──────────────────────────────────────────────────────────

export interface BillingProvider {
  readonly id: string;

  /** True only when the provider's secret is present (else all ops fail closed). */
  isConfigured(): boolean;

  createCheckoutSession(input: CreateCheckoutInput): Promise<BillingResult<CheckoutSession>>;

  createBillingPortalSession(input: CreatePortalInput): Promise<BillingResult<PortalSession>>;

  /**
   * Verify a raw webhook body against the signature header and normalize it.
   * MUST fail closed (NO_SECRET) when the signing secret is absent, and reject
   * bad/stale signatures.
   */
  verifyAndParseWebhook(
    rawBody: string,
    signatureHeader: string | null,
    nowSeconds?: number,
  ): Promise<WebhookVerifyResult>;

  /** The mode the server is configured for (true = live). Bound against events. */
  expectedLivemode(): boolean;

  /**
   * Retrieve the CURRENT subscription object directly from the provider (never
   * trusting webhook metadata alone) for authoritative reconciliation.
   */
  retrieveSubscription(subscriptionId: string): Promise<BillingResult<RetrievedSubscription>>;

  /** True when the given recurring price id is one of the server-configured prices. */
  isConfiguredPrice(priceId: string): boolean;
}
