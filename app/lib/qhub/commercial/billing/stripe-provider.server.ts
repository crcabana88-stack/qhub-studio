/**
 * QHUB Commercial Launch — STRIPE BILLING PROVIDER (SERVER ONLY)
 * app/lib/qhub/commercial/billing/stripe-provider.server.ts
 *
 * Implements BillingProvider over Stripe's REST API using fetch + Web Crypto — no
 * SDK dependency, edge/workerd-compatible. It handles ONLY payment mechanics.
 * Access decisions never come from here (see entitlements.server.ts).
 *
 * SECRETS: read from env at call time and NEVER logged or returned to the browser.
 *   STRIPE_SECRET_KEY               server secret (sk_test_… at launch)
 *   STRIPE_WEBHOOK_SECRET           webhook signing secret (whsec_…)
 *   STRIPE_PRICE_BUILDER_BETA_MONTHLY / _ANNUAL
 *   STRIPE_PRICE_GUIDED_BUILDER_MONTHLY / _SETUP
 * Absent secret → the operation FAILS CLOSED (no charge, no session).
 */

import type {
  BillingProvider,
  BillingResult,
  CheckoutSession,
  CreateCheckoutInput,
  CreatePortalInput,
  NormalizedBillingEvent,
  PortalSession,
  WebhookVerifyResult,
  BillingEventType,
} from '~/lib/qhub/commercial/billing/billing-provider';
import type { SubscriptionStatus } from '~/lib/qhub/commercial/entitlements.server';
import type { PlanId } from '~/lib/qhub/commercial/plans';
import { getPlan } from '~/lib/qhub/commercial/plans';

const STRIPE_API = 'https://api.stripe.com';
const DEFAULT_TOLERANCE_SECONDS = 300;

export class StripeBillingProvider implements BillingProvider {
  readonly id = 'stripe';

  constructor(private readonly _env: Record<string, string | undefined>) {}

  private _secret(): string {
    return this._env.STRIPE_SECRET_KEY ?? process.env.STRIPE_SECRET_KEY ?? '';
  }

  private _webhookSecret(): string {
    return this._env.STRIPE_WEBHOOK_SECRET ?? process.env.STRIPE_WEBHOOK_SECRET ?? '';
  }

  private _resolvePriceId(envName: string): string {
    return this._env[envName] ?? process.env[envName] ?? '';
  }

  isConfigured(): boolean {
    return this._secret().length > 0;
  }

  // ─── Checkout ─────────────────────────────────────────────────────────────────

  async createCheckoutSession(input: CreateCheckoutInput): Promise<BillingResult<CheckoutSession>> {
    if (!this.isConfigured()) {
      return fail('BILLING_NOT_CONFIGURED', 'Billing is not configured. STRIPE_SECRET_KEY is missing.');
    }

    const plan = getPlan(input.planId);

    if (!plan) {
      return fail('UNKNOWN_PLAN', `Unknown plan: ${input.planId}`);
    }

    const priceRef = input.interval === 'year' ? plan.prices.annual : plan.prices.monthly;

    if (!priceRef) {
      return fail('PRICE_UNAVAILABLE', `Plan ${input.planId} has no ${input.interval} price.`);
    }

    const recurringPriceId = this._resolvePriceId(priceRef.stripePriceEnv);

    if (!recurringPriceId) {
      return fail('PRICE_ID_MISSING', `Missing Stripe price id env: ${priceRef.stripePriceEnv}`);
    }

    const form = new URLSearchParams();
    form.set('mode', 'subscription');
    form.set('success_url', input.successUrl);
    form.set('cancel_url', input.cancelUrl);
    form.set('client_reference_id', input.orgId);
    form.set('line_items[0][price]', recurringPriceId);
    form.set('line_items[0][quantity]', '1');
    form.set('metadata[org_id]', input.orgId);
    form.set('metadata[plan_id]', input.planId);
    form.set('subscription_data[metadata][org_id]', input.orgId);
    form.set('subscription_data[metadata][plan_id]', input.planId);

    if (input.providerCustomerId) {
      form.set('customer', input.providerCustomerId);
    } else {
      form.set('customer_email', input.customerEmail);
    }

    // Optional one-time setup fee (Guided Builder).
    if (input.includeSetupFee && plan.prices.setupFee) {
      const setupId = this._resolvePriceId(plan.prices.setupFee.stripePriceEnv);

      if (!setupId) {
        return fail(
          'SETUP_PRICE_ID_MISSING',
          `Missing Stripe setup-fee price id env: ${plan.prices.setupFee.stripePriceEnv}`,
        );
      }

      form.set('line_items[1][price]', setupId);
      form.set('line_items[1][quantity]', '1');
    }

    const res = await this._post('/v1/checkout/sessions', form);

    if (!res.ok) {
      return fail('STRIPE_ERROR', res.error);
    }

    const body = res.body as { id?: string; url?: string };

    if (!body.id || !body.url) {
      return fail('STRIPE_MALFORMED', 'Stripe returned no session id/url.');
    }

    return { ok: true, value: { sessionId: body.id, url: body.url } };
  }

  // ─── Billing portal ─────────────────────────────────────────────────────────────

  async createBillingPortalSession(input: CreatePortalInput): Promise<BillingResult<PortalSession>> {
    if (!this.isConfigured()) {
      return fail('BILLING_NOT_CONFIGURED', 'Billing is not configured. STRIPE_SECRET_KEY is missing.');
    }

    const form = new URLSearchParams();
    form.set('customer', input.providerCustomerId);
    form.set('return_url', input.returnUrl);

    const res = await this._post('/v1/billing_portal/sessions', form);

    if (!res.ok) {
      return fail('STRIPE_ERROR', res.error);
    }

    const body = res.body as { url?: string };

    if (!body.url) {
      return fail('STRIPE_MALFORMED', 'Stripe returned no portal url.');
    }

    return { ok: true, value: { url: body.url } };
  }

  // ─── Webhook verification (Web Crypto HMAC-SHA256) ──────────────────────────────

  async verifyAndParseWebhook(
    rawBody: string,
    signatureHeader: string | null,
    nowSeconds: number = Math.floor(Date.now() / 1000),
  ): Promise<WebhookVerifyResult> {
    const secret = this._webhookSecret();

    if (!secret) {
      return { ok: false, error: 'Webhook secret not configured.', code: 'NO_SECRET' };
    }

    if (!signatureHeader) {
      return { ok: false, error: 'Missing Stripe-Signature header.', code: 'MALFORMED' };
    }

    const parsed = parseSignatureHeader(signatureHeader);

    if (!parsed || parsed.v1.length === 0) {
      return { ok: false, error: 'Malformed Stripe-Signature header.', code: 'MALFORMED' };
    }

    if (Math.abs(nowSeconds - parsed.t) > DEFAULT_TOLERANCE_SECONDS) {
      return { ok: false, error: 'Webhook timestamp outside tolerance.', code: 'STALE' };
    }

    const expected = await hmacSha256Hex(secret, `${parsed.t}.${rawBody}`);
    const matches = parsed.v1.some((sig) => timingSafeEqualHex(sig, expected));

    if (!matches) {
      return { ok: false, error: 'Webhook signature verification failed.', code: 'BAD_SIGNATURE' };
    }

    let event: unknown;

    try {
      event = JSON.parse(rawBody);
    } catch {
      return { ok: false, error: 'Webhook body is not valid JSON.', code: 'MALFORMED' };
    }

    const normalized = normalizeStripeEvent(event);

    if (!normalized) {
      return { ok: false, error: 'Webhook event could not be normalized.', code: 'MALFORMED' };
    }

    return { ok: true, event: normalized };
  }

  // ─── HTTP ─────────────────────────────────────────────────────────────────────

  private async _post(
    path: string,
    form: URLSearchParams,
  ): Promise<{ ok: true; body: unknown } | { ok: false; error: string }> {
    try {
      const resp = await fetch(`${STRIPE_API}${path}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this._secret()}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: form.toString(),
      });

      const body = await resp.json().catch(() => ({}));

      if (!resp.ok) {
        const msg = (body as { error?: { message?: string } })?.error?.message ?? `Stripe HTTP ${resp.status}`;
        return { ok: false, error: msg };
      }

      return { ok: true, body };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'Stripe request failed.' };
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function fail<T>(code: string, error: string): BillingResult<T> {
  return { ok: false, code, error };
}

/** Parse `t=...,v1=...,v1=...` into a timestamp + candidate signatures. */
export function parseSignatureHeader(header: string): { t: number; v1: string[] } | null {
  let t = NaN;
  const v1: string[] = [];

  for (const part of header.split(',')) {
    const [k, v] = part.split('=');

    if (k === 't') {
      t = Number.parseInt(v, 10);
    } else if (k === 'v1' && v) {
      v1.push(v.trim());
    }
  }

  if (Number.isNaN(t)) {
    return null;
  }

  return { t, v1 };
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));

  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time hex comparison. */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

function mapStripeStatus(s: string | undefined): SubscriptionStatus {
  switch (s) {
    case 'active':
      return 'active';
    case 'trialing':
      return 'trialing';
    case 'past_due':
      return 'past_due';
    case 'canceled':
      return 'canceled';
    case 'incomplete':
    case 'incomplete_expired':
    case 'unpaid':
      return 'incomplete';
    default:
      return 'none';
  }
}

function mapEventType(rawType: string): BillingEventType {
  switch (rawType) {
    case 'checkout.session.completed':
      return 'checkout.completed';
    case 'customer.subscription.updated':
    case 'customer.subscription.created':
      return 'subscription.updated';
    case 'customer.subscription.deleted':
      return 'subscription.deleted';
    case 'invoice.payment_failed':
      return 'invoice.payment_failed';
    case 'invoice.paid':
    case 'invoice.payment_succeeded':
      return 'invoice.paid';
    default:
      return 'unknown';
  }
}

/** Normalize a verified Stripe event into the provider-neutral shape. */
export function normalizeStripeEvent(event: unknown): NormalizedBillingEvent | null {
  const e = event as {
    id?: string;
    type?: string;
    data?: { object?: Record<string, unknown> };
  };

  if (!e || typeof e.id !== 'string' || typeof e.type !== 'string') {
    return null;
  }

  const obj = e.data?.object ?? {};
  const metadata = (obj.metadata as Record<string, string> | undefined) ?? {};
  const type = mapEventType(e.type);

  const planId = (metadata.plan_id as PlanId | undefined) ?? undefined;
  const orgId = metadata.org_id ?? (obj.client_reference_id as string | undefined) ?? undefined;

  const customerId = typeof obj.customer === 'string' ? obj.customer : undefined;
  const subscriptionId =
    typeof obj.subscription === 'string'
      ? obj.subscription
      : typeof obj.id === 'string' && e.type.startsWith('customer.subscription')
        ? (obj.id as string)
        : undefined;

  const status = e.type.startsWith('customer.subscription')
    ? mapStripeStatus(obj.status as string | undefined)
    : type === 'checkout.completed'
      ? 'active'
      : type === 'invoice.payment_failed'
        ? 'past_due'
        : undefined;

  const currentPeriodEnd = typeof obj.current_period_end === 'number' ? obj.current_period_end : undefined;

  return {
    providerEventId: e.id,
    type,
    rawType: e.type,
    providerCustomerId: customerId,
    providerSubscriptionId: subscriptionId,
    orgId,
    planId,
    status,
    currentPeriodEnd,
  };
}

/** Factory — the runtime uses this so the provider is swappable. */
export function createBillingProvider(env: Record<string, string | undefined>): BillingProvider {
  return new StripeBillingProvider(env);
}
