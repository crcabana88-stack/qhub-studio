/**
 * QHUB Commercial Launch — Stripe billing provider (webhook verification, fail-closed)
 * app/test/commercial-billing.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  StripeBillingProvider,
  parseSignatureHeader,
  hmacSha256Hex,
  timingSafeEqualHex,
  normalizeStripeEvent,
} from '~/lib/qhub/commercial/billing/stripe-provider.server';

const WHSEC = 'whsec_test_secret_123';

async function signedHeader(secret: string, body: string, t: number): Promise<string> {
  const sig = await hmacSha256Hex(secret, `${t}.${body}`);
  return `t=${t},v1=${sig}`;
}

describe('signature parsing + hmac', () => {
  it('parses a Stripe-Signature header', () => {
    const p = parseSignatureHeader('t=1700000000,v1=abc,v1=def');
    expect(p?.t).toBe(1700000000);
    expect(p?.v1).toEqual(['abc', 'def']);
  });

  it('rejects a header with no timestamp', () => {
    expect(parseSignatureHeader('v1=abc')).toBeNull();
  });

  it('timing-safe compare', () => {
    expect(timingSafeEqualHex('abcd', 'abcd')).toBe(true);
    expect(timingSafeEqualHex('abcd', 'abce')).toBe(false);
    expect(timingSafeEqualHex('abc', 'abcd')).toBe(false);
  });
});

describe('webhook verification (fail closed)', () => {
  it('fails closed when the webhook secret is absent (NO_SECRET)', async () => {
    const provider = new StripeBillingProvider({});
    const r = await provider.verifyAndParseWebhook('{}', 't=1,v1=x', 1);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('NO_SECRET');
  });

  it('accepts a correctly signed, fresh payload', async () => {
    const provider = new StripeBillingProvider({ STRIPE_WEBHOOK_SECRET: WHSEC });
    const t = 1_800_000_000;
    const body = JSON.stringify({
      id: 'evt_1',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_1',
          customer: 'cus_1',
          status: 'active',
          metadata: { org_id: 'org_1', plan_id: 'builder_beta' },
        },
      },
    });
    const header = await signedHeader(WHSEC, body, t);
    const r = await provider.verifyAndParseWebhook(body, header, t);
    expect(r.ok).toBe(true);

    if (r.ok) {
      expect(r.event.providerEventId).toBe('evt_1');
      expect(r.event.type).toBe('subscription.updated');
      expect(r.event.orgId).toBe('org_1');
      expect(r.event.planId).toBe('builder_beta');
      expect(r.event.status).toBe('active');
    }
  });

  it('rejects a tampered body (BAD_SIGNATURE)', async () => {
    const provider = new StripeBillingProvider({ STRIPE_WEBHOOK_SECRET: WHSEC });
    const t = 1_800_000_000;
    const header = await signedHeader(WHSEC, '{"id":"evt_1"}', t);
    const r = await provider.verifyAndParseWebhook('{"id":"evt_tampered"}', header, t);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('BAD_SIGNATURE');
  });

  it('rejects a stale timestamp (STALE)', async () => {
    const provider = new StripeBillingProvider({ STRIPE_WEBHOOK_SECRET: WHSEC });
    const t = 1_800_000_000;
    const body = '{"id":"evt_1","type":"invoice.paid","data":{"object":{}}}';
    const header = await signedHeader(WHSEC, body, t);

    // now is 10 minutes later than the signature timestamp → outside 5-min tolerance
    const r = await provider.verifyAndParseWebhook(body, header, t + 600);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('STALE');
  });

  it('rejects a wrong secret', async () => {
    const provider = new StripeBillingProvider({ STRIPE_WEBHOOK_SECRET: WHSEC });
    const t = 1_800_000_000;
    const body = '{"id":"evt_1","type":"invoice.paid","data":{"object":{}}}';
    const header = await signedHeader('whsec_other', body, t);
    const r = await provider.verifyAndParseWebhook(body, header, t);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('BAD_SIGNATURE');
  });
});

describe('checkout / portal fail closed without secret', () => {
  it('createCheckoutSession fails closed when STRIPE_SECRET_KEY is absent', async () => {
    const provider = new StripeBillingProvider({});
    const r = await provider.createCheckoutSession({
      orgId: 'org_1',
      userId: 'u1',
      customerEmail: 'a@b.com',
      planId: 'builder_beta',
      interval: 'month',
      successUrl: 'https://x/ok',
      cancelUrl: 'https://x/no',
    });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('BILLING_NOT_CONFIGURED');
  });

  it('createBillingPortalSession fails closed when STRIPE_SECRET_KEY is absent', async () => {
    const provider = new StripeBillingProvider({});
    const r = await provider.createBillingPortalSession({ providerCustomerId: 'cus_1', returnUrl: 'https://x' });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('BILLING_NOT_CONFIGURED');
  });

  it('fails closed when the price-id env is missing (no charge without config)', async () => {
    const provider = new StripeBillingProvider({ STRIPE_SECRET_KEY: 'sk_test_x' });
    const r = await provider.createCheckoutSession({
      orgId: 'org_1',
      userId: 'u1',
      customerEmail: 'a@b.com',
      planId: 'builder_beta',
      interval: 'month',
      successUrl: 'https://x/ok',
      cancelUrl: 'https://x/no',
    });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('PRICE_ID_MISSING');
  });
});

describe('event normalization', () => {
  it('maps checkout.session.completed', () => {
    const n = normalizeStripeEvent({
      id: 'evt_2',
      type: 'checkout.session.completed',
      data: {
        object: {
          customer: 'cus_9',
          subscription: 'sub_9',
          client_reference_id: 'org_9',
          metadata: { plan_id: 'guided_builder' },
        },
      },
    });
    expect(n?.type).toBe('checkout.completed');
    expect(n?.orgId).toBe('org_9');
    expect(n?.planId).toBe('guided_builder');
    expect(n?.providerSubscriptionId).toBe('sub_9');
    expect(n?.status).toBe('active');
  });

  it('maps subscription.deleted to canceled', () => {
    const n = normalizeStripeEvent({
      id: 'evt_3',
      type: 'customer.subscription.deleted',
      data: { object: { id: 'sub_3', customer: 'cus_3', status: 'canceled', metadata: { org_id: 'org_3' } } },
    });
    expect(n?.type).toBe('subscription.deleted');
    expect(n?.status).toBe('canceled');
    expect(n?.providerSubscriptionId).toBe('sub_3');
  });

  it('returns null for a malformed event', () => {
    expect(normalizeStripeEvent({ nope: true })).toBeNull();
  });
});
