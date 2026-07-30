/**
 * QHUB Commercial Launch R2 — /api/billing/webhook (inbox + binding + reconcile)
 * app/test/commercial-webhook-route.test.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { NormalizedBillingEvent, WebhookVerifyResult } from '~/lib/qhub/commercial/billing/billing-provider';

const H = vi.hoisted(() => ({
  createProvider: vi.fn(),
  planForPrice: vi.fn(),
  claim: vi.fn(),
  apply: vi.fn(),
  getOrgByCustomer: vi.fn(),
  setState: vi.fn(),
  upsertCustomer: vi.fn(),
  verify: vi.fn(),
  retrieve: vi.fn(),
  reconcile: vi.fn(),
  lines: vi.fn(),
  requireReady: vi.fn(),
}));

vi.mock('~/lib/qhub/commercial/billing/stripe-provider.server', () => ({
  createBillingProvider: H.createProvider,
  planIdForConfiguredPrice: H.planForPrice,
}));
vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({
  claimWebhookEvent: H.claim,
  applySubscriptionEvent: H.apply,
  getOrgByCustomer: H.getOrgByCustomer,
  setWebhookState: H.setState,
  upsertBillingCustomer: H.upsertCustomer,
  reconcileCheckout: H.reconcile,
}));

// Deterministic readiness injection — mock the route-level gate the webhook calls.
vi.mock('~/lib/qhub/commercial/commercial-schema-check.server', () => ({
  requireCommercialReady: H.requireReady,
}));

const READY_GATE = {
  ok: true,
  token: { schemaVersion: '2026-07-30.commercial-launch-r7', targetKey: 't', checkedAt: '0' },
} as const;
const NOT_READY_GATE = {
  ok: false,
  response: new Response(JSON.stringify({ ok: false, error: 'commercial_unavailable' }), { status: 500 }),
};

import { action } from '~/routes/api.billing.webhook';

function evt(over: Partial<NormalizedBillingEvent> = {}): NormalizedBillingEvent {
  return {
    providerEventId: 'evt_1',
    type: 'subscription.updated',
    rawType: 'customer.subscription.updated',
    providerCustomerId: 'cus_1',
    providerSubscriptionId: 'sub_1',
    orgId: 'org_1',
    planId: 'builder_beta',
    status: 'active',
    livemode: false,
    eventCreated: 1000,
    ...over,
  };
}

function provider() {
  return {
    id: 'stripe',
    isConfigured: () => true,
    expectedLivemode: () => false,
    isConfiguredPrice: (p: string) => p === 'price_ok',
    retrieveSubscription: H.retrieve,
    retrieveCheckoutSessionPriceIds: H.lines,
    verifyAndParseWebhook: H.verify,
  };
}

function req(body = '{}') {
  return {
    request: new Request('https://app.qhub.test/api/billing/webhook', {
      method: 'POST',
      headers: { 'stripe-signature': 't=1,v1=x' },
      body,
    }),
    context: { cloudflare: { env: {} } },
    params: {},
  } as never;
}

function verifyOk(e: NormalizedBillingEvent) {
  H.verify.mockResolvedValue({ ok: true, event: e } as WebhookVerifyResult);
}

beforeEach(() => {
  vi.clearAllMocks();
  H.requireReady.mockResolvedValue(READY_GATE);
  H.createProvider.mockReturnValue(provider());
  H.planForPrice.mockReturnValue('builder_beta');
  H.apply.mockResolvedValue('applied');
  H.setState.mockResolvedValue(undefined);
  H.upsertCustomer.mockResolvedValue(undefined);
  H.retrieve.mockResolvedValue({
    ok: true,
    value: {
      id: 'sub_1',
      customerId: 'cus_1',
      status: 'active',
      priceId: 'price_ok',
      livemode: false,
      currentPeriodEnd: 123,
      metadata: { org_id: 'org_1' },
    },
  });
  H.getOrgByCustomer.mockResolvedValue('org_1');
  H.lines.mockResolvedValue({ ok: true, value: ['price_ok'] });
  H.reconcile.mockResolvedValue({ ok: true, idempotent: false, org: 'org_1' });
});

describe('webhook verification failures', () => {
  it('503 when the secret is absent', async () => {
    H.verify.mockResolvedValue({ ok: false, error: 'no secret', code: 'NO_SECRET' });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(503);
  });

  it('400 on a bad signature', async () => {
    H.verify.mockResolvedValue({ ok: false, error: 'bad', code: 'BAD_SIGNATURE' });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(400);
  });

  it('400 on a test/live mode mismatch', async () => {
    H.verify.mockResolvedValue({ ok: false, error: 'mode', code: 'MODE_MISMATCH' });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(400);
  });
});

describe('webhook fails closed on schema NOT READY (R4)', () => {
  it('returns a retryable 500 and does NOT claim or mutate when NOT READY', async () => {
    verifyOk(evt());
    H.requireReady.mockResolvedValue(NOT_READY_GATE);

    const res = (await action(req())) as Response;

    // Retryable so Stripe redelivers once the schema is ready.
    expect(res.status).toBe(500);

    // Signature verified, but nothing beyond it happened.
    expect(H.verify).toHaveBeenCalledTimes(1);
    expect(H.claim).not.toHaveBeenCalled();
    expect(H.apply).not.toHaveBeenCalled();
    expect(H.reconcile).not.toHaveBeenCalled();

    // The event is neither PROCESSED nor marked permanent — no state written at all.
    expect(H.setState).not.toHaveBeenCalled();
  });

  it('does not reach reconciliation for a checkout event when NOT READY', async () => {
    verifyOk(
      evt({
        type: 'checkout.completed',
        rawType: 'checkout.session.completed',
        checkoutIntentId: 'intent_1',
        checkoutSessionId: 'cs_1',
      }),
    );
    H.requireReady.mockResolvedValue(NOT_READY_GATE);

    const res = (await action(req())) as Response;
    expect(res.status).toBe(500);
    expect(H.reconcile).not.toHaveBeenCalled();
    expect(H.setState).not.toHaveBeenCalled();
  });
});

describe('webhook inbox state machine', () => {
  it('returns duplicate for an already-processed event', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('DUPLICATE');

    const res = (await action(req())) as Response;
    const body = (await res.json()) as { duplicate?: boolean };
    expect(res.status).toBe(200);
    expect(body.duplicate).toBe(true);
    expect(H.apply).not.toHaveBeenCalled();
  });

  it('returns inProgress for an in-flight event', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('IN_PROGRESS');

    const res = (await action(req())) as Response;
    const body = (await res.json()) as { inProgress?: boolean };
    expect(body.inProgress).toBe(true);
    expect(H.apply).not.toHaveBeenCalled();
  });
});

describe('authoritative reconciliation', () => {
  it('claims, retrieves, validates, applies, then marks PROCESSED', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('CLAIMED');

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.retrieve).toHaveBeenCalledWith('sub_1');
    expect(H.apply).toHaveBeenCalledTimes(1);
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'PROCESSED' }),
      expect.anything(),
    );
  });

  it('rejects an unknown price permanently (FAILED_PERMANENT, 200)', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('CLAIMED');
    H.retrieve.mockResolvedValue({
      ok: true,
      value: {
        id: 'sub_1',
        customerId: 'cus_1',
        status: 'active',
        priceId: 'price_UNKNOWN',
        livemode: false,
        currentPeriodEnd: 1,
        metadata: { org_id: 'org_1' },
      },
    });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.apply).not.toHaveBeenCalled();
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_PERMANENT', errorCode: 'unknown_price' }),
      expect.anything(),
    );
  });

  it('rejects a customer mismatch permanently', async () => {
    verifyOk(evt({ providerCustomerId: 'cus_1' }));
    H.claim.mockResolvedValue('CLAIMED');
    H.retrieve.mockResolvedValue({
      ok: true,
      value: {
        id: 'sub_1',
        customerId: 'cus_OTHER',
        status: 'active',
        priceId: 'price_ok',
        livemode: false,
        currentPeriodEnd: 1,
        metadata: { org_id: 'org_1' },
      },
    });

    const res = (await action(req())) as Response;
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_PERMANENT', errorCode: 'customer_mismatch' }),
      expect.anything(),
    );
    expect(res.status).toBe(200);
  });

  it('subscription.updated with no authoritative customer mapping fails permanently', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('CLAIMED');
    H.getOrgByCustomer.mockResolvedValue(null); // no mapping → metadata cannot establish org

    const res = (await action(req())) as Response;
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_PERMANENT', errorCode: 'unknown_customer' }),
      expect.anything(),
    );
    expect(res.status).toBe(200);
  });

  const checkoutEvt = () =>
    evt({
      type: 'checkout.completed',
      rawType: 'checkout.session.completed',
      checkoutIntentId: 'intent_1',
      checkoutSessionId: 'cs_1',
    });

  it('checkout.completed reconciles ONLY through the atomic reconcile RPC (which marks PROCESSED)', async () => {
    verifyOk(checkoutEvt());
    H.claim.mockResolvedValue('CLAIMED');

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.reconcile).toHaveBeenCalledTimes(1);
    expect(H.reconcile.mock.calls[0][1]).toMatchObject({ intentId: 'intent_1', sessionId: 'cs_1' });

    // The RPC marks PROCESSED atomically — the handler must NOT double-mark.
    expect(H.setState).not.toHaveBeenCalled();
  });

  it('checkout.completed without an intent/session id is a permanent failure', async () => {
    verifyOk(evt({ type: 'checkout.completed', rawType: 'checkout.session.completed', checkoutIntentId: undefined }));
    H.claim.mockResolvedValue('CLAIMED');

    const res = (await action(req())) as Response;
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_PERMANENT', errorCode: 'missing_checkout_intent' }),
      expect.anything(),
    );
    expect(H.reconcile).not.toHaveBeenCalled();
    expect(res.status).toBe(200);
  });

  it('checkout.completed reconcile binding mismatch fails permanently', async () => {
    verifyOk(checkoutEvt());
    H.claim.mockResolvedValue('CLAIMED');
    H.reconcile.mockResolvedValue({ ok: false, reason: 'binding_mismatch' });

    const res = (await action(req())) as Response;
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_PERMANENT', errorCode: 'binding_mismatch' }),
      expect.anything(),
    );
    expect(res.status).toBe(200);
  });

  it('checkout.completed lease_lost is a no-op (another worker owns it)', async () => {
    verifyOk(checkoutEvt());
    H.claim.mockResolvedValue('CLAIMED');
    H.reconcile.mockResolvedValue({ ok: false, reason: 'lease_lost' });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.setState).not.toHaveBeenCalled();
  });

  it('stays retryable (500) on a transient Stripe retrieval error', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('CLAIMED');
    H.retrieve.mockResolvedValue({ ok: false, error: 'network', code: 'STRIPE_ERROR' });

    const res = (await action(req())) as Response;
    expect(res.status).toBe(500);
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'FAILED_RETRYABLE' }),
      expect.anything(),
    );
  });

  it('ignores a stale out-of-order event without error', async () => {
    verifyOk(evt());
    H.claim.mockResolvedValue('CLAIMED');
    H.apply.mockResolvedValue('stale');

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.setState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ state: 'PROCESSED' }),
      expect.anything(),
    );
  });

  it('applies a cancellation for subscription.deleted', async () => {
    verifyOk(evt({ type: 'subscription.deleted', rawType: 'customer.subscription.deleted', status: 'canceled' }));
    H.claim.mockResolvedValue('CLAIMED');

    const res = (await action(req())) as Response;
    expect(res.status).toBe(200);
    expect(H.apply).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ status: 'canceled' }),
      expect.anything(),
    );
    expect(H.retrieve).not.toHaveBeenCalled();
  });
});
