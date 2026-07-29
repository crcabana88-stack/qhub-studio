/**
 * QHUB Commercial Launch — /api/billing/webhook route (verify + idempotency)
 * app/test/commercial-billing-webhook-route.test.ts
 *
 * Proves the webhook route fails closed on a bad/absent signature and processes
 * each verified event exactly once (replay protection), applying the subscription
 * change only on the first delivery.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { WebhookVerifyResult } from '~/lib/qhub/commercial/billing/billing-provider';

const { mockCreateProvider, mockVerify, mockRecordOnce, mockUpsertSub, mockUpsertCust, mockMarkProcessed } = vi.hoisted(
  () => ({
    mockCreateProvider: vi.fn(),
    mockVerify: vi.fn(),
    mockRecordOnce: vi.fn(),
    mockUpsertSub: vi.fn(),
    mockUpsertCust: vi.fn(),
    mockMarkProcessed: vi.fn(),
  }),
);

vi.mock('~/lib/qhub/commercial/billing/stripe-provider.server', () => ({
  createBillingProvider: mockCreateProvider,
}));

vi.mock('~/lib/qhub/commercial/commercial-store.server', () => ({
  recordWebhookEventOnce: mockRecordOnce,
  upsertSubscription: mockUpsertSub,
  upsertBillingCustomer: mockUpsertCust,
  markWebhookProcessed: mockMarkProcessed,
}));

import { action } from '~/routes/api.billing.webhook';

function provider(verifyResult: WebhookVerifyResult) {
  mockVerify.mockResolvedValue(verifyResult);
  mockCreateProvider.mockReturnValue({ id: 'stripe', isConfigured: () => true, verifyAndParseWebhook: mockVerify });
}

function req(body = '{}') {
  return new Request('https://app.qhub.test/api/billing/webhook', {
    method: 'POST',
    headers: { 'stripe-signature': 't=1,v1=x' },
    body,
  });
}

function ctx(request: Request) {
  return { request, context: { cloudflare: { env: {} } }, params: {} } as never;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockUpsertSub.mockResolvedValue(undefined);
  mockUpsertCust.mockResolvedValue(undefined);
  mockMarkProcessed.mockResolvedValue(undefined);
});

describe('billing webhook route', () => {
  it('returns 503 when the webhook secret is not configured', async () => {
    provider({ ok: false, error: 'no secret', code: 'NO_SECRET' });

    const res = (await action(ctx(req()))) as Response;
    expect(res.status).toBe(503);
    expect(mockUpsertSub).not.toHaveBeenCalled();
  });

  it('returns 400 on a bad signature and applies nothing', async () => {
    provider({ ok: false, error: 'bad', code: 'BAD_SIGNATURE' });

    const res = (await action(ctx(req()))) as Response;
    expect(res.status).toBe(400);
    expect(mockUpsertSub).not.toHaveBeenCalled();
  });

  it('processes a new verified event once and applies the subscription', async () => {
    provider({
      ok: true,
      event: {
        providerEventId: 'evt_new',
        type: 'subscription.updated',
        rawType: 'customer.subscription.updated',
        providerCustomerId: 'cus_1',
        providerSubscriptionId: 'sub_1',
        orgId: 'org_1',
        planId: 'builder_beta',
        status: 'active',
      },
    });
    mockRecordOnce.mockResolvedValue(true);

    const res = (await action(ctx(req()))) as Response;
    const body = (await res.json()) as { received?: boolean; duplicate?: boolean };
    expect(res.status).toBe(200);
    expect(body.received).toBe(true);
    expect(mockUpsertSub).toHaveBeenCalledTimes(1);
    expect(mockUpsertSub.mock.calls[0][0]).toMatchObject({ orgId: 'org_1', planId: 'builder_beta', status: 'active' });
    expect(mockMarkProcessed).toHaveBeenCalledTimes(1);
  });

  it('skips a duplicate event (replay protection) without re-applying', async () => {
    provider({
      ok: true,
      event: {
        providerEventId: 'evt_dup',
        type: 'subscription.updated',
        rawType: 'customer.subscription.updated',
        providerCustomerId: 'cus_1',
        providerSubscriptionId: 'sub_1',
        orgId: 'org_1',
        planId: 'builder_beta',
        status: 'active',
      },
    });
    mockRecordOnce.mockResolvedValue(false); // already seen

    const res = (await action(ctx(req()))) as Response;
    const body = (await res.json()) as { received?: boolean; duplicate?: boolean };
    expect(res.status).toBe(200);
    expect(body.duplicate).toBe(true);
    expect(mockUpsertSub).not.toHaveBeenCalled();
  });
});
