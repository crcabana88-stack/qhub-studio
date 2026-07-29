/**
 * QHUB Commercial Launch R2 — POST /api/billing/portal
 * app/routes/api.billing.portal.ts
 *
 * Creates a Stripe-hosted Billing Portal session for the caller's OWN org customer
 * only (loaded server-side — a caller can never open another tenant's portal).
 * Authority: an authoritative billing-admin membership (PORTAL capability). CSRF
 * (same-origin), a rate limit, and a server-owned return URL apply.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { createBillingProvider } from '~/lib/qhub/commercial/billing/stripe-provider.server';
import { requireCommercialReady } from '~/lib/qhub/commercial/commercial-schema-check.server';
import { getSubscriptionSnapshot } from '~/lib/qhub/commercial/commercial-store.server';
import { appUrl, checkRateLimit, isSameOrigin } from '~/lib/qhub/commercial/request-guards.server';

export async function action({ request, context }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  if (!isSameOrigin(request, env)) {
    return json({ ok: false, error: 'csrf_origin_rejected' }, { status: 403 });
  }

  const guard = await requireCommercialContext(request, env, 'PORTAL');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  if (!ctx.orgId) {
    return json({ ok: false, error: 'no_org_context' }, { status: 403 });
  }

  // Fail closed on schema readiness BEFORE any Stripe call.
  const ready = await requireCommercialReady(env);

  if (!ready.ok) {
    return ready.response;
  }

  const rate = checkRateLimit(`portal:${ctx.orgId}`, 5, 60_000);

  if (!rate.allowed) {
    return json({ ok: false, error: 'rate_limited' }, { status: 429 });
  }

  const provider = createBillingProvider(env);

  if (!provider.isConfigured()) {
    return json({ ok: false, error: 'billing_not_configured', code: 'BILLING_NOT_CONFIGURED' }, { status: 503 });
  }

  // Customer id comes from the org's OWN durable record — never from the client.
  const snap = await getSubscriptionSnapshot(ctx.orgId, env).catch(() => null);

  if (!snap?.providerCustomerId) {
    return json({ ok: false, error: 'no_billing_customer' }, { status: 400 });
  }

  const returnUrl = appUrl(env, '/build');

  if (!returnUrl) {
    return json({ ok: false, error: 'app_origin_not_configured' }, { status: 503 });
  }

  const result = await provider.createBillingPortalSession({ providerCustomerId: snap.providerCustomerId, returnUrl });

  if (!result.ok) {
    return json({ ok: false, error: result.error, code: result.code }, { status: 502 });
  }

  return json({ url: result.value.url });
}
