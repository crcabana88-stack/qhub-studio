/**
 * QHUB Commercial Launch — GET /api/entitlements
 * app/routes/api.entitlements.ts
 *
 * Authenticated. Returns the server-resolved effective entitlements for the caller's
 * org. This is the same resolution the enforcement paths use — the UI reads it for
 * display only; it is never the security boundary.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  // Commercial-safe: returns the caller's OWN authoritative entitlements only.
  const guard = await requireCommercialContext(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  return json({
    orgId: ctx.orgId,
    planId: ctx.resolved.planId,
    status: ctx.resolved.status,
    serviceState: ctx.resolved.serviceState,
    entitlements: ctx.resolved.entitlements,
  });
}
