/**
 * QHUB Commercial Launch — GET /api/entitlements
 * app/routes/api.entitlements.ts
 *
 * Authenticated. Returns the server-resolved effective entitlements for the caller's
 * org. This is the same resolution the enforcement paths use — the UI reads it for
 * display only; it is never the security boundary.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { loadOrgEntitlements } from '~/lib/qhub/commercial/entitlements.server';

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ error: 'unauthorized' }, { status: 401 });
  }

  const resolved = await loadOrgEntitlements(session.orgId, env);

  return json({
    orgId: session.orgId,
    planId: resolved.planId,
    status: resolved.status,
    serviceState: resolved.serviceState,
    entitlements: resolved.entitlements,
  });
}
