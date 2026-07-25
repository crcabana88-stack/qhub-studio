/**
 * QHUB Gate 02 — Classification analysis endpoint
 * app/routes/api.classify.ts
 *
 * POST /api/classify  { description, conversationId }
 *   → returns a PROVISIONAL ClassificationResult (rules floor + AI proposal).
 *
 * This endpoint does NOT write to the ledger. The CLASSIFICATION_ASSIGNED event
 * is emitted only after the user confirms, via POST /api/governance
 * (action=CLASSIFICATION_CONFIRMED), using server-authoritative identity.
 *
 * SECURITY: requires an authenticated session. Identity is never taken from the
 * request body.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { classifyApplication } from '~/lib/qhub/classifier.server';

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false, error: 'Unauthenticated' }, { status: 401 });
  }

  let body: { description?: string; conversationId?: string };
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Invalid request body' }, { status: 400 });
  }

  const description = (body.description ?? '').trim();
  if (!description) {
    return json({ ok: false, error: 'Missing description' }, { status: 400 });
  }

  try {
    const classification = await classifyApplication(description, env);
    return json({ ok: true, classification });
  } catch (err) {
    console.error('[api.classify] error:', err);
    return json({ ok: false, error: 'Classification failed' }, { status: 500 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
