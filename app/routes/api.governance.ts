// @qhub-route: INTERNAL_SERVER_ONLY
/**
 * QHUB Governance Server Action
 * app/routes/api.governance.ts
 *
 * The single server-side entry point for browser-initiated governance events.
 *
 * SECURITY CONTRACT:
 *   - Requires authenticated session (Supabase cookie).
 *     Unauthenticated requests → 401.
 *   - Browser supplies ONLY an intent (action + app context).
 *     The server determines actor identity, org, timestamp, gate state.
 *   - HMAC signing happens server-side via GovernanceService.
 *     The HMAC secret never leaves the server process.
 *   - The raw AWS endpoint is never exposed to the browser.
 *
 * INTENT SCHEMA:
 *   POST /api/governance
 *   Body: { action, appId, conversationId, ...action-specific fields }
 *
 *   action = 'PROJECT_CREATED'     → records GENESIS event
 *   action = 'AI_MODEL_USED'       → records AI_BOM event
 *   action = 'DEPLOYMENT_GATE_CHECK' → queries gate, records GATE_PASSED/BLOCKED
 *
 * RESPONSE:
 *   200: { ok: true, gateState?: 'APPROVED'|'BLOCKED'|'UNKNOWN'|'ERROR' }
 *   400: { ok: false, error: string }
 *   401: { ok: false, error: 'Unauthenticated' }
 *   500: { ok: false, error: string }
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { createGovernanceService, type GovernanceIntent } from '~/lib/qhub/governance-service.server';
import { generateStableSessionId } from '~/lib/qhub/session-id.server';

export async function action({ request, context }: ActionFunctionArgs) {
  // ── 1. Authoritative context + capability (APP_BUILD) ─────────────────────────
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const guard = await requireStaff(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;

  if (!ctx.orgId) {
    return json({ ok: false, error: 'no_org_context' }, { status: 403 });
  }

  const session = { userId: ctx.userId, orgId: ctx.orgId, role: ctx.role ?? 'staff' };

  // ── 2. Parse intent ─────────────────────────────────────────────────────────
  let intent: GovernanceIntent;

  try {
    intent = await request.json<GovernanceIntent>();
  } catch {
    return json({ ok: false, error: 'Invalid request body' }, { status: 400 });
  }

  // Validate required base fields
  if (!intent?.action || !intent?.conversationId) {
    return json({ ok: false, error: 'Missing required fields: action, conversationId' }, { status: 400 });
  }

  // Validate action is a known intent type (reject unknown actions at the boundary)
  const allowedActions: GovernanceIntent['action'][] = [
    'PROJECT_CREATED',
    'AI_MODEL_USED',
    'DEPLOYMENT_GATE_CHECK',
    'CLASSIFICATION_CONFIRMED',
    'POLICY_ASSIGN',
    'POLICY_ACKNOWLEDGE',
  ];

  if (!allowedActions.includes(intent.action)) {
    return json({ ok: false, error: `Unknown action: ${intent.action}` }, { status: 400 });
  }

  /*
   * ── 3. Build server-authoritative context ──────────────────────────────────
   * Actor identity comes from the verified server session — not from the browser intent.
   */
  const sessionId = generateStableSessionId(session.userId, intent.conversationId);

  const svc = createGovernanceService({
    userId: session.userId, // Server-authoritative: from Supabase JWT
    orgId: session.orgId, // Server-authoritative: from the DB-backed staff context
    sessionId,
    env,
  });

  // ── 4. Handle intent ────────────────────────────────────────────────────────
  try {
    const result = await svc.handleIntent(intent);
    return json(result);
  } catch (err) {
    console.error('[api.governance] Unhandled error:', err);
    return json({ ok: false, error: 'Internal governance error' }, { status: 500 });
  }
}

// GET is not supported
export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
