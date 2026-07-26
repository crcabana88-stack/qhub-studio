/**
 * QHUB Gate 04 — Governed-action enforcement endpoint
 * app/routes/api.enforce.ts
 *
 * POST /api/enforce  { conversationId, action:{...}, idempotencyKey? }
 *   → runs the central enforceGovernedAction() and returns the browser-safe
 *     decision. This is a PROTECTED route: it authenticates server-side and never
 *     trusts a browser-supplied tenant, tier, policy, plan, decision, digest, or
 *     evaluation id.
 *
 * The response exposes only safe fields (decision, reason codes, ids/hashes,
 * required attestations, control statuses) — never secrets or raw parameters.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { generateStableSessionId } from '~/lib/qhub/session-id.server';
import { enforceGovernedAction, type EnforceActionInput } from '~/lib/qhub/enforcement.server';
import type { GovernedActionType } from '~/lib/qhub/enforcement';

const VALID_ACTIONS: GovernedActionType[] = [
  'AI_MODEL_INVOCATION',
  'APP_GENERATION',
  'CODE_MODIFICATION',
  'PREVIEW_CREATION',
  'DEPLOYMENT_EXECUTION',
  'PRODUCTION_EXECUTION',
  'EXTERNAL_DATA_TRANSMISSION',
  'DATABASE_MUTATION',
  'CREDENTIAL_USE',
  'TRADING_OR_ORDER_ROUTING',
  'AGENT_TOOL_EXECUTION',
];

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false, error: 'Unauthenticated' }, { status: 401 });
  }

  let body: {
    conversationId?: string;
    idempotencyKey?: string;
    action?: Partial<EnforceActionInput> & { action_type?: GovernedActionType };
  };

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Invalid request body' }, { status: 400 });
  }

  const conversationId = (body.conversationId ?? '').trim();
  const a = body.action ?? {};

  if (!conversationId || !a.action_type || !VALID_ACTIONS.includes(a.action_type)) {
    return json({ ok: false, error: 'Missing conversationId or valid action.action_type' }, { status: 400 });
  }

  const sessionId = generateStableSessionId(session.userId, conversationId);

  try {
    const decision = await enforceGovernedAction({
      session: { userId: session.userId, orgId: session.orgId, role: session.role },
      conversationId,
      action: {
        action_type: a.action_type,
        target_resource: a.target_resource ?? 'studio://action',
        operation: a.operation ?? 'invoke',
        material_parameters: a.material_parameters ?? null,
        model_identity: a.model_identity ?? null,
        provider_identity: a.provider_identity ?? null,
        tool_identity: a.tool_identity ?? null,
        environment: a.environment ?? 'PREVIEW',
        autonomy_requested: a.autonomy_requested ?? 'NONE',
        app_version_ref: a.app_version_ref ?? null,
      },
      idempotencyKey: body.idempotencyKey,
      sessionId,
      env,
    });

    return json({ ok: true, ...decision });
  } catch (err) {
    console.error('[api.enforce] error:', err);
    // Fail closed — never treat an enforcement error as permission.
    return json({ ok: false, decision: 'DENY', reason_codes: ['DECISION_RECORD_FAILED'], error: 'Enforcement error' }, { status: 500 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
