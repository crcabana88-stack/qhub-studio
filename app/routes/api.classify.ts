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
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { classifyApplication } from '~/lib/qhub/classifier.server';
import { tierRank } from '~/lib/qhub/classification';
import { LAUNCH_MAX_RISK_TIER } from '~/lib/qhub/commercial/plans';
import { persistProposal } from '~/lib/qhub/qhub-app.server';

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const guard = await requireCommercialContext(request, env, 'APP_BUILD');

  if (!guard.ok) {
    return guard.response;
  }

  const ctx = guard.ctx;
  const session = { userId: ctx.userId, orgId: ctx.orgId ?? '', role: ctx.role ?? 'staff' };

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

  const conversationId = (body.conversationId ?? '').trim();

  try {
    const classification = await classifyApplication(description, env);

    /*
     * Commercial boundary: a use case that classifies above the launch cap (T2/T3)
     * is denied for non-staff — the launch tier supports T0/T1 only.
     */
    if (!ctx.isStaff && tierRank(classification.risk_tier) > tierRank(LAUNCH_MAX_RISK_TIER)) {
      return json(
        {
          ok: false,
          error: 'tier_above_launch_cap',
          risk_tier: classification.risk_tier,
          message: `This use case classifies as ${classification.risk_tier}. The launch tier supports ${LAUNCH_MAX_RISK_TIER} and below.`,
        },
        { status: 403 },
      );
    }

    /*
     * Gate 03 Phase 0: persist the provisional classification server-side and
     * hand the browser only an opaque proposal_id. On confirmation the server
     * reloads the authoritative signals from this proposal — the browser can
     * never rewrite them to lower the deterministic floor.
     */
    let proposalId: string | null = null;

    try {
      proposalId = await persistProposal(
        {
          orgId: session.orgId,
          conversationId,
          description,
          provisional: classification,
          createdBy: session.userId,
        },
        env,
      );
    } catch (persistErr) {
      /*
       * Non-fatal: if the proposals table is unavailable we still return the
       * provisional result for display. Confirmation will fail closed without
       * a valid proposal_id (server never trusts browser-supplied signals).
       */
      console.error('[api.classify] proposal persistence failed:', persistErr);
    }

    return json({ ok: true, classification, proposalId });
  } catch (err) {
    console.error('[api.classify] error:', err);
    return json({ ok: false, error: 'Classification failed' }, { status: 500 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
