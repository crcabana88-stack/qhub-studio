/**
 * QHUB Gate 04 — Approval & kill-switch management
 * app/routes/api.enforcement.ts
 *
 * POST /api/enforcement { op, ... }
 *   op = 'grant_approval'   — grant a scoped, single-use approval for an exact digest
 *   op = 'revoke_approval'  — revoke a still-GRANTED approval
 *   op = 'kill_switch'      — set the server-authoritative kill switch
 *
 * Server-authoritative: approver identity/role come from the session, never the
 * body. Approvals are bound to the exact action_digest + current policy/plan
 * hashes; the browser cannot broaden scope or self-approve an independent role.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { getOrCreateQhubApp, getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan, grantApproval, revokeApproval, setKillSwitch } from '~/lib/qhub/enforcement-store.server';

const ATTESTATION_ROLES: Record<string, string[]> = {
  OWNER_ATTESTATION: ['owner', 'admin'],
  AUTHORIZED_GOVERNANCE_APPROVAL: ['governance', 'compliance', 'security'],
  CHANGE_ATTESTATION: ['owner', 'admin'],
};
const KILL_SWITCH_ROLES = ['owner', 'admin', 'governance', 'security'];

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false, error: 'Unauthenticated' }, { status: 401 });
  }

  let body: any;

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Invalid request body' }, { status: 400 });
  }

  const conversationId = (body.conversationId ?? '').trim();

  if (!conversationId) {
    return json({ ok: false, error: 'Missing conversationId' }, { status: 400 });
  }

  let app;

  try {
    app = await getOrCreateQhubApp({ orgId: session.orgId, userId: session.userId, conversationId }, env);
  } catch {
    return json({ ok: false, error: 'App identity lookup failed' }, { status: 500 });
  }

  if (app.org_id !== session.orgId) {
    return json({ ok: false, error: 'Tenant mismatch' }, { status: 403 });
  }

  switch (body.op) {
    case 'grant_approval': {
      const attestationType: string = body.attestationType;
      const actionDigest: string = body.actionDigest;

      if (!attestationType || !actionDigest || !ATTESTATION_ROLES[attestationType]) {
        return json({ ok: false, error: 'Missing/invalid attestationType or actionDigest' }, { status: 400 });
      }

      // Approver role is server-authoritative; must be authorized for this attestation.
      if (!ATTESTATION_ROLES[attestationType].includes(session.role)) {
        return json({ ok: false, error: `Role '${session.role}' may not grant ${attestationType}` }, { status: 403 });
      }

      const profile = await getPolicyProfile(app.qhub_app_id, env);
      const plan = await getActivePlan(app.qhub_app_id, session.orgId, env);

      if (!profile || !plan) {
        return json({ ok: false, error: 'No policy/enforcement plan to scope the approval to' }, { status: 409 });
      }

      const res = await grantApproval(
        {
          orgId: session.orgId,
          qhubAppId: app.qhub_app_id,
          attestationType,
          actionDigest,
          policyProfileHash: profile.policy_profile_hash,
          enforcementPlanHash: plan.enforcement_plan_hash,
          approverId: session.userId,
          approverRole: session.role,
          ttlMinutes: 60,
          createdBy: session.userId,
        },
        env,
      );

      return json(res.ok ? { ok: true, approvalId: res.approvalId } : { ok: false, error: res.error }, { status: res.ok ? 200 : 409 });
    }

    case 'revoke_approval': {
      if (!body.approvalId) {
        return json({ ok: false, error: 'Missing approvalId' }, { status: 400 });
      }

      const ok = await revokeApproval(body.approvalId, session.orgId, env);

      return json({ ok }, { status: ok ? 200 : 409 });
    }

    case 'kill_switch': {
      if (!KILL_SWITCH_ROLES.includes(session.role)) {
        return json({ ok: false, error: `Role '${session.role}' may not toggle the kill switch` }, { status: 403 });
      }

      const active = body.active === true;
      const ok = await setKillSwitch(app.qhub_app_id, session.orgId, active, String(body.reason ?? ''), session.userId, env);

      return json({ ok, active }, { status: ok ? 200 : 500 });
    }

    default:
      return json({ ok: false, error: 'Unknown op' }, { status: 400 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
