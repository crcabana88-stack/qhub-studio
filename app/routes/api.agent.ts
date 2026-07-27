/**
 * QHUB Agent Framework Foundation — Agent API
 * app/routes/api.agent.ts
 *
 * POST /api/agent { op, ... }
 *   op = 'create'   — build server-authoritative manifest + create draft agent
 *   op = 'version'  — create a new immutable version (material change)
 *   op = 'freeze'   — freeze the current version's manifest
 *   op = 'bind_release' — bind an APPROVED Gate 05 release to a frozen version
 *   op = 'state'    — request a lifecycle transition (server decides)
 *   op = 'suspend'  — kill switch (durable suspend)
 *   op = 'run'      — start (or replay) a governed run
 *   op = 'resume'   — resume an AWAITING_APPROVAL run after Gate 04 approval
 *   op = 'get'      — load one agent (+ current version)
 *   op = 'list'     — list agents for the tenant
 *
 * PROTECTED: authenticates server-side; never trusts a browser-supplied tenant,
 * owner, policy, plan, release approval, role, manifest hash, or status.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import { generateStableSessionId } from '~/lib/qhub/session-id.server';
import { buildAgentManifest } from '~/lib/qhub/agent/agent-manifest.server';
import {
  createDraftAgent,
  createAgentVersion,
  freezeAgentVersion,
  bindApprovedRelease,
  getApprovedReleaseForBinding,
  getAgent,
  getAgentVersion,
  listAgents,
} from '~/lib/qhub/agent/agent-registry.server';
import { transitionAgentState, killSwitchAgent } from '~/lib/qhub/agent/agent-lifecycle.server';
import { runAgent, resumeAgentRun } from '~/lib/qhub/agent/agent-run.server';
import { assertAgentSchemaReady } from '~/lib/qhub/agent/agent-schema-check.server';

export async function action({ request, context }: ActionFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false, error: 'Unauthenticated' }, { status: 401 });
  }

  // Fail closed for EVERY agent op if the Agent Framework schema is not ready.
  try {
    await assertAgentSchemaReady(env);
  } catch {
    return json({ ok: false, error: 'Agent Framework schema not ready' }, { status: 503 });
  }

  const sess = { userId: session.userId, orgId: session.orgId, role: session.role };

  let body: any;

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Invalid request body' }, { status: 400 });
  }

  switch (body.op) {
    case 'create': {
      const conversationId = (body.conversationId ?? '').trim();

      if (!conversationId) {
        return json({ ok: false, error: 'Missing conversationId' }, { status: 400 });
      }

      const built = await buildAgentManifest({ ...body.manifest, session: sess, conversationId, env });

      if (!built.ok || !built.built) {
        return json({ ok: false, error: built.error }, { status: 409 });
      }

      const created = await createDraftAgent(
        { manifest: built.built.manifest, manifest_hash: built.built.manifest_hash },
        env,
      );

      return json(
        {
          ok: created.ok,
          agent_id: created.agent_id,
          agent_version_id: created.agent_version_id,
          manifest_hash: built.built.manifest_hash,
          reason: created.reason,
        },
        { status: created.ok ? 200 : 409 },
      );
    }

    case 'version': {
      const conversationId = (body.conversationId ?? '').trim();
      const built = await buildAgentManifest(
        { ...body.manifest, session: sess, conversationId, env },
        { agent_id: body.agent_id },
      );

      if (!built.ok || !built.built) {
        return json({ ok: false, error: built.error }, { status: 409 });
      }

      const res = await createAgentVersion(
        { manifest: built.built.manifest, manifest_hash: built.built.manifest_hash },
        env,
      );

      return json(
        {
          ok: res.ok,
          agent_version_id: res.agent_version_id,
          manifest_hash: built.built.manifest_hash,
          reason: res.reason,
        },
        { status: res.ok ? 200 : 409 },
      );
    }

    case 'freeze': {
      const ok = await freezeAgentVersion(body.agent_version_id, session.orgId, env);

      return json({ ok }, { status: ok ? 200 : 409 });
    }

    case 'bind_release': {
      /*
       * Server-authoritative: verify the release is APPROVED for this tenant and
       * resolve its exact hash + APPROVE decision; the browser supplies neither.
       */
      const approved = await getApprovedReleaseForBinding(body.release_candidate_id, session.orgId, env);

      if (!approved) {
        return json({ ok: false, error: 'RELEASE_NOT_APPROVED' }, { status: 409 });
      }

      const version = await getAgentVersion(body.agent_version_id, session.orgId, env);

      if (!version || version.qhub_app_id !== approved.qhub_app_id) {
        return json({ ok: false, error: 'RELEASE_APP_MISMATCH' }, { status: 409 });
      }

      const ok = await bindApprovedRelease(
        {
          agent_version_id: body.agent_version_id,
          org_id: session.orgId,
          release_candidate_id: body.release_candidate_id,
          release_candidate_hash: approved.release_candidate_hash,
          deployment_decision_id: approved.deployment_decision_id,
        },
        env,
      );

      return json({ ok, release_candidate_hash: approved.release_candidate_hash }, { status: ok ? 200 : 409 });
    }

    case 'state': {
      const res = await transitionAgentState({
        session: sess,
        agent_id: body.agent_id,
        to: body.to,
        policy_allows_active: body.policy_allows_active,
        env,
      });

      return json(res, { status: res.ok ? 200 : 409 });
    }

    case 'suspend': {
      const res = await killSwitchAgent({ session: sess, agent_id: body.agent_id, env });

      return json(res, { status: res.ok ? 200 : 409 });
    }

    case 'run': {
      const conversationId = (body.conversationId ?? '').trim();
      const sessionId = generateStableSessionId(session.userId, conversationId || body.agent_id);
      const res = await runAgent({
        session: sess,
        conversationId,
        agent_id: body.agent_id,
        idempotency_key: body.idempotency_key ?? crypto.randomUUID(),
        synthetic_inputs: body.synthetic_inputs ?? {},
        sessionId,
        env,
      });

      return json(res, { status: res.ok ? 200 : 409 });
    }

    case 'resume': {
      const sessionId = generateStableSessionId(session.userId, body.agent_id);
      const res = await resumeAgentRun({
        session: sess,
        run_id: body.run_id,
        approved_evaluation_id: body.approved_evaluation_id,
        synthetic_inputs: body.synthetic_inputs ?? {},
        sessionId,
        env,
      });

      return json(res, { status: res.ok ? 200 : 409 });
    }

    case 'get': {
      const agent = await getAgent(body.agent_id, session.orgId, env);

      if (!agent) {
        return json({ ok: false, error: 'Agent not found' }, { status: 404 });
      }

      const version = agent.current_version_id
        ? await getAgentVersion(agent.current_version_id, session.orgId, env)
        : null;

      return json({ ok: true, agent, version });
    }

    case 'list': {
      const agents = await listAgents(session.orgId, env);

      return json({ ok: true, agents });
    }

    default:
      return json({ ok: false, error: 'Unknown op' }, { status: 400 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
