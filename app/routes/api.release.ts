/**
 * QHUB Gate 05 — Release readiness, attestation & deployment authorization
 * app/routes/api.release.ts
 *
 * POST /api/release { op, ... }
 *   op = 'freeze'    — snapshot the exact version → release candidate + hash (server-computed)
 *   op = 'attest'    — sign an attestation bound to the exact release hash (role-gated)
 *   op = 'evaluate'  — evaluate the release for deployment → APPROVE/REJECT
 *   op = 'receipt'   — generate the release-assurance receipt
 *   op = 'revoke'    — revoke a valid attestation
 *
 * Server-authoritative: the browser supplies file/model/connector facts to freeze,
 * but NEVER the release hash, signer role/authority, policy refs, or decision.
 */

import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { createHash } from 'node:crypto';
import { getSession } from '~/lib/auth/session';
import { generateStableSessionId } from '~/lib/qhub/session-id.server';
import { freezeReleaseCandidate, signAttestation, evaluateReleaseForDeployment } from '~/lib/qhub/attestation.server';
import { getReleaseCandidate, getAttestationsForRelease, revokeAttestation } from '~/lib/qhub/attestation-store.server';
import { canonicalReceiptString, deriveAttestationRequirements } from '~/lib/qhub/release-manifest';
import { RELEASE_RECEIPT_VERSION, type AttestationPurpose, type FileManifestEntry } from '~/lib/qhub/release-candidate';
import { getPolicyProfile } from '~/lib/qhub/qhub-app.server';
import { getActivePlan } from '~/lib/qhub/enforcement-store.server';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

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

  const sess = { userId: session.userId, orgId: session.orgId, role: session.role };
  const sessionId = generateStableSessionId(session.userId, conversationId);

  switch (body.op) {
    case 'freeze': {
      const files: FileManifestEntry[] = Array.isArray(body.files) ? body.files : [];

      const r = await freezeReleaseCandidate({
        session: sess,
        conversationId,
        files,
        declared_models: Array.isArray(body.declared_models) ? body.declared_models : [],
        declared_connectors: Array.isArray(body.declared_connectors) ? body.declared_connectors : [],
        declared_data_access: Array.isArray(body.declared_data_access) ? body.declared_data_access : [],
        dependency_lockfile_hash: body.dependency_lockfile_hash ?? null,
        source_commit: body.source_commit ?? null,
        target_environment: body.target_environment ?? 'PRODUCTION',
        deployment_target: body.deployment_target ?? 'unspecified',
        release_scope: body.release_scope ?? 'full',
        sessionId,
        env,
      });

      return json(r, { status: r.ok ? 200 : 409 });
    }

    case 'attest': {
      const r = await signAttestation({
        session: sess,
        conversationId,
        release_candidate_id: body.release_candidate_id,
        attestation_purpose: body.attestation_purpose as AttestationPurpose,
        sessionId,
        env,
      });

      return json(r, { status: r.ok ? 200 : 403 });
    }

    case 'evaluate': {
      const r = await evaluateReleaseForDeployment({
        session: sess,
        conversationId,
        release_candidate_id: body.release_candidate_id,
        target_environment: body.target_environment ?? 'PRODUCTION',
        sessionId,
        env,
      });

      return json(r);
    }

    case 'revoke': {
      const ok = await revokeAttestation(body.attestation_id, session.orgId, env);
      return json({ ok }, { status: ok ? 200 : 409 });
    }

    case 'receipt': {
      const rc = await getReleaseCandidate(body.release_candidate_id, session.orgId, env);

      if (!rc) {
        return json({ ok: false, error: 'Release not found' }, { status: 404 });
      }

      const profile = await getPolicyProfile(rc.qhub_app_id, env);
      const stored = await getActivePlan(rc.qhub_app_id, session.orgId, env);
      const requirements = profile && stored ? deriveAttestationRequirements(profile, stored.plan) : [];
      const atts = (await getAttestationsForRelease(rc.release_candidate_id, session.orgId, env)).filter((a) => a.status === 'VALID');

      const receiptBase = {
        receipt_version: RELEASE_RECEIPT_VERSION,
        release_candidate_id: rc.release_candidate_id,
        release_candidate_hash: rc.release_candidate_hash,
        qhub_app_id: rc.qhub_app_id,
        qhub_app_version: rc.qhub_app_version,
        target_environment: rc.target_environment,
        risk_tier: rc.risk_tier,
        classification_version: rc.classification_version,
        policy_profile_hash: rc.policy_profile_hash,
        enforcement_plan_hash: rc.enforcement_plan_hash,
        required_attestation_purposes: requirements.map((r) => r.purpose),
        completed_attestations: atts.map((a) => ({ attestation_id: a.attestation_id, purpose: a.attestation_purpose, signer_role: a.signer_role })),
        deployment_decision: rc.status === 'APPROVED' ? ('APPROVE' as const) : rc.status === 'REJECTED' ? ('REJECT' as const) : null,
        deployment_decision_id: null,
        known_exceptions: [] as string[],
      };
      const receipt_hash = sha256(canonicalReceiptString(receiptBase));

      return json({ ok: true, receipt: { ...receiptBase, generated_at: new Date().toISOString(), receipt_hash } });
    }

    default:
      return json({ ok: false, error: 'Unknown op' }, { status: 400 });
  }
}

export async function loader() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
