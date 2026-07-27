/**
 * QHUB Gate 05 — Attestation & release persistence — SERVER ONLY
 * app/lib/qhub/attestation-store.server.ts
 *
 * Durable records for release candidates, attestations, and deployment decisions.
 * Tenant-scoped by org_id; service-role client bypasses RLS. Security-critical
 * transitions (freeze idempotency, one-valid-attestation, single deployment) rely
 * on DB unique indexes + conditional writes. Never returns secrets.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { Attestation, ReleaseCandidate } from './release-candidate';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Attestation] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

// ─── Release candidates ───────────────────────────────────────────────────────

/** Insert a release candidate; idempotent on (app, release_candidate_hash). */
export async function upsertReleaseCandidate(
  rc: ReleaseCandidate,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; rc?: any; error?: string }> {
  const sb = admin(env);
  const row = {
    org_id: orgId,
    qhub_app_id: rc.qhub_app_id,
    qhub_app_version: rc.qhub_app_version,
    conversation_id: rc.conversation_id,
    release_candidate_hash: rc.release_candidate_hash,
    canonical_file_manifest_hash: rc.canonical_file_manifest_hash,
    file_count: rc.file_count,
    dependency_lockfile_hash: rc.dependency_lockfile_hash,
    build_artifact_digest: rc.build_artifact_digest,
    classification_version: rc.classification_version,
    classification_reference: rc.classification_reference,
    risk_tier: rc.risk_tier,
    policy_profile_id: rc.policy_profile_id,
    policy_profile_version: rc.policy_profile_version,
    policy_profile_hash: rc.policy_profile_hash,
    enforcement_plan_id: rc.enforcement_plan_id,
    enforcement_plan_version: rc.enforcement_plan_version,
    enforcement_plan_hash: rc.enforcement_plan_hash,
    model_manifest_hash: rc.model_manifest_hash,
    connector_manifest_hash: rc.connector_manifest_hash,
    data_access_manifest_hash: rc.data_access_manifest_hash,
    target_environment: rc.target_environment,
    deployment_target: rc.deployment_target,
    release_scope: rc.release_scope,
    manifest: rc,
    manifest_version: rc.manifest_version,
    status: rc.status,
    created_by: rc.created_by,
  };
  const { data, error } = await sb.from('qhub_release_candidates').insert(row).select('*').single();

  if (error) {
    if (error.code === '23505') {
      const { data: existing } = await sb
        .from('qhub_release_candidates')
        .select('*')
        .eq('qhub_app_id', rc.qhub_app_id)
        .eq('release_candidate_hash', rc.release_candidate_hash)
        .maybeSingle();

      return existing ? { ok: true, rc: existing } : { ok: false, error: error.message };
    }

    return { ok: false, error: error.message };
  }

  return { ok: true, rc: data };
}

/** Count existing release candidates for an app (for version labelling). */
export async function getReleaseCandidateCount(
  qhubAppId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<number> {
  const sb = admin(env);
  const { count } = await sb
    .from('qhub_release_candidates')
    .select('release_candidate_id', { count: 'exact', head: true })
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId);

  return count ?? 0;
}

export async function getReleaseCandidate(
  releaseCandidateId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<any | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_release_candidates')
    .select('*')
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId)
    .maybeSingle();

  return (data as any) ?? null;
}

/** Freeze a release candidate (DRAFT → FROZEN). Idempotent for an already-frozen RC. */
export async function freezeReleaseCandidate(
  releaseCandidateId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_release_candidates')
    .update({ status: 'FROZEN', frozen_at: new Date().toISOString() })
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId)
    .in('status', ['DRAFT', 'FROZEN', 'AWAITING_ATTESTATION'])
    .select('release_candidate_id');

  return !!data && data.length === 1;
}

/** Supersede all other non-terminal release candidates for the app. */
export async function supersedeOtherReleases(
  qhubAppId: string,
  orgId: string,
  keepId: string,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb
    .from('qhub_release_candidates')
    .update({ status: 'SUPERSEDED' })
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId)
    .neq('release_candidate_id', keepId)
    .in('status', ['DRAFT', 'FROZEN', 'AWAITING_ATTESTATION', 'APPROVED']);
}

export async function setReleaseStatus(
  releaseCandidateId: string,
  orgId: string,
  status: string,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb
    .from('qhub_release_candidates')
    .update({ status })
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId);
}

// ─── Attestations ─────────────────────────────────────────────────────────────

export async function insertAttestation(
  att: Attestation,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; error?: string }> {
  const sb = admin(env);
  const { error } = await sb.from('qhub_attestations').insert({
    attestation_id: att.attestation_id,
    org_id: orgId,
    qhub_app_id: att.qhub_app_id,
    release_candidate_id: att.release_candidate_id,
    release_candidate_hash: att.release_candidate_hash,
    qhub_app_version: att.qhub_app_version,
    signer_user_id: att.signer_user_id,
    signer_org_id: att.signer_org_id,
    signer_role: att.signer_role,
    authority_source: att.authority_source,
    attestation_purpose: att.attestation_purpose,
    attestation_scope: att.attestation_scope,
    target_environment: att.target_environment,
    policy_profile_id: att.policy_profile_id,
    policy_profile_version: att.policy_profile_version,
    policy_profile_hash: att.policy_profile_hash,
    enforcement_plan_id: att.enforcement_plan_id,
    enforcement_plan_version: att.enforcement_plan_version,
    enforcement_plan_hash: att.enforcement_plan_hash,
    attestation_statement_version: att.attestation_statement_version,
    attestation_statement_hash: att.attestation_statement_hash,
    signed_at: att.signed_at,
    expires_at: att.expires_at,
    status: att.status,
    supersedes_attestation_id: att.supersedes_attestation_id,
    evidence_reference: att.evidence_reference,
  });

  if (error) {
    // 23505 = a VALID attestation for this (rc, purpose, signer) already exists.
    return {
      ok: false,
      error: error.code === '23505' ? 'A valid attestation for this role/signer already exists' : error.message,
    };
  }

  return { ok: true };
}

/** Valid attestations for a release candidate (expiry computed on read). */
export async function getAttestationsForRelease(
  releaseCandidateId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<Attestation[]> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_attestations')
    .select('*')
    .eq('release_candidate_id', releaseCandidateId)
    .eq('org_id', orgId);

  if (!data) {
    return [];
  }

  const now = Date.now();

  return (data as any[]).map((a) => ({
    ...a,
    status: a.status === 'VALID' && a.expires_at && new Date(a.expires_at).getTime() < now ? 'EXPIRED' : a.status,
  })) as Attestation[];
}

export async function revokeAttestation(
  attestationId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_attestations')
    .update({ status: 'REVOKED' })
    .eq('attestation_id', attestationId)
    .eq('org_id', orgId)
    .eq('status', 'VALID')
    .select('attestation_id');

  return !!data && data.length === 1;
}

// ─── Deployment decisions ─────────────────────────────────────────────────────

export async function recordDeploymentDecision(
  decision: {
    decision_id: string;
    org_id: string;
    qhub_app_id: string;
    release_candidate_id: string;
    release_candidate_hash: string;
    decision: 'APPROVE' | 'REJECT';
    reason_codes: string[];
    satisfied_requirements: string[];
    missing_requirements: string[];
    target_environment: string;
    decided_by: string;
  },
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { error } = await sb.from('qhub_deployment_decisions').insert(decision);

  if (error) {
    console.error('[Attestation] recordDeploymentDecision failed:', error.message);
    return false;
  }

  return true;
}

/** Atomically mark a release deployed exactly once (idempotent single execution). */
export async function markDeployedOnce(
  releaseCandidateId: string,
  orgId: string,
  receipt: Record<string, unknown>,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);

  // Insert a deployed=true decision row; the partial unique index makes it single-use.
  const { error } = await sb.from('qhub_deployment_decisions').insert({
    org_id: orgId,
    qhub_app_id: (receipt.qhub_app_id as string) ?? null,
    release_candidate_id: releaseCandidateId,
    release_candidate_hash: (receipt.release_candidate_hash as string) ?? '',
    decision: 'APPROVE',
    target_environment: (receipt.target_environment as string) ?? 'PRODUCTION',
    deployed: true,
    deployment_receipt: receipt,
    decided_by: (receipt.deployed_by as string) ?? 'system',
  });

  return !error;
}
