/**
 * QHUB Gate 04 — Enforcement persistence & TOCTOU-safe claims — SERVER ONLY
 * app/lib/qhub/enforcement-store.server.ts
 *
 * Durable records for enforcement plans, control evaluations, and scoped
 * single-use approvals, plus the kill switch. Security-critical transitions use
 * service-role-only Postgres functions so they cannot race:
 *   - claimEvaluation(): flips claimed false->true exactly once (side-effect gate)
 *   - consumeApproval():  flips GRANTED->CONSUMED exactly once (single-use)
 *
 * Never returns secrets. Service-role client bypasses RLS; all queries are
 * explicitly tenant-scoped by org_id.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { EnforcementPlan, GatheredApproval } from './enforcement';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Enforcement] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

// ─── Enforcement plans ────────────────────────────────────────────────────────

export interface StoredPlan {
  enforcement_plan_id: string;
  org_id: string;
  qhub_app_id: string;
  enforcement_plan_version: number;
  policy_profile_id: string | null;
  policy_profile_hash: string;
  enforcement_plan_hash: string;
  status: string;
  plan: EnforcementPlan;
}

const STORED_PLAN_COLUMNS =
  'enforcement_plan_id, org_id, qhub_app_id, enforcement_plan_version, policy_profile_id, policy_profile_hash, enforcement_plan_hash, status, plan';

/** Get the ACTIVE plan for an app (tenant-scoped). Null if none. */
export async function getActivePlan(
  qhubAppId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<StoredPlan | null> {
  const sb = admin(env);
  const { data, error } = await sb
    .from('qhub_enforcement_plans')
    .select(STORED_PLAN_COLUMNS)
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId)
    .eq('status', 'ACTIVE')
    .maybeSingle();

  if (error) {
    console.error('[Enforcement] getActivePlan failed:', error.message);
    return null;
  }

  return (data as StoredPlan | null) ?? null;
}

/**
 * Persist a freshly compiled plan as ACTIVE, superseding any prior ACTIVE plan
 * for the app. Returns the stored plan (with server id + hash) or null on error.
 */
export async function persistActivePlan(
  plan: EnforcementPlan,
  orgId: string,
  generatedBy: string,
  env: Record<string, string | undefined>,
): Promise<StoredPlan | null> {
  const sb = admin(env);

  // Supersede prior ACTIVE plans first (keeps the partial-unique-index invariant).
  await sb
    .from('qhub_enforcement_plans')
    .update({ status: 'SUPERSEDED' })
    .eq('qhub_app_id', plan.qhub_app_id)
    .eq('org_id', orgId)
    .eq('status', 'ACTIVE');

  const { data, error } = await sb
    .from('qhub_enforcement_plans')
    .insert({
      enforcement_plan_id: plan.enforcement_plan_id,
      org_id: orgId,
      qhub_app_id: plan.qhub_app_id,
      enforcement_plan_version: plan.enforcement_plan_version,
      classification_version: plan.classification_version,
      policy_profile_id: plan.policy_profile_id,
      policy_profile_version: plan.policy_profile_version,
      policy_profile_hash: plan.policy_profile_hash,
      policy_catalog_version: plan.policy_catalog_version,
      risk_tier: plan.risk_tier,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      plan,
      status: 'ACTIVE',
      compiler_version: plan.compiler_version,
      generated_at: plan.generated_at,
      generated_by: generatedBy,
    })
    .select(STORED_PLAN_COLUMNS)
    .single();

  if (error || !data) {
    console.error('[Enforcement] persistActivePlan failed:', error?.message);
    return null;
  }

  return data as StoredPlan;
}

// ─── Approvals ────────────────────────────────────────────────────────────────

/** Gather approvals for THIS exact digest, computing effective status (expiry). */
export async function gatherApprovals(
  qhubAppId: string,
  orgId: string,
  actionDigest: string,
  env: Record<string, string | undefined>,
): Promise<GatheredApproval[]> {
  const sb = admin(env);
  const { data, error } = await sb
    .from('qhub_control_approvals')
    .select(
      'attestation_type, approver_id, approver_role, action_digest, scoped_policy_profile_hash, scoped_enforcement_plan_hash, status, expires_at',
    )
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId)
    .eq('action_digest', actionDigest);

  if (error || !data) {
    return [];
  }

  const now = Date.now();

  return data.map((a: any) => ({
    attestation_type: a.attestation_type,
    approver_id: a.approver_id,
    approver_role: a.approver_role,
    scoped_action_digest: a.action_digest,
    scoped_policy_profile_hash: a.scoped_policy_profile_hash,
    scoped_enforcement_plan_hash: a.scoped_enforcement_plan_hash,
    status:
      a.status === 'GRANTED' && new Date(a.expires_at).getTime() < now
        ? 'EXPIRED'
        : (a.status as GatheredApproval['status']),
    expires_at: a.expires_at,
  }));
}

export async function grantApproval(
  params: {
    orgId: string;
    qhubAppId: string;
    attestationType: string;
    actionDigest: string;
    policyProfileHash: string;
    enforcementPlanHash: string;
    approverId: string;
    approverRole: string;
    ttlMinutes: number;
    createdBy: string;
  },
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; approvalId?: string; error?: string }> {
  const sb = admin(env);
  const expiresAt = new Date(Date.now() + params.ttlMinutes * 60_000).toISOString();
  const { data, error } = await sb
    .from('qhub_control_approvals')
    .insert({
      org_id: params.orgId,
      qhub_app_id: params.qhubAppId,
      attestation_type: params.attestationType,
      action_digest: params.actionDigest,
      scoped_policy_profile_hash: params.policyProfileHash,
      scoped_enforcement_plan_hash: params.enforcementPlanHash,
      approver_id: params.approverId,
      approver_role: params.approverRole,
      single_use: true,
      status: 'GRANTED',
      expires_at: expiresAt,
      created_by: params.createdBy,
    })
    .select('approval_id')
    .single();

  if (error) {
    return { ok: false, error: error.message };
  }

  return { ok: true, approvalId: data.approval_id as string };
}

export async function revokeApproval(
  approvalId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_control_approvals')
    .update({ status: 'REVOKED' })
    .eq('approval_id', approvalId)
    .eq('org_id', orgId)
    .eq('status', 'GRANTED')
    .select('approval_id');

  return !!data && data.length === 1;
}

/** Consume all unexpired GRANTED single-use approvals in one atomic transaction. */
export async function consumeApprovalsForDigest(
  qhubAppId: string,
  orgId: string,
  actionDigest: string,
  evaluationId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { error } = await sb.rpc('qhub_consume_control_approvals', {
    p_qhub_app_id: qhubAppId,
    p_org_id: orgId,
    p_action_digest: actionDigest,
    p_evaluation_id: evaluationId,
  });

  if (error) {
    console.error('[Enforcement] approval consumption failed:', error.message);
    return false;
  }

  return true;
}

// ─── Evaluations ──────────────────────────────────────────────────────────────

export interface EvaluationRecord {
  evaluation_id: string;
  action_request_id: string;
  parent_evaluation_id: string | null;
  org_id: string;
  qhub_app_id: string;
  action_type: string;
  action_digest: string;
  environment: string;
  decision: string;
  reason_codes: string[];
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string;
  control_results: unknown;
  control_results_hash: string;
  required_attestations: string[];
  evaluator_version: string;
  idempotency_key: string | null;
  created_by: string;
}

/** Look up an evaluation by its id (tenant-scoped) — used for E2 re-evaluation. */
export async function getEvaluationById(
  evaluationId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<any | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_control_evaluations')
    .select('*')
    .eq('evaluation_id', evaluationId)
    .eq('org_id', orgId)
    .maybeSingle();

  return (data as any) ?? null;
}

/** Look up an evaluation by its unique action_request_id (replay dedup). */
export async function getEvaluationByActionRequestId(
  orgId: string,
  actionRequestId: string,
  env: Record<string, string | undefined>,
): Promise<any | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_control_evaluations')
    .select('*')
    .eq('org_id', orgId)
    .eq('action_request_id', actionRequestId)
    .maybeSingle();

  return (data as any) ?? null;
}

/** Look up an evaluation by idempotency key (for duplicate-request dedup). */
export async function getEvaluationByIdempotency(
  orgId: string,
  qhubAppId: string,
  idempotencyKey: string,
  env: Record<string, string | undefined>,
): Promise<(EvaluationRecord & { claimed: boolean }) | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_control_evaluations')
    .select('*')
    .eq('org_id', orgId)
    .eq('qhub_app_id', qhubAppId)
    .eq('idempotency_key', idempotencyKey)
    .maybeSingle();

  return (data as any) ?? null;
}

/**
 * Insert the evaluation (the CONTROL_DECISION_RECORDED authoritative record).
 * Returns { ok, duplicate?, existing? }. On idempotency/action_request collision
 * the existing row is returned so the caller reuses that decision.
 */
export async function insertEvaluation(
  rec: EvaluationRecord,
  env: Record<string, string | undefined>,
): Promise<{ ok: boolean; duplicate?: boolean; existing?: any; error?: string }> {
  const sb = admin(env);
  const { error } = await sb.from('qhub_control_evaluations').insert({
    evaluation_id: rec.evaluation_id,
    action_request_id: rec.action_request_id,
    parent_evaluation_id: rec.parent_evaluation_id,
    org_id: rec.org_id,
    qhub_app_id: rec.qhub_app_id,
    action_type: rec.action_type,
    action_digest: rec.action_digest,
    environment: rec.environment,
    decision: rec.decision,
    reason_codes: rec.reason_codes,
    policy_profile_id: rec.policy_profile_id,
    policy_profile_version: rec.policy_profile_version,
    policy_profile_hash: rec.policy_profile_hash,
    enforcement_plan_id: rec.enforcement_plan_id,
    enforcement_plan_version: rec.enforcement_plan_version,
    enforcement_plan_hash: rec.enforcement_plan_hash,
    control_results: rec.control_results,
    control_results_hash: rec.control_results_hash,
    required_attestations: rec.required_attestations,
    evaluator_version: rec.evaluator_version,
    idempotency_key: rec.idempotency_key,
    created_by: rec.created_by,
  });

  if (error) {
    // 23505 = unique_violation (action_request_id or idempotency_key) → replay dedup.
    if (error.code === '23505') {
      const existing =
        (await getEvaluationByActionRequestId(rec.org_id, rec.action_request_id, env)) ??
        (rec.idempotency_key
          ? await getEvaluationByIdempotency(rec.org_id, rec.qhub_app_id, rec.idempotency_key, env)
          : null);

      if (existing) {
        return { ok: false, duplicate: true, existing };
      }
    }

    return { ok: false, error: error.message };
  }

  return { ok: true };
}

/**
 * Atomically claim an ALLOW evaluation for the single protected side effect.
 * Returns true only for the first caller (claimed false->true). Fail-closed.
 */
export async function claimEvaluation(
  evaluationId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data, error } = await sb.rpc('qhub_claim_control_evaluation', {
    p_evaluation_id: evaluationId,
    p_org_id: orgId,
  });

  if (error) {
    console.error('[Enforcement] claimEvaluation failed:', error.message);
    return false;
  }

  return data === true;
}

/** Record the post-action evidence outcome (durable outbox state). */
export async function markActionEvidence(
  evaluationId: string,
  orgId: string,
  state: 'COMMITTED' | 'FAILED',
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data, error } = await sb
    .from('qhub_control_evaluations')
    .update({ action_event_state: state })
    .eq('evaluation_id', evaluationId)
    .eq('org_id', orgId)
    .select('evaluation_id');

  if (error || !data || data.length !== 1) {
    console.error(
      '[Enforcement] markActionEvidence failed:',
      error?.message ?? `expected one evaluation row, updated ${data?.length ?? 0}`,
    );

    return false;
  }

  return true;
}

// ─── Kill switch ──────────────────────────────────────────────────────────────

export async function getKillSwitch(
  qhubAppId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_applications')
    .select('kill_switch_active')
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId)
    .maybeSingle();

  return !!data?.kill_switch_active;
}

export async function setKillSwitch(
  qhubAppId: string,
  orgId: string,
  active: boolean,
  reason: string,
  setBy: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_applications')
    .update({
      kill_switch_active: active,
      kill_switch_reason: reason,
      kill_switch_set_by: setBy,
      kill_switch_set_at: new Date().toISOString(),
    })
    .eq('qhub_app_id', qhubAppId)
    .eq('org_id', orgId)
    .select('qhub_app_id');

  return !!data && data.length === 1;
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
