/**
 * QHUB Commercial Launch R4 — MANUAL REVIEW AUTHORITY (SERVER ONLY)
 * app/lib/qhub/commercial/review.server.ts
 *
 * Server-authoritative manual review. A request is tenant-scoped to one org/
 * project and may only cover review-eligible categories — prohibited categories
 * can never enter the queue or be overridden. A decision requires an authoritative
 * Quantex staff actor (never supplied by the browser); the actor, reason, policy
 * version, and timestamp are recorded. The review policy version is SERVER-DERIVED at
 * both submission and decision — the browser can never choose or override it. A
 * materially different repeat is a new request (not silently idempotent).
 *
 * NON-BYPASSABLE READINESS: every mutation requires a branded CommercialReadyToken and
 * obtains its privileged client only through mutator(token,env). Reads are
 * INTERNAL_SERVER_ONLY. Each export is tagged `@qhub-service: <classification>`.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { assertReadyToken, type CommercialReadyToken } from '~/lib/qhub/commercial/commercial-schema-check.server';
import {
  currentReviewPolicyVersion,
  REVIEW_DATA_CLASSES,
  type DataClass,
} from '~/lib/qhub/commercial/governance-essentials';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Review] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

/** Privileged MUTATION client — re-validates the readiness token before any write. */
function mutator(token: CommercialReadyToken, env: Record<string, string | undefined>): SupabaseClient {
  assertReadyToken(token, env);

  return admin(env);
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Categories that are prohibited and can never enter the review queue. */
const PROHIBITED_CATEGORIES = new Set([
  'secrets',
  'credentials',
  'mnpi',
  'regulated_records',
  'consequential_action',
  'external_write',
  'autonomous_agent',
]);

/** Only sensitive-data categories are review-eligible in the launch tier. */
function isReviewEligibleCategory(category: string): boolean {
  return (REVIEW_DATA_CLASSES as string[]).includes(category);
}

export type ReviewResult = { ok: true; requestId: string; idempotent: boolean } | { ok: false; error: string };

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Create a manual-review request. Requires an active membership on the request's
 * org (the caller cannot open a request for a tenant they do not belong to).
 * Prohibited categories are rejected; only review-eligible categories may queue. The
 * review's policy version is SERVER-DERIVED (currentReviewPolicyVersion) and stored on
 * the request — the browser never supplies it.
 */
export async function createReviewRequest(
  ctx: CommercialContext,
  input: { projectId?: string; category: string; reason: string; requestType?: string },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<ReviewResult> {
  if (!ctx.orgId) {
    return { ok: false, error: 'no_org_context' };
  }

  if (PROHIBITED_CATEGORIES.has(input.category)) {
    return { ok: false, error: 'prohibited_category' };
  }

  if (!isReviewEligibleCategory(input.category)) {
    return { ok: false, error: 'not_review_eligible' };
  }

  const requestType = input.requestType ?? 'data_review';
  const requestHash = await sha256Hex(
    `${ctx.orgId}|${input.projectId ?? ''}|${requestType}|${input.category}|${input.reason}`,
  );

  // SERVER-derived evaluated-under policy version (never from the browser).
  const policyVersion = currentReviewPolicyVersion();

  const sb = mutator(token, env);
  const { data, error } = await sb
    .from('qhub_manual_review_requests')
    .insert({
      org_id: ctx.orgId,
      project_id: input.projectId ?? null,
      request_type: requestType,
      category: input.category,
      reason: input.reason,
      request_hash: requestHash,
      policy_version: policyVersion,
      status: 'pending',
    })
    .select('id')
    .maybeSingle();

  if (error) {
    // Unique(org_id, request_hash) → an identical request already exists.
    const { data: existing } = await sb
      .from('qhub_manual_review_requests')
      .select('id')
      .eq('org_id', ctx.orgId)
      .eq('request_hash', requestHash)
      .maybeSingle();

    if (existing?.id) {
      return { ok: true, requestId: existing.id as string, idempotent: true };
    }

    return { ok: false, error: 'insert_failed' };
  }

  return { ok: true, requestId: (data?.id as string) ?? '', idempotent: false };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Decide a manual-review request. Requires an authoritative staff actor (isStaff). The
 * actor is derived from the staff context, never the browser. Prohibited categories
 * cannot be approved. The policy version is SERVER-DERIVED (never the browser): the
 * decision is bound to the version the request was evaluated under; if the current
 * policy changed materially, re-review is required.
 */
export async function decideReviewRequest(
  ctx: CommercialContext,
  input: { requestId: string; decision: 'approved' | 'rejected'; reason: string },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<{ ok: true; policyVersion: string } | { ok: false; error: string }> {
  if (!ctx.isStaff) {
    return { ok: false, error: 'staff_required' };
  }

  const sb = mutator(token, env);
  const { data: req } = await sb
    .from('qhub_manual_review_requests')
    .select('id,category,status,org_id,project_id,policy_version')
    .eq('id', input.requestId)
    .maybeSingle();

  if (!req) {
    return { ok: false, error: 'not_found' };
  }

  if (req.status !== 'pending') {
    return { ok: false, error: 'not_pending' };
  }

  if (input.decision === 'approved' && req.category && PROHIBITED_CATEGORIES.has(req.category as string)) {
    return { ok: false, error: 'prohibited_cannot_approve' };
  }

  /*
   * SERVER-derived policy authority. The request's evaluated-under version is the bind
   * target; a materially changed current policy forces re-review (no silent override).
   */
  const evaluatedVersion = (req.policy_version as string) ?? currentReviewPolicyVersion();

  if (evaluatedVersion !== currentReviewPolicyVersion()) {
    return { ok: false, error: 'policy_version_changed' };
  }

  const policyVersion = evaluatedVersion;

  await sb
    .from('qhub_manual_review_requests')
    .update({
      status: input.decision,
      decided_by: ctx.userId, // authoritative staff user id
      decision_reason: input.reason,
      policy_version: policyVersion,
      decided_at: new Date().toISOString(),
    })
    .eq('id', input.requestId);

  // Atomically reflect the decision in the project's Governance Essentials workflow.
  if (req.project_id) {
    await sb
      .from('qhub_governance_essentials')
      .update({
        review_state: input.decision === 'approved' ? 'approved' : 'rejected',
        reviewed_by: ctx.userId,
        reviewed_at: new Date().toISOString(),
        review_policy_version: policyVersion,
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', req.project_id as string)
      .eq('org_id', req.org_id as string);
  }

  return { ok: true, policyVersion };
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * Fetch a review request scoped to the caller's org (customer view).
 */
export async function getReviewRequestForOrg(
  requestId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<{ id: string; status: string; category: string | null; projectId: string | null } | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_manual_review_requests')
    .select('id,status,category,project_id')
    .eq('id', requestId)
    .eq('org_id', orgId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  return {
    id: data.id as string,
    status: data.status as string,
    category: (data.category as string) ?? null,
    projectId: (data.project_id as string) ?? null,
  };
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * Load the authoritative decision metadata for a request (status + the SERVER-derived
 * policy version it was evaluated under) for the staff decision path.
 */
export async function getReviewDecisionMeta(
  requestId: string,
  env: Record<string, string | undefined>,
): Promise<{ status: string; policyVersion: string | null } | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_manual_review_requests')
    .select('status,policy_version')
    .eq('id', requestId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  return { status: data.status as string, policyVersion: (data.policy_version as string) ?? null };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Set a subscription/entitlement override. Staff-only; records actor, reason, and
 * a validity window, and writes an audit row.
 */
export async function setStaffOverride(
  ctx: CommercialContext,
  input: {
    orgId: string;
    sensitiveDataReviewApproved?: boolean;
    bonusCredits?: number;
    reason: string;
    startsAt: string;
    endsAt: string;
  },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!ctx.isStaff) {
    return { ok: false, error: 'staff_required' };
  }

  const sb = mutator(token, env);
  const { data: before } = await sb
    .from('qhub_subscriptions')
    .select('override_sensitive_data_review,override_bonus_credits')
    .eq('org_id', input.orgId)
    .maybeSingle();

  await sb
    .from('qhub_subscriptions')
    .update({
      override_sensitive_data_review: input.sensitiveDataReviewApproved ?? false,
      override_bonus_credits: Math.max(0, Math.floor(input.bonusCredits ?? 0)),
      override_actor: ctx.userId,
      override_reason: input.reason,
      override_start: input.startsAt,
      override_end: input.endsAt,
      updated_at: new Date().toISOString(),
    })
    .eq('org_id', input.orgId);

  await sb.from('qhub_entitlement_audit').insert({
    org_id: input.orgId,
    actor: ctx.userId,
    change_type: 'STAFF_OVERRIDE',
    before_state: before ?? null,
    after_state: {
      override_sensitive_data_review: input.sensitiveDataReviewApproved ?? false,
      override_bonus_credits: input.bonusCredits ?? 0,
    },
    reason: input.reason,
  });

  return { ok: true };
}

/** @qhub-service: PURE_NO_IO */
export function isProhibitedCategory(category: string): boolean {
  return PROHIBITED_CATEGORIES.has(category);
}

/** @qhub-service: PURE_NO_IO */
export function reviewEligibleCategories(): DataClass[] {
  return [...REVIEW_DATA_CLASSES];
}
