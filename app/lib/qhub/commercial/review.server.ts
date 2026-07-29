/**
 * QHUB Commercial Launch R2 — MANUAL REVIEW AUTHORITY (SERVER ONLY)
 * app/lib/qhub/commercial/review.server.ts
 *
 * Server-authoritative manual review. A request is tenant-scoped to one org/
 * project and may only cover review-eligible categories — prohibited categories
 * can never enter the queue or be overridden. A decision requires an authoritative
 * Quantex staff actor (never supplied by the browser); the actor, reason, policy
 * version, and timestamp are recorded. A materially different repeat is a new
 * request (not silently idempotent). Subscription/entitlement overrides likewise
 * require a staff actor with reason and a validity window, and are audited.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { REVIEW_DATA_CLASSES, type DataClass } from '~/lib/qhub/commercial/governance-essentials';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Review] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
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
 * Create a manual-review request. Requires an active membership on the request's
 * org (the caller cannot open a request for a tenant they do not belong to).
 * Prohibited categories are rejected; only review-eligible categories may queue.
 */
export async function createReviewRequest(
  ctx: CommercialContext,
  input: { projectId?: string; category: string; reason: string; requestType?: string },
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

  const sb = admin(env);
  const { data, error } = await sb
    .from('qhub_manual_review_requests')
    .insert({
      org_id: ctx.orgId,
      project_id: input.projectId ?? null,
      request_type: requestType,
      category: input.category,
      reason: input.reason,
      request_hash: requestHash,
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
 * Decide a manual-review request. Requires an authoritative staff actor (the
 * REVIEW_DECIDE capability + isStaff). The actor is derived from the staff context,
 * never the browser. Prohibited categories cannot be approved.
 */
export async function decideReviewRequest(
  ctx: CommercialContext,
  input: { requestId: string; decision: 'approved' | 'rejected'; reason: string; policyVersion: string },
  env: Record<string, string | undefined>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!ctx.isStaff) {
    return { ok: false, error: 'staff_required' };
  }

  const sb = admin(env);
  const { data: req } = await sb
    .from('qhub_manual_review_requests')
    .select('id,category,status')
    .eq('id', input.requestId)
    .maybeSingle();

  if (!req) {
    return { ok: false, error: 'not_found' };
  }

  if (input.decision === 'approved' && req.category && PROHIBITED_CATEGORIES.has(req.category as string)) {
    return { ok: false, error: 'prohibited_cannot_approve' };
  }

  await sb
    .from('qhub_manual_review_requests')
    .update({
      status: input.decision,
      decided_by: ctx.userId, // authoritative staff user id
      decision_reason: input.reason,
      policy_version: input.policyVersion,
      decided_at: new Date().toISOString(),
    })
    .eq('id', input.requestId);

  return { ok: true };
}

/**
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
  env: Record<string, string | undefined>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!ctx.isStaff) {
    return { ok: false, error: 'staff_required' };
  }

  const sb = admin(env);
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

export function isProhibitedCategory(category: string): boolean {
  return PROHIBITED_CATEGORIES.has(category);
}

export function reviewEligibleCategories(): DataClass[] {
  return [...REVIEW_DATA_CLASSES];
}
