/**
 * QHUB Commercial Launch — DURABLE COMMERCIAL STORE (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-store.server.ts
 *
 * Service-role-only access to the commercial tables (subscriptions, billing
 * customers, webhook events, usage credits/ledger, onboarding, acknowledgments,
 * manual review, entitlement audit). All billing writes go through here; the anon/
 * authenticated roles hold no grants (see the migration's RESTRICTIVE RLS).
 *
 * SECRETS: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY, read at call time, never
 * logged. Absent → throws (fail closed).
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { ManualOverrides, SubscriptionStatus } from '~/lib/qhub/commercial/entitlements.server';
import type { PlanId } from '~/lib/qhub/commercial/plans';
import { currentUsagePeriod, needsReset } from '~/lib/qhub/commercial/usage';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Commercial] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

// ─── Subscription snapshot ──────────────────────────────────────────────────────

export interface SubscriptionSnapshot {
  planId: PlanId;
  status: SubscriptionStatus;
  overrides?: ManualOverrides;
  providerCustomerId?: string;
  providerSubscriptionId?: string;
  currentPeriodEnd?: number;
}

/** The active/most-recent subscription for an org, or null when none. */
export async function getSubscriptionSnapshot(
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<SubscriptionSnapshot | null> {
  const sb = admin(env);
  const { data, error } = await sb
    .from('qhub_subscriptions')
    .select(
      'plan_id,status,override_sensitive_data_review,override_bonus_credits,provider_customer_id,provider_subscription_id,current_period_end',
    )
    .eq('org_id', orgId)
    .order('updated_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error || !data) {
    return null;
  }

  return {
    planId: (data.plan_id as PlanId) ?? 'none',
    status: (data.status as SubscriptionStatus) ?? 'none',
    overrides: {
      sensitiveDataReviewApproved: !!data.override_sensitive_data_review,
      bonusBuildCredits: (data.override_bonus_credits as number) ?? 0,
    },
    providerCustomerId: (data.provider_customer_id as string) ?? undefined,
    providerSubscriptionId: (data.provider_subscription_id as string) ?? undefined,
    currentPeriodEnd: (data.current_period_end as number) ?? undefined,
  };
}

export interface UpsertSubscriptionInput {
  orgId: string;
  planId: PlanId;
  status: SubscriptionStatus;
  provider: string;
  providerCustomerId?: string;
  providerSubscriptionId?: string;
  currentPeriodEnd?: number;
}

/** Upsert the subscription for an org (called from verified webhook processing). */
export async function upsertSubscription(
  input: UpsertSubscriptionInput,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_subscriptions').upsert(
    {
      org_id: input.orgId,
      plan_id: input.planId,
      status: input.status,
      provider: input.provider,
      provider_customer_id: input.providerCustomerId ?? null,
      provider_subscription_id: input.providerSubscriptionId ?? null,
      current_period_end: input.currentPeriodEnd ?? null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'org_id,provider' },
  );
}

export async function upsertBillingCustomer(
  input: { orgId: string; provider: string; providerCustomerId: string; email: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_billing_customers').upsert(
    {
      org_id: input.orgId,
      provider: input.provider,
      provider_customer_id: input.providerCustomerId,
      email: input.email,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'org_id,provider' },
  );
}

// ─── Webhook idempotency (replay protection) ────────────────────────────────────

/**
 * Record a webhook event id. Returns true if this id is NEW (first time seen), so
 * the caller processes it exactly once. A duplicate returns false → skip.
 */
export async function recordWebhookEventOnce(
  input: { provider: string; providerEventId: string; eventType: string },
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = admin(env);
  const { error } = await sb.from('qhub_billing_webhook_events').insert({
    provider: input.provider,
    provider_event_id: input.providerEventId,
    event_type: input.eventType,
    received_at: new Date().toISOString(),
  });

  if (error) {
    // Unique-violation → already seen → not new (idempotent skip).
    return false;
  }

  return true;
}

export async function markWebhookProcessed(
  input: { provider: string; providerEventId: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb
    .from('qhub_billing_webhook_events')
    .update({ processed_at: new Date().toISOString() })
    .eq('provider', input.provider)
    .eq('provider_event_id', input.providerEventId);
}

// ─── Counts (for seat/project limits) ────────────────────────────────────────────

export async function countProjects(orgId: string, env: Record<string, string | undefined>): Promise<number> {
  const sb = admin(env);
  const { count } = await sb
    .from('qhub_applications')
    .select('qhub_app_id', { count: 'exact', head: true })
    .eq('org_id', orgId);

  return count ?? 0;
}

// ─── Usage credits ──────────────────────────────────────────────────────────────

export interface UsageSnapshot {
  periodKey: string;
  allotted: number;
  used: number;
  remaining: number;
}

/**
 * Fetch (or lazily create/reset) the current-period credit row for an org, using
 * the provided monthly allotment. Resets when the stored period is stale.
 */
export async function getOrInitUsage(
  orgId: string,
  monthlyAllotment: number,
  env: Record<string, string | undefined>,
  now: Date = new Date(),
): Promise<UsageSnapshot> {
  const sb = admin(env);
  const period = currentUsagePeriod(now);

  const { data } = await sb
    .from('qhub_usage_credits')
    .select('period_key,allotted,used')
    .eq('org_id', orgId)
    .order('period_start', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!data || needsReset(data.period_key as string, now)) {
    await sb.from('qhub_usage_credits').upsert(
      {
        org_id: orgId,
        period_key: period.periodKey,
        period_start: period.periodStart,
        period_end: period.periodEnd,
        allotted: monthlyAllotment,
        used: 0,
        updated_at: now.toISOString(),
      },
      { onConflict: 'org_id,period_key' },
    );

    return { periodKey: period.periodKey, allotted: monthlyAllotment, used: 0, remaining: monthlyAllotment };
  }

  const allotted = (data.allotted as number) ?? 0;
  const used = (data.used as number) ?? 0;

  return { periodKey: data.period_key as string, allotted, used, remaining: Math.max(0, allotted - used) };
}

/**
 * Consume one build credit atomically via the guarded RPC. Returns the remaining
 * credits, or null when exhausted / not consumable.
 */
export async function consumeBuildCredit(
  orgId: string,
  monthlyAllotment: number,
  env: Record<string, string | undefined>,
  now: Date = new Date(),
): Promise<number | null> {
  await getOrInitUsage(orgId, monthlyAllotment, env, now);

  const sb = admin(env);
  const period = currentUsagePeriod(now);
  const { data, error } = await sb.rpc('qhub_consume_build_credit', {
    p_org_id: orgId,
    p_period_key: period.periodKey,
  });

  if (error || data === null || data === undefined) {
    return null;
  }

  await appendUsageLedger({ orgId, eventType: 'BUILD_CREDIT_CONSUMED', creditsDelta: -1 }, env);

  return data as number;
}

export async function appendUsageLedger(
  input: { orgId: string; eventType: string; creditsDelta: number; metadata?: Record<string, unknown> },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_usage_ledger').insert({
    org_id: input.orgId,
    event_type: input.eventType,
    credits_delta: input.creditsDelta,
    metadata: input.metadata ?? {},
    created_at: new Date().toISOString(),
  });
}

// ─── Onboarding + acknowledgments ────────────────────────────────────────────────

export interface OnboardingState {
  orgId: string;
  planSelected: PlanId;
  acknowledgedTerms: boolean;
  acknowledgedProhibitedData: boolean;
  firstProjectCreated: boolean;
  guidedCustomer: boolean;
  completed: boolean;
}

export async function getOnboardingState(
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<OnboardingState | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_onboarding_state')
    .select(
      'org_id,plan_selected,acknowledged_terms,acknowledged_prohibited_data,first_project_created,guided_customer,completed',
    )
    .eq('org_id', orgId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  return {
    orgId: data.org_id as string,
    planSelected: (data.plan_selected as PlanId) ?? 'none',
    acknowledgedTerms: !!data.acknowledged_terms,
    acknowledgedProhibitedData: !!data.acknowledged_prohibited_data,
    firstProjectCreated: !!data.first_project_created,
    guidedCustomer: !!data.guided_customer,
    completed: !!data.completed,
  };
}

export async function upsertOnboardingState(
  state: OnboardingState,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_onboarding_state').upsert(
    {
      org_id: state.orgId,
      plan_selected: state.planSelected,
      acknowledged_terms: state.acknowledgedTerms,
      acknowledged_prohibited_data: state.acknowledgedProhibitedData,
      first_project_created: state.firstProjectCreated,
      guided_customer: state.guidedCustomer,
      completed: state.completed,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'org_id' },
  );
}

export async function recordAcknowledgment(
  input: { orgId: string; userId: string; ackType: string; ackVersion: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_acknowledgments').insert({
    org_id: input.orgId,
    user_id: input.userId,
    ack_type: input.ackType,
    ack_version: input.ackVersion,
    acknowledged_at: new Date().toISOString(),
  });
}

// ─── Manual review queue ─────────────────────────────────────────────────────────

export interface ManualReviewRequest {
  orgId: string;
  projectId?: string;
  requestType: string;
  reason: string;
}

export async function createManualReviewRequest(
  input: ManualReviewRequest,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_manual_review_requests').insert({
    org_id: input.orgId,
    project_id: input.projectId ?? null,
    request_type: input.requestType,
    reason: input.reason,
    status: 'pending',
    created_at: new Date().toISOString(),
  });
}

export async function decideManualReview(
  input: { requestId: string; decision: 'approved' | 'rejected'; actor: string; reason: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb
    .from('qhub_manual_review_requests')
    .update({
      status: input.decision,
      decided_by: input.actor,
      decision_reason: input.reason,
      decided_at: new Date().toISOString(),
    })
    .eq('id', input.requestId);
}

// ─── Entitlement-change audit ────────────────────────────────────────────────────

export async function recordEntitlementChange(
  input: { orgId: string; actor: string; changeType: string; before: unknown; after: unknown; reason?: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = admin(env);
  await sb.from('qhub_entitlement_audit').insert({
    org_id: input.orgId,
    actor: input.actor,
    change_type: input.changeType,
    before_state: input.before ?? null,
    after_state: input.after ?? null,
    reason: input.reason ?? null,
    created_at: new Date().toISOString(),
  });
}
