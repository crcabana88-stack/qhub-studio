/**
 * QHUB Commercial Launch — DURABLE COMMERCIAL STORE (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-store.server.ts
 *
 * Service-role-only access to the commercial tables (subscriptions, billing
 * customers, webhook events, usage credits/ledger, onboarding, acknowledgments,
 * manual review, entitlement audit). All billing writes go through here; the anon/
 * authenticated roles hold no grants (see the migration's RESTRICTIVE RLS).
 *
 * NON-BYPASSABLE READINESS: every EXPORTED mutation requires a branded
 * CommercialReadyToken and obtains its privileged client ONLY through mutator(token,env),
 * which re-validates the token against the current target BEFORE any write. The token
 * can be produced only by the central readiness service after an exact READY result, so
 * no mutation can run against an unmigrated / wrong / stale target. Pure reads use
 * admin(env) directly and are classified INTERNAL_SERVER_ONLY.
 *
 * Each exported function is tagged `@qhub-service: <classification>` for the executable
 * architecture test (commercial-architecture.test.ts).
 *
 * SECRETS: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY, read at call time, never
 * logged. Absent → throws (fail closed).
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { assertReadyToken, type CommercialReadyToken } from '~/lib/qhub/commercial/commercial-schema-check.server';
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

/**
 * Privileged client for MUTATIONS ONLY. Re-validates the readiness token against the
 * current target (throws CommercialNotReadyError on any mismatch) BEFORE returning the
 * service-role client — the single runtime choke-point that makes readiness
 * non-bypassable at the store boundary.
 */
function mutator(token: CommercialReadyToken, env: Record<string, string | undefined>): SupabaseClient {
  assertReadyToken(token, env);

  return admin(env);
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

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * The active/most-recent subscription for an org, or null when none.
 */
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Upsert the subscription for an org (called from verified webhook processing).
 */
export async function upsertSubscription(
  token: CommercialReadyToken,
  input: UpsertSubscriptionInput,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function upsertBillingCustomer(
  token: CommercialReadyToken,
  input: {
    orgId: string;
    provider: string;
    providerCustomerId: string;
    email: string;
    livemode?: boolean;
    stripeAccount?: string;
  },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
  await sb.from('qhub_billing_customers').upsert(
    {
      org_id: input.orgId,
      provider: input.provider,
      provider_customer_id: input.providerCustomerId,
      email: input.email,
      livemode: input.livemode ?? false,
      stripe_account: input.stripeAccount ?? null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'org_id,provider' },
  );
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * The authoritative org mapped to a provider customer id, or null.
 */
export async function getOrgByCustomer(
  provider: string,
  providerCustomerId: string,
  env: Record<string, string | undefined>,
): Promise<string | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_billing_customers')
    .select('org_id')
    .eq('provider', provider)
    .eq('provider_customer_id', providerCustomerId)
    .maybeSingle();

  return (data?.org_id as string) ?? null;
}

// ─── Webhook inbox (recoverable state machine) ──────────────────────────────────

export type WebhookClaim = 'CLAIMED' | 'DUPLICATE' | 'IN_PROGRESS';

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Atomically claim a webhook event for processing via the guarded RPC. A NEW event
 * (or a retryable one) transitions to PROCESSING and returns CLAIMED; an already-
 * processed/permanently-failed event returns DUPLICATE; an in-flight one returns
 * IN_PROGRESS. Only a unique-violation on the event id is treated as a duplicate —
 * transient failures throw and stay retryable.
 */
export async function claimWebhookEvent(
  token: CommercialReadyToken,
  input: {
    provider: string;
    providerEventId: string;
    eventType: string;
    livemode: boolean;
    account: string | null;
    eventCreated: number;
    payloadHash: string;
    owner: string;
    leaseSeconds?: number;
  },
  env: Record<string, string | undefined>,
): Promise<WebhookClaim> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_claim_webhook_event', {
    p_provider: input.provider,
    p_event_id: input.providerEventId,
    p_event_type: input.eventType,
    p_livemode: input.livemode,
    p_account: input.account,
    p_event_created: input.eventCreated,
    p_payload_hash: input.payloadHash,
    p_owner: input.owner,
    p_lease_seconds: input.leaseSeconds ?? 120,
  });

  if (error) {
    // DB errors are never silently ignored — surface for a retry.
    throw new Error(`[Webhook] claim failed: ${error.message}`);
  }

  return (data as WebhookClaim) ?? 'IN_PROGRESS';
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Lease-bound webhook state transition: only the current processing_owner (with a
 * non-expired lease) may mutate the event. Returns 'OK' | 'LEASE_LOST'.
 */
export async function setWebhookState(
  token: CommercialReadyToken,
  input: { provider: string; providerEventId: string; owner: string; state: string; errorCode?: string },
  env: Record<string, string | undefined>,
): Promise<'OK' | 'LEASE_LOST'> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_mark_webhook_state', {
    p_provider: input.provider,
    p_event_id: input.providerEventId,
    p_owner: input.owner,
    p_state: input.state,
    p_error_code: input.errorCode ?? null,
  });

  if (error) {
    throw new Error(`[Webhook] mark state failed: ${error.message}`);
  }

  return (data as 'OK' | 'LEASE_LOST') ?? 'LEASE_LOST';
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Apply a reconciled subscription mutation with an out-of-order guard: an event
 * whose created time is not newer than the last applied one is ignored ('stale'),
 * so a delayed 'active' event can never resurrect a later 'canceled' state.
 */
export async function applySubscriptionEvent(
  token: CommercialReadyToken,
  input: UpsertSubscriptionInput & {
    eventCreated: number;
    providerPriceId?: string;
    livemode?: boolean;
    stripeAccount?: string;
  },
  env: Record<string, string | undefined>,
): Promise<'applied' | 'stale'> {
  const sb = mutator(token, env);
  const { data: existing } = await sb
    .from('qhub_subscriptions')
    .select('last_event_created')
    .eq('org_id', input.orgId)
    .eq('provider', input.provider)
    .maybeSingle();

  if (
    existing &&
    typeof existing.last_event_created === 'number' &&
    input.eventCreated <= existing.last_event_created
  ) {
    return 'stale';
  }

  await sb.from('qhub_subscriptions').upsert(
    {
      org_id: input.orgId,
      plan_id: input.planId,
      status: input.status,
      provider: input.provider,
      provider_customer_id: input.providerCustomerId ?? null,
      provider_subscription_id: input.providerSubscriptionId ?? null,
      provider_price_id: input.providerPriceId ?? null,
      livemode: input.livemode ?? false,
      stripe_account: input.stripeAccount ?? null,
      current_period_end: input.currentPeriodEnd ?? null,
      last_event_created: input.eventCreated,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'org_id,provider' },
  );

  return 'applied';
}

// ─── Counts (for seat/project limits) ────────────────────────────────────────────

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 */
export async function countProjects(orgId: string, env: Record<string, string | undefined>): Promise<number> {
  const sb = admin(env);
  const { count } = await sb
    .from('qhub_project_entitlements')
    .select('project_id', { count: 'exact', head: true })
    .eq('org_id', orgId)
    .eq('active', true);

  return count ?? 0;
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * The authoritative owning org of a project, or null when the project is unknown.
 */
export async function getProjectOwnership(
  projectId: string,
  env: Record<string, string | undefined>,
): Promise<string | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_project_entitlements')
    .select('org_id')
    .eq('project_id', projectId)
    .maybeSingle();

  return (data?.org_id as string) ?? null;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Create a project transactionally under the plan's project cap (enforced by the
 * one-active-guided partial-unique index + an app-level active-count check for
 * Builder Beta). Returns the new project id or a reason.
 */
export async function createProjectEntitlement(
  token: CommercialReadyToken,
  input: { orgId: string; createdBy: string; planId: string; maxProjects: number },
  env: Record<string, string | undefined>,
): Promise<{ ok: true; projectId: string } | { ok: false; reason: string }> {
  const sb = mutator(token, env);
  const active = await countProjects(input.orgId, env);

  if (active >= input.maxProjects) {
    return { ok: false, reason: 'project_limit_reached' };
  }

  const { data, error } = await sb
    .from('qhub_project_entitlements')
    .insert({
      project_id: crypto.randomUUID(),
      org_id: input.orgId,
      created_by: input.createdBy,
      plan_id: input.planId,
      active: true,
    })
    .select('project_id')
    .maybeSingle();

  if (error) {
    // Unique-violation (e.g. the one-active-guided index) → limit reached.
    return { ok: false, reason: 'project_limit_reached' };
  }

  return { ok: true, projectId: data?.project_id as string };
}

// ─── Usage credits ──────────────────────────────────────────────────────────────

export interface UsageSnapshot {
  periodKey: string;
  allotted: number;
  used: number;
  remaining: number;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Fetch (or lazily create/reset) the current-period credit row for an org, using the
 * provided monthly allotment. Resets when the stored period is stale (a write), so it
 * requires the readiness token.
 */
export async function getOrInitUsage(
  token: CommercialReadyToken,
  orgId: string,
  monthlyAllotment: number,
  env: Record<string, string | undefined>,
  now: Date = new Date(),
): Promise<UsageSnapshot> {
  const sb = mutator(token, env);
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

export interface CreditResult {
  ok: boolean;
  idempotent?: boolean;
  remaining?: number;
  ledger_id?: string;
  reason?: string;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Consume build credits atomically via the project-derived R3 RPC (single
 * transaction: derive org/ownership/eligibility → lock period → validate → idempotency
 * → decrement → append immutable ledger row). The RPC returns a structured result;
 * an exact retry (same key + canonical hash + units) returns the prior balance, a
 * changed request under the same key is rejected, and overdraw is impossible.
 */
export async function consumeBuildCredit(
  token: CommercialReadyToken,
  input: { projectId: string; idempotencyKey: string; canonicalHash: string; units: number },
  env: Record<string, string | undefined>,
): Promise<CreditResult> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_consume_build_credit', {
    p_project_id: input.projectId,
    p_idempotency_key: input.idempotencyKey,
    p_canonical_hash: input.canonicalHash,
    p_units: input.units,
  });

  if (error || data === null || data === undefined) {
    return { ok: false, reason: error?.message ?? 'rpc_error' };
  }

  return data as CreditResult;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function appendUsageLedger(
  token: CommercialReadyToken,
  input: { orgId: string; eventType: string; creditsDelta: number; metadata?: Record<string, unknown> },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 */
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function upsertOnboardingState(
  token: CommercialReadyToken,
  state: OnboardingState,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function recordAcknowledgment(
  token: CommercialReadyToken,
  input: { orgId: string; userId: string; ackType: string; ackVersion: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function createManualReviewRequest(
  token: CommercialReadyToken,
  input: ManualReviewRequest,
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
  await sb.from('qhub_manual_review_requests').insert({
    org_id: input.orgId,
    project_id: input.projectId ?? null,
    request_type: input.requestType,
    reason: input.reason,
    status: 'pending',
    created_at: new Date().toISOString(),
  });
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function decideManualReview(
  token: CommercialReadyToken,
  input: { requestId: string; decision: 'approved' | 'rejected'; actor: string; reason: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function recordEntitlementChange(
  token: CommercialReadyToken,
  input: { orgId: string; actor: string; changeType: string; before: unknown; after: unknown; reason?: string },
  env: Record<string, string | undefined>,
): Promise<void> {
  const sb = mutator(token, env);
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

// ─── Checkout intents (opaque tenant binding) ───────────────────────────────────

export interface CheckoutIntentInput {
  orgId: string;
  requestedBy: string;
  membershipId: string | null;
  planId: string;
  expectedRecurringPriceId: string;
  expectedSetupPriceId: string | null;
  expectedMode: 'test' | 'live';
  expectedAccount: string | null;
  expectedAppOrigin: string;
  idempotencyKey: string;
  expiresAt: string;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Create (or idempotently return) a checkout intent. An exact retry with the same
 * (org, idempotency_key) returns the existing intent; a materially different request
 * under the same key is rejected.
 */
export async function createCheckoutIntent(
  token: CommercialReadyToken,
  input: CheckoutIntentInput,
  env: Record<string, string | undefined>,
): Promise<{ ok: true; intentId: string; nonce: string; idempotent: boolean } | { ok: false; reason: string }> {
  const sb = mutator(token, env);
  const nonce = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const row = {
    org_id: input.orgId,
    requested_by: input.requestedBy,
    membership_id: input.membershipId,
    plan_id: input.planId,
    expected_recurring_price_id: input.expectedRecurringPriceId,
    expected_setup_price_id: input.expectedSetupPriceId,
    expected_mode: input.expectedMode,
    expected_account: input.expectedAccount,
    expected_app_origin: input.expectedAppOrigin,
    idempotency_key: input.idempotencyKey,
    nonce,
    expires_at: input.expiresAt,
  };

  const { data, error } = await sb.from('qhub_checkout_intents').insert(row).select('id,nonce').maybeSingle();

  if (!error && data) {
    return { ok: true, intentId: data.id as string, nonce: data.nonce as string, idempotent: false };
  }

  // Unique(org, idempotency_key) → an intent already exists for this key.
  const { data: existing } = await sb
    .from('qhub_checkout_intents')
    .select('id,nonce,plan_id,expected_recurring_price_id,expected_setup_price_id')
    .eq('org_id', input.orgId)
    .eq('idempotency_key', input.idempotencyKey)
    .maybeSingle();

  if (!existing) {
    return { ok: false, reason: 'intent_create_failed' };
  }

  const same =
    existing.plan_id === input.planId &&
    existing.expected_recurring_price_id === input.expectedRecurringPriceId &&
    (existing.expected_setup_price_id ?? null) === input.expectedSetupPriceId;

  if (!same) {
    return { ok: false, reason: 'idempotency_conflict' };
  }

  return { ok: true, intentId: existing.id as string, nonce: existing.nonce as string, idempotent: true };
}

export type IntentConsume = 'CONSUMED' | 'EXPIRED' | 'ALREADY' | 'MISMATCH' | 'NOT_FOUND';

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Atomically consume a checkout intent via the guarded RPC.
 */
export async function consumeCheckoutIntent(
  token: CommercialReadyToken,
  input: {
    intentId: string;
    orgId: string;
    recurringPriceId: string;
    mode: string;
    account: string | null;
    sessionId: string;
    customerId: string;
    subscriptionId: string;
  },
  env: Record<string, string | undefined>,
): Promise<IntentConsume> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_consume_checkout_intent', {
    p_intent_id: input.intentId,
    p_org_id: input.orgId,
    p_recurring_price: input.recurringPriceId,
    p_mode: input.mode,
    p_account: input.account,
    p_session_id: input.sessionId,
    p_customer_id: input.customerId,
    p_subscription_id: input.subscriptionId,
  });

  if (error) {
    throw new Error(`[Checkout] intent consume failed: ${error.message}`);
  }

  return (data as IntentConsume) ?? 'NOT_FOUND';
}

// ─── Invitations + transactional seat acceptance ────────────────────────────────

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function createInvitation(
  token: CommercialReadyToken,
  input: { orgId: string; email: string; role: string; tokenHash: string; invitedBy: string; expiresAt: string },
  env: Record<string, string | undefined>,
): Promise<{ ok: true; invitationId: string } | { ok: false; reason: string }> {
  const sb = mutator(token, env);
  const { data, error } = await sb
    .from('qhub_org_invitations')
    .insert({
      org_id: input.orgId,
      email: input.email.toLowerCase(),
      role: input.role,
      token_hash: input.tokenHash,
      invited_by: input.invitedBy,
      expires_at: input.expiresAt,
    })
    .select('id')
    .maybeSingle();

  if (error || !data) {
    // Active-invitation uniqueness (org, lower(email)) → already invited.
    return { ok: false, reason: 'already_invited_or_failed' };
  }

  return { ok: true, invitationId: data.id as string };
}

export type AcceptResult =
  | 'ACCEPTED'
  | 'SEAT_LIMIT'
  | 'INVALID'
  | 'EMAIL_MISMATCH'
  | 'TOKEN_MISMATCH'
  | 'INELIGIBLE'
  | 'ALREADY';

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Transactionally accept an invitation via the guarded RPC. The caller supplies NO
 * seat cap — the RPC verifies the recipient email + token and derives the plan +
 * seat cap from the org's authoritative active subscription under a lock.
 */
export async function acceptInvitation(
  token: CommercialReadyToken,
  input: { invitationId: string; userId: string; userEmail: string; tokenHash: string },
  env: Record<string, string | undefined>,
): Promise<AcceptResult> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_accept_invitation', {
    p_invitation_id: input.invitationId,
    p_user_id: input.userId,
    p_user_email: input.userEmail,
    p_token_hash: input.tokenHash,
  });

  if (error) {
    throw new Error(`[Seat] accept failed: ${error.message}`);
  }

  return (data as AcceptResult) ?? 'INVALID';
}

export interface RpcResult {
  ok: boolean;
  reason?: string;
  idempotent?: boolean;
  org?: string;
  project_id?: string;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * ONE atomic checkout reconciliation (lease-bound; binds+consumes+PROCESSED together).
 */
export async function reconcileCheckout(
  token: CommercialReadyToken,
  input: {
    provider: string;
    eventId: string;
    owner: string;
    intentId: string;
    sessionId: string;
    customerId: string;
    subscriptionId: string;
    recurringPrice: string;
    setupPresent: boolean;
    mode: string;
    account: string | null;
    status: string;
    currentPeriodEnd: number | null;
    eventCreated: number;
  },
  env: Record<string, string | undefined>,
): Promise<RpcResult> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_reconcile_checkout', {
    p_provider: input.provider,
    p_event_id: input.eventId,
    p_owner: input.owner,
    p_intent_id: input.intentId,
    p_session_id: input.sessionId,
    p_customer_id: input.customerId,
    p_subscription_id: input.subscriptionId,
    p_recurring_price: input.recurringPrice,
    p_setup_present: input.setupPresent,
    p_mode: input.mode,
    p_account: input.account,
    p_status: input.status,
    p_current_period_end: input.currentPeriodEnd,
    p_event_created: input.eventCreated,
  });

  if (error) {
    throw new Error(`[Checkout] reconcile failed: ${error.message}`);
  }

  return (data as RpcResult) ?? { ok: false, reason: 'rpc_error' };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * ONE atomic review decision (request + governance + immutable audit).
 */
export async function decideReviewAtomic(
  token: CommercialReadyToken,
  input: {
    requestId: string;
    actor: string;
    isStaff: boolean;
    decision: string;
    reason: string;
    policyVersion: string;
  },
  env: Record<string, string | undefined>,
): Promise<RpcResult> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_decide_review', {
    p_request_id: input.requestId,
    p_actor: input.actor,
    p_is_staff: input.isStaff,
    p_decision: input.decision,
    p_reason: input.reason,
    p_policy_version: input.policyVersion,
  });

  if (error) {
    throw new Error(`[Review] decide failed: ${error.message}`);
  }

  return (data as RpcResult) ?? { ok: false, reason: 'rpc_error' };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * ONE atomic project creation with transactional cap + idempotency.
 */
export async function createProjectAtomic(
  token: CommercialReadyToken,
  input: { orgId: string; createdBy: string; idempotencyKey: string; requestHash: string },
  env: Record<string, string | undefined>,
): Promise<RpcResult> {
  const sb = mutator(token, env);
  const { data, error } = await sb.rpc('qhub_create_project', {
    p_org_id: input.orgId,
    p_created_by: input.createdBy,
    p_idempotency_key: input.idempotencyKey,
    p_request_hash: input.requestHash,
  });

  if (error) {
    throw new Error(`[Project] create failed: ${error.message}`);
  }

  return (data as RpcResult) ?? { ok: false, reason: 'rpc_error' };
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * Load a checkout intent's authoritative org + bound expectations (or null).
 */
export async function getCheckoutIntent(
  intentId: string,
  env: Record<string, string | undefined>,
): Promise<{ orgId: string; planId: string; recurringPriceId: string; mode: string; account: string | null } | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_checkout_intents')
    .select('org_id,plan_id,expected_recurring_price_id,expected_mode,expected_account')
    .eq('id', intentId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  return {
    orgId: data.org_id as string,
    planId: data.plan_id as string,
    recurringPriceId: data.expected_recurring_price_id as string,
    mode: data.expected_mode as string,
    account: (data.expected_account as string) ?? null,
  };
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * The owning org of an invitation (for seat-cap resolution on acceptance).
 */
export async function getInvitationOrg(
  invitationId: string,
  env: Record<string, string | undefined>,
): Promise<string | null> {
  const sb = admin(env);
  const { data } = await sb.from('qhub_org_invitations').select('org_id').eq('id', invitationId).maybeSingle();

  return (data?.org_id as string) ?? null;
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' as const;
