/**
 * QHUB Commercial Launch — ENTITLEMENTS (SERVER-AUTHORITATIVE)
 * app/lib/qhub/commercial/entitlements.server.ts
 *
 * The ONE place access is decided for the commercial tier. Resolves an effective
 * Entitlements object from (plan defaults + subscription status + server-set manual
 * overrides) and exposes fail-closed decision functions. The browser UI may hide or
 * disable controls for UX, but this module — not the UI — is the security boundary.
 *
 * The resolution and decision functions are PURE (no I/O) so they are exhaustively
 * unit-testable. loadOrgEntitlements() is the thin async adapter that reads the
 * durable subscription/override snapshot from the commercial store.
 *
 * Launch invariants enforced here regardless of stored config:
 *   - agent building is never allowed
 *   - consequential external actions are never allowed
 *   - risk tier never exceeds LAUNCH_MAX_RISK_TIER (T1)
 */

import type { RiskTier } from '~/lib/qhub/classification';
import { tierRank } from '~/lib/qhub/classification';
import {
  type Entitlements,
  type PlanId,
  basePlanEntitlements,
  isPaidPlan,
  LAUNCH_MAX_RISK_TIER,
  NO_PLAN_ENTITLEMENTS,
} from '~/lib/qhub/commercial/plans';

// ─── Subscription status ────────────────────────────────────────────────────────

/** Normalized subscription status (provider-neutral; mapped from Stripe). */
export type SubscriptionStatus = 'active' | 'trialing' | 'past_due' | 'canceled' | 'incomplete' | 'none';

/** Whether the subscription grants full service. */
export function isServiceableStatus(s: SubscriptionStatus): boolean {
  return s === 'active' || s === 'trialing';
}

/** past_due keeps read/export but blocks new consumption; others below cut fully. */
export function isRestrictedStatus(s: SubscriptionStatus): boolean {
  return s === 'past_due';
}

export type ServiceState = 'active' | 'restricted' | 'inactive';

export function serviceStateOf(planId: PlanId, status: SubscriptionStatus): ServiceState {
  if (!isPaidPlan(planId)) {
    return 'inactive';
  }

  if (isServiceableStatus(status)) {
    return 'active';
  }

  if (isRestrictedStatus(status)) {
    return 'restricted';
  }

  return 'inactive';
}

// ─── Server-set manual overrides (Guided Builder only) ──────────────────────────

/**
 * Overrides that Quantex staff may set server-side (never the browser) to unlock a
 * supervised exception. Only honored when the plan allows manual-review exceptions.
 */
export interface ManualOverrides {
  /** Allow personal/financial data handling after manual review. */
  sensitiveDataReviewApproved?: boolean;

  /** Extra one-off build credits granted this period. */
  bonusBuildCredits?: number;
}

export interface EntitlementContext {
  planId: PlanId;
  status: SubscriptionStatus;
  overrides?: ManualOverrides;
}

// ─── Resolution ─────────────────────────────────────────────────────────────────

export interface ResolvedEntitlements {
  entitlements: Entitlements;
  serviceState: ServiceState;
  planId: PlanId;
  status: SubscriptionStatus;
}

/**
 * Resolve the effective, enforceable entitlements. Pure — no I/O.
 *
 * - inactive service → NO_PLAN (fully fail-closed)
 * - restricted (past_due) → base capabilities kept for read/export, but no new
 *   builds (credits→0), no new projects, no publishing
 * - active → base plan entitlements, plus honored manual overrides
 * - launch invariants clamped last
 */
export function resolveEntitlements(ctx: EntitlementContext): ResolvedEntitlements {
  const serviceState = serviceStateOf(ctx.planId, ctx.status);

  if (serviceState === 'inactive') {
    return { entitlements: { ...NO_PLAN_ENTITLEMENTS }, serviceState, planId: ctx.planId, status: ctx.status };
  }

  const ent: Entitlements = basePlanEntitlements(ctx.planId);

  // Honored manual overrides (only when the plan permits them).
  if (ent.manualReviewExceptionsAllowed && ctx.overrides) {
    if (ctx.overrides.sensitiveDataReviewApproved) {
      ent.sensitiveDataReviewAllowed = true;
    }

    if (typeof ctx.overrides.bonusBuildCredits === 'number' && ctx.overrides.bonusBuildCredits > 0) {
      ent.buildCreditsPerMonth += Math.floor(ctx.overrides.bonusBuildCredits);
    }
  }

  // Restricted (past_due): keep read/export, cut new consumption.
  if (serviceState === 'restricted') {
    ent.buildCreditsPerMonth = 0;
    ent.publishMode = 'export_only';
  }

  clampLaunchInvariants(ent);

  return { entitlements: ent, serviceState, planId: ctx.planId, status: ctx.status };
}

/** Defense-in-depth: no stored config can breach the launch boundary. */
function clampLaunchInvariants(ent: Entitlements): void {
  ent.agentBuilding = false;
  ent.consequentialActions = false;
  ent.externalWriteConnectors = false;

  if (tierRank(ent.maxRiskTier) > tierRank(LAUNCH_MAX_RISK_TIER)) {
    ent.maxRiskTier = LAUNCH_MAX_RISK_TIER;
  }
}

// ─── Decisions ──────────────────────────────────────────────────────────────────

export interface EntitlementDecision {
  allowed: boolean;
  reasonCode: string;
  message: string;
}

const ALLOW: EntitlementDecision = { allowed: true, reasonCode: 'ALLOWED', message: 'Allowed.' };

function deny(reasonCode: string, message: string): EntitlementDecision {
  return { allowed: false, reasonCode, message };
}

export function decideProjectCreation(ent: Entitlements, currentProjectCount: number): EntitlementDecision {
  if (!ent.appBuilding) {
    return deny('APP_BUILDING_DISABLED', 'App building is not available on your current plan.');
  }

  if (currentProjectCount >= ent.maxProjects) {
    return deny('PROJECT_LIMIT_REACHED', `Your plan allows up to ${ent.maxProjects} projects.`);
  }

  return ALLOW;
}

export function decideSeatAddition(ent: Entitlements, currentSeatCount: number): EntitlementDecision {
  if (currentSeatCount >= ent.seats) {
    return deny('SEAT_LIMIT_REACHED', `Your plan allows up to ${ent.seats} user(s).`);
  }

  return ALLOW;
}

export function decideRiskTier(ent: Entitlements, tier: RiskTier): EntitlementDecision {
  if (tierRank(tier) > tierRank(ent.maxRiskTier)) {
    return deny('RISK_TIER_NOT_ALLOWED', `This tier (${tier}) exceeds your plan limit (${ent.maxRiskTier}).`);
  }

  return ALLOW;
}

export function decideAppBuild(ent: Entitlements): EntitlementDecision {
  if (!ent.appBuilding) {
    return deny('APP_BUILDING_DISABLED', 'App building is not available on your current plan.');
  }

  return ALLOW;
}

/** Agent building is never available at launch — always denied. */
export function decideAgentBuild(_ent: Entitlements): EntitlementDecision {
  return deny(
    'AGENT_BUILDING_INSTITUTIONAL',
    'Agent building is part of the institutional offering, not the launch tier.',
  );
}

export function decideExternalWrite(ent: Entitlements): EntitlementDecision {
  if (!ent.externalWriteConnectors) {
    return deny('EXTERNAL_WRITE_DISABLED', 'External write connectors are not available in the launch tier.');
  }

  return ALLOW;
}

/** Consequential external actions are prohibited at launch — always denied. */
export function decideConsequentialAction(_ent: Entitlements): EntitlementDecision {
  return deny(
    'CONSEQUENTIAL_ACTION_PROHIBITED',
    'Consequential external actions are not available in the launch tier.',
  );
}

export function decideCodeExport(ent: Entitlements): EntitlementDecision {
  if (!ent.codeExport) {
    return deny('CODE_EXPORT_DISABLED', 'Source export is not available on your current plan.');
  }

  return ALLOW;
}

export function decideEvidenceExport(ent: Entitlements): EntitlementDecision {
  if (!ent.evidenceExport) {
    return deny('EVIDENCE_EXPORT_DISABLED', 'Evidence export is not available on your current plan.');
  }

  return ALLOW;
}

/**
 * Publishing always requires the controlled path. When the plan uses manual_review,
 * a server-recorded review approval is required — a caller-supplied boolean here is
 * only honored as the review outcome (still resolved server-side by the caller).
 */
export function decidePublish(ent: Entitlements, reviewApproved: boolean): EntitlementDecision {
  if (ent.publishMode === 'export_only') {
    return deny('PUBLISH_EXPORT_ONLY', 'Your current plan supports controlled export only, not hosted publishing.');
  }

  if (!reviewApproved) {
    return deny('PUBLISH_REVIEW_REQUIRED', 'Publication requires a completed manual review.');
  }

  return ALLOW;
}

export function decideSensitiveData(ent: Entitlements): EntitlementDecision {
  if (!ent.sensitiveDataReviewAllowed) {
    return deny(
      'SENSITIVE_DATA_NOT_ALLOWED',
      'Personal, financial, or restricted data is not permitted on your current plan.',
    );
  }

  return ALLOW;
}

export function decideBuildCredit(remainingCredits: number): EntitlementDecision {
  if (remainingCredits <= 0) {
    return deny('BUILD_CREDITS_EXHAUSTED', 'You have used all build credits for this period.');
  }

  return ALLOW;
}

// ─── Async adapter (durable snapshot → resolution) ──────────────────────────────

/**
 * Load and resolve an org's effective entitlements from the durable commercial
 * store. Fails closed to NO_PLAN when nothing is on file or the store is unavailable.
 */
export async function loadOrgEntitlements(
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<ResolvedEntitlements> {
  // Imported lazily to keep the pure logic above import-light and testable.
  const { getSubscriptionSnapshot } = await import('~/lib/qhub/commercial/commercial-store.server');
  const snap = await getSubscriptionSnapshot(orgId, env);

  if (!snap) {
    return resolveEntitlements({ planId: 'none', status: 'none' });
  }

  return resolveEntitlements({ planId: snap.planId, status: snap.status, overrides: snap.overrides });
}
