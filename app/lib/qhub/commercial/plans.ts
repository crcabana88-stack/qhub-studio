/**
 * QHUB Commercial Launch — PLAN CATALOG (BROWSER-SAFE)
 * app/lib/qhub/commercial/plans.ts
 *
 * Single source of truth for the initial commercial product boundary:
 *   - QHub Builder Beta
 *   - QHub Guided Builder
 *
 * Prices and entitlements are CONFIGURATION here, never scattered hard-coded UI
 * logic. Reference prices are display values only; the real Stripe price IDs are
 * supplied later via environment variables at the human checkpoint and resolved
 * server-side (see billing/stripe-provider.server.ts). Nothing in this file
 * activates a real charge.
 *
 * This module contains NO secrets and NO server-only APIs; safe to import from
 * the browser (pricing page, plan cards, entitlement gates in the UI). The UI is
 * NEVER the security boundary — see entitlements.server.ts for enforcement.
 *
 * COMMERCIAL PRODUCT BOUNDARY (low-risk T0/T1 only):
 *   The launch tier intentionally does NOT support autonomous agents,
 *   consequential external actions, payments/money movement, external writes to
 *   customer systems, regulated/sensitive data, MNPI, credentials in prompts,
 *   real-time execution adapters, or any institutional-assurance claim.
 */

import type { RiskTier } from '~/lib/qhub/classification';

// ─── Identity ─────────────────────────────────────────────────────────────────

/** Commercial plans available at launch. `none` = unpaid / no active subscription. */
export type PlanId = 'none' | 'builder_beta' | 'guided_builder';

export type BillingInterval = 'month' | 'year';

/** Support tiers (display + routing). */
export type SupportLevel = 'community' | 'standard' | 'priority';

/** How a built application may be published to the outside world. */
export type PublishMode =
  | 'export_only' // customer exports source; no QHub-hosted publish
  | 'manual_review'; // publication requires a QHub/Quantex manual review gate

// ─── Product-state labels (honest capability status) ────────────────────────────

/** Used across the website + builder entry to label what is real today. */
export type ProductState = 'available' | 'private_beta' | 'preview' | 'planned';

export const PRODUCT_STATE_LABEL: Record<ProductState, string> = {
  available: 'Available',
  private_beta: 'Private Beta',
  preview: 'Preview',
  planned: 'Planned',
};

// ─── Entitlements (the enforceable capability set) ──────────────────────────────

/**
 * The server-authoritative capability set for a plan. entitlements.server.ts
 * resolves an effective Entitlements object (plan defaults + subscription status
 * + manual-review overrides) and is the ONLY place access is decided.
 */
export interface Entitlements {
  /** Max users (seats) that may belong to the org under this plan. */
  seats: number;

  /** Max private projects. */
  maxProjects: number;

  /** Monthly build-credit allowance (refills each billing period). */
  buildCreditsPerMonth: number;

  /** Highest risk tier the customer may operate at. Launch tier caps at T1. */
  maxRiskTier: RiskTier;

  /** Prompt-to-app building. */
  appBuilding: boolean;

  /**
   * Autonomous agent building. DISABLED for the entire launch tier — this is the
   * institutional offering, not the commercial product. Never true at launch.
   */
  agentBuilding: boolean;

  /** Controlled source-code export. */
  codeExport: boolean;

  /** Basic evidence / governance-record export. */
  evidenceExport: boolean;

  /** How the customer may publish. */
  publishMode: PublishMode;

  /**
   * External write connectors (writes to customer systems). DISABLED at launch —
   * only read/non-consequential connectors are permitted.
   */
  externalWriteConnectors: boolean;

  /**
   * Consequential external actions (money movement, order routing, production
   * writes). PROHIBITED at launch. Never true.
   */
  consequentialActions: boolean;

  /** Whether personal/financial/restricted data may be requested for review. */
  sensitiveDataReviewAllowed: boolean;

  /** Support routing. */
  support: SupportLevel;

  /**
   * When true, a server-side manual-review flag (set only by Quantex staff) can
   * unlock supervised exceptions. Guided Builder only. The exception itself is
   * still resolved server-side, never by the browser.
   */
  manualReviewExceptionsAllowed: boolean;
}

// ─── Pricing (reference/display config only) ────────────────────────────────────

export interface PriceRef {
  /** Amount in the smallest currency unit (USD cents). Display/reference only. */
  amountCents: number;
  currency: 'usd';
  interval: BillingInterval | 'one_time';

  /**
   * The environment-variable NAME that will hold the real Stripe price/product id
   * (supplied at the human checkpoint). Resolved server-side; never a literal id
   * here. Absence fails the checkout closed.
   */
  stripePriceEnv: string;
}

export interface PlanConfig {
  id: PlanId;
  name: string;

  /** Short marketing line. */
  tagline: string;

  /** Honest availability state for the website + entry. */
  state: ProductState;

  /** Recurring + one-time reference prices, keyed by role. */
  prices: {
    monthly?: PriceRef;
    annual?: PriceRef;
    setupFee?: PriceRef;
  };
  entitlements: Entitlements;

  /** Human-readable capability bullets for plan cards (derived, honest). */
  highlights: string[];
}

// ─── Launch caps (defense-in-depth constants) ───────────────────────────────────

/** The commercial launch NEVER exceeds this tier, regardless of plan config. */
export const LAUNCH_MAX_RISK_TIER: RiskTier = 'T1';

// ─── Plan catalog ───────────────────────────────────────────────────────────────

export const PLAN_CATALOG: Record<Exclude<PlanId, 'none'>, PlanConfig> = {
  builder_beta: {
    id: 'builder_beta',
    name: 'QHub Builder Beta',
    tagline: 'Prompt-to-app building with Governance Essentials for low-risk work.',
    state: 'private_beta',
    prices: {
      monthly: {
        amountCents: 7900,
        currency: 'usd',
        interval: 'month',
        stripePriceEnv: 'STRIPE_PRICE_BUILDER_BETA_MONTHLY',
      },
      annual: {
        amountCents: 79000,
        currency: 'usd',
        interval: 'year',
        stripePriceEnv: 'STRIPE_PRICE_BUILDER_BETA_ANNUAL',
      },
    },
    entitlements: {
      seats: 1,
      maxProjects: 5,
      buildCreditsPerMonth: 200,
      maxRiskTier: 'T1',
      appBuilding: true,
      agentBuilding: false,
      codeExport: true,
      evidenceExport: true,
      publishMode: 'manual_review',
      externalWriteConnectors: false,
      consequentialActions: false,
      sensitiveDataReviewAllowed: false,
      support: 'standard',
      manualReviewExceptionsAllowed: false,
    },
    highlights: [
      '1 user, up to 5 private projects',
      'App building only — T0 / T1',
      'Governance Essentials included',
      'Monthly build-credit allowance',
      'Controlled source export',
      'Manual / controlled publishing',
      'Standard support',
    ],
  },

  guided_builder: {
    id: 'guided_builder',
    name: 'QHub Guided Builder',
    tagline: 'Quantex-supported design, build, and controlled launch of one governed application.',
    state: 'private_beta',
    prices: {
      monthly: {
        amountCents: 49900,
        currency: 'usd',
        interval: 'month',
        stripePriceEnv: 'STRIPE_PRICE_GUIDED_BUILDER_MONTHLY',
      },
      setupFee: {
        amountCents: 150000,
        currency: 'usd',
        interval: 'one_time',
        stripePriceEnv: 'STRIPE_PRICE_GUIDED_BUILDER_SETUP',
      },
    },
    entitlements: {
      seats: 5,

      // Product = exactly ONE active launch application (enforced in DB + guard + tests).
      maxProjects: 1,
      buildCreditsPerMonth: 1000,
      maxRiskTier: 'T1',
      appBuilding: true,
      agentBuilding: false,
      codeExport: true,
      evidenceExport: true,
      publishMode: 'manual_review',
      externalWriteConnectors: false,
      consequentialActions: false,

      /*
       * Guided customers may request supervised review of personal/financial data
       * handling — still fail-closed until a Quantex manual-review flag is set.
       */
      sensitiveDataReviewAllowed: true,
      support: 'priority',
      manualReviewExceptionsAllowed: true,
    },
    highlights: [
      'Up to 5 users, 1 guided launch application',
      'Quantex-supported use-case design',
      'Classification & policy setup',
      'Guided build sessions',
      'Manual release review + deployment assistance',
      'Basic evidence export',
      'Priority support + monthly adoption review',
    ],
  },
};

/** Entitlements for an org with NO active paid subscription (fully fail-closed). */
export const NO_PLAN_ENTITLEMENTS: Entitlements = {
  seats: 1,
  maxProjects: 0,
  buildCreditsPerMonth: 0,
  maxRiskTier: 'T0',
  appBuilding: false,
  agentBuilding: false,
  codeExport: false,
  evidenceExport: false,
  publishMode: 'export_only',
  externalWriteConnectors: false,
  consequentialActions: false,
  sensitiveDataReviewAllowed: false,
  support: 'community',
  manualReviewExceptionsAllowed: false,
};

// ─── Accessors ──────────────────────────────────────────────────────────────────

export function getPlan(id: PlanId): PlanConfig | null {
  if (id === 'none') {
    return null;
  }

  return PLAN_CATALOG[id] ?? null;
}

/** Base (pre-subscription-status, pre-override) entitlements for a plan. */
export function basePlanEntitlements(id: PlanId): Entitlements {
  const plan = getPlan(id);

  if (!plan) {
    return { ...NO_PLAN_ENTITLEMENTS };
  }

  return { ...plan.entitlements };
}

export function isPaidPlan(id: PlanId): id is Exclude<PlanId, 'none'> {
  return id === 'builder_beta' || id === 'guided_builder';
}

/** Ordered list for pricing pages. */
export function listPlans(): PlanConfig[] {
  return [PLAN_CATALOG.builder_beta, PLAN_CATALOG.guided_builder];
}

/** Format a reference price for display. Never used to charge. */
export function formatPriceRef(p: PriceRef): string {
  const dollars = (p.amountCents / 100).toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 2 });
  const suffix = p.interval === 'month' ? '/mo' : p.interval === 'year' ? '/yr' : ' one-time';

  return `$${dollars}${suffix}`;
}
