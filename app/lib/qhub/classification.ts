/**
 * QHUB Gate 02 — Classification taxonomy & schema (BROWSER-SAFE)
 * app/lib/qhub/classification.ts
 *
 * This module is the single source of truth for the CLASSIFY stage of the QHUB
 * compliance lifecycle (01 CLASSIFY → 02 POLICY → 03 BUILD → 04 ATTEST).
 *
 * The authoritative, persisted taxonomy is the ledger-native T0–T3 tiers.
 * There is intentionally NO separate Low/Medium/High/Critical enum — friendly
 * display labels are derived here, but persisted values are always T0–T3.
 *
 * Contains NO secrets and NO server-only APIs; safe to import from the browser.
 */

// ─── Risk tiers (ledger-native, authoritative) ────────────────────────────────

export type RiskTier = 'T0' | 'T1' | 'T2' | 'T3';

/** UNCLASSIFIED is the pre-classification default; not a valid final tier. */
export type PersistedRiskTier = RiskTier | 'UNCLASSIFIED';

export const RISK_TIERS: RiskTier[] = ['T0', 'T1', 'T2', 'T3'];

/** Ordinal rank for comparisons. Higher = more consequential. */
export function tierRank(t: PersistedRiskTier): number {
  switch (t) {
    case 'T3':
      return 3;
    case 'T2':
      return 2;
    case 'T1':
      return 1;
    case 'T0':
      return 0;
    default:
      return -1; // UNCLASSIFIED
  }
}

/** Return the higher (more consequential) of two tiers. */
export function maxTier(a: RiskTier, b: RiskTier): RiskTier {
  return tierRank(a) >= tierRank(b) ? a : b;
}

export function tierAtLeast(t: PersistedRiskTier, floor: RiskTier): boolean {
  return tierRank(t) >= tierRank(floor);
}

/** Friendly, business-user display metadata. Persisted value stays T0–T3. */
export const TIER_DISPLAY: Record<RiskTier, { label: string; short: string; blurb: string }> = {
  T0: {
    label: 'T0 · Minimal',
    short: 'Minimal',
    blurb: 'Prototype or public data. No integrations, no sensitive information, no external action.',
  },
  T1: {
    label: 'T1 · Low',
    short: 'Low',
    blurb: 'Internal productivity with limited business data. Read-only, no material customer or financial consequence.',
  },
  T2: {
    label: 'T2 · Elevated',
    short: 'Elevated',
    blurb:
      'Client or transaction data, a regulated or books-and-records workflow, external integrations, AI recommendations, or controlled write capability.',
  },
  T3: {
    label: 'T3 · High / Consequential',
    short: 'High',
    blurb:
      'Trading/order action, money or asset movement, autonomous production action, external customer communication, or consequential financial/regulatory decisions.',
  },
};

// ─── Regulatory applicability (tags, not legal conclusions) ────────────────────

export type RegulatoryDomain =
  | 'SEC'
  | 'FINRA'
  | 'CFTC'
  | 'NFA'
  | 'MSRB'
  | 'BANKING'
  | 'PRIVACY'
  | 'CYBERSECURITY'
  | 'BOOKS_AND_RECORDS'
  | 'SUPERVISION'
  | 'INTERNAL_POLICY'
  | 'NONE_IDENTIFIED';

export const REGULATORY_DOMAINS: RegulatoryDomain[] = [
  'SEC',
  'FINRA',
  'CFTC',
  'NFA',
  'MSRB',
  'BANKING',
  'PRIVACY',
  'CYBERSECURITY',
  'BOOKS_AND_RECORDS',
  'SUPERVISION',
  'INTERNAL_POLICY',
  'NONE_IDENTIFIED',
];

// ─── Detected signals (drive both the rules engine and the card) ──────────────

/** Categories of data the app handles. */
export type DataClass =
  | 'PUBLIC'
  | 'INTERNAL_BUSINESS'
  | 'CLIENT_PII'
  | 'TRANSACTION_DATA'
  | 'FINANCIAL_ACCOUNT'
  | 'REGULATED_RECORDS'
  | 'MNPI'
  | 'CREDENTIALS';

/** External integration types the app connects to. */
export type IntegrationType =
  | 'NONE'
  | 'READ_ONLY_API'
  | 'EXTERNAL_SYSTEM_OF_RECORD'
  | 'BUSINESS_SYSTEM_WRITE'
  | 'PAYMENTS_OR_TRANSFERS'
  | 'TRADING_OR_ORDERS'
  | 'OUTBOUND_COMMUNICATION';

/** What the AI does inside the app at runtime. */
export type AiBehavior =
  | 'NONE'
  | 'INFORMATIONAL'
  | 'RECOMMENDATION'
  | 'FINANCIAL_RECOMMENDATION'
  | 'CONSEQUENTIAL_DECISION';

/** How autonomously the app can act. */
export type AutonomyLevel = 'NONE' | 'HUMAN_IN_LOOP' | 'HUMAN_ON_LOOP' | 'AUTONOMOUS';

/** Where the app is intended to run. */
export type DeploymentSurface = 'PREVIEW_ONLY' | 'INTERNAL' | 'PRODUCTION';

export type ClassificationMethod = 'RULES_ONLY' | 'AI_PROPOSED' | 'HUMAN_CONFIRMED' | 'HUMAN_CORRECTED';

/**
 * The structured signals the classifier extracts from the app description.
 * The deterministic rules engine consumes exactly these.
 */
export interface ClassificationSignals {
  data_classes: DataClass[];
  integration_types: IntegrationType[];
  ai_behavior: AiBehavior;
  autonomy_level: AutonomyLevel;
  deployment_surface: DeploymentSurface;
  regulatory_domains: RegulatoryDomain[];
}

/**
 * The full classification record. This is the CLASSIFICATION_ASSIGNED event
 * payload and the persisted current classification on qhub_applications.
 */
export interface ClassificationResult {
  classification_version: number;
  risk_tier: RiskTier; // final tier (>= risk_floor, always)
  risk_floor: RiskTier; // deterministic minimum
  ai_proposed_tier: RiskTier;
  classification_method: ClassificationMethod;
  regulatory_domains: RegulatoryDomain[];
  data_classes: DataClass[];
  integration_types: IntegrationType[];
  ai_behavior: AiBehavior;
  autonomy_level: AutonomyLevel;
  deployment_surface: DeploymentSurface;
  rationale: string; // plain-English explanation
  floor_reasons: string[]; // which deterministic rules fired
  confidence: number; // 0..1 (AI confidence)
  confirmed_by: string | null; // server-authoritative user id, set on confirm
  confirmed_at: string | null; // ISO timestamp, set on confirm
  classifier_version: string;
}

export const CLASSIFIER_VERSION = 'gate02-classifier-1.0.0';
