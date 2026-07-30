/**
 * QHUB Commercial Launch — GOVERNANCE ESSENTIALS (BROWSER-SAFE)
 * app/lib/qhub/commercial/governance-essentials.ts
 *
 * The lightweight, customer-facing governance flow for low-risk T0/T1 apps.
 * This is the commercial-tier complement to the institutional Gates — it produces
 * a structured risk classification, policy guidance, a version record, and a human
 * acknowledgment. It makes NO institutional-assurance or compliance claim.
 *
 * The disposition function here is the DECLARED boundary of the launch product. It
 * FAILS CLOSED: anything outside public / synthetic / approved-ordinary-internal
 * data, or any prohibited signal (secrets, MNPI, regulated records, consequential
 * actions), is blocked or routed to manual Quantex review — never silently allowed.
 *
 * No secrets, no server-only APIs — safe to import from the browser. Server routes
 * re-run evaluateGovernanceEssentials() authoritatively; the UI never decides.
 */

import type { RiskTier } from '~/lib/qhub/classification';
import { LAUNCH_MAX_RISK_TIER } from '~/lib/qhub/commercial/plans';

// ─── Data declaration taxonomy ──────────────────────────────────────────────────

export type DataClass = 'public' | 'synthetic' | 'ordinary_internal' | 'personal' | 'financial' | 'restricted';

export const DATA_CLASSES: DataClass[] = [
  'public',
  'synthetic',
  'ordinary_internal',
  'personal',
  'financial',
  'restricted',
];

export const DATA_CLASS_LABEL: Record<DataClass, string> = {
  public: 'Public',
  synthetic: 'Synthetic / test',
  ordinary_internal: 'Ordinary internal',
  personal: 'Personal data',
  financial: 'Financial data',
  restricted: 'Restricted / regulated',
};

/** Data classes that may proceed without manual review in the launch tier. */
export const PROCEED_DATA_CLASSES: DataClass[] = ['public', 'synthetic', 'ordinary_internal'];

/** Data classes that require blocking or manual Quantex review. */
export const REVIEW_DATA_CLASSES: DataClass[] = ['personal', 'financial', 'restricted'];

// ─── Prohibited signals (hard stops for the launch tier) ────────────────────────

export interface UseCaseSignals {
  /** Declared data classes present in the app. */
  dataClasses: DataClass[];

  /** Customer asserts the app needs autonomous agent behavior. */
  requestsAutonomousAgent?: boolean;

  /** Customer asserts the app needs to take consequential external actions. */
  requestsConsequentialAction?: boolean;

  /** Customer asserts the app writes to external customer systems. */
  requestsExternalWrite?: boolean;

  /** Customer asserts the app will handle secrets / credentials / API keys in prompts. */
  handlesSecretsOrCredentials?: boolean;

  /** Customer asserts material non-public information is involved. */
  involvesMnpi?: boolean;

  /** Customer asserts regulated records (e.g. brokerage, health) are involved. */
  involvesRegulatedRecords?: boolean;

  /** The classified risk tier for the use case (from basic classification). */
  riskTier?: RiskTier;
}

export type Disposition = 'proceed' | 'manual_review' | 'blocked' | 'prohibited';

export interface GovernanceEssentialsResult {
  disposition: Disposition;

  /** Machine reason codes (stable, testable). */
  reasonCodes: string[];

  /** Customer-facing explanation lines. */
  messages: string[];

  /** Whether a Quantex manual-review request should be created. */
  requiresManualReview: boolean;
}

// ─── Boundary evaluation (fail closed) ──────────────────────────────────────────

/**
 * Evaluate a declared use case against the commercial launch boundary.
 *
 * Ordering (most-severe first):
 *   1. PROHIBITED — secrets/credentials, MNPI, regulated records, consequential
 *      actions, external writes, or autonomous agents. Never available at launch.
 *   2. BLOCKED — risk tier above the launch cap (T2/T3).
 *   3. MANUAL_REVIEW — personal / financial / restricted data present.
 *   4. PROCEED — public / synthetic / ordinary-internal only, T0/T1.
 */
export function evaluateGovernanceEssentials(signals: UseCaseSignals): GovernanceEssentialsResult {
  const reasonCodes: string[] = [];
  const messages: string[] = [];

  // 1. Hard prohibitions — these are never part of the launch tier.
  if (signals.handlesSecretsOrCredentials) {
    reasonCodes.push('PROHIBITED_SECRETS_IN_PROMPTS');
    messages.push('Secrets, credentials, and API keys must never be placed in prompts or app content.');
  }

  if (signals.involvesMnpi) {
    reasonCodes.push('PROHIBITED_MNPI');
    messages.push('Material non-public information is not permitted in the launch tier.');
  }

  if (signals.involvesRegulatedRecords) {
    reasonCodes.push('PROHIBITED_REGULATED_RECORDS');
    messages.push('Regulated records are not supported in the launch tier.');
  }

  if (signals.requestsConsequentialAction) {
    reasonCodes.push('PROHIBITED_CONSEQUENTIAL_ACTION');
    messages.push(
      'Consequential external actions (payments, trading, production writes) are not available in this tier.',
    );
  }

  if (signals.requestsExternalWrite) {
    reasonCodes.push('PROHIBITED_EXTERNAL_WRITE');
    messages.push('Writing to external customer systems is not available in this tier.');
  }

  if (signals.requestsAutonomousAgent) {
    reasonCodes.push('PROHIBITED_AUTONOMOUS_AGENT');
    messages.push('Autonomous agents are part of the institutional offering, not the launch tier.');
  }

  if (reasonCodes.length > 0) {
    return { disposition: 'prohibited', reasonCodes, messages, requiresManualReview: false };
  }

  // 2. Risk tier above the launch cap.
  if (signals.riskTier && tierAboveLaunchCap(signals.riskTier)) {
    reasonCodes.push('BLOCKED_TIER_ABOVE_LAUNCH_CAP');
    messages.push(
      `This use case classifies as ${signals.riskTier}. The launch tier supports ${LAUNCH_MAX_RISK_TIER} and below.`,
    );

    return { disposition: 'blocked', reasonCodes, messages, requiresManualReview: false };
  }

  // 3. Sensitive data present → manual review.
  const sensitive = signals.dataClasses.filter((c) => REVIEW_DATA_CLASSES.includes(c));

  if (sensitive.length > 0) {
    reasonCodes.push('MANUAL_REVIEW_SENSITIVE_DATA');
    messages.push(
      `Declared data (${sensitive.map((c) => DATA_CLASS_LABEL[c]).join(', ')}) requires manual Quantex review before proceeding.`,
    );

    return { disposition: 'manual_review', reasonCodes, messages, requiresManualReview: true };
  }

  // 4. Clean low-risk path.
  reasonCodes.push('PROCEED_LOW_RISK');
  messages.push('This use case is within the low-risk launch boundary and may proceed.');

  return { disposition: 'proceed', reasonCodes, messages, requiresManualReview: false };
}

function tierAboveLaunchCap(tier: RiskTier): boolean {
  const rank: Record<RiskTier, number> = { T0: 0, T1: 1, T2: 2, T3: 3 };

  return rank[tier] > rank[LAUNCH_MAX_RISK_TIER];
}

// ─── The 10-step customer flow definition ───────────────────────────────────────

export interface FlowStep {
  key: string;
  title: string;
  description: string;
}

export const GOVERNANCE_ESSENTIALS_FLOW: FlowStep[] = [
  { key: 'purpose', title: 'Purpose declaration', description: 'State what this application is for.' },
  { key: 'use_case', title: 'Use-case description', description: 'Describe what it will do and for whom.' },
  { key: 'data', title: 'Data declaration', description: 'Declare the classes of data involved.' },
  { key: 'classification', title: 'Basic classification', description: 'Determine the T0/T1 risk tier.' },
  { key: 'model', title: 'Model declaration', description: 'Declare which AI model(s) the app uses.' },
  { key: 'connectors', title: 'Connector declaration', description: 'Declare any read/non-consequential connectors.' },
  { key: 'policy_card', title: 'Baseline policy card', description: 'Review the generated policy guidance.' },
  { key: 'version', title: 'Version record', description: 'Record this version of the application.' },
  { key: 'acknowledgment', title: 'Human acknowledgment', description: 'Acknowledge responsibility and restrictions.' },
  { key: 'evidence', title: 'Basic evidence export', description: 'Export the governance record.' },
];

// ─── Baseline policy card ────────────────────────────────────────────────────────

/**
 * The authoritative, server-owned review policy version. This is the ONLY source of a
 * review's policy version — the browser may never supply or override it. Bump this when
 * the baseline policy card's material rules change (which forces re-review of requests
 * submitted under an older version).
 */
export const REVIEW_POLICY_VERSION = '2026-07-30.governance-essentials.v1';

/**
 * The current REQUIRED human-acknowledgment version. A review approval (and a model/build/
 * publication/export authorization) is valid only when the project's stored acknowledgment
 * version matches this. Bump when the acceptable-use terms materially change (forces a fresh
 * acknowledgment + a new review).
 */
export const REQUIRED_ACKNOWLEDGMENT_VERSION = '2026-07-30.acceptable-use.v1';

/**
 * The current Governance Essentials POLICY-CARD version (the baseline policy card's identity).
 * A stored policy_card_version other than this means the project was evaluated under an older
 * Governance record and must be re-declared + re-reviewed.
 */
export const GOVERNANCE_POLICY_CARD_VERSION = '2026-07-30.policy-card.v1';

/** The current applicable review policy version (server-derived, project-scoped). */
export function currentReviewPolicyVersion(): string {
  return REVIEW_POLICY_VERSION;
}

/** The current required acknowledgment version (server-derived). */
export function currentRequiredAcknowledgmentVersion(): string {
  return REQUIRED_ACKNOWLEDGMENT_VERSION;
}

/** The current Governance Essentials policy-card version (server-derived). */
export function currentGovernancePolicyCardVersion(): string {
  return GOVERNANCE_POLICY_CARD_VERSION;
}

/** The MATERIAL declaration inputs that define a project's governance identity (R8 §6). */
export interface DeclarationIdentityParts {
  orgId: string;
  projectId: string;
  purpose: string;
  useCase: string;
  dataClasses: DataClass[];
  riskTier: RiskTier;
  modelDeclaration: string;
  connectorDeclaration: string[];
  policyCardVersion: string;
}

/**
 * R8 §6: the canonical, deterministic STRING whose SHA-256 is the declaration_identity_hash.
 * It binds the MATERIAL customer declaration (business purpose, use-case, data declaration,
 * model declaration, connector declaration, risk classification) together with the policy-card
 * identity and the project/org identity. Data classes + connectors are sorted and text is
 * trimmed so the identity is stable under cosmetic reordering/whitespace; ANY material change
 * (purpose/use-case/data/model/connector/risk/policy-card/project) yields a different identity,
 * which invalidates a review bound to the old one. Server-derived values only.
 */
export function buildDeclarationIdentityString(parts: DeclarationIdentityParts): string {
  const norm = (s: string) => s.trim();

  return JSON.stringify({
    v: 'qhub-declaration-identity-1',
    org: parts.orgId,
    project: parts.projectId,
    purpose: norm(parts.purpose),
    useCase: norm(parts.useCase),
    data: [...parts.dataClasses].sort(),
    riskTier: parts.riskTier,
    model: norm(parts.modelDeclaration),
    connectors: [...parts.connectorDeclaration].map(norm).sort(),
    policyCard: parts.policyCardVersion,
  });
}

export interface PolicyCard {
  tier: RiskTier;
  allowedDataClasses: DataClass[];
  guidance: string[];
  restrictions: string[];
}

/** Generate a baseline, honest policy card for a permitted low-risk use case. */
export function baselinePolicyCard(tier: RiskTier, dataClasses: DataClass[]): PolicyCard {
  return {
    tier,
    allowedDataClasses: dataClasses.filter((c) => PROCEED_DATA_CLASSES.includes(c)),
    guidance: [
      'Keep prompts and app content free of secrets, credentials, and API keys.',
      'Use public, synthetic, or ordinary internal data only.',
      'Review generated output before relying on it.',
      'Publish only through the controlled review process.',
    ],
    restrictions: [
      'No autonomous agents or consequential external actions.',
      'No personal, financial, or restricted data without manual Quantex review.',
      `Risk tier capped at ${LAUNCH_MAX_RISK_TIER} for this product.`,
    ],
  };
}

// ─── Customer language (verbatim, honest) ───────────────────────────────────────

export const GOVERNANCE_ESSENTIALS_STATEMENT =
  'Governance Essentials provides structured risk classification, policy guidance, ' +
  'version records, and human review. Customers remain responsible for determining ' +
  'their legal, regulatory, security, and organizational obligations.';

export const SHARED_RESPONSIBILITY_STATEMENT =
  'QHub provides governance tooling and guidance for low-risk T0/T1 applications. ' +
  'It does not provide legal, regulatory, or compliance certification, and does not ' +
  'make institutional-assurance claims. You remain responsible for your obligations.';
