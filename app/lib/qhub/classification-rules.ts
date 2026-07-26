/**
 * QHUB Gate 02 — Deterministic risk-floor engine (PURE, INDEPENDENTLY TESTABLE)
 * app/lib/qhub/classification-rules.ts
 *
 * Establishes the NON-BYPASSABLE minimum risk tier from structured signals.
 * A single high-risk characteristic may determine the final tier (spec §3).
 *
 * This engine is pure (no I/O, no secrets) so it can be unit-tested in isolation
 * and reused on both server and client. The AI classifier may propose a HIGHER
 * tier, never a lower one than the floor this computes.
 */

import type { ClassificationSignals, RiskTier } from './classification';

export interface RiskFloorResult {
  floor: RiskTier;
  reasons: string[];
}

/**
 * Compute the deterministic minimum risk tier.
 * Evaluates the most consequential rules first (T3), then T2, else a low baseline.
 * ALL matching reasons are collected for transparency in the classification card.
 */
export function computeRiskFloor(signals: ClassificationSignals): RiskFloorResult {
  const {
    data_classes: dataClasses,
    integration_types: integrationTypes,
    ai_behavior: aiBehavior,
    autonomy_level: autonomyLevel,
    deployment_surface: deploymentSurface,
  } = signals;

  const t3: string[] = [];
  const t2: string[] = [];

  // ── T3 — High / Consequential ─────────────────────────────────────────────
  if (integrationTypes.includes('TRADING_OR_ORDERS')) {
    t3.push('Can create, release, route, modify, or cancel financial transactions / orders');
  }

  if (integrationTypes.includes('PAYMENTS_OR_TRANSFERS')) {
    t3.push('Can move money or assets');
  }

  if (integrationTypes.includes('OUTBOUND_COMMUNICATION')) {
    t3.push('Can communicate externally on behalf of the firm');
  }

  if (aiBehavior === 'CONSEQUENTIAL_DECISION') {
    t3.push('Makes consequential customer, credit, suitability, trading, or compliance decisions');
  }

  if (autonomyLevel === 'AUTONOMOUS' && deploymentSurface === 'PRODUCTION') {
    t3.push('Acts autonomously in production');
  }

  if (dataClasses.includes('MNPI')) {
    t3.push('Exposes or transmits material non-public information (MNPI)');
  }

  if (dataClasses.includes('CREDENTIALS')) {
    t3.push('Handles credentials / secrets (highly sensitive data)');
  }

  // ── T2 — Elevated ──────────────────────────────────────────────────────────
  if (
    dataClasses.includes('CLIENT_PII') ||
    dataClasses.includes('TRANSACTION_DATA') ||
    dataClasses.includes('FINANCIAL_ACCOUNT')
  ) {
    t2.push('Handles client or transaction information');
  }

  if (dataClasses.includes('REGULATED_RECORDS')) {
    t2.push('Handles regulated records');
  }

  if (signals.regulatory_domains.includes('SUPERVISION')) {
    t2.push('Supports a supervisory / compliance workflow');
  }

  if (signals.regulatory_domains.includes('BOOKS_AND_RECORDS')) {
    t2.push('Has books-and-records relevance');
  }

  if (integrationTypes.includes('EXTERNAL_SYSTEM_OF_RECORD')) {
    t2.push('Integrates with an external system of record');
  }

  if (aiBehavior === 'FINANCIAL_RECOMMENDATION') {
    t2.push('Produces AI-generated financial recommendations');
  }

  if (integrationTypes.includes('BUSINESS_SYSTEM_WRITE')) {
    t2.push('Has write access to business systems');
  }

  if (t3.length > 0) {
    return { floor: 'T3', reasons: t3 };
  }

  if (t2.length > 0) {
    return { floor: 'T2', reasons: t2 };
  }

  /*
   * ── T1 vs T0 baseline ──────────────────────────────────────────────────────
   * T0 requires: only public data, no integrations, no AI consequence.
   */
  const onlyPublicData = dataClasses.length === 0 || dataClasses.every((d) => d === 'PUBLIC');
  const noIntegrations = integrationTypes.length === 0 || integrationTypes.every((i) => i === 'NONE');
  const noAiConsequence = aiBehavior === 'NONE' || aiBehavior === 'INFORMATIONAL';
  const notAutonomous = autonomyLevel === 'NONE' || autonomyLevel === 'HUMAN_IN_LOOP';

  if (onlyPublicData && noIntegrations && noAiConsequence && notAutonomous) {
    return {
      floor: 'T0',
      reasons: ['Public data only, no integrations, no sensitive information, no external action'],
    };
  }

  const t1Reasons: string[] = [];

  if (dataClasses.includes('INTERNAL_BUSINESS')) {
    t1Reasons.push('Handles limited internal business data');
  }

  if (integrationTypes.includes('READ_ONLY_API')) {
    t1Reasons.push('Uses read-only external data');
  }

  if (aiBehavior === 'RECOMMENDATION') {
    t1Reasons.push('Provides non-financial recommendations');
  }

  if (t1Reasons.length === 0) {
    t1Reasons.push('Internal productivity with no material customer or financial consequence');
  }

  return { floor: 'T1', reasons: t1Reasons };
}
