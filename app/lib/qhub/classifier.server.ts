/* eslint-disable @typescript-eslint/naming-convention -- pre-existing DB-mapped snake_case / private-method naming; unrelated to R6 (module is only annotated with __QHUB_MODULE_CLASSIFICATION) */
/**
 * QHUB Gate 02 — AI classifier (SERVER ONLY)
 * app/lib/qhub/classifier.server.ts
 *
 * Analyzes the user's application description and proposes a classification:
 *   1. AI extracts structured signals + a proposed tier (validated against enums).
 *   2. The deterministic rules engine computes a non-bypassable floor.
 *   3. Final proposed tier = max(rule floor, AI proposed tier).
 *
 * The AI may recommend a HIGHER tier than the floor, never lower. If the AI call
 * fails or returns garbage, a deterministic keyword fallback extracts signals so
 * classification is never silently skipped or under-classified.
 *
 * Server-only: reads ANTHROPIC_API_KEY from env; never imported by the browser.
 */

import {
  CLASSIFIER_VERSION,
  maxTier,
  type AiBehavior,
  type AutonomyLevel,
  type ClassificationResult,
  type ClassificationSignals,
  type DataClass,
  type DeploymentSurface,
  type IntegrationType,
  type RegulatoryDomain,
  type RiskTier,
} from './classification';
import { computeRiskFloor } from './classification-rules';

const DATA_CLASSES: DataClass[] = [
  'PUBLIC',
  'INTERNAL_BUSINESS',
  'CLIENT_PII',
  'TRANSACTION_DATA',
  'FINANCIAL_ACCOUNT',
  'REGULATED_RECORDS',
  'MNPI',
  'CREDENTIALS',
];
const INTEGRATION_TYPES: IntegrationType[] = [
  'NONE',
  'READ_ONLY_API',
  'EXTERNAL_SYSTEM_OF_RECORD',
  'BUSINESS_SYSTEM_WRITE',
  'PAYMENTS_OR_TRANSFERS',
  'TRADING_OR_ORDERS',
  'OUTBOUND_COMMUNICATION',
];
const AI_BEHAVIORS: AiBehavior[] = [
  'NONE',
  'INFORMATIONAL',
  'RECOMMENDATION',
  'FINANCIAL_RECOMMENDATION',
  'CONSEQUENTIAL_DECISION',
];
const AUTONOMY_LEVELS: AutonomyLevel[] = ['NONE', 'HUMAN_IN_LOOP', 'HUMAN_ON_LOOP', 'AUTONOMOUS'];
const DEPLOYMENT_SURFACES: DeploymentSurface[] = ['PREVIEW_ONLY', 'INTERNAL', 'PRODUCTION'];
const REG_DOMAINS: RegulatoryDomain[] = [
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
const RISK_TIERS: RiskTier[] = ['T0', 'T1', 'T2', 'T3'];

function keepValid<T>(value: unknown, allowed: T[]): T[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((v): v is T => allowed.includes(v as T));
}

function oneOf<T>(value: unknown, allowed: T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback;
}

const CLASSIFIER_MODEL = 'claude-sonnet-4-6';

const SYSTEM = `You are the QHUB compliance classifier for a financial-services firm.
Given an application description, extract governance signals and propose a risk tier.
Respond with a SINGLE JSON object and nothing else — no prose, no markdown fences.

JSON schema (use ONLY these enum values):
{
  "data_classes": string[]      // subset of: PUBLIC, INTERNAL_BUSINESS, CLIENT_PII, TRANSACTION_DATA, FINANCIAL_ACCOUNT, REGULATED_RECORDS, MNPI, CREDENTIALS
  "integration_types": string[] // subset of: NONE, READ_ONLY_API, EXTERNAL_SYSTEM_OF_RECORD, BUSINESS_SYSTEM_WRITE, PAYMENTS_OR_TRANSFERS, TRADING_OR_ORDERS, OUTBOUND_COMMUNICATION
  "ai_behavior": string         // one of: NONE, INFORMATIONAL, RECOMMENDATION, FINANCIAL_RECOMMENDATION, CONSEQUENTIAL_DECISION
  "autonomy_level": string      // one of: NONE, HUMAN_IN_LOOP, HUMAN_ON_LOOP, AUTONOMOUS
  "deployment_surface": string  // one of: PREVIEW_ONLY, INTERNAL, PRODUCTION
  "regulatory_domains": string[]// subset of: SEC, FINRA, CFTC, NFA, MSRB, BANKING, PRIVACY, CYBERSECURITY, BOOKS_AND_RECORDS, SUPERVISION, INTERNAL_POLICY, NONE_IDENTIFIED
  "proposed_tier": string       // one of: T0, T1, T2, T3
  "rationale": string           // 1-3 plain-English sentences a business user understands
  "confidence": number          // 0..1
}

Tier meaning:
- T0 Minimal: prototype/public data, no integrations, no sensitive info, no external action.
- T1 Low: internal productivity, limited business data, read-only, no material consequence.
- T2 Elevated: client/transaction data, regulated/books-and-records workflow, external systems of record, AI financial recommendations, or business-system write.
- T3 High: trading/order action, money movement, external communication on the firm's behalf, consequential decisions, autonomous production action, or MNPI/PII exposure.
When uncertain, choose the HIGHER tier. Regulatory domains are applicability tags, not legal conclusions.`;

function extractJson(text: string): Record<string, unknown> | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');

  if (start === -1 || end === -1 || end <= start) {
    return null;
  }

  try {
    return JSON.parse(text.slice(start, end + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Deterministic keyword fallback when the AI call is unavailable/invalid. */
function heuristicSignals(description: string): { signals: ClassificationSignals; tier: RiskTier } {
  const d = description.toLowerCase();
  const has = (...words: string[]) => words.some((w) => d.includes(w));

  const data_classes: DataClass[] = [];
  const integration_types: IntegrationType[] = [];
  const regulatory_domains: RegulatoryDomain[] = [];
  let ai_behavior: AiBehavior = 'NONE';
  let autonomy_level: AutonomyLevel = 'NONE';
  let deployment_surface: DeploymentSurface = 'INTERNAL';

  if (has('trade', 'trading', 'order execution', 'execute order', 'buy/sell', 'brokerage order')) {
    integration_types.push('TRADING_OR_ORDERS');
    regulatory_domains.push('SEC', 'FINRA');
  }

  if (has('payment', 'transfer money', 'move money', 'wire', 'ach', 'disburse', 'payout')) {
    integration_types.push('PAYMENTS_OR_TRANSFERS');
  }

  if (has('email customer', 'send email', 'sms', 'notify client', 'outreach', 'send message to')) {
    integration_types.push('OUTBOUND_COMMUNICATION');
  }

  if (has('client', 'customer', 'account holder', 'investor')) {
    data_classes.push('CLIENT_PII');
  }

  if (has('trade data', 'transaction', 'commission', 'settlement', 'reconcile', 'reconciliation')) {
    data_classes.push('TRANSACTION_DATA');
  }

  if (has('books and records', 'recordkeeping', 'compliance record', 'audit record')) {
    data_classes.push('REGULATED_RECORDS');
    regulatory_domains.push('BOOKS_AND_RECORDS');
  }

  if (has('supervis', 'compliance workflow', 'surveillance')) {
    regulatory_domains.push('SUPERVISION');
  }

  if (has('recommend', 'advice', 'suitab')) {
    ai_behavior = has('financ', 'invest', 'portfolio', 'trade') ? 'FINANCIAL_RECOMMENDATION' : 'RECOMMENDATION';
  }

  if (has('autonomous', 'automatically execute', 'without human', 'agent that acts', 'auto-execute')) {
    autonomy_level = 'AUTONOMOUS';
    deployment_surface = 'PRODUCTION';
  }

  if (has('accounting', 'quickbooks', 'erp', 'salesforce', 'crm', 'system of record')) {
    integration_types.push('EXTERNAL_SYSTEM_OF_RECORD');
  }

  if (has('marketing', 'landing page', 'microsite', 'brochure', 'public website') && data_classes.length === 0) {
    data_classes.push('PUBLIC');
    deployment_surface = 'INTERNAL';
  }

  if (data_classes.length === 0) {
    data_classes.push('INTERNAL_BUSINESS');
  }

  if (integration_types.length === 0) {
    integration_types.push('NONE');
  }

  if (regulatory_domains.length === 0) {
    regulatory_domains.push('NONE_IDENTIFIED');
  }

  const signals: ClassificationSignals = {
    data_classes,
    integration_types,
    ai_behavior,
    autonomy_level,
    deployment_surface,
    regulatory_domains,
  };
  const { floor } = computeRiskFloor(signals);

  return { signals, tier: floor };
}

async function callAnthropicClassifier(
  description: string,
  apiKey: string,
): Promise<{ signals: ClassificationSignals; proposed: RiskTier; rationale: string; confidence: number } | null> {
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: CLASSIFIER_MODEL,
        max_tokens: 700,
        system: SYSTEM,
        messages: [{ role: 'user', content: `Application description:\n${description}` }],
      }),
      signal: AbortSignal.timeout(20000),
    });

    if (!res.ok) {
      console.error('[Classifier] Anthropic classify call failed:', res.status);
      return null;
    }

    const data = (await res.json()) as { content?: { type: string; text?: string }[] };
    const text = (data.content ?? []).map((c) => c.text ?? '').join('');
    const parsed = extractJson(text);

    if (!parsed) {
      return null;
    }

    const signals: ClassificationSignals = {
      data_classes: keepValid(parsed.data_classes, DATA_CLASSES),
      integration_types: keepValid(parsed.integration_types, INTEGRATION_TYPES),
      ai_behavior: oneOf(parsed.ai_behavior, AI_BEHAVIORS, 'NONE'),
      autonomy_level: oneOf(parsed.autonomy_level, AUTONOMY_LEVELS, 'NONE'),
      deployment_surface: oneOf(parsed.deployment_surface, DEPLOYMENT_SURFACES, 'INTERNAL'),
      regulatory_domains: keepValid(parsed.regulatory_domains, REG_DOMAINS),
    };

    if (signals.data_classes.length === 0) {
      signals.data_classes = ['INTERNAL_BUSINESS'];
    }

    if (signals.integration_types.length === 0) {
      signals.integration_types = ['NONE'];
    }

    if (signals.regulatory_domains.length === 0) {
      signals.regulatory_domains = ['NONE_IDENTIFIED'];
    }

    const proposed = oneOf(parsed.proposed_tier, RISK_TIERS, 'T1');
    const rationale = typeof parsed.rationale === 'string' ? parsed.rationale : '';
    const confidenceRaw = typeof parsed.confidence === 'number' ? parsed.confidence : 0.6;
    const confidence = Math.max(0, Math.min(1, confidenceRaw));

    return { signals, proposed, rationale, confidence };
  } catch (err) {
    console.error('[Classifier] Anthropic classify error:', err);
    return null;
  }
}

/**
 * Produce a PROVISIONAL classification (not yet confirmed, not yet ledgered).
 * Final tier is always >= the deterministic floor.
 */
export async function classifyApplication(
  description: string,
  env: Record<string, string | undefined>,
): Promise<ClassificationResult> {
  const apiKey = env.ANTHROPIC_API_KEY ?? process.env.ANTHROPIC_API_KEY ?? '';

  const ai = apiKey ? await callAnthropicClassifier(description, apiKey) : null;

  let signals: ClassificationSignals;
  let aiProposed: RiskTier;
  let rationale: string;
  let confidence: number;
  let usedAi: boolean;

  if (ai) {
    signals = ai.signals;
    aiProposed = ai.proposed;
    rationale = ai.rationale;
    confidence = ai.confidence;
    usedAi = true;
  } else {
    const h = heuristicSignals(description);
    signals = h.signals;
    aiProposed = h.tier;
    rationale = 'Automated keyword analysis (AI classifier unavailable). Review and confirm the tier.';
    confidence = 0.4;
    usedAi = false;
  }

  const { floor, reasons } = computeRiskFloor(signals);
  const finalTier = maxTier(floor, aiProposed);

  if (!rationale) {
    rationale = `Classified ${finalTier} based on the described data, integrations, and AI behavior.`;
  }

  return {
    classification_version: 1,
    risk_tier: finalTier,
    risk_floor: floor,
    ai_proposed_tier: aiProposed,
    classification_method: usedAi ? 'AI_PROPOSED' : 'RULES_ONLY',
    regulatory_domains: signals.regulatory_domains,
    data_classes: signals.data_classes,
    integration_types: signals.integration_types,
    ai_behavior: signals.ai_behavior,
    autonomy_level: signals.autonomy_level,
    deployment_surface: signals.deployment_surface,
    rationale,
    floor_reasons: reasons,
    confidence,
    confirmed_by: null,
    confirmed_at: null,
    classifier_version: CLASSIFIER_VERSION,
  };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
