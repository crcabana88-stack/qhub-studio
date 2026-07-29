/**
 * QHUB Commercial Launch — Governance Essentials boundary
 * app/test/commercial-governance-essentials.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateGovernanceEssentials,
  baselinePolicyCard,
  GOVERNANCE_ESSENTIALS_FLOW,
} from '~/lib/qhub/commercial/governance-essentials';

describe('governance essentials disposition (fail closed)', () => {
  it('proceeds for public / synthetic / ordinary-internal at T0/T1', () => {
    const r = evaluateGovernanceEssentials({ dataClasses: ['public', 'ordinary_internal'], riskTier: 'T1' });
    expect(r.disposition).toBe('proceed');
    expect(r.reasonCodes).toContain('PROCEED_LOW_RISK');
    expect(r.requiresManualReview).toBe(false);
  });

  it('routes personal / financial / restricted data to manual review', () => {
    for (const dc of ['personal', 'financial', 'restricted'] as const) {
      const r = evaluateGovernanceEssentials({ dataClasses: ['public', dc], riskTier: 'T1' });
      expect(r.disposition).toBe('manual_review');
      expect(r.requiresManualReview).toBe(true);
      expect(r.reasonCodes).toContain('MANUAL_REVIEW_SENSITIVE_DATA');
    }
  });

  it('blocks tiers above the launch cap', () => {
    const t2 = evaluateGovernanceEssentials({ dataClasses: ['public'], riskTier: 'T2' });
    expect(t2.disposition).toBe('blocked');
    expect(t2.reasonCodes).toContain('BLOCKED_TIER_ABOVE_LAUNCH_CAP');

    const t3 = evaluateGovernanceEssentials({ dataClasses: ['public'], riskTier: 'T3' });
    expect(t3.disposition).toBe('blocked');
  });

  it('prohibits secrets, MNPI, regulated records, consequential/external/agent', () => {
    const cases = [
      { handlesSecretsOrCredentials: true, code: 'PROHIBITED_SECRETS_IN_PROMPTS' },
      { involvesMnpi: true, code: 'PROHIBITED_MNPI' },
      { involvesRegulatedRecords: true, code: 'PROHIBITED_REGULATED_RECORDS' },
      { requestsConsequentialAction: true, code: 'PROHIBITED_CONSEQUENTIAL_ACTION' },
      { requestsExternalWrite: true, code: 'PROHIBITED_EXTERNAL_WRITE' },
      { requestsAutonomousAgent: true, code: 'PROHIBITED_AUTONOMOUS_AGENT' },
    ];

    for (const c of cases) {
      const r = evaluateGovernanceEssentials({ dataClasses: ['public'], riskTier: 'T0', ...c });
      expect(r.disposition).toBe('prohibited');
      expect(r.reasonCodes).toContain(c.code);
    }
  });

  it('prohibition takes precedence over an otherwise-clean low-risk use case', () => {
    const r = evaluateGovernanceEssentials({ dataClasses: ['public'], riskTier: 'T0', requestsAutonomousAgent: true });
    expect(r.disposition).toBe('prohibited');
  });

  it('baseline policy card only surfaces proceed-eligible data classes', () => {
    const card = baselinePolicyCard('T1', ['public', 'personal', 'synthetic']);
    expect(card.allowedDataClasses).toEqual(['public', 'synthetic']);
    expect(card.restrictions.some((r) => r.includes('T1'))).toBe(true);
  });

  it('defines the 10-step customer flow', () => {
    expect(GOVERNANCE_ESSENTIALS_FLOW).toHaveLength(10);
    expect(GOVERNANCE_ESSENTIALS_FLOW[0].key).toBe('purpose');
    expect(GOVERNANCE_ESSENTIALS_FLOW.at(-1)?.key).toBe('evidence');
  });
});
