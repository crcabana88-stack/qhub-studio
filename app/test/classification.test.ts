/**
 * QHUB Gate 02 — Classification rules & reference cases
 * app/test/classification.test.ts
 */

import { describe, it, expect } from 'vitest';
import { computeRiskFloor } from '~/lib/qhub/classification-rules';
import { maxTier, tierRank, type ClassificationSignals } from '~/lib/qhub/classification';

function signals(overrides: Partial<ClassificationSignals>): ClassificationSignals {
  return {
    data_classes: [],
    integration_types: ['NONE'],
    ai_behavior: 'NONE',
    autonomy_level: 'NONE',
    deployment_surface: 'INTERNAL',
    regulatory_domains: ['NONE_IDENTIFIED'],
    ...overrides,
  };
}

describe('tier helpers', () => {
  it('ranks tiers and takes the higher one', () => {
    expect(tierRank('T3')).toBeGreaterThan(tierRank('T2'));
    expect(tierRank('T0')).toBeLessThan(tierRank('T1'));
    expect(maxTier('T1', 'T3')).toBe('T3');
    expect(maxTier('T3', 'T0')).toBe('T3');
    expect(maxTier('T2', 'T2')).toBe('T2');
  });
});

describe('deterministic floors — T2 triggers (spec §3)', () => {
  it('client/transaction/financial data → at least T2', () => {
    expect(computeRiskFloor(signals({ data_classes: ['CLIENT_PII'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ data_classes: ['TRANSACTION_DATA'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ data_classes: ['FINANCIAL_ACCOUNT'] })).floor).toBe('T2');
  });
  it('regulated records / supervision / books-and-records → T2', () => {
    expect(computeRiskFloor(signals({ data_classes: ['REGULATED_RECORDS'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ regulatory_domains: ['SUPERVISION'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ regulatory_domains: ['BOOKS_AND_RECORDS'] })).floor).toBe('T2');
  });
  it('external system of record / business write / AI financial rec → T2', () => {
    expect(computeRiskFloor(signals({ integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ integration_types: ['BUSINESS_SYSTEM_WRITE'] })).floor).toBe('T2');
    expect(computeRiskFloor(signals({ ai_behavior: 'FINANCIAL_RECOMMENDATION' })).floor).toBe('T2');
  });
});

describe('deterministic floors — T3 triggers (single high-risk characteristic)', () => {
  it('trading/orders alone → T3', () => {
    expect(computeRiskFloor(signals({ integration_types: ['TRADING_OR_ORDERS'] })).floor).toBe('T3');
  });
  it('payments/transfers alone → T3', () => {
    expect(computeRiskFloor(signals({ integration_types: ['PAYMENTS_OR_TRANSFERS'] })).floor).toBe('T3');
  });
  it('outbound external communication → T3', () => {
    expect(computeRiskFloor(signals({ integration_types: ['OUTBOUND_COMMUNICATION'] })).floor).toBe('T3');
  });
  it('consequential decision → T3', () => {
    expect(computeRiskFloor(signals({ ai_behavior: 'CONSEQUENTIAL_DECISION' })).floor).toBe('T3');
  });
  it('autonomous in production → T3', () => {
    expect(
      computeRiskFloor(signals({ autonomy_level: 'AUTONOMOUS', deployment_surface: 'PRODUCTION' })).floor,
    ).toBe('T3');
  });
  it('MNPI or credentials exposure → T3', () => {
    expect(computeRiskFloor(signals({ data_classes: ['MNPI'] })).floor).toBe('T3');
    expect(computeRiskFloor(signals({ data_classes: ['CREDENTIALS'] })).floor).toBe('T3');
  });
});

describe('deterministic floors — low baseline', () => {
  it('public only, no integrations, no AI → T0', () => {
    expect(computeRiskFloor(signals({ data_classes: ['PUBLIC'] })).floor).toBe('T0');
  });
  it('internal business data / read-only → T1', () => {
    expect(computeRiskFloor(signals({ data_classes: ['INTERNAL_BUSINESS'] })).floor).toBe('T1');
    expect(computeRiskFloor(signals({ integration_types: ['READ_ONLY_API'] })).floor).toBe('T1');
  });
});

describe('reference cases (spec §10)', () => {
  it('A. public marketing microsite → T0/T1', () => {
    const floor = computeRiskFloor(
      signals({ data_classes: ['PUBLIC'], integration_types: ['NONE'], ai_behavior: 'NONE' }),
    ).floor;
    expect(tierRank(floor)).toBeLessThanOrEqual(tierRank('T1'));
  });

  it('B. commission reconciliation using client trade + accounting data → T2', () => {
    const floor = computeRiskFloor(
      signals({
        data_classes: ['CLIENT_PII', 'TRANSACTION_DATA'],
        integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'],
        ai_behavior: 'INFORMATIONAL',
        autonomy_level: 'HUMAN_IN_LOOP',
        regulatory_domains: ['BOOKS_AND_RECORDS'],
      }),
    ).floor;
    expect(floor).toBe('T2');
  });

  it('C. autonomous trading / order-execution agent → T3', () => {
    const floor = computeRiskFloor(
      signals({
        data_classes: ['CLIENT_PII', 'TRANSACTION_DATA'],
        integration_types: ['TRADING_OR_ORDERS'],
        ai_behavior: 'CONSEQUENTIAL_DECISION',
        autonomy_level: 'AUTONOMOUS',
        deployment_surface: 'PRODUCTION',
        regulatory_domains: ['SEC', 'FINRA'],
      }),
    ).floor;
    expect(floor).toBe('T3');
  });
});

describe('downgrade below floor is blocked', () => {
  it('a confirmed tier below the floor clamps up to the floor', () => {
    const floor = computeRiskFloor(signals({ data_classes: ['CLIENT_PII'] })).floor; // T2
    const confirmedTier = 'T1'; // user tries to downgrade
    const finalTier = maxTier(floor, confirmedTier);
    expect(finalTier).toBe('T2'); // downgrade blocked
  });
  it('a confirmed tier above the floor is honored (AI/human may raise)', () => {
    const floor = computeRiskFloor(signals({ data_classes: ['INTERNAL_BUSINESS'] })).floor; // T1
    const finalTier = maxTier(floor, 'T3');
    expect(finalTier).toBe('T3');
  });
});
