/**
 * QHUB Gate 03 — Policy engine & reference cases
 * app/test/policy-engine.test.ts
 */

import { describe, it, expect } from 'vitest';
import { buildPolicyProfile, canonicalPolicyString, type PolicyEngineInput } from '~/lib/qhub/policy-engine';
import type { ClassificationSignals, RegulatoryDomain, RiskTier } from '~/lib/qhub/classification';

function input(
  tier: RiskTier,
  signals: Partial<ClassificationSignals>,
  regulatoryDomains: RegulatoryDomain[] = ['NONE_IDENTIFIED'],
): PolicyEngineInput {
  return {
    qhub_app_id: 'app-1',
    classification_version: 1,
    classification_reference: 'chain-1',
    risk_tier: tier,
    regulatory_domains: regulatoryDomains,
    policy_profile_version: 1,
    generated_by: 'svc',
    signals: {
      data_classes: [],
      integration_types: ['NONE'],
      ai_behavior: 'NONE',
      autonomy_level: 'NONE',
      deployment_surface: 'INTERNAL',
      regulatory_domains: regulatoryDomains,
      ...signals,
    },
  };
}

const ids = (cs: { control_id: string }[]) => cs.map((c) => c.control_id);

describe('mandatory controls are never weakened', () => {
  it('every required control is MANDATORY; conditional/advisory are not', () => {
    const p = buildPolicyProfile(input('T3', { integration_types: ['TRADING_OR_ORDERS'] }));
    expect(p.required_controls.every((c) => c.enforcement_level === 'MANDATORY')).toBe(true);
    expect(p.required_controls.length).toBeGreaterThan(0);
  });
});

describe('reference case A — public marketing microsite (T0)', () => {
  const p = buildPolicyProfile(input('T0', { data_classes: ['PUBLIC'] }));
  it('has only baseline controls, no enterprise controls', () => {
    expect(ids(p.required_controls)).toContain('SD-NO-CLIENT-SECRETS');
    expect(ids(p.required_controls)).toContain('AE-BASELINE-EVENTS');
    expect(ids(p.required_controls)).not.toContain('HO-OWNER-ATTESTATION');
    expect(ids(p.required_controls)).not.toContain('DE-PREVIEW-ONLY');
    expect(ids(p.required_controls)).not.toContain('IA-FORMAL-RBAC');
  });
  it('requires no attestations', () => {
    expect(p.required_attestations).toHaveLength(0);
  });
});

describe('reference case B — commission reconciliation (T2)', () => {
  const p = buildPolicyProfile(
    input(
      'T2',
      {
        data_classes: ['CLIENT_PII', 'TRANSACTION_DATA'],
        integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'],
        ai_behavior: 'INFORMATIONAL',
      },
      ['BOOKS_AND_RECORDS', 'SUPERVISION', 'SEC', 'FINRA'],
    ),
  );
  it('includes RBAC, tenant isolation, encryption, integration allowlist, books-and-records', () => {
    const req = ids(p.required_controls);
    expect(req).toEqual(
      expect.arrayContaining([
        'IA-FORMAL-RBAC',
        'TI-STRICT-ISOLATION',
        'DP-ENCRYPTION',
        'IT-INTEGRATION-ALLOWLIST',
        'RR-BOOKS-RECORDS',
      ]),
    );
  });
  it('requires owner attestation before production, but is not preview-only', () => {
    expect(ids(p.required_controls)).toContain('HO-OWNER-ATTESTATION');
    expect(p.required_attestations).toContain('OWNER_ATTESTATION');
    expect(ids(p.required_controls)).not.toContain('DE-PREVIEW-ONLY');
  });
});

describe('reference case C — autonomous trading agent (T3)', () => {
  const p = buildPolicyProfile(
    input(
      'T3',
      {
        data_classes: ['CLIENT_PII', 'MNPI'],
        integration_types: ['TRADING_OR_ORDERS'],
        ai_behavior: 'CONSEQUENTIAL_DECISION',
        autonomy_level: 'AUTONOMOUS',
        deployment_surface: 'PRODUCTION',
      },
      ['SEC', 'FINRA', 'CFTC'],
    ),
  );
  it('is preview-only with kill switch, limits, no unrestricted autonomy, authorized approval', () => {
    const req = ids(p.required_controls);
    expect(req).toEqual(
      expect.arrayContaining([
        'DE-PREVIEW-ONLY',
        'IR-KILL-SWITCH',
        'RM-ACTION-LIMITS',
        'RM-NO-UNRESTRICTED-AUTONOMY',
        'DE-EXPLICIT-PROD-APPROVAL',
        'HO-DUAL-CONTROL',
        'RM-RUNTIME-MONITORING',
      ]),
    );
  });
  it('requires authorized governance approval; preview constraint present', () => {
    expect(p.required_attestations).toContain('AUTHORIZED_GOVERNANCE_APPROVAL');
    expect(p.preview_constraints.some((c) => c.constraint_id === 'DE-PREVIEW-ONLY')).toBe(true);
  });
});

describe('deduplication of multiply-triggered controls', () => {
  it('a control triggered by several rules appears once with all reasons', () => {
    // AE-ENHANCED-EVIDENCE is triggered by MNPI, business-write, trading, payments, autonomy.
    const p = buildPolicyProfile(
      input('T3', {
        data_classes: ['MNPI'],
        integration_types: ['TRADING_OR_ORDERS', 'PAYMENTS_OR_TRANSFERS'],
        autonomy_level: 'AUTONOMOUS',
        deployment_surface: 'PRODUCTION',
      }),
    );
    const evidence = p.required_controls.filter((c) => c.control_id === 'AE-ENHANCED-EVIDENCE');
    expect(evidence).toHaveLength(1);
    expect(evidence[0].applicability_reasons.length).toBeGreaterThan(1);
  });
});

describe('policy profile hash stability', () => {
  it('identical canonical input → identical string', () => {
    const a = buildPolicyProfile(input('T2', { data_classes: ['CLIENT_PII'] }, ['SEC']));
    const b = buildPolicyProfile(input('T2', { data_classes: ['CLIENT_PII'] }, ['SEC']));
    expect(canonicalPolicyString(a)).toBe(canonicalPolicyString(b));
  });
  it('different tier → different string', () => {
    const a = buildPolicyProfile(input('T1', { data_classes: ['INTERNAL_BUSINESS'] }));
    const b = buildPolicyProfile(input('T2', { data_classes: ['CLIENT_PII'] }));
    expect(canonicalPolicyString(a)).not.toBe(canonicalPolicyString(b));
  });
  it('canonical string ignores timestamps/ids (order-independent content)', () => {
    const base = input('T2', { data_classes: ['CLIENT_PII'] }, ['SEC', 'FINRA']);
    const reordered = { ...base, regulatory_domains: ['FINRA', 'SEC'] as RegulatoryDomain[] };
    reordered.signals = { ...base.signals, regulatory_domains: ['FINRA', 'SEC'] };
    expect(canonicalPolicyString(buildPolicyProfile(base))).toBe(canonicalPolicyString(buildPolicyProfile(reordered)));
  });
});
