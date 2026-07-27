/**
 * QHUB Gate 05 — release manifest & requirement derivation tests
 * app/test/release-core.test.ts
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import type { ClassificationSignals, RegulatoryDomain, RiskTier } from '~/lib/qhub/classification';
import { buildPolicyProfile } from '~/lib/qhub/policy-engine';
import { compileEnforcementPlan } from '~/lib/qhub/enforcement-plan';
import {
  canonicalFileManifestString,
  canonicalReleaseCandidateString,
  canonicalReceiptString,
  canonicalStatementString,
  deriveAttestationRequirements,
} from '~/lib/qhub/release-manifest';
import { RELEASE_MANIFEST_VERSION, type FileManifestEntry, type ReleaseCandidate } from '~/lib/qhub/release-candidate';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function signals(o: Partial<ClassificationSignals> = {}): ClassificationSignals {
  return {
    data_classes: [],
    integration_types: ['NONE'],
    ai_behavior: 'NONE',
    autonomy_level: 'NONE',
    deployment_surface: 'INTERNAL',
    regulatory_domains: ['NONE_IDENTIFIED'],
    ...o,
  };
}

function classification(
  tier: RiskTier,
  s: Partial<ClassificationSignals> = {},
  d: RegulatoryDomain[] = ['NONE_IDENTIFIED'],
) {
  const sig = signals(s);
  return {
    classification_version: 1,
    risk_tier: tier,
    risk_floor: tier,
    ai_proposed_tier: tier,
    classification_method: 'HUMAN_CONFIRMED' as const,
    regulatory_domains: d,
    data_classes: sig.data_classes,
    integration_types: sig.integration_types,
    ai_behavior: sig.ai_behavior,
    autonomy_level: sig.autonomy_level,
    deployment_surface: sig.deployment_surface,
    rationale: 'x',
    floor_reasons: [],
    confidence: 0.9,
    confirmed_by: 'u',
    confirmed_at: 'x',
    classifier_version: 'v',
  };
}

function profileFor(
  tier: RiskTier,
  s: Partial<ClassificationSignals> = {},
  d: RegulatoryDomain[] = ['NONE_IDENTIFIED'],
) {
  const p = buildPolicyProfile({
    qhub_app_id: 'app-1',
    classification_version: 1,
    classification_reference: 'c',
    risk_tier: tier,
    regulatory_domains: d,
    signals: signals({ ...s, regulatory_domains: d }),
    policy_profile_version: 1,
    generated_by: 'svc',
  });
  p.policy_profile_id = 'pp-1';
  p.policy_profile_hash = sha256('policy-' + tier);
  p.generated_at = 'x';

  return p;
}

function planFor(tier: RiskTier, s: Partial<ClassificationSignals> = {}, d: RegulatoryDomain[] = ['NONE_IDENTIFIED']) {
  const plan = compileEnforcementPlan({
    profile: profileFor(tier, s, d),
    classification: classification(tier, s, d),
    enforcement_plan_version: 1,
  });
  plan.enforcement_plan_id = 'ep-1';
  plan.enforcement_plan_hash = sha256('plan-' + tier);
  plan.generated_at = 'x';

  return plan;
}

const FILES: FileManifestEntry[] = [
  { path: 'src/App.tsx', sha256: sha256('appcode'), size: 100 },
  { path: 'package.json', sha256: sha256('pkg'), size: 50 },
];

function rc(
  over: Partial<ReleaseCandidate> = {},
): Omit<
  ReleaseCandidate,
  | 'release_candidate_id'
  | 'created_at'
  | 'created_by'
  | 'release_candidate_hash'
  | 'status'
  | 'supersedes_release_candidate_id'
> {
  return {
    qhub_app_id: 'app-1',
    qhub_app_version: 1,
    conversation_id: 'conv-1',
    source_commit: null,
    canonical_file_manifest_hash: sha256(canonicalFileManifestString(FILES)),
    file_count: FILES.length,
    build_artifact_digest: null,
    dependency_lockfile_hash: sha256('lock-v1'),
    classification_version: 1,
    classification_reference: 'chain-1',
    risk_tier: 'T2',
    policy_profile_id: 'pp-1',
    policy_profile_version: 1,
    policy_profile_hash: sha256('policy-T2'),
    enforcement_plan_id: 'ep-1',
    enforcement_plan_version: 1,
    enforcement_plan_hash: sha256('plan-T2'),
    model_manifest_hash: sha256('models:claude-sonnet-4-6'),
    connector_manifest_hash: sha256('connectors:sor'),
    data_access_manifest_hash: sha256('data:client_pii'),
    target_environment: 'PRODUCTION',
    deployment_target: 'netlify:prod',
    release_scope: 'full',
    manifest_version: RELEASE_MANIFEST_VERSION,
    ...over,
  };
}

const H = (r: ReturnType<typeof rc>) => sha256(canonicalReleaseCandidateString(r));

describe('canonical file manifest', () => {
  it('is order-independent and stable', () => {
    expect(canonicalFileManifestString(FILES)).toBe(canonicalFileManifestString([...FILES].reverse()));
  });
  it('changes when a file content hash changes', () => {
    const changed = [{ ...FILES[0], sha256: sha256('appcode-EDITED') }, FILES[1]];
    expect(canonicalFileManifestString(FILES)).not.toBe(canonicalFileManifestString(changed));
  });
});

describe('release_candidate_hash', () => {
  it('is stable for identical inputs (test 1)', () => {
    expect(H(rc())).toBe(H(rc()));
  });
  it('changes on source-file change (test 2)', () => {
    const edited = rc({ canonical_file_manifest_hash: sha256('different-manifest') });
    expect(H(rc())).not.toBe(H(edited));
  });
  it('changes on dependency-lockfile change (test 3)', () => {
    expect(H(rc())).not.toBe(H(rc({ dependency_lockfile_hash: sha256('lock-v2') })));
  });
  it('changes on model/provider change (test 4)', () => {
    expect(H(rc())).not.toBe(H(rc({ model_manifest_hash: sha256('models:other') })));
  });
  it('changes on connector/tool change (test 5)', () => {
    expect(H(rc())).not.toBe(H(rc({ connector_manifest_hash: sha256('connectors:other') })));
  });
  it('changes on data-access change', () => {
    expect(H(rc())).not.toBe(H(rc({ data_access_manifest_hash: sha256('data:other') })));
  });
  it('changes on policy revision (test 6)', () => {
    expect(H(rc())).not.toBe(H(rc({ policy_profile_hash: sha256('policy-REVISED') })));
  });
  it('changes on enforcement-plan revision (test 7)', () => {
    expect(H(rc())).not.toBe(H(rc({ enforcement_plan_hash: sha256('plan-REVISED') })));
  });
  it('changes on target-environment change (test 8)', () => {
    expect(H(rc())).not.toBe(H(rc({ target_environment: 'STAGING' })));
  });
  it('changes on classification revision', () => {
    expect(H(rc())).not.toBe(H(rc({ classification_version: 2 })));
  });
});

describe('deriveAttestationRequirements (from policy, not tier alone)', () => {
  it('T0 requires no formal attestation', () => {
    expect(
      deriveAttestationRequirements(
        profileFor('T0', { data_classes: ['PUBLIC'] }),
        planFor('T0', { data_classes: ['PUBLIC'] }),
      ),
    ).toHaveLength(0);
  });
  it('T2 requires business-owner attestation', () => {
    const reqs = deriveAttestationRequirements(
      profileFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, [
        'BOOKS_AND_RECORDS',
      ]),
      planFor('T2', { data_classes: ['CLIENT_PII'], integration_types: ['EXTERNAL_SYSTEM_OF_RECORD'] }, [
        'BOOKS_AND_RECORDS',
      ]),
    );
    expect(reqs.map((r) => r.purpose)).toContain('BUSINESS_OWNER');
  });
  it('T3 requires owner + governance (dual, 2 distinct) + change/technology', () => {
    const s = {
      data_classes: ['MNPI' as const],
      integration_types: ['TRADING_OR_ORDERS' as const],
      autonomy_level: 'AUTONOMOUS' as const,
      deployment_surface: 'PRODUCTION' as const,
    };
    const reqs = deriveAttestationRequirements(
      profileFor('T3', s, ['SEC', 'FINRA', 'CFTC']),
      planFor('T3', s, ['SEC', 'FINRA', 'CFTC']),
    );
    const byPurpose = Object.fromEntries(reqs.map((r) => [r.purpose, r]));
    expect(byPurpose.BUSINESS_OWNER).toBeTruthy();
    expect(byPurpose.GOVERNANCE.min_signers).toBe(2);
    expect(byPurpose.GOVERNANCE.distinct_signers).toBe(true);
    expect(byPurpose.TECHNOLOGY).toBeTruthy();
  });
});

describe('statement + receipt hashes', () => {
  it('statement hash stable for identical inputs', () => {
    const p = {
      version: 'v1',
      purpose: 'BUSINESS_OWNER' as const,
      statement: 'I attest...',
      release_candidate_hash: 'abc',
      target_environment: 'PRODUCTION',
      scope: 'full',
    };
    expect(sha256(canonicalStatementString(p))).toBe(sha256(canonicalStatementString({ ...p })));
  });
  it('receipt hash stable + changes with release hash', () => {
    const base = {
      receipt_version: 'v1',
      release_candidate_id: 'rc-1',
      release_candidate_hash: 'H1',
      qhub_app_id: 'app-1',
      qhub_app_version: 1,
      target_environment: 'PRODUCTION' as const,
      risk_tier: 'T2' as const,
      classification_version: 1,
      policy_profile_hash: 'p',
      enforcement_plan_hash: 'e',
      required_attestation_purposes: ['BUSINESS_OWNER' as const],
      completed_attestations: [],
      deployment_decision: 'APPROVE' as const,
      deployment_decision_id: 'd1',
      known_exceptions: [],
    };
    expect(sha256(canonicalReceiptString(base))).toBe(sha256(canonicalReceiptString({ ...base })));
    expect(sha256(canonicalReceiptString(base))).not.toBe(
      sha256(canonicalReceiptString({ ...base, release_candidate_hash: 'H2' })),
    );
  });
});
