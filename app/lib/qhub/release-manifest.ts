/**
 * QHUB Gate 05 — Release manifest & attestation-requirement derivation (PURE)
 * app/lib/qhub/release-manifest.ts
 *
 * Canonical serializers (hash preimages) and the deterministic derivation of
 * required attestations from the confirmed policy profile + enforcement plan.
 * PURE: no I/O, no crypto, no secrets. Identical inputs → identical strings.
 */

import type { PolicyProfile } from './policy';
import type { EnforcementPlan } from './enforcement';
import type {
  AttestationPurpose,
  AttestationRequirement,
  FileManifestEntry,
  ReleaseAssuranceReceipt,
  ReleaseCandidate,
} from './release-candidate';

/** Canonical string over the file manifest — the `canonical_file_manifest_hash` preimage. */
export function canonicalFileManifestString(files: FileManifestEntry[]): string {
  const rows = files.map((f) => `${f.path}|${f.sha256}|${f.size}`).sort();

  return JSON.stringify(rows);
}

/**
 * Canonical string over the release candidate's MATERIAL content — the
 * `release_candidate_hash` preimage. Excludes ids/timestamps/status/actor. Any
 * material change (files, deps, models, connectors, data access, classification,
 * policy, plan, environment, target, scope, version) yields a different hash.
 */
export function canonicalReleaseCandidateString(
  rc: Omit<
    ReleaseCandidate,
    | 'release_candidate_id'
    | 'created_at'
    | 'created_by'
    | 'release_candidate_hash'
    | 'status'
    | 'supersedes_release_candidate_id'
  >,
): string {
  const canonical = {
    manifest_version: rc.manifest_version,
    qhub_app_id: rc.qhub_app_id,
    source_commit: rc.source_commit,
    canonical_file_manifest_hash: rc.canonical_file_manifest_hash,
    file_count: rc.file_count,
    build_artifact_digest: rc.build_artifact_digest,
    dependency_lockfile_hash: rc.dependency_lockfile_hash,
    classification_version: rc.classification_version,
    risk_tier: rc.risk_tier,
    policy_profile_version: rc.policy_profile_version,
    policy_profile_hash: rc.policy_profile_hash,
    enforcement_plan_version: rc.enforcement_plan_version,
    enforcement_plan_hash: rc.enforcement_plan_hash,
    model_manifest_hash: rc.model_manifest_hash,
    connector_manifest_hash: rc.connector_manifest_hash,
    data_access_manifest_hash: rc.data_access_manifest_hash,
    target_environment: rc.target_environment,
    deployment_target: rc.deployment_target,
    release_scope: rc.release_scope,
  };

  return JSON.stringify(canonical);
}

/**
 * Derive required attestations from the assigned policy profile + enforcement
 * plan — NOT from risk tier alone. Empty when policy requires no formal
 * attestation (e.g. T0). Dual control (from the plan) raises GOVERNANCE to two
 * distinct signers.
 */
export function deriveAttestationRequirements(profile: PolicyProfile, plan: EnforcementPlan): AttestationRequirement[] {
  const reqs: AttestationRequirement[] = [];
  const att = new Set(profile.required_attestations);
  const hasDual = plan.approval_requirements.some((r) => r.requirement_id === 'REQ-DUAL' && r.min_approvals >= 2);

  if (att.has('OWNER_ATTESTATION')) {
    reqs.push({
      requirement_id: 'ATT-OWNER',
      purpose: 'BUSINESS_OWNER',
      roles: ['owner', 'admin'],
      min_signers: 1,
      distinct_signers: false,
    });
  }

  if (att.has('AUTHORIZED_GOVERNANCE_APPROVAL')) {
    reqs.push({
      requirement_id: 'ATT-GOV',
      purpose: 'GOVERNANCE',
      roles: ['governance', 'compliance', 'security'],
      min_signers: hasDual ? 2 : 1,
      distinct_signers: true,
    });
  }

  if (att.has('CHANGE_ATTESTATION')) {
    reqs.push({
      requirement_id: 'ATT-CHANGE',
      purpose: 'TECHNOLOGY',
      roles: ['owner', 'admin', 'technology'],
      min_signers: 1,
      distinct_signers: false,
    });
  }

  return reqs.sort((a, b) => a.requirement_id.localeCompare(b.requirement_id));
}

/** Canonical string for an attestation statement — the statement_hash preimage. */
export function canonicalStatementString(params: {
  version: string;
  purpose: AttestationPurpose;
  statement: string;
  release_candidate_hash: string;
  target_environment: string;
  scope: string;
}): string {
  return JSON.stringify({
    version: params.version,
    purpose: params.purpose,
    statement: params.statement,
    release_candidate_hash: params.release_candidate_hash,
    target_environment: params.target_environment,
    scope: params.scope,
  });
}

/** The versioned, explicit attestation statement shown to (and hashed for) a signer. */
export function attestationStatementText(purpose: AttestationPurpose, env: string): string {
  const role: Record<AttestationPurpose, string> = {
    BUSINESS_OWNER: 'the application owner',
    COMPLIANCE: 'a compliance approver',
    GOVERNANCE: 'an authorized governance approver',
    SECURITY: 'a security approver',
    TECHNOLOGY: 'a technology approver',
    MODEL_RISK: 'a model-risk approver',
    DESIGNATED_PRINCIPAL: 'a designated principal',
    DEPLOYMENT_AUTHORIZER: 'the deployment authorizer',
  };

  return (
    `As ${role[purpose]}, I attest that I have reviewed THIS EXACT QHUB release ` +
    `candidate (identified by its release hash), understand its business purpose and ` +
    `assigned controls, and authorize it for the ${env} environment and the stated ` +
    `scope, subject to the listed restrictions and known exceptions. I understand this ` +
    `authorization applies only to this exact version and is void if any code, ` +
    `dependency, model, connector, data access, policy, enforcement plan, or target ` +
    `environment changes.`
  );
}

/** Canonical string for a release-assurance receipt — the receipt_hash preimage. */
export function canonicalReceiptString(r: Omit<ReleaseAssuranceReceipt, 'receipt_hash' | 'generated_at'>): string {
  return JSON.stringify({
    receipt_version: r.receipt_version,
    release_candidate_id: r.release_candidate_id,
    release_candidate_hash: r.release_candidate_hash,
    qhub_app_id: r.qhub_app_id,
    qhub_app_version: r.qhub_app_version,
    target_environment: r.target_environment,
    risk_tier: r.risk_tier,
    classification_version: r.classification_version,
    policy_profile_hash: r.policy_profile_hash,
    enforcement_plan_hash: r.enforcement_plan_hash,
    required_attestation_purposes: [...r.required_attestation_purposes].sort(),
    completed_attestations: r.completed_attestations
      .map((c) => `${c.purpose}|${c.signer_role}|${c.attestation_id}`)
      .sort(),
    deployment_decision: r.deployment_decision,
    deployment_decision_id: r.deployment_decision_id,
    known_exceptions: [...r.known_exceptions].sort(),
  });
}
