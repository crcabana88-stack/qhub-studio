/**
 * QHUB Gate 05 — Exact-version attestation types (BROWSER-SAFE)
 * app/lib/qhub/release-candidate.ts
 *
 * Shared type surface for the ATTEST stage: freezing an exact release candidate,
 * collecting authorized human attestations bound to its hash, and authorizing
 * deployment. Contains NO secrets and NO server-only APIs.
 */

import type { RiskTier } from './classification';

// ─── File manifest ────────────────────────────────────────────────────────────

/** One generated file, identified by path + content hash (never raw content). */
export interface FileManifestEntry {
  path: string;
  sha256: string; // hex sha256 of the file content (computed client-side, canonicalized server-side)
  size: number;
}

// ─── Release candidate ────────────────────────────────────────────────────────

export type ReleaseStatus =
  | 'DRAFT'
  | 'FROZEN'
  | 'AWAITING_ATTESTATION'
  | 'APPROVED'
  | 'REJECTED'
  | 'SUPERSEDED'
  | 'DEPLOYED';

export type TargetEnvironment = 'PREVIEW' | 'STAGING' | 'PRODUCTION';

/**
 * The canonical, versioned identity of an exact app/agent version submitted for
 * attestation. `release_candidate_hash` is computed SERVER-SIDE from the canonical
 * representation; identical canonical inputs → identical hash; any material change
 * → a different hash. Contains only hashes/refs — never raw source, secrets, or data.
 */
export interface ReleaseCandidate {
  release_candidate_id: string;
  qhub_app_id: string;
  qhub_app_version: number;
  conversation_id: string;

  source_commit: string | null;
  canonical_file_manifest_hash: string;
  file_count: number;
  build_artifact_digest: string | null;
  dependency_lockfile_hash: string | null;

  classification_version: number;
  classification_reference: string | null;
  risk_tier: RiskTier;

  policy_profile_id: string;
  policy_profile_version: number;
  policy_profile_hash: string;

  enforcement_plan_id: string;
  enforcement_plan_version: number;
  enforcement_plan_hash: string;

  model_manifest_hash: string; // declared models/providers
  connector_manifest_hash: string; // declared connectors/tools
  data_access_manifest_hash: string; // declared data access

  target_environment: TargetEnvironment;
  deployment_target: string;
  release_scope: string;

  created_by: string;
  created_at: string;
  manifest_version: string;
  release_candidate_hash: string;
  status: ReleaseStatus;
  supersedes_release_candidate_id: string | null;
}

// ─── Attestation requirements ─────────────────────────────────────────────────

export type AttestationPurpose =
  | 'BUSINESS_OWNER'
  | 'COMPLIANCE'
  | 'GOVERNANCE'
  | 'SECURITY'
  | 'TECHNOLOGY'
  | 'MODEL_RISK'
  | 'DESIGNATED_PRINCIPAL'
  | 'DEPLOYMENT_AUTHORIZER';

export interface AttestationRequirement {
  requirement_id: string;
  purpose: AttestationPurpose;

  /** Roles that may satisfy this purpose (server-authoritative role mapping). */
  roles: string[];
  min_signers: number;

  /** True when the signers must be independent (no self-approval, distinct people). */
  distinct_signers: boolean;
}

// ─── Attestation ──────────────────────────────────────────────────────────────

export type AttestationStatus = 'VALID' | 'SUPERSEDED' | 'REVOKED' | 'EXPIRED' | 'INVALIDATED';

export interface Attestation {
  attestation_id: string;
  release_candidate_id: string;
  release_candidate_hash: string;
  qhub_app_id: string;
  qhub_app_version: number;
  signer_user_id: string;
  signer_org_id: string;
  signer_role: string;
  authority_source: string;
  attestation_purpose: AttestationPurpose;
  attestation_scope: string;
  target_environment: TargetEnvironment;
  policy_profile_id: string;
  policy_profile_version: number;
  policy_profile_hash: string;
  enforcement_plan_id: string;
  enforcement_plan_version: number;
  enforcement_plan_hash: string;
  attestation_statement_version: string;
  attestation_statement_hash: string;
  signed_at: string;
  expires_at: string | null;
  status: AttestationStatus;
  supersedes_attestation_id: string | null;
  evidence_reference: string | null;
}

// ─── Deployment decision ──────────────────────────────────────────────────────

export type DeploymentDecisionValue = 'APPROVE' | 'REJECT';

export interface DeploymentDecision {
  decision_id: string;
  release_candidate_id: string;
  release_candidate_hash: string;
  qhub_app_id: string;
  decision: DeploymentDecisionValue;
  reason_codes: string[];
  satisfied_requirements: string[];
  missing_requirements: string[];
  target_environment: TargetEnvironment;
  decided_at: string;
  decided_by: string;
}

export type ReleaseReasonCode =
  | 'APPROVED_ALL_ATTESTATIONS'
  | 'NOT_FROZEN'
  | 'HASH_MISMATCH'
  | 'SCHEMA_NOT_READY'
  | 'CLASSIFICATION_STALE'
  | 'POLICY_STALE'
  | 'PLAN_STALE'
  | 'MISSING_ATTESTATION'
  | 'ATTESTATION_EXPIRED'
  | 'ATTESTATION_REVOKED'
  | 'ATTESTATION_SUPERSEDED'
  | 'ATTESTATION_WRONG_RELEASE'
  | 'ATTESTATION_WRONG_ENVIRONMENT'
  | 'SIGNER_NOT_AUTHORIZED'
  | 'SELF_APPROVAL_DENIED'
  | 'DISTINCT_SIGNERS_REQUIRED'
  | 'TENANT_MISMATCH'
  | 'RELEASE_NOT_FOUND'
  | 'ENVIRONMENT_MISMATCH'
  | 'DECISION_RECORD_FAILED';

// ─── Release assurance receipt ────────────────────────────────────────────────

export interface ReleaseAssuranceReceipt {
  receipt_version: string;
  release_candidate_id: string;
  release_candidate_hash: string;
  qhub_app_id: string;
  qhub_app_version: number;
  target_environment: TargetEnvironment;
  risk_tier: RiskTier;
  classification_version: number;
  policy_profile_hash: string;
  enforcement_plan_hash: string;
  required_attestation_purposes: AttestationPurpose[];
  completed_attestations: { attestation_id: string; purpose: AttestationPurpose; signer_role: string }[];
  deployment_decision: DeploymentDecisionValue | null;
  deployment_decision_id: string | null;
  known_exceptions: string[];
  generated_at: string;
  receipt_hash: string;
}

export const RELEASE_MANIFEST_VERSION = 'gate05-manifest-1.0.0';
export const ATTESTATION_STATEMENT_VERSION = 'gate05-statement-1.0.0';
export const RELEASE_RECEIPT_VERSION = 'gate05-receipt-1.0.0';
