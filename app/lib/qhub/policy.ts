/**
 * QHUB Gate 03 — Policy types (BROWSER-SAFE)
 * app/lib/qhub/policy.ts
 *
 * Shared type surface for the POLICY stage of the QHUB lifecycle
 * (01 CLASSIFY → 02 POLICY → 03 BUILD → 04 ATTEST).
 *
 * Contains NO secrets and NO server-only APIs.
 */

import type { RegulatoryDomain, RiskTier } from './classification';

// ─── Enforcement & lifecycle ──────────────────────────────────────────────────

export type EnforcementLevel = 'MANDATORY' | 'CONDITIONAL' | 'ADVISORY';

export type LifecycleStage = 'PRE_BUILD' | 'BUILD' | 'PREVIEW' | 'PRE_DEPLOY' | 'DEPLOY' | 'RUNTIME';

export type ControlCategory =
  | 'IDENTITY_AND_ACCESS'
  | 'TENANT_ISOLATION'
  | 'DATA_PROTECTION'
  | 'MODEL_GOVERNANCE'
  | 'INTEGRATIONS_AND_TOOLS'
  | 'SECURE_DEVELOPMENT'
  | 'AUDIT_AND_EVIDENCE'
  | 'HUMAN_OVERSIGHT'
  | 'DEPLOYMENT'
  | 'RUNTIME_MONITORING'
  | 'RECORDS_AND_RETENTION'
  | 'INCIDENT_RESPONSE';

// ─── Canonical control definition (from the catalog) ──────────────────────────

export interface PolicyControl {
  control_id: string;
  title: string;
  category: ControlCategory;
  requirement: string;
  rationale: string;
  enforcement_level: EnforcementLevel;
  lifecycle_stage: LifecycleStage;
  verification_method: string;
  evidence_required: string;
  source_refs: string[];
  status: 'ACTIVE' | 'DEPRECATED';

  /** Concise, machine-readable statement for the governed-build handoff (if actionable at generation/runtime). */
  constraint?: string;
}

/** A control as it appears in a generated profile — with why it applies. */
export interface AppliedControl extends PolicyControl {
  applicability_reasons: string[];
}

// ─── Policy profile (the deterministic output) ────────────────────────────────

export type PolicyStatus = 'PROVISIONAL' | 'ASSIGNED' | 'ACKNOWLEDGED' | 'SUPERSEDED';

/** A concise, machine-readable constraint for the governed-build handoff. */
export interface Constraint {
  constraint_id: string;
  statement: string;
  control_ids: string[];
}

export interface PolicyProfile {
  policy_profile_id: string;
  qhub_app_id: string;
  classification_version: number;
  classification_reference: string | null; // chain_id or event hash
  policy_profile_version: number;
  policy_catalog_version: string;
  risk_tier: RiskTier;
  regulatory_domains: RegulatoryDomain[];

  required_controls: AppliedControl[]; // MANDATORY
  conditional_controls: AppliedControl[]; // CONDITIONAL
  advisory_controls: AppliedControl[]; // ADVISORY

  build_constraints: Constraint[];
  preview_constraints: Constraint[];
  deployment_constraints: Constraint[];
  runtime_constraints: Constraint[];

  required_attestations: string[];
  required_evidence: string[];

  generated_at: string;
  generated_by: string;
  confirmed_by: string | null;
  confirmed_at: string | null;
  policy_profile_hash: string;
  status: PolicyStatus;
}

// ─── Gate state machine (conceptual, spec §Gate States) ───────────────────────

export type PolicyGateState =
  | 'CLASSIFICATION_COMPLETE'
  | 'POLICY_REQUIRED'
  | 'POLICY_ASSIGNED'
  | 'POLICY_ACKNOWLEDGED'
  | 'BUILD_ALLOWED'
  | 'PREVIEW_ALLOWED'
  | 'PRODUCTION_APPROVAL_PENDING'
  | 'PRODUCTION_APPROVED'
  | 'BLOCKED';
