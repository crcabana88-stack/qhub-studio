/**
 * QHUB Gate 04 — Control Enforcement types (BROWSER-SAFE)
 * app/lib/qhub/enforcement.ts
 *
 * Shared type surface for the ENFORCE stage: turning a confirmed Gate 03 policy
 * profile into deterministic, fail-closed runtime decisions for one exact action.
 *
 * Contains NO secrets and NO server-only APIs.
 */

import type { RiskTier } from './classification';

// ─── Governed actions (the protected side effects) ────────────────────────────

/**
 * Every action type the enforcement engine can reason about. Only a subset is
 * OPERATIONALLY WIRED to a real executing route today (see WIRED_ACTION_TYPES in
 * enforcement-catalog.ts); the rest are evaluated (so their DENY/REQUIRE_APPROVAL
 * is authoritative) but have no side-effect adapter yet.
 */
export type GovernedActionType =
  | 'AI_MODEL_INVOCATION' // the real, wired side effect (→ AI_MODEL_INVOKED event)
  | 'APP_GENERATION'
  | 'CODE_MODIFICATION'
  | 'PREVIEW_CREATION'
  | 'DEPLOYMENT_EXECUTION'
  | 'PRODUCTION_EXECUTION'
  | 'EXTERNAL_DATA_TRANSMISSION'
  | 'DATABASE_MUTATION'
  | 'CREDENTIAL_USE'
  | 'TRADING_OR_ORDER_ROUTING'
  | 'AGENT_TOOL_EXECUTION';

export type Environment = 'PREVIEW' | 'INTERNAL' | 'PRODUCTION';

// ─── Decision & control result ────────────────────────────────────────────────

/** Closed decision enum. No WARN/CONDITIONAL — advisory findings live in reason_codes. */
export type Decision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export type ControlStatus = 'PASS' | 'FAIL' | 'REQUIRE_APPROVAL' | 'NOT_APPLICABLE';

export type EnforcementPhase = 'RUNTIME' | 'BUILD_TIME' | 'DEPLOY_TIME' | 'ATTESTATION' | 'PROHIBITION';

export type FailureMode = 'FAIL_CLOSED' | 'FAIL_OPEN';

/** Operating mode stamped on the decision — always fail-closed for mandatory controls. */
export type EnforcementMode = 'FAIL_CLOSED';

/**
 * Stable, non-secret reason codes. Safe to surface to the browser. Additive only —
 * never renumber or repurpose an existing code (they appear in immutable evidence).
 */
export type ReasonCode =
  | 'ALLOWED_BASELINE'
  | 'ALLOWED_APPROVED'
  | 'NO_SESSION'
  | 'TENANT_MISMATCH'
  | 'APP_NOT_FOUND'
  | 'SCHEMA_NOT_READY'
  | 'CLASSIFICATION_MISSING'
  | 'POLICY_MISSING'
  | 'POLICY_HASH_MISMATCH'
  | 'PLAN_MISSING'
  | 'PLAN_COMPILE_FAILED'
  | 'PLAN_HASH_MISMATCH'
  | 'PLAN_SUPERSEDED'
  | 'UNSUPPORTED_MANDATORY_CONTROL'
  | 'CLIENT_OVERRIDE_REJECTED'
  | 'ACTION_DIGEST_MISMATCH'
  | 'ACTION_TYPE_NOT_PROTECTED'
  | 'ATTESTATION_REQUIRED'
  | 'ATTESTATION_MISSING'
  | 'ATTESTATION_EXPIRED'
  | 'ATTESTATION_CONSUMED'
  | 'ATTESTATION_REVOKED'
  | 'ATTESTATION_WRONG_SCOPE'
  | 'ATTESTATION_WRONG_ROLE'
  | 'DUAL_CONTROL_REQUIRED'
  | 'SELF_APPROVAL_DENIED'
  | 'KILL_SWITCH_ACTIVE'
  | 'ACTION_NOT_ALLOWLISTED'
  | 'UNRESTRICTED_AUTONOMY_DENIED'
  | 'PREVIEW_ONLY_PRODUCTION_DENIED'
  | 'PRODUCTION_APPROVAL_REQUIRED'
  | 'RBAC_DENIED'
  | 'EGRESS_DENIED'
  | 'LIMIT_EXCEEDED'
  | 'MODEL_NOT_APPROVED'
  | 'REPLAY_DENIED'
  | 'EVALUATION_CONSUMED'
  | 'DECISION_RECORD_FAILED'
  | 'APPROVAL_CONSUMPTION_FAILED'
  | 'LEDGER_UNAVAILABLE';

export interface ControlResult {
  control_id: string;
  status: ControlStatus;
  reason_code: ReasonCode;
}

// ─── Enforcement plan ─────────────────────────────────────────────────────────

export interface EnforcementPlanEntry {
  control_id: string;
  title: string;
  phase: EnforcementPhase;
  adapter: string;

  /** Which action types this control gates. */
  guards: GovernedActionType[];
  mandatory: boolean;
  failure_mode: FailureMode;

  /** Whether a registered adapter exists to enforce this control at runtime. */
  enforceable: boolean;
  params?: Record<string, string | number | boolean | string[]>;
}

export interface ApprovalRequirement {
  requirement_id: string;
  attestation_type: string; // e.g. OWNER_ATTESTATION, AUTHORIZED_GOVERNANCE_APPROVAL
  applies_to: GovernedActionType[];

  /** Number of distinct approvals required (2 = dual control / four-eyes). */
  min_approvals: number;
  distinct_approvers: boolean;

  /** Roles that may satisfy this requirement (empty = any authenticated approver). */
  roles: string[];
}

export interface ActionLimit {
  limit_id: string;
  applies_to: GovernedActionType[];
  kind: 'VALUE' | 'RATE' | 'COUNT';
  max: number;
}

export interface AllowlistSet {
  models: string[]; // empty = no model restriction
  tools: string[];
  integrations: string[];
}

export type EnforcementPlanStatus = 'ACTIVE' | 'SUPERSEDED' | 'SUSPENDED';

export interface EnforcementPlan {
  enforcement_plan_id: string;
  enforcement_plan_version: number;
  qhub_app_id: string;
  classification_version: number;
  policy_profile_id: string;
  policy_profile_version: number;
  policy_profile_hash: string;
  policy_catalog_version: string;
  risk_tier: RiskTier;

  protected_action_types: GovernedActionType[];
  control_rules: EnforcementPlanEntry[];
  approval_requirements: ApprovalRequirement[];
  limits: ActionLimit[];
  allowlists: AllowlistSet;

  /** Action types restricted to preview/sandbox until production is authorized. */
  preview_only_actions: GovernedActionType[];

  /** Action types whose PRODUCTION environment requires explicit authorized approval. */
  production_restricted_actions: GovernedActionType[];

  /** Action types on which unrestricted autonomy is prohibited. */
  no_unrestricted_autonomy_actions: GovernedActionType[];
  kill_switch_required: boolean;

  generated_at: string;
  compiler_version: string;
  enforcement_plan_hash: string;
  status: EnforcementPlanStatus;
}

// ─── Canonical action request ─────────────────────────────────────────────────

export interface CanonicalActionRequest {
  tenant_id: string; // client_id / org_id (server-authoritative)
  qhub_app_id: string;
  action_request_id: string; // server-issued nonce
  action_type: GovernedActionType;
  target_resource: string;
  operation: string;
  material_parameters_hash: string; // sha256 of material params — never raw params
  model_identity: string | null;
  provider_identity: string | null;
  tool_identity: string | null;
  environment: Environment;
  app_version_ref: string | null;
  policy_profile_id: string;
  policy_profile_version: number;
  policy_profile_hash: string;
  enforcement_plan_id: string;
  enforcement_plan_version: number;
  enforcement_plan_hash: string;
}

// ─── Decision engine I/O ──────────────────────────────────────────────────────

/** An approval as gathered from the store — authoritative, never browser-supplied. */
export interface GatheredApproval {
  attestation_type: string;
  approver_id: string;
  approver_role: string;

  /** Digest the approval was scoped to; must equal the action_digest under evaluation. */
  scoped_action_digest: string;
  scoped_policy_profile_hash: string;
  scoped_enforcement_plan_hash: string;
  status: 'GRANTED' | 'CONSUMED' | 'REVOKED' | 'EXPIRED';
  expires_at: string;
}

export interface DecisionEngineInput {
  request: CanonicalActionRequest;
  action_digest: string;
  plan: EnforcementPlan;
  risk_tier: RiskTier;
  environment: Environment;

  /** Whether the caller requested unrestricted autonomous behavior. */
  autonomy_requested: 'NONE' | 'RESTRICTED' | 'UNRESTRICTED';
  kill_switch_active: boolean;

  /** Approvals already gathered for THIS exact action_digest + versions. */
  approvals: GatheredApproval[];

  /** Current usage per limit_id (for limit checks). */
  limit_usage: Record<string, number>;

  /** Actor requesting the action (for self-approval / RBAC checks). */
  actor_id: string;
  actor_role: string;
}

export interface EnforcementResult {
  decision: Decision;
  reason_codes: ReasonCode[];
  control_results: ControlResult[];
  required_attestations: string[];
  enforcement_plan_hash: string;
  evaluator_version: string;
}

// ─── Versions ─────────────────────────────────────────────────────────────────

export const ENFORCEMENT_COMPILER_VERSION = 'gate04-compiler-1.0.0';
export const ENFORCEMENT_EVALUATOR_VERSION = 'gate04-evaluator-1.0.0';
