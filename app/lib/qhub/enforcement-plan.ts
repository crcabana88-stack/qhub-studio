/**
 * QHUB Gate 04 — Enforcement-plan compiler & canonical serializers (PURE)
 * app/lib/qhub/enforcement-plan.ts
 *
 * Compiles a confirmed Gate 03 policy profile + classification into a versioned,
 * deterministic enforcement plan, and provides the canonical strings that are
 * hashed (server-side) into `enforcement_plan_hash` and `action_digest`.
 *
 * PURE: no I/O, no crypto, no secrets. Independently unit-testable. Identical
 * canonical inputs always produce identical canonical strings (and thus hashes).
 */

import type { ClassificationResult, ClassificationSignals, RiskTier } from './classification';
import type { PolicyProfile } from './policy';
import {
  CONTROL_ENFORCEMENT,
  PRODUCTION_CAPABLE_ACTIONS,
  protectedActionTypesFor,
} from './enforcement-catalog';
import {
  ENFORCEMENT_COMPILER_VERSION,
  type ActionLimit,
  type AllowlistSet,
  type ApprovalRequirement,
  type CanonicalActionRequest,
  type EnforcementPlan,
  type EnforcementPlanEntry,
  type GovernedActionType,
} from './enforcement';

/** Models permitted for AI_MODEL_INVOCATION when an allowlist control applies. */
export const APPROVED_MODELS: string[] = ['claude-sonnet-4-6', 'claude-sonnet-4-5', 'claude-opus-4-8'];

function intersect(a: GovernedActionType[], b: GovernedActionType[]): GovernedActionType[] {
  const set = new Set(b);
  return a.filter((x) => set.has(x)).sort();
}

export interface CompilePlanInput {
  profile: PolicyProfile;
  classification: ClassificationResult;
  enforcement_plan_version: number;
}

/**
 * Compile the deterministic enforcement plan. Leaves server-only fields empty
 * (`enforcement_plan_id`, `generated_at`, `enforcement_plan_hash`).
 */
export function compileEnforcementPlan(input: CompilePlanInput): EnforcementPlan {
  const { profile, classification } = input;
  const signals: ClassificationSignals = {
    data_classes: classification.data_classes,
    integration_types: classification.integration_types,
    ai_behavior: classification.ai_behavior,
    autonomy_level: classification.autonomy_level,
    deployment_surface: classification.deployment_surface,
    regulatory_domains: classification.regulatory_domains,
  };
  const tier: RiskTier = profile.risk_tier;
  const protectedActions = protectedActionTypesFor(signals, tier);

  const requiredIds = new Set(profile.required_controls.map((c) => c.control_id));

  // Control rules: runtime-adapter controls become gating rules; other mandatory
  // controls become evidence/attestation entries (enforceable, non-gating).
  const control_rules: EnforcementPlanEntry[] = [];

  for (const control of profile.required_controls) {
    const mapping = CONTROL_ENFORCEMENT[control.control_id];

    if (mapping) {
      const guards = intersect(mapping.guards, protectedActions);
      control_rules.push({
        control_id: control.control_id,
        title: mapping.title,
        phase: mapping.phase,
        adapter: mapping.adapter,
        guards,
        mandatory: true,
        failure_mode: 'FAIL_CLOSED',
        enforceable: true,
      });
    } else {
      control_rules.push({
        control_id: control.control_id,
        title: control.title,
        phase: control.lifecycle_stage === 'RUNTIME' ? 'RUNTIME' : 'BUILD_TIME',
        adapter: 'EVIDENCE_ASSERTION',
        guards: [],
        mandatory: true,
        failure_mode: 'FAIL_CLOSED',
        enforceable: true,
      });
    }
  }

  control_rules.sort((a, b) => a.control_id.localeCompare(b.control_id));

  // Approval requirements derived from present controls.
  const approval_requirements: ApprovalRequirement[] = [];

  if (requiredIds.has('HO-OWNER-ATTESTATION')) {
    approval_requirements.push({
      requirement_id: 'REQ-OWNER',
      attestation_type: 'OWNER_ATTESTATION',
      applies_to: intersect(CONTROL_ENFORCEMENT['HO-OWNER-ATTESTATION'].guards, protectedActions),
      min_approvals: 1,
      distinct_approvers: false,
      roles: ['owner', 'admin'],
    });
  }

  if (requiredIds.has('DE-EXPLICIT-PROD-APPROVAL')) {
    approval_requirements.push({
      requirement_id: 'REQ-AUTH-GOV',
      attestation_type: 'AUTHORIZED_GOVERNANCE_APPROVAL',
      applies_to: intersect(PRODUCTION_CAPABLE_ACTIONS, protectedActions),
      min_approvals: 1,
      distinct_approvers: false,
      roles: ['governance', 'compliance', 'security'],
    });
  }

  if (requiredIds.has('HO-DUAL-CONTROL')) {
    approval_requirements.push({
      requirement_id: 'REQ-DUAL',
      attestation_type: 'AUTHORIZED_GOVERNANCE_APPROVAL',
      applies_to: intersect(CONTROL_ENFORCEMENT['HO-DUAL-CONTROL'].guards, protectedActions),
      min_approvals: 2,
      distinct_approvers: true,
      roles: ['governance', 'compliance', 'security'],
    });
  }

  approval_requirements.sort((a, b) => a.requirement_id.localeCompare(b.requirement_id));

  // Limits.
  const limits: ActionLimit[] = [];

  if (requiredIds.has('RM-ACTION-LIMITS')) {
    limits.push({
      limit_id: 'LIM-CONSEQUENTIAL-COUNT',
      applies_to: intersect(CONTROL_ENFORCEMENT['RM-ACTION-LIMITS'].guards, protectedActions),
      kind: 'COUNT',
      max: 100,
    });
  }

  // Allowlists.
  const allowlists: AllowlistSet = {
    models: requiredIds.has('MG-APPROVED-MODEL') || requiredIds.has('IT-STRICT-ALLOWLISTS') ? [...APPROVED_MODELS].sort() : [],
    tools: [],
    integrations: [],
  };

  const preview_only_actions = requiredIds.has('DE-PREVIEW-ONLY')
    ? intersect(PRODUCTION_CAPABLE_ACTIONS, protectedActions)
    : [];
  const production_restricted_actions = requiredIds.has('DE-EXPLICIT-PROD-APPROVAL')
    ? intersect(PRODUCTION_CAPABLE_ACTIONS, protectedActions)
    : [];
  const no_unrestricted_autonomy_actions = requiredIds.has('RM-NO-UNRESTRICTED-AUTONOMY')
    ? intersect(CONTROL_ENFORCEMENT['RM-NO-UNRESTRICTED-AUTONOMY'].guards, protectedActions)
    : [];

  return {
    enforcement_plan_id: '', // server-issued
    enforcement_plan_version: input.enforcement_plan_version,
    qhub_app_id: profile.qhub_app_id,
    classification_version: profile.classification_version,
    policy_profile_id: profile.policy_profile_id,
    policy_profile_version: profile.policy_profile_version,
    policy_profile_hash: profile.policy_profile_hash,
    policy_catalog_version: profile.policy_catalog_version,
    risk_tier: tier,

    protected_action_types: protectedActions,
    control_rules,
    approval_requirements,
    limits,
    allowlists,

    preview_only_actions,
    production_restricted_actions,
    no_unrestricted_autonomy_actions,
    kill_switch_required: requiredIds.has('IR-KILL-SWITCH'),

    generated_at: '', // server-set
    compiler_version: ENFORCEMENT_COMPILER_VERSION,
    enforcement_plan_hash: '', // server-set from canonicalEnforcementPlanString
    status: 'ACTIVE',
  };
}

/**
 * Canonical string over the ENFORCEMENT-DETERMINING content only (never ids,
 * timestamps). Bound to policy_profile_hash so a policy revision necessarily
 * changes the plan hash. This is the `enforcement_plan_hash` preimage.
 */
export function canonicalEnforcementPlanString(p: EnforcementPlan): string {
  const canonical = {
    compiler: p.compiler_version,
    catalog: p.policy_catalog_version,
    tier: p.risk_tier,
    classification_version: p.classification_version,
    policy_profile_hash: p.policy_profile_hash,
    protected_action_types: [...p.protected_action_types].sort(),
    control_rules: p.control_rules
      .map((c) => `${c.control_id}|${c.adapter}|${c.phase}|${c.mandatory}|${c.failure_mode}|${[...c.guards].sort().join(',')}`)
      .sort(),
    approval_requirements: p.approval_requirements
      .map((a) => `${a.requirement_id}|${a.attestation_type}|${a.min_approvals}|${a.distinct_approvers}|${[...a.applies_to].sort().join(',')}|${[...a.roles].sort().join(',')}`)
      .sort(),
    limits: p.limits.map((l) => `${l.limit_id}|${l.kind}|${l.max}|${[...l.applies_to].sort().join(',')}`).sort(),
    allowlists: {
      models: [...p.allowlists.models].sort(),
      tools: [...p.allowlists.tools].sort(),
      integrations: [...p.allowlists.integrations].sort(),
    },
    preview_only_actions: [...p.preview_only_actions].sort(),
    production_restricted_actions: [...p.production_restricted_actions].sort(),
    no_unrestricted_autonomy_actions: [...p.no_unrestricted_autonomy_actions].sort(),
    kill_switch_required: p.kill_switch_required,
  };

  return JSON.stringify(canonical);
}

/**
 * Canonical string for a protected action request. This is the `action_digest`
 * preimage — it binds the decision to the EXACT operation. Deterministic field
 * order; every material field is included so any change yields a new digest.
 * Never contains raw params/secrets — only the material_parameters_hash.
 */
export function canonicalActionRequestString(r: CanonicalActionRequest): string {
  const canonical = {
    tenant_id: r.tenant_id,
    qhub_app_id: r.qhub_app_id,
    action_request_id: r.action_request_id,
    action_type: r.action_type,
    target_resource: r.target_resource,
    operation: r.operation,
    material_parameters_hash: r.material_parameters_hash,
    model_identity: r.model_identity,
    provider_identity: r.provider_identity,
    tool_identity: r.tool_identity,
    environment: r.environment,
    app_version_ref: r.app_version_ref,
    policy_profile_id: r.policy_profile_id,
    policy_profile_version: r.policy_profile_version,
    policy_profile_hash: r.policy_profile_hash,
    enforcement_plan_id: r.enforcement_plan_id,
    enforcement_plan_version: r.enforcement_plan_version,
    enforcement_plan_hash: r.enforcement_plan_hash,
  };

  return JSON.stringify(canonical);
}
