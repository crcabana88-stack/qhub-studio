/**
 * QHUB Gate 04 — Deterministic decision engine (PURE, INDEPENDENTLY TESTABLE)
 * app/lib/qhub/enforcement-decision.ts
 *
 * Given authoritative state (plan + action request + digest + approvals +
 * kill-switch + limits), produce ONE authoritative decision. No I/O, no crypto,
 * no clock — expiry/consumption are reflected in approval `status` by the caller.
 *
 * Aggregation: any FAIL → DENY; else any REQUIRE_APPROVAL → REQUIRE_APPROVAL;
 * else ALLOW. Mandatory controls are fail-closed.
 */

import {
  ENFORCEMENT_EVALUATOR_VERSION,
  type ApprovalRequirement,
  type ControlResult,
  type Decision,
  type DecisionEngineInput,
  type EnforcementResult,
  type GatheredApproval,
  type ReasonCode,
} from './enforcement';

const ADAPTER_REQUIREMENT: Record<string, string> = {
  OWNER_ATTESTATION: 'REQ-OWNER',
  PROD_APPROVAL: 'REQ-AUTH-GOV',
  PREVIEW_ONLY: 'REQ-AUTH-GOV',
  DUAL_CONTROL: 'REQ-DUAL',
};

const AUTHENTICATED_ROLES = ['owner', 'admin', 'governance', 'compliance', 'security', 'builder'];

function hostOf(resource: string): string {
  try {
    return new URL(resource).host;
  } catch {
    return resource;
  }
}

/** Count distinct valid approvers for a requirement (independence-aware). */
function requirementSatisfied(
  req: ApprovalRequirement,
  valid: GatheredApproval[],
  actorId: string,
): boolean {
  let pool = valid.filter(
    (a) => a.attestation_type === req.attestation_type && (req.roles.length === 0 || req.roles.includes(a.approver_role)),
  );

  if (req.distinct_approvers) {
    // Independent approval: the requesting actor cannot count toward the quorum.
    pool = pool.filter((a) => a.approver_id !== actorId);
  }

  return new Set(pool.map((a) => a.approver_id)).size >= req.min_approvals;
}

export function evaluate(input: DecisionEngineInput): EnforcementResult {
  const { plan, request, action_digest, environment, kill_switch_active, autonomy_requested, actor_id, actor_role } =
    input;
  const action = request.action_type;

  const results: ControlResult[] = [];
  const reasons = new Set<ReasonCode>();
  const requiredAtt = new Set<string>();
  let hardDeny = false;
  let needApproval = false;
  let sawApprovedControl = false;

  const finish = (): EnforcementResult => {
    let decision: Decision;

    if (hardDeny) {
      decision = 'DENY';
    } else if (needApproval) {
      decision = 'REQUIRE_APPROVAL';
    } else {
      decision = 'ALLOW';
      reasons.add(sawApprovedControl ? 'ALLOWED_APPROVED' : 'ALLOWED_BASELINE');
    }

    return {
      decision,
      reason_codes: Array.from(reasons).sort(),
      control_results: results.sort((a, b) => a.control_id.localeCompare(b.control_id)),
      required_attestations: Array.from(requiredAtt).sort(),
      enforcement_plan_hash: plan.enforcement_plan_hash,
      evaluator_version: ENFORCEMENT_EVALUATOR_VERSION,
    };
  };

  // 0. The action type must be governed by the plan.
  if (!plan.protected_action_types.includes(action)) {
    hardDeny = true;
    reasons.add('ACTION_TYPE_NOT_PROTECTED');
    results.push({ control_id: 'PLAN-SCOPE', status: 'FAIL', reason_code: 'ACTION_TYPE_NOT_PROTECTED' });
    return finish();
  }

  // Approvals valid ONLY for this exact digest + policy + plan versions.
  const valid = input.approvals.filter(
    (a) =>
      a.status === 'GRANTED' &&
      a.scoped_action_digest === action_digest &&
      a.scoped_policy_profile_hash === plan.policy_profile_hash &&
      a.scoped_enforcement_plan_hash === plan.enforcement_plan_hash,
  );
  const reqById: Record<string, ApprovalRequirement> = Object.fromEntries(
    plan.approval_requirements.map((r) => [r.requirement_id, r]),
  );

  const fail = (id: string, rc: ReasonCode) => {
    hardDeny = true;
    reasons.add(rc);
    results.push({ control_id: id, status: 'FAIL', reason_code: rc });
  };
  const pass = (id: string) => {
    results.push({ control_id: id, status: 'PASS', reason_code: 'ALLOWED_BASELINE' });
  };
  const require = (id: string, rc: ReasonCode, att: string) => {
    needApproval = true;
    reasons.add(rc);
    requiredAtt.add(att);
    results.push({ control_id: id, status: 'REQUIRE_APPROVAL', reason_code: rc });
  };

  const approvalCheck = (id: string, adapter: 'OWNER_ATTESTATION' | 'PROD_APPROVAL' | 'PREVIEW_ONLY' | 'DUAL_CONTROL', prodOnly: boolean, rc: ReasonCode) => {
    if (prodOnly && environment !== 'PRODUCTION') {
      pass(id);
      return;
    }

    const req = reqById[ADAPTER_REQUIREMENT[adapter]];

    if (!req) {
      pass(id);
      return;
    }

    if (requirementSatisfied(req, valid, actor_id)) {
      sawApprovedControl = true;
      results.push({ control_id: id, status: 'PASS', reason_code: 'ALLOWED_APPROVED' });
    } else {
      require(id, rc, req.attestation_type);
    }
  };

  for (const rule of plan.control_rules) {
    if (!rule.guards.includes(action)) {
      continue; // not applicable to this action type
    }

    const id = rule.control_id;

    switch (rule.adapter) {
      case 'KILL_SWITCH':
        if (kill_switch_active) {
          fail(id, 'KILL_SWITCH_ACTIVE');
        } else {
          pass(id);
        }

        break;
      case 'NO_UNRESTRICTED_AUTONOMY':
        if (autonomy_requested === 'UNRESTRICTED') {
          fail(id, 'UNRESTRICTED_AUTONOMY_DENIED');
        } else {
          pass(id);
        }

        break;
      case 'ACTION_LIMITS': {
        const lim = plan.limits.find((l) => l.applies_to.includes(action));

        if (lim && (input.limit_usage[lim.limit_id] ?? 0) >= lim.max) {
          fail(id, 'LIMIT_EXCEEDED');
        } else {
          pass(id);
        }

        break;
      }
      case 'MODEL_ALLOWLIST':
        if (
          action === 'AI_MODEL_INVOCATION' &&
          plan.allowlists.models.length > 0 &&
          !plan.allowlists.models.includes(request.model_identity ?? '')
        ) {
          fail(id, 'MODEL_NOT_APPROVED');
        } else {
          pass(id);
        }

        break;
      case 'EGRESS_ALLOWLIST':
        if (plan.allowlists.integrations.length > 0 && !plan.allowlists.integrations.includes(hostOf(request.target_resource))) {
          fail(id, 'EGRESS_DENIED');
        } else {
          pass(id);
        }

        break;
      case 'RBAC':
        if (!AUTHENTICATED_ROLES.includes(actor_role)) {
          fail(id, 'RBAC_DENIED');
        } else {
          pass(id);
        }

        break;
      case 'TENANT_ISOLATION':
        if (request.target_resource.startsWith('tenant:') && request.target_resource.split(':')[1] !== request.tenant_id) {
          fail(id, 'TENANT_MISMATCH');
        } else {
          pass(id);
        }

        break;
      case 'OWNER_ATTESTATION':
        approvalCheck(id, 'OWNER_ATTESTATION', false, 'ATTESTATION_REQUIRED');
        break;
      case 'PROD_APPROVAL':
        approvalCheck(id, 'PROD_APPROVAL', true, 'PRODUCTION_APPROVAL_REQUIRED');
        break;
      case 'PREVIEW_ONLY':
        approvalCheck(id, 'PREVIEW_ONLY', true, 'PREVIEW_ONLY_PRODUCTION_DENIED');
        break;
      case 'DUAL_CONTROL':
        approvalCheck(id, 'DUAL_CONTROL', true, 'DUAL_CONTROL_REQUIRED');
        break;
      case 'EVIDENCE_ASSERTION':
        pass(id); // build-time/evidence control — asserted, not a runtime action gate
        break;
      default:
        if (rule.mandatory) {
          fail(id, 'UNSUPPORTED_MANDATORY_CONTROL');
        } else {
          results.push({ control_id: id, status: 'NOT_APPLICABLE', reason_code: 'ALLOWED_BASELINE' });
        }
    }
  }

  return finish();
}
