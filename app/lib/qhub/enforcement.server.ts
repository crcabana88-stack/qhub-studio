/**
 * QHUB Gate 04 — Central enforcement entry point — SERVER ONLY
 * app/lib/qhub/enforcement.server.ts
 *
 * enforceGovernedAction() is the ONE path every protected route must use. It
 * reconstructs all authority server-side (never from the caller), evaluates the
 * exact action, durably records CONTROL_DECISION_RECORDED BEFORE any side effect,
 * and permits at most one side effect per single-use ALLOW.
 *
 * The caller supplies only: the authenticated session, the conversation, and the
 * action facts. It may NOT supply risk tier, policy, plan, evaluation_id,
 * action_digest, decision, or approval status.
 */

import { createHash, randomUUID } from 'node:crypto';
import { getOrCreateQhubApp, getChainId, getClassification, getPolicyProfile } from './qhub-app.server';
import { canonicalPolicyString } from './policy-engine';
import {
  compileEnforcementPlan,
  canonicalEnforcementPlanString,
  canonicalActionRequestString,
} from './enforcement-plan';
import { evaluate } from './enforcement-decision';
import { assertGovernanceSchemaReady } from './schema-check.server';
import { createGovernanceService } from './governance-service.server';
import * as store from './enforcement-store.server';
import {
  ENFORCEMENT_EVALUATOR_VERSION,
  type CanonicalActionRequest,
  type ControlResult,
  type Decision,
  type Environment,
  type GovernedActionType,
  type ReasonCode,
} from './enforcement';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/** Deterministic stringify with sorted keys (stable material-parameter hashing). */
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') {
    return JSON.stringify(v);
  }

  if (Array.isArray(v)) {
    return `[${v.map(stableStringify).join(',')}]`;
  }

  const keys = Object.keys(v as Record<string, unknown>).sort();

  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((v as Record<string, unknown>)[k])}`).join(',')}}`;
}

export interface EnforceActionInput {
  action_type: GovernedActionType;
  target_resource: string;
  operation: string;
  material_parameters?: unknown; // hashed server-side; never stored raw
  model_identity?: string | null;
  provider_identity?: string | null;
  tool_identity?: string | null;
  environment: Environment;
  autonomy_requested?: 'NONE' | 'RESTRICTED' | 'UNRESTRICTED';
  app_version_ref?: string | null;
}

export interface EnforceInput {
  session: { userId: string; orgId: string; role: string };
  conversationId: string;
  action: EnforceActionInput;
  idempotencyKey?: string;
  parentEvaluationId?: string; // for E2 re-evaluation after approval
  sessionId: string;
  env: Record<string, string | undefined>;
}

export interface EnforceOutput {
  decision: Decision;
  reason_codes: ReasonCode[];
  action_type: GovernedActionType | null;
  qhub_app_id: string | null;
  evaluation_id: string | null;
  action_request_id: string | null;
  action_digest: string | null;
  policy_profile_id: string | null;
  policy_profile_version: number | null;
  policy_profile_hash: string | null;
  enforcement_plan_id: string | null;
  enforcement_plan_version: number | null;
  enforcement_plan_hash: string | null;
  required_attestations: string[];
  controls_involved: { control_id: string; status: string }[];
  evidence_recorded: boolean;
  side_effect_performed: boolean;
}

function blocked(reason: ReasonCode, actionType: GovernedActionType, appId: string | null = null): EnforceOutput {
  return {
    decision: 'DENY',
    reason_codes: [reason],
    action_type: actionType,
    qhub_app_id: appId,
    evaluation_id: null,
    action_request_id: null,
    action_digest: null,
    policy_profile_id: null,
    policy_profile_version: null,
    policy_profile_hash: null,
    enforcement_plan_id: null,
    enforcement_plan_version: null,
    enforcement_plan_hash: null,
    required_attestations: [],
    controls_involved: [],
    evidence_recorded: false,
    side_effect_performed: false,
  };
}

export async function enforceGovernedAction(input: EnforceInput): Promise<EnforceOutput> {
  const { session, conversationId, action, env, sessionId } = input;

  // 1. Schema readiness — fail closed.
  try {
    await assertGovernanceSchemaReady(env);
  } catch {
    return blocked('SCHEMA_NOT_READY', action.action_type);
  }

  // 2. Server-owned app identity + tenant ownership.
  let app;

  try {
    app = await getOrCreateQhubApp({ orgId: session.orgId, userId: session.userId, conversationId }, env);
  } catch {
    return blocked('APP_NOT_FOUND', action.action_type);
  }

  if (app.org_id !== session.orgId) {
    return blocked('TENANT_MISMATCH', action.action_type);
  }

  // 3. Confirmed classification.
  const classification = await getClassification(app.qhub_app_id, env);

  if (!classification) {
    return blocked('CLASSIFICATION_MISSING', action.action_type, app.qhub_app_id);
  }

  // 4. Assigned policy profile + hash recomputation.
  const profile = await getPolicyProfile(app.qhub_app_id, env);

  if (!profile) {
    return blocked('POLICY_MISSING', action.action_type, app.qhub_app_id);
  }

  if (sha256(canonicalPolicyString(profile)) !== profile.policy_profile_hash) {
    return blocked('POLICY_HASH_MISMATCH', action.action_type, app.qhub_app_id);
  }

  // 5. Active enforcement plan — compile & persist if absent or policy revised.
  const stored = await store.getActivePlan(app.qhub_app_id, session.orgId, env);
  const storedBindingValid =
    !stored ||
    (stored.enforcement_plan_id === stored.plan.enforcement_plan_id &&
      stored.org_id === session.orgId &&
      stored.qhub_app_id === app.qhub_app_id &&
      stored.plan.qhub_app_id === app.qhub_app_id &&
      stored.policy_profile_id === stored.plan.policy_profile_id &&
      stored.policy_profile_hash === stored.plan.policy_profile_hash &&
      stored.enforcement_plan_hash === stored.plan.enforcement_plan_hash);

  if (!storedBindingValid) {
    return blocked('PLAN_HASH_MISMATCH', action.action_type, app.qhub_app_id);
  }

  let plan = stored?.plan ?? null;

  if (!plan || plan.policy_profile_hash !== profile.policy_profile_hash) {
    const compiled = compileEnforcementPlan({
      profile,
      classification,
      enforcement_plan_version: (stored?.plan.enforcement_plan_version ?? 0) + 1,
    });
    compiled.enforcement_plan_id = randomUUID();
    compiled.generated_at = new Date().toISOString();
    compiled.enforcement_plan_hash = sha256(canonicalEnforcementPlanString(compiled));

    const persisted = await store.persistActivePlan(compiled, session.orgId, session.userId, env);

    if (!persisted) {
      return blocked('PLAN_COMPILE_FAILED', action.action_type, app.qhub_app_id);
    }

    const persistedBindingValid =
      persisted.enforcement_plan_id === compiled.enforcement_plan_id &&
      persisted.org_id === session.orgId &&
      persisted.qhub_app_id === app.qhub_app_id &&
      persisted.plan.enforcement_plan_id === persisted.enforcement_plan_id &&
      persisted.plan.qhub_app_id === persisted.qhub_app_id &&
      persisted.policy_profile_id === compiled.policy_profile_id &&
      persisted.policy_profile_hash === compiled.policy_profile_hash &&
      persisted.enforcement_plan_hash === compiled.enforcement_plan_hash &&
      sha256(canonicalEnforcementPlanString(persisted.plan)) === persisted.enforcement_plan_hash;

    if (!persistedBindingValid) {
      return blocked('PLAN_COMPILE_FAILED', action.action_type, app.qhub_app_id);
    }

    plan = persisted.plan;
  } else if (sha256(canonicalEnforcementPlanString(plan)) !== plan.enforcement_plan_hash) {
    return blocked('PLAN_HASH_MISMATCH', action.action_type, app.qhub_app_id);
  }

  /*
   * 6a. Re-evaluation (E2) after approval: load the parent (server-side, never
   * trusted from the browser) to link the audit chain and to assert E2 resolves
   * to the SAME content digest as E1 (else the action changed → DENY). The digest
   * is content-based, so E2 matches E1 without reusing the per-attempt request id.
   */
  let parentDigest: string | null = null;

  if (input.parentEvaluationId) {
    const parent = await store.getEvaluationById(input.parentEvaluationId, session.orgId, env);

    if (!parent || parent.qhub_app_id !== app.qhub_app_id) {
      return blocked('ACTION_DIGEST_MISMATCH', action.action_type, app.qhub_app_id);
    }

    parentDigest = parent.action_digest;
  }

  // 6. Canonical action request + server-computed content digest.
  const request: CanonicalActionRequest = {
    tenant_id: session.orgId,
    qhub_app_id: app.qhub_app_id,
    action_request_id: randomUUID(),
    action_type: action.action_type,
    target_resource: action.target_resource,
    operation: action.operation,
    material_parameters_hash: sha256(stableStringify(action.material_parameters ?? null)),
    model_identity: action.model_identity ?? null,
    provider_identity: action.provider_identity ?? null,
    tool_identity: action.tool_identity ?? null,
    environment: action.environment,
    app_version_ref: action.app_version_ref ?? null,
    policy_profile_id: profile.policy_profile_id,
    policy_profile_version: profile.policy_profile_version,
    policy_profile_hash: profile.policy_profile_hash,
    enforcement_plan_id: plan.enforcement_plan_id,
    enforcement_plan_version: plan.enforcement_plan_version,
    enforcement_plan_hash: plan.enforcement_plan_hash,
  };
  const actionDigest = sha256(canonicalActionRequestString(request));

  /*
   * 6b. A re-evaluation must resolve to the SAME action — a changed action digest
   * means the operation changed and the parent authorization does not apply.
   */
  if (parentDigest && actionDigest !== parentDigest) {
    return blocked('ACTION_DIGEST_MISMATCH', action.action_type, app.qhub_app_id);
  }

  // 7. Idempotency — a duplicate request returns the prior decision, no re-exec.
  if (input.idempotencyKey) {
    const existing = await store.getEvaluationByIdempotency(session.orgId, app.qhub_app_id, input.idempotencyKey, env);

    if (existing) {
      return fromExisting(existing);
    }
  }

  // 8. Authoritative state for the engine.
  const approvals = await store.gatherApprovals(app.qhub_app_id, session.orgId, actionDigest, env);
  const killSwitch = await store.getKillSwitch(app.qhub_app_id, session.orgId, env);

  // 9. Deterministic decision.
  const result = evaluate({
    request,
    action_digest: actionDigest,
    plan,
    risk_tier: profile.risk_tier,
    environment: action.environment,
    autonomy_requested: action.autonomy_requested ?? 'NONE',
    kill_switch_active: killSwitch,
    approvals,
    limit_usage: {},
    actor_id: session.userId,
    actor_role: session.role,
  });

  const evaluationId = randomUUID();
  const controlResultsHash = sha256(stableStringify(result.control_results));
  const compactControls = result.control_results.map((c: ControlResult) => ({
    control_id: c.control_id,
    status: c.status,
  }));

  // 10. Persist the authoritative evaluation record.
  const ins = await store.insertEvaluation(
    {
      evaluation_id: evaluationId,
      action_request_id: request.action_request_id,
      parent_evaluation_id: input.parentEvaluationId ?? null,
      org_id: session.orgId,
      qhub_app_id: app.qhub_app_id,
      action_type: action.action_type,
      action_digest: actionDigest,
      environment: action.environment,
      decision: result.decision,
      reason_codes: result.reason_codes,
      policy_profile_id: profile.policy_profile_id,
      policy_profile_version: profile.policy_profile_version,
      policy_profile_hash: profile.policy_profile_hash,
      enforcement_plan_id: plan.enforcement_plan_id,
      enforcement_plan_version: plan.enforcement_plan_version,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      control_results: compactControls,
      control_results_hash: controlResultsHash,
      required_attestations: result.required_attestations,
      evaluator_version: ENFORCEMENT_EVALUATOR_VERSION,
      idempotency_key: input.idempotencyKey ?? null,
      created_by: session.userId,
    },
    env,
  );

  if (!ins.ok && ins.duplicate && ins.existing) {
    return fromExisting(ins.existing);
  }

  if (!ins.ok) {
    return blocked('DECISION_RECORD_FAILED', action.action_type, app.qhub_app_id);
  }

  // 11. Durable CONTROL_DECISION_RECORDED on-chain, BEFORE any side effect.
  const gov = createGovernanceService({ userId: session.userId, orgId: session.orgId, sessionId, env });
  const chainId = app.chain_id ?? (await getChainId(conversationId, session.orgId, env));
  const decisionEvent = await gov.recordControlDecision({
    conversationId,
    chainId,
    riskTier: profile.risk_tier,
    qhubAppId: app.qhub_app_id,
    payload: {
      evaluation_id: evaluationId,
      action_request_id: request.action_request_id,
      parent_evaluation_id: input.parentEvaluationId ?? null,
      action_type: action.action_type,
      action_digest: actionDigest,
      environment: action.environment,
      decision: result.decision,
      reason_codes: result.reason_codes,
      policy_profile_id: profile.policy_profile_id,
      policy_profile_version: profile.policy_profile_version,
      policy_profile_hash: profile.policy_profile_hash,
      enforcement_plan_id: plan.enforcement_plan_id,
      enforcement_plan_version: plan.enforcement_plan_version,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      control_results: compactControls,
      control_results_hash: controlResultsHash,
      required_attestations: result.required_attestations,
      evaluated_at: new Date().toISOString(),
      evaluator_version: ENFORCEMENT_EVALUATOR_VERSION,
      enforcement_mode: 'FAIL_CLOSED',
    },
  });

  const base = toOutput(result, request, evaluationId, actionDigest, app.qhub_app_id, compactControls);

  // Fail closed: if the decision could not be durably recorded on-chain, do not execute.
  if (!decisionEvent.ok) {
    await store.markActionEvidence(evaluationId, session.orgId, 'FAILED', env);
    return {
      ...base,
      reason_codes: [...base.reason_codes, 'DECISION_RECORD_FAILED'],
      evidence_recorded: false,
      side_effect_performed: false,
    };
  }

  // 12. Non-ALLOW → the recorded decision (DENY is the block record) is the result.
  if (result.decision !== 'ALLOW') {
    return { ...base, evidence_recorded: true, side_effect_performed: false };
  }

  // 13. ALLOW → atomically claim the single-use side effect.
  const claimed = await store.claimEvaluation(evaluationId, session.orgId, env);

  if (!claimed) {
    // Already claimed (replay/concurrent) — no second side effect.
    return {
      ...base,
      reason_codes: [...base.reason_codes, 'REPLAY_DENIED'],
      evidence_recorded: true,
      side_effect_performed: false,
    };
  }

  const approvalsConsumed = await store.consumeApprovalsForDigest(
    app.qhub_app_id,
    session.orgId,
    actionDigest,
    evaluationId,
    env,
  );

  if (!approvalsConsumed) {
    return {
      ...base,
      reason_codes: [...base.reason_codes, 'APPROVAL_CONSUMPTION_FAILED'],
      evidence_recorded: true,
      side_effect_performed: false,
    };
  }

  // Perform the protected side effect for WIRED action types only.
  let sideEffectPerformed = false;
  let evidenceRecorded = true;

  if (action.action_type === 'AI_MODEL_INVOCATION') {
    const ai = await gov.recordAiModelInvokedDirect({
      conversationId,
      provider: action.provider_identity ?? 'Anthropic',
      model: action.model_identity ?? 'unknown',
      enforcement: {
        evaluation_id: evaluationId,
        action_request_id: request.action_request_id,
        action_digest: actionDigest,
        enforcement_plan_id: plan.enforcement_plan_id,
        enforcement_plan_version: plan.enforcement_plan_version,
        enforcement_plan_hash: plan.enforcement_plan_hash,
      },
    });
    sideEffectPerformed = ai.ok;
    evidenceRecorded = ai.ok;

    // Post-action evidence must not vanish silently — mark the outbox state.
    await store.markActionEvidence(evaluationId, session.orgId, ai.ok ? 'COMMITTED' : 'FAILED', env);
  } else {
    // Not operationally wired to a side effect adapter — decision recorded only.
    await store.markActionEvidence(evaluationId, session.orgId, 'COMMITTED', env);
  }

  return { ...base, evidence_recorded: evidenceRecorded, side_effect_performed: sideEffectPerformed };
}

function toOutput(
  result: { decision: Decision; reason_codes: ReasonCode[]; required_attestations: string[] },
  request: CanonicalActionRequest,
  evaluationId: string,
  actionDigest: string,
  appId: string,
  controls: { control_id: string; status: string }[],
): EnforceOutput {
  return {
    decision: result.decision,
    reason_codes: result.reason_codes,
    action_type: request.action_type,
    qhub_app_id: appId,
    evaluation_id: evaluationId,
    action_request_id: request.action_request_id,
    action_digest: actionDigest,
    policy_profile_id: request.policy_profile_id,
    policy_profile_version: request.policy_profile_version,
    policy_profile_hash: request.policy_profile_hash,
    enforcement_plan_id: request.enforcement_plan_id,
    enforcement_plan_version: request.enforcement_plan_version,
    enforcement_plan_hash: request.enforcement_plan_hash,
    required_attestations: result.required_attestations,
    controls_involved: controls,
    evidence_recorded: false,
    side_effect_performed: false,
  };
}

function fromExisting(row: any): EnforceOutput {
  return {
    decision: row.decision,
    reason_codes: [...(row.reason_codes ?? []), 'REPLAY_DENIED'],
    action_type: row.action_type,
    qhub_app_id: row.qhub_app_id,
    evaluation_id: row.evaluation_id,
    action_request_id: row.action_request_id,
    action_digest: row.action_digest,
    policy_profile_id: row.policy_profile_id ?? null,
    policy_profile_version: row.policy_profile_version ?? null,
    policy_profile_hash: row.policy_profile_hash ?? null,
    enforcement_plan_id: row.enforcement_plan_id ?? null,
    enforcement_plan_version: row.enforcement_plan_version ?? null,
    enforcement_plan_hash: row.enforcement_plan_hash ?? null,
    required_attestations: row.required_attestations ?? [],
    controls_involved: Array.isArray(row.control_results) ? row.control_results : [],
    evidence_recorded: true,
    side_effect_performed: false,
  };
}
