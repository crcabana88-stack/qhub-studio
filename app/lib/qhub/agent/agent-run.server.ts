/**
 * QHUB Agent Framework Foundation — Run orchestrator (SERVER ONLY)
 * app/lib/qhub/agent/agent-run.server.ts
 *
 * Owns the governed run loop. Every model/tool/connector action the runtime
 * provider proposes is routed through the central Gate 04 enforcement path
 * (enforceGovernedAction). The provider never executes anything and never
 * receives credentials — it only proposes and receives governed results. DENY
 * yields no execution; REQUIRE_APPROVAL pauses the run; ALLOW/SIMULATED records a
 * receipt. Limits, kill-switch, idempotency/replay, and fail-closed evidence are
 * enforced here. Evidence stores hashes/summaries only — never raw params,
 * prompts, chain-of-thought, or secrets.
 */

/* eslint-disable @typescript-eslint/naming-convention -- local bindings mirror snake_case DB columns so payloads read 1:1 against the schema */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { createHash, randomUUID } from 'node:crypto';
import { enforceGovernedAction } from '~/lib/qhub/enforcement.server';
import { getAgent, getAgentVersion, type AgentRow, type AgentVersionRow } from './agent-registry.server';
import { checkReleaseBinding } from './agent-release-binding.server';
import { canRunInState } from './agent-lifecycle';
import { selectRuntimeProvider } from './runtime/provider-registry.server';
import { canonicalRunString, type AgentRunState } from './agent-run';
import type { GovernedActionResult, ProposedAction, RuntimeManifestView } from './runtime/provider';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

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

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[AgentRun] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

export interface RunAgentInput {
  session: { userId: string; orgId: string; role: string };
  conversationId: string;
  agent_id: string;
  idempotency_key: string;
  synthetic_inputs: Record<string, unknown>;
  sessionId: string;
  env: Record<string, string | undefined>;
}

export type RunReasonCode =
  | 'AGENT_NOT_FOUND'
  | 'KILL_SWITCH_ACTIVE'
  | 'NOT_RUNNABLE_STATE'
  | 'SUSPENDED'
  | 'RETIRED'
  | 'NO_CURRENT_VERSION'
  | 'RELEASE_NOT_APPROVED'
  | 'RELEASE_STALE'
  | 'MANIFEST_CHANGED'
  | 'UNKNOWN_PROVIDER'
  | 'ACTION_LIMIT_EXCEEDED'
  | 'MODEL_CALL_LIMIT_EXCEEDED'
  | 'RUNTIME_TIMEOUT'
  | 'GOVERNED_ACTION_DENIED'
  | 'EVIDENCE_WRITE_FAILED'
  | 'PROVIDER_FAILED';

export interface RunResult {
  ok: boolean;
  run_id?: string;
  state: AgentRunState | 'BLOCKED';
  reason_codes: RunReasonCode[];
  pending_evaluation_id?: string | null;
  awaiting_step_index?: number | null;
  proposed_action_count?: number;
  approved_action_count?: number;
  denied_action_count?: number;
}

function manifestView(version: AgentVersionRow): RuntimeManifestView {
  const m = version.manifest;

  return {
    agent_id: m.agent_id,
    agent_version_id: m.agent_version_id,
    operating_mode: m.operating_mode,
    autonomy_level: m.autonomy_level,
    primary_model: m.primary_model,
    approved_models: m.approved_models,
    approved_tool_ids: m.approved_tools.map((t) => t.tool_id),
    approved_connector_ids: m.approved_connectors.map((c) => c.connector_id),
    goal_definition: m.goal_definition,
    execution_environment: m.execution_environment,
  };
}

/** Blocked-run helper (no side effects, no run row). */
function blocked(reason: RunReasonCode): RunResult {
  return { ok: false, state: 'BLOCKED', reason_codes: [reason] };
}

/**
 * Start (or replay) a governed agent run. Fail-closed at every gate. In this
 * phase SIMULATION runs use synthetic inputs; SUPERVISED/ACTIVE additionally
 * require a current Gate 05 release binding.
 */
export async function runAgent(input: RunAgentInput): Promise<RunResult> {
  const { session, env } = input;
  const agent = await getAgent(input.agent_id, session.orgId, env);

  if (!agent) {
    return blocked('AGENT_NOT_FOUND');
  }

  if (agent.kill_switch_active) {
    return blocked('KILL_SWITCH_ACTIVE');
  }

  const runnable = canRunInState(agent.current_lifecycle_state);

  if (!runnable.ok) {
    return blocked((runnable.reason as RunReasonCode) ?? 'NOT_RUNNABLE_STATE');
  }

  if (!agent.current_version_id) {
    return blocked('NO_CURRENT_VERSION');
  }

  const version = await getAgentVersion(agent.current_version_id, session.orgId, env);

  if (!version) {
    return blocked('NO_CURRENT_VERSION');
  }

  // SUPERVISED / ACTIVE require a current, matching Gate 05 approval.
  if (agent.current_lifecycle_state === 'SUPERVISED' || agent.current_lifecycle_state === 'ACTIVE') {
    const binding = await checkReleaseBinding(version, env);

    if (!binding.release_approved) {
      return blocked('RELEASE_NOT_APPROVED');
    }

    if (binding.release_stale) {
      return blocked('RELEASE_STALE');
    }

    if (!binding.manifest_matches_release) {
      return blocked('MANIFEST_CHANGED');
    }
  }

  // Idempotency / replay: one run per (agent_version, key).
  const sb = admin(env);
  const existing = await sb
    .from('qhub_agent_runs')
    .select('*')
    .eq('agent_version_id', version.agent_version_id)
    .eq('idempotency_key', input.idempotency_key)
    .eq('org_id', session.orgId)
    .maybeSingle();

  if (existing.data) {
    const r = existing.data as Record<string, unknown>;

    return {
      ok: true,
      run_id: r.run_id as string,
      state: r.current_state as AgentRunState,
      reason_codes: [],
      pending_evaluation_id: (r.pending_evaluation_id as string) ?? null,
      awaiting_step_index: (r.current_step as number) ?? null,
      proposed_action_count: r.proposed_action_count as number,
      approved_action_count: r.approved_action_count as number,
      denied_action_count: r.denied_action_count as number,
    };
  }

  const selection = selectRuntimeProvider(version.manifest.runtime_provider, version.manifest.runtime_provider_version);

  if (!selection.ok || !selection.provider) {
    return blocked('UNKNOWN_PROVIDER');
  }

  const provider = selection.provider;
  const run_id = randomUUID();
  const input_hash = sha256(stableStringify(input.synthetic_inputs));
  const run_hash = sha256(
    canonicalRunString({
      agent_id: agent.agent_id,
      agent_version_id: version.agent_version_id,
      release_candidate_hash: version.release_candidate_hash,
      org_id: session.orgId,
      qhub_app_id: version.qhub_app_id,
      initiating_user_id: session.userId,
      operating_mode: version.operating_mode as AgentRow['current_operating_mode'],
      runtime_provider: provider.provider_id,
      runtime_provider_version: provider.provider_version,
      policy_profile_hash: version.policy_profile_hash,
      enforcement_plan_hash: version.enforcement_plan_hash,
      primary_model: version.manifest.primary_model,
      input_hash,
      idempotency_key: input.idempotency_key,
    }),
  );

  const insertRun = await sb.from('qhub_agent_runs').insert({
    run_id,
    agent_id: agent.agent_id,
    agent_version_id: version.agent_version_id,
    org_id: session.orgId,
    qhub_app_id: version.qhub_app_id,
    release_candidate_id: version.release_candidate_id,
    release_candidate_hash: version.release_candidate_hash,
    initiating_user_id: session.userId,
    operating_mode: version.operating_mode,
    runtime_provider: provider.provider_id,
    runtime_provider_version: provider.provider_version,
    current_state: 'RUNNING',
    current_step: 0,
    policy_profile_hash: version.policy_profile_hash,
    enforcement_plan_hash: version.enforcement_plan_hash,
    primary_model: version.manifest.primary_model,
    input_hash,
    idempotency_key: input.idempotency_key,
    proposed_action_count: 0,
    approved_action_count: 0,
    denied_action_count: 0,
    run_hash,
  });

  if (insertRun.error) {
    // Duplicate key on a concurrent replay → return the winner.
    const dup = await sb
      .from('qhub_agent_runs')
      .select('run_id, current_state')
      .eq('agent_version_id', version.agent_version_id)
      .eq('idempotency_key', input.idempotency_key)
      .eq('org_id', session.orgId)
      .maybeSingle();

    if (dup.data) {
      return {
        ok: true,
        run_id: (dup.data as Record<string, unknown>).run_id as string,
        state: (dup.data as Record<string, unknown>).current_state as AgentRunState,
        reason_codes: [],
      };
    }

    return blocked('EVIDENCE_WRITE_FAILED');
  }

  await provider.init({ manifest: manifestView(version), synthetic_inputs: input.synthetic_inputs });

  return driveRun({
    sb,
    run_id,
    agent,
    version,
    session,
    provider,
    env,
    sessionId: input.sessionId,
    startStep: 0,
    priorResults: [],
    counters: { proposed: 0, approved: 0, denied: 0, modelCalls: 0 },
  });
}

interface DriveContext {
  sb: SupabaseClient;
  run_id: string;
  agent: AgentRow;
  version: AgentVersionRow;
  session: { userId: string; orgId: string; role: string };
  provider: import('./runtime/provider').AgentRuntimeProvider;
  env: Record<string, string | undefined>;
  sessionId: string;
  startStep: number;
  priorResults: GovernedActionResult[];
  counters: { proposed: number; approved: number; denied: number; modelCalls: number };
}

/** The bounded, limit-enforced governed step loop. */
async function driveRun(ctx: DriveContext): Promise<RunResult> {
  const { sb, run_id, version, session, provider, env } = ctx;
  const limits = version.manifest.action_limits;
  const deadline = Date.now() + limits.max_runtime_seconds * 1000;
  let stepIndex = ctx.startStep;
  let priorResults = ctx.priorResults;
  const counters = ctx.counters;

  // Re-check kill switch immediately before executing (durable flag may have flipped).
  const fresh = await getAgent(ctx.agent.agent_id, session.orgId, env);

  if (fresh?.kill_switch_active) {
    await finishRun(sb, run_id, session.orgId, 'SUSPENDED', counters, 'KILL_SWITCH_ACTIVE');

    return { ok: false, run_id, state: 'SUSPENDED', reason_codes: ['KILL_SWITCH_ACTIVE'], ...counterOut(counters) };
  }

  while (true) {
    if (Date.now() > deadline) {
      await finishRun(sb, run_id, session.orgId, 'FAILED', counters, 'RUNTIME_TIMEOUT');

      return { ok: false, run_id, state: 'FAILED', reason_codes: ['RUNTIME_TIMEOUT'], ...counterOut(counters) };
    }

    const out = await provider.step({ step_index: stepIndex, prior_results: priorResults });

    if (out.kind === 'FAIL') {
      await finishRun(sb, run_id, session.orgId, 'FAILED', counters, out.error_reason ?? 'PROVIDER_FAILED');

      return { ok: false, run_id, state: 'FAILED', reason_codes: ['PROVIDER_FAILED'], ...counterOut(counters) };
    }

    if (out.kind === 'COMPLETE') {
      const output_hash = sha256(stableStringify({ summary: out.output_summary ?? '', steps: stepIndex }));
      await sb
        .from('qhub_agent_runs')
        .update({
          current_state: 'COMPLETED',
          current_step: stepIndex,
          output_hash,
          completed_at: new Date().toISOString(),
          ...counterCols(counters),
        })
        .eq('run_id', run_id)
        .eq('org_id', session.orgId);

      return { ok: true, run_id, state: 'COMPLETED', reason_codes: [], ...counterOut(counters) };
    }

    const actions = out.proposed_actions ?? [];
    priorResults = [];

    for (const action of actions) {
      // Enforce limits BEFORE any governed action (fail-closed).
      if (counters.proposed >= limits.max_actions_per_run) {
        await finishRun(sb, run_id, session.orgId, 'FAILED', counters, 'ACTION_LIMIT_EXCEEDED');

        return { ok: false, run_id, state: 'FAILED', reason_codes: ['ACTION_LIMIT_EXCEEDED'], ...counterOut(counters) };
      }

      if (action.action_type === 'AI_MODEL_INVOCATION' && counters.modelCalls >= limits.max_model_calls_per_run) {
        await finishRun(sb, run_id, session.orgId, 'FAILED', counters, 'MODEL_CALL_LIMIT_EXCEEDED');

        return {
          ok: false,
          run_id,
          state: 'FAILED',
          reason_codes: ['MODEL_CALL_LIMIT_EXCEEDED'],
          ...counterOut(counters),
        };
      }

      counters.proposed += 1;

      if (action.action_type === 'AI_MODEL_INVOCATION') {
        counters.modelCalls += 1;
      }

      const decision = await routeThroughGate04(ctx, action, stepIndex);

      const stepRecorded = await recordStep(sb, {
        run_id,
        org_id: session.orgId,
        step_index: stepIndex,
        step_kind: action.step_kind,
        action_type: action.action_type,
        evaluation_id: decision.evaluation_id,
        decision: decision.result.decision,
        reason_codes: decision.result.reason_codes,
        receipt_id: decision.result.receipt_id,
        input_hash: sha256(stableStringify(action.material_parameters ?? null)),
        summary: action.summary,
      });

      if (!stepRecorded) {
        // Fail closed: an unrecorded governed action must not be treated as done.
        await finishRun(sb, run_id, session.orgId, 'FAILED', counters, 'EVIDENCE_WRITE_FAILED');

        return { ok: false, run_id, state: 'FAILED', reason_codes: ['EVIDENCE_WRITE_FAILED'], ...counterOut(counters) };
      }

      if (decision.result.decision === 'DENY') {
        counters.denied += 1;
        await finishRun(sb, run_id, session.orgId, 'FAILED', counters, 'GOVERNED_ACTION_DENIED');

        return {
          ok: false,
          run_id,
          state: 'FAILED',
          reason_codes: ['GOVERNED_ACTION_DENIED'],
          ...counterOut(counters),
        };
      }

      if (decision.result.decision === 'REQUIRE_APPROVAL') {
        await sb
          .from('qhub_agent_runs')
          .update({
            current_state: 'AWAITING_APPROVAL',
            current_step: stepIndex,
            pending_evaluation_id: decision.evaluation_id,
            ...counterCols(counters),
          })
          .eq('run_id', run_id)
          .eq('org_id', session.orgId);

        return {
          ok: true,
          run_id,
          state: 'AWAITING_APPROVAL',
          reason_codes: [],
          pending_evaluation_id: decision.evaluation_id,
          awaiting_step_index: stepIndex,
          ...counterOut(counters),
        };
      }

      // ALLOW / SIMULATED / EXECUTED.
      counters.approved += 1;
      priorResults.push(decision.result);
    }

    stepIndex += 1;
    await sb
      .from('qhub_agent_runs')
      .update({ current_step: stepIndex, ...counterCols(counters) })
      .eq('run_id', run_id)
      .eq('org_id', session.orgId);
  }
}

/** Route one proposed action through the central Gate 04 enforcement path. */
async function routeThroughGate04(
  ctx: DriveContext,
  action: ProposedAction,
  stepIndex: number,
  parentEvaluationId?: string,
): Promise<{ result: GovernedActionResult; evaluation_id: string | null }> {
  const { session, env, sessionId } = ctx;

  const enforceOut = await enforceGovernedAction<{ ok: true }>({
    session,
    conversationId: ctx.version.qhub_app_id, // stable per-agent-app conversation surrogate
    action: {
      action_type: action.action_type,
      target_resource: action.target_resource,
      operation: action.operation,
      material_parameters: action.material_parameters,
      model_identity: action.model_identity ?? null,
      environment: mapEnvironment(ctx.version.manifest.execution_environment),
      autonomy_requested: 'NONE',
    },
    idempotencyKey: `${ctx.run_id}:${stepIndex}`,
    parentEvaluationId,
    sessionId,
    env,

    // Governed internal execution for model calls (deterministic, no secrets).
    internalExecution:
      action.action_type === 'AI_MODEL_INVOCATION'
        ? { action_type: 'AI_MODEL_INVOCATION', invoke: () => ({ ok: true }) }
        : undefined,
  });

  const decision = enforceOut.decision;
  const mapped: GovernedActionResult['decision'] =
    decision === 'ALLOW'
      ? enforceOut.execution_mode === 'SIMULATION'
        ? 'SIMULATED'
        : enforceOut.side_effect_performed
          ? 'EXECUTED'
          : 'ALLOW'
      : decision;

  return {
    evaluation_id: enforceOut.evaluation_id,
    result: {
      decision: mapped,
      reason_codes: enforceOut.reason_codes,
      receipt_id: enforceOut.receipt?.receipt_id ?? null,
      safe_result: enforceOut.receipt ? { execution_status: enforceOut.receipt.execution_status } : null,
    },
  };
}

function mapEnvironment(target: string): 'PREVIEW' | 'INTERNAL' | 'PRODUCTION' {
  if (target === 'PRODUCTION') {
    return 'PRODUCTION';
  }

  if (target === 'STAGING') {
    return 'INTERNAL';
  }

  return 'PREVIEW';
}

async function recordStep(
  sb: SupabaseClient,
  step: {
    run_id: string;
    org_id: string;
    step_index: number;
    step_kind: string;
    action_type: string | null;
    evaluation_id: string | null;
    decision: string;
    reason_codes: string[];
    receipt_id: string | null;
    input_hash: string;
    summary: string;
  },
): Promise<boolean> {
  const { error } = await sb.from('qhub_agent_run_steps').insert(step);

  return !error;
}

function counterCols(c: { proposed: number; approved: number; denied: number }) {
  return { proposed_action_count: c.proposed, approved_action_count: c.approved, denied_action_count: c.denied };
}

function counterOut(c: { proposed: number; approved: number; denied: number }) {
  return { proposed_action_count: c.proposed, approved_action_count: c.approved, denied_action_count: c.denied };
}

async function finishRun(
  sb: SupabaseClient,
  run_id: string,
  org_id: string,
  state: AgentRunState,
  counters: { proposed: number; approved: number; denied: number },
  error_reference: string,
): Promise<void> {
  await sb
    .from('qhub_agent_runs')
    .update({ current_state: state, error_reference, completed_at: new Date().toISOString(), ...counterCols(counters) })
    .eq('run_id', run_id)
    .eq('org_id', org_id);
}

/**
 * Resume an AWAITING_APPROVAL run after the exact pending action was approved
 * (Gate 04 E2 with parentEvaluationId). Only the exact approved action resumes;
 * a wrong/absent parent evaluation fails closed.
 */
export async function resumeAgentRun(input: {
  session: { userId: string; orgId: string; role: string };
  run_id: string;
  approved_evaluation_id: string;
  synthetic_inputs: Record<string, unknown>;
  sessionId: string;
  env: Record<string, string | undefined>;
}): Promise<RunResult> {
  const { session, env } = input;
  const sb = admin(env);
  const runRow = await sb
    .from('qhub_agent_runs')
    .select('*')
    .eq('run_id', input.run_id)
    .eq('org_id', session.orgId)
    .maybeSingle();

  if (!runRow.data) {
    return blocked('AGENT_NOT_FOUND');
  }

  const run = runRow.data as Record<string, unknown>;

  if (run.current_state !== 'AWAITING_APPROVAL' || run.pending_evaluation_id !== input.approved_evaluation_id) {
    return { ok: false, run_id: input.run_id, state: 'BLOCKED', reason_codes: ['GOVERNED_ACTION_DENIED'] };
  }

  const agent = await getAgent(run.agent_id as string, session.orgId, env);

  if (!agent || agent.kill_switch_active) {
    await finishRun(
      sb,
      input.run_id,
      session.orgId,
      'SUSPENDED',
      {
        proposed: run.proposed_action_count as number,
        approved: run.approved_action_count as number,
        denied: run.denied_action_count as number,
      },
      'KILL_SWITCH_ACTIVE',
    );

    return { ok: false, run_id: input.run_id, state: 'SUSPENDED', reason_codes: ['KILL_SWITCH_ACTIVE'] };
  }

  const version = await getAgentVersion(run.agent_version_id as string, session.orgId, env);

  if (!version) {
    return blocked('NO_CURRENT_VERSION');
  }

  const selection = selectRuntimeProvider(version.manifest.runtime_provider, version.manifest.runtime_provider_version);

  if (!selection.ok || !selection.provider) {
    return blocked('UNKNOWN_PROVIDER');
  }

  await selection.provider.init({ manifest: manifestView(version), synthetic_inputs: input.synthetic_inputs });

  const stepIndex = run.current_step as number;
  const counters = {
    proposed: run.proposed_action_count as number,
    approved: run.approved_action_count as number,
    denied: run.denied_action_count as number,
    modelCalls: 0,
  };

  /*
   * Re-drive the pending step: the provider re-proposes the exact action, now
   * re-enforced with parentEvaluationId (E2) → executes only the approved action.
   */
  const out = await selection.provider.step({ step_index: stepIndex, prior_results: [] });

  if (out.kind !== 'PROPOSE' || !out.proposed_actions?.length) {
    return { ok: false, run_id: input.run_id, state: 'BLOCKED', reason_codes: ['PROVIDER_FAILED'] };
  }

  const ctx: DriveContext = {
    sb,
    run_id: input.run_id,
    agent,
    version,
    session,
    provider: selection.provider,
    env,
    sessionId: input.sessionId,
    startStep: stepIndex,
    priorResults: [],
    counters,
  };
  const action = out.proposed_actions[0];
  const decision = await routeThroughGate04(ctx, action, stepIndex, input.approved_evaluation_id);

  const recorded = await recordStep(sb, {
    run_id: input.run_id,
    org_id: session.orgId,
    step_index: stepIndex,
    step_kind: action.step_kind,
    action_type: action.action_type,
    evaluation_id: decision.evaluation_id,
    decision: decision.result.decision,
    reason_codes: decision.result.reason_codes,
    receipt_id: decision.result.receipt_id,
    input_hash: sha256(stableStringify(action.material_parameters ?? null)),
    summary: action.summary,
  });

  if (!recorded) {
    await finishRun(sb, input.run_id, session.orgId, 'FAILED', counters, 'EVIDENCE_WRITE_FAILED');

    return { ok: false, run_id: input.run_id, state: 'FAILED', reason_codes: ['EVIDENCE_WRITE_FAILED'] };
  }

  if (decision.result.decision === 'DENY') {
    counters.denied += 1;
    await finishRun(sb, input.run_id, session.orgId, 'FAILED', counters, 'GOVERNED_ACTION_DENIED');

    return { ok: false, run_id: input.run_id, state: 'FAILED', reason_codes: ['GOVERNED_ACTION_DENIED'] };
  }

  counters.approved += 1;
  await sb
    .from('qhub_agent_runs')
    .update({
      current_state: 'RUNNING',
      pending_evaluation_id: null,
      current_step: stepIndex + 1,
      ...counterCols(counters),
    })
    .eq('run_id', input.run_id)
    .eq('org_id', session.orgId);

  return driveRun({ ...ctx, startStep: stepIndex + 1, priorResults: [decision.result], counters });
}
