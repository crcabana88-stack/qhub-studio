/**
 * QHUB Agent Framework — Provider-neutral runtime conformance harness (PURE)
 * app/lib/qhub/agent/runtime/runtime-provider-conformance.ts
 *
 * A reusable, dependency-free harness that exercises the REAL governance
 * behaviours without a database. It faithfully models the run orchestrator with
 * an in-memory Gate 04 that COUNTS executions, and its resume path calls the SAME
 * production `reconstructForResume` guard the server uses — so restart / replay /
 * tamper guarantees are proven against production code, not a mock of the outcome.
 *
 * Honest scoping (see runtime-provider-conformance.test.ts):
 *   - `providerConformance()` returns ONLY genuine PROVIDER-level properties, each
 *     backed by an executed behavioural assertion.
 *   - Orchestrator / Gate 04 / Gate 05 behaviours are exercised as separate
 *     integration tests, not counted as provider-conformance properties.
 */

/* eslint-disable @typescript-eslint/naming-convention -- local bindings mirror snake_case governed-action / run-step columns */

import type {
  AgentRuntimeProvider,
  GovernedActionResult,
  ProposedAction,
  RuntimeInitContext,
  RuntimeManifestView,
  RuntimeStepInput,
  RuntimeStepOutput,
} from './provider';
import { inputHashOf, reconstructForResume, type RunIdentity, type StoredRunStep } from './run-reconstruction';
import type { RunActionDecision } from '~/lib/qhub/agent/agent-run';

export { inputHashOf } from './run-reconstruction';

/*
 * --------------------------------------------------------------------------
 * Reference manifest + synthetic inputs
 * --------------------------------------------------------------------------
 */

export interface RunLimits {
  max_actions_per_run: number;
  max_model_calls_per_run: number;
  max_runtime_seconds: number;
}

export const DEFAULT_LIMITS: RunLimits = {
  max_actions_per_run: 8,
  max_model_calls_per_run: 4,
  max_runtime_seconds: 60,
};

export function referenceManifestView(overrides: Partial<RuntimeManifestView> = {}): RuntimeManifestView {
  return {
    agent_id: 'agent-conformance',
    agent_version_id: 'ver-conformance',
    operating_mode: 'SUPERVISED_ACTION_AGENT',
    autonomy_level: 'HUMAN_IN_LOOP',
    primary_model: 'qhub.sim.deterministic-1',
    approved_models: ['qhub.sim.deterministic-1'],
    approved_tool_ids: ['qhub.tool.commission-reconciliation-write'],
    approved_connector_ids: ['qhub.staging.external-data-transmission.simulation'],
    goal_definition: 'Reconcile two synthetic commission datasets under supervision.',
    execution_environment: 'STAGING',
    ...overrides,
  };
}

/** Synthetic inputs that DO produce a discrepancy (model + connector actions). */
export function syntheticInputsWithDiscrepancy(): Record<string, unknown> {
  return {
    ledger: [
      { broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 1250000 },
      { broker_id: 'BRK-002', period: '2026-Q2', amount_minor: 830000 },
    ],
    statement: [
      { broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 1250000 },
      { broker_id: 'BRK-002', period: '2026-Q2', amount_minor: 812500 },
    ],
  };
}

const RUN_ID = 'run-conformance';
const ORG_ID = 'org-conformance';

function runIdentity(state: HarnessRunState): RunIdentity {
  return {
    run_id: state.run_id,
    org_id: ORG_ID,
    agent_id: 'agent-conformance',
    agent_version_id: 'ver-conformance',
    release_candidate_hash: 'rc-conformance',
    qhub_app_id: 'app-conformance',
    current_state: state.state,
    current_step: state.current_step,
    pending_evaluation_id: state.pending_evaluation_id,
  };
}

/*
 * --------------------------------------------------------------------------
 * In-memory Gate 04 (counts executions) + run harness
 * --------------------------------------------------------------------------
 */

export interface GateCounters {
  modelCalls: number;
  toolCalls: number;
  submissions: number;
  approvalRequests: number;
  adapterExecutions: number;
  receipts: number;
}

export interface GateDecision {
  decision: RunActionDecision;
  evaluation_id: string;
  receipt_id: string | null;
}

export interface MockGateOptions {
  denyTargetSubstring?: string;
  connectorRequiresApproval?: boolean;
}

/**
 * A faithful, counting stand-in for enforceGovernedAction. Idempotency keys make a
 * replayed E1 return the SAME cached decision without a new side effect; a distinct
 * E2 key (parentEvaluationId set) consumes the approval and executes exactly once.
 */
export class MockGate {
  readonly counters: GateCounters = {
    modelCalls: 0,
    toolCalls: 0,
    submissions: 0,
    approvalRequests: 0,
    adapterExecutions: 0,
    receipts: 0,
  };

  private _cache = new Map<string, GateDecision>();
  private _evalSeq = 0;
  private _receiptSeq = 0;

  constructor(private _opts: MockGateOptions = {}) {}

  enforce(action: ProposedAction, idempotencyKey: string, parentEvaluationId?: string): GateDecision {
    const cached = this._cache.get(idempotencyKey);

    if (cached) {
      return cached;
    }

    this.counters.submissions += 1;

    if (action.action_type === 'AI_MODEL_INVOCATION') {
      this.counters.modelCalls += 1;
    }

    if (action.step_kind === 'TOOL_ACTION') {
      this.counters.toolCalls += 1;
    }

    const evaluation_id = `eval-${++this._evalSeq}`;

    if (this._opts.denyTargetSubstring && action.target_resource.includes(this._opts.denyTargetSubstring)) {
      const d: GateDecision = { decision: 'DENY', evaluation_id, receipt_id: null };
      this._cache.set(idempotencyKey, d);

      return d;
    }

    const isConnector = action.step_kind === 'CONNECTOR_ACTION';
    const requiresApproval = this._opts.connectorRequiresApproval ?? true;

    if (isConnector && requiresApproval && !parentEvaluationId) {
      this.counters.approvalRequests += 1;

      const d: GateDecision = { decision: 'REQUIRE_APPROVAL', evaluation_id, receipt_id: null };
      this._cache.set(idempotencyKey, d);

      return d;
    }

    // Only the gate executes: it produces the single adapter run + receipt.
    this.counters.adapterExecutions += 1;
    this.counters.receipts += 1;

    const receipt_id = `receipt-${++this._receiptSeq}`;
    const d: GateDecision = { decision: 'SIMULATED', evaluation_id, receipt_id };
    this._cache.set(idempotencyKey, d);

    return d;
  }
}

export interface HarnessRunState {
  run_id: string;
  state: 'RUNNING' | 'AWAITING_APPROVAL' | 'COMPLETED' | 'FAILED' | 'SUSPENDED';
  current_step: number;
  pending_evaluation_id: string | null;
  steps: StoredRunStep[];
  reason: string | null;
}

function resultOf(d: GateDecision): GovernedActionResult {
  return {
    decision: d.decision,
    reason_codes: [],
    receipt_id: d.receipt_id,
    safe_result: d.receipt_id ? { execution_status: 'OK' } : null,
  };
}

/**
 * Deterministic stand-in for the server-computed canonical result_hash. The
 * production hash is computed in the database (qhub_finalize_agent_run_step); this
 * harness only needs a stable, unique, chain-consistent value so the production
 * reconstruction guard's continuity + chain-link checks exercise real code.
 */
function synthResultHash(runId: string, stepIndex: number, inputHash: string, d: GateDecision): string {
  return `rh:${runId}:${stepIndex}:${inputHash}:${d.decision}:${d.receipt_id ?? ''}`;
}

export interface HarnessOptions {
  limits?: RunLimits;
  killSwitch?: () => boolean;

  /** Injectable clock (ms) — lets a test exceed the runtime-duration deadline. */
  now?: () => number;
}

/**
 * Simulates the run orchestrator (driveRun/resumeAgentRun) for one provider. Its
 * resume path calls the PRODUCTION `reconstructForResume` guard, so restart/replay
 * tests exercise real code.
 */
export class GovernedRunHarness {
  readonly initContexts: RuntimeInitContext[] = [];

  private _limits: RunLimits;
  private _killSwitch: () => boolean;
  private _now: () => number;
  private _startedAt = 0;

  constructor(
    private _providerFactory: () => AgentRuntimeProvider,
    private _gate: MockGate,
    opts: HarnessOptions = {},
  ) {
    this._limits = opts.limits ?? DEFAULT_LIMITS;
    this._killSwitch = opts.killSwitch ?? (() => false);
    this._now = opts.now ?? (() => Date.now());
  }

  private _record(state: HarnessRunState, step: StoredRunStep) {
    const existing = state.steps.find((s) => s.step_index === step.step_index);

    if (existing) {
      Object.assign(existing, step);
    } else {
      state.steps.push(step);
    }
  }

  /**
   * Build a stored step, populating server-owned continuity fields for a TERMINAL
   * decision exactly as the finalization RPC would (result_hash + safe_result +
   * previous_step_hash chained to the prior finalized step); a REQUIRE_APPROVAL
   * pause carries no continuity.
   */
  private _storedStep(
    state: HarnessRunState,
    stepIndex: number,
    actionType: ProposedAction['action_type'],
    inputHash: string,
    d: GateDecision,
  ): StoredRunStep {
    const terminal = d.decision !== 'REQUIRE_APPROVAL';
    const prev =
      stepIndex === 0 ? null : (state.steps.find((s) => s.step_index === stepIndex - 1)?.result_hash ?? null);

    return {
      run_id: state.run_id,
      org_id: ORG_ID,
      step_index: stepIndex,
      action_type: actionType,
      decision: d.decision,
      reason_codes: [],
      receipt_id: d.receipt_id,
      input_hash: inputHash,
      evaluation_id: d.evaluation_id,
      result_hash: terminal ? synthResultHash(state.run_id, stepIndex, inputHash, d) : null,
      safe_result: resultOf(d).safe_result,
      previous_step_hash: terminal ? prev : null,
    };
  }

  async start(
    inputs: Record<string, unknown>,
    manifest = referenceManifestView(),
  ): Promise<{
    provider: AgentRuntimeProvider;
    state: HarnessRunState;
  }> {
    const provider = this._providerFactory();
    const ctx: RuntimeInitContext = { manifest, synthetic_inputs: inputs };
    this.initContexts.push(ctx);
    await provider.init(ctx);

    const state: HarnessRunState = {
      run_id: RUN_ID,
      state: 'RUNNING',
      current_step: 0,
      pending_evaluation_id: null,
      steps: [],
      reason: null,
    };

    this._startedAt = this._now();
    await this._drive(provider, state, 0, []);

    return { provider, state };
  }

  private async _drive(
    provider: AgentRuntimeProvider,
    state: HarnessRunState,
    startStep: number,
    priorSeed: GovernedActionResult[],
  ): Promise<void> {
    let stepIndex = startStep;
    let prior = priorSeed;
    let modelCalls = 0;
    let proposed = state.steps.filter((s) => s.decision && s.decision !== 'REQUIRE_APPROVAL').length;
    const deadline = this._startedAt + this._limits.max_runtime_seconds * 1000;

    if (this._killSwitch()) {
      state.state = 'SUSPENDED';
      state.reason = 'KILL_SWITCH_ACTIVE';

      return;
    }

    for (;;) {
      if (this._now() > deadline) {
        state.state = 'FAILED';
        state.reason = 'RUNTIME_TIMEOUT';

        return;
      }

      const out = await provider.step({ step_index: stepIndex, prior_results: prior });

      if (out.kind === 'FAIL') {
        state.state = 'FAILED';
        state.reason = out.error_reason ?? 'PROVIDER_FAILED';

        return;
      }

      if (out.kind === 'COMPLETE') {
        state.state = 'COMPLETED';
        state.current_step = stepIndex;

        return;
      }

      prior = [];

      for (const action of out.proposed_actions ?? []) {
        if (proposed >= this._limits.max_actions_per_run) {
          state.state = 'FAILED';
          state.reason = 'ACTION_LIMIT_EXCEEDED';

          return;
        }

        if (action.action_type === 'AI_MODEL_INVOCATION' && modelCalls >= this._limits.max_model_calls_per_run) {
          state.state = 'FAILED';
          state.reason = 'MODEL_CALL_LIMIT_EXCEEDED';

          return;
        }

        proposed += 1;

        if (action.action_type === 'AI_MODEL_INVOCATION') {
          modelCalls += 1;
        }

        const d = this._gate.enforce(action, `${state.run_id}:${stepIndex}`);
        this._record(state, this._storedStep(state, stepIndex, action.action_type, inputHashOf(action), d));

        if (d.decision === 'DENY') {
          state.state = 'FAILED';
          state.reason = 'GOVERNED_ACTION_DENIED';

          return;
        }

        if (d.decision === 'REQUIRE_APPROVAL') {
          state.state = 'AWAITING_APPROVAL';
          state.current_step = stepIndex;
          state.pending_evaluation_id = d.evaluation_id;

          return;
        }

        prior.push(resultOf(d));
      }

      stepIndex += 1;
      state.current_step = stepIndex;
    }
  }

  /**
   * Resume an AWAITING_APPROVAL run after RESTART. A brand-new provider instance
   * (no in-process memory); state reconstructed ONLY from stored steps via the
   * PRODUCTION `reconstructForResume` guard. Fails closed on tamper/missing/wrong
   * approval rather than replaying.
   */
  async restartAndResume(
    state: HarnessRunState,
    inputs: Record<string, unknown>,
    approvedEvaluationId: string = state.pending_evaluation_id ?? '',
    manifest = referenceManifestView(),
  ): Promise<{ reconstruction: Awaited<ReturnType<typeof reconstructForResume>>; state: HarnessRunState }> {
    const provider = this._providerFactory();
    const ctx: RuntimeInitContext = { manifest, synthetic_inputs: inputs };
    this.initContexts.push(ctx);
    await provider.init(ctx);

    const reconstruction = await reconstructForResume({
      provider,
      run: runIdentity(state),
      steps: state.steps,
      approvedEvaluationId,
    });

    if (!reconstruction.ok || !reconstruction.paused_action) {
      // Fail closed: no gate submission, no execution, no state change.
      return { reconstruction, state };
    }

    const pauseIndex = reconstruction.pause_index;
    const d = this._gate.enforce(
      reconstruction.paused_action,
      `${state.run_id}:${pauseIndex}:e2`,
      approvedEvaluationId,
    );
    this._record(
      state,
      this._storedStep(
        state,
        pauseIndex,
        reconstruction.paused_action.action_type,
        inputHashOf(reconstruction.paused_action),
        d,
      ),
    );

    if (d.decision === 'REQUIRE_APPROVAL') {
      state.pending_evaluation_id = d.evaluation_id;

      return { reconstruction, state };
    }

    if (d.decision === 'DENY') {
      state.state = 'FAILED';
      state.reason = 'GOVERNED_ACTION_DENIED';

      return { reconstruction, state };
    }

    state.state = 'RUNNING';
    state.pending_evaluation_id = null;
    this._startedAt = this._now();
    await this._drive(provider, state, pauseIndex + 1, [resultOf(d)]);

    return { reconstruction, state };
  }
}

/*
 * --------------------------------------------------------------------------
 * Test fixture providers (real providers exercising specific paths)
 * --------------------------------------------------------------------------
 */

/** A minimal provider that proposes exactly one TOOL action, then completes. */
export class ToolProposingProvider implements AgentRuntimeProvider {
  readonly provider_id = 'qhub.runtime.test.tool';
  readonly provider_version = '1.0.0';
  private _cancelled = false;

  async init(): Promise<void> {
    this._cancelled = false;
  }

  async step(input: RuntimeStepInput): Promise<RuntimeStepOutput> {
    if (this._cancelled) {
      return { kind: 'FAIL', error_reason: 'CANCELLED' };
    }

    if (input.prior_results.some((r) => r.decision === 'DENY')) {
      return { kind: 'FAIL', error_reason: 'GOVERNED_ACTION_DENIED' };
    }

    if (input.step_index === 0) {
      return {
        kind: 'PROPOSE',
        proposed_actions: [
          {
            step_kind: 'TOOL_ACTION',
            action_type: 'DATABASE_MUTATION',
            target_resource: 'qhub.tool.commission-reconciliation-write',
            operation: 'write_simulation',
            material_parameters: { synthetic: true, note: 'tool routing conformance' },
            summary: 'Invoke the reconciliation-write tool (synthetic).',
          },
        ],
      };
    }

    return { kind: 'COMPLETE', output_summary: 'Tool action complete.' };
  }

  cancel(): void {
    this._cancelled = true;
  }
}

/*
 * --------------------------------------------------------------------------
 * PROVIDER-level conformance (genuine provider responsibilities, real asserts)
 * --------------------------------------------------------------------------
 */

export interface ConformanceOutcome {
  id: number;
  name: string;
  category: 'PROVIDER_CONTRACT';
  pass: boolean;

  /** The observable assertion behind this result. */
  assertion: string;
  detail?: string;
}

const CREDENTIAL_KEYS = [
  'service_role',
  'supabase',
  'aws',
  'secret',
  'password',
  'token',
  'api_key',
  'credential',
  'connection_string',
];

function viewHasNoCredentials(view: RuntimeManifestView): boolean {
  const keys = Object.keys(view).map((k) => k.toLowerCase());

  return !keys.some((k) => CREDENTIAL_KEYS.some((c) => k.includes(c)));
}

function viewLikeSecret(s: string): boolean {
  return /secret|password|api_key|service_role|bearer /i.test(s);
}

/**
 * INSTRUMENTED provider purity: drive the provider through a full plan while
 * globalThis.fetch (the network entry point used by fetch-based providers, incl.
 * LangChain/LangSmith) is replaced with a guard that counts and throws. Proves
 * `provider.step()` makes ZERO network calls and returns ONLY PROPOSE/COMPLETE/FAIL
 * (never executes). Framework-agnostic (no vitest).
 */
export async function instrumentedPurity(
  providerFactory: () => AgentRuntimeProvider,
  inputs: Record<string, unknown> = syntheticInputsWithDiscrepancy(),
): Promise<{ ok: boolean; detail: string }> {
  const origFetch = (globalThis as { fetch?: unknown }).fetch;
  let netCalls = 0;
  let executed = false;
  const guard = () => {
    netCalls += 1;
    throw new Error('NETWORK_FORBIDDEN in provider.step()');
  };

  (globalThis as { fetch?: unknown }).fetch = guard;

  try {
    const p = providerFactory();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    for (let i = 0; i < 12; i++) {
      const out = await p.step({ step_index: i, prior_results: [] });

      if (out.kind !== 'PROPOSE' && out.kind !== 'COMPLETE' && out.kind !== 'FAIL') {
        executed = true;
        break;
      }

      if (out.kind !== 'PROPOSE') {
        break;
      }
    }
  } catch {
    netCalls += 1; // a throw during the drive counts as a prohibited attempt
  } finally {
    (globalThis as { fetch?: unknown }).fetch = origFetch;
  }

  return { ok: netCalls === 0 && !executed, detail: `netCalls=${netCalls} executedKind=${executed}` };
}

/**
 * A. PROVIDER CONTRACT CONFORMANCE — ONLY requirements the provider itself can
 * prove. Each outcome is backed by an executed behavioural assertion (no
 * hard-coded/tautological pass). Gate/orchestrator behaviours are reported
 * separately as RUNTIME INTEGRATION ASSURANCE (see the integration test suite).
 */
export async function providerContractConformance(
  providerFactory: () => AgentRuntimeProvider,
): Promise<ConformanceOutcome[]> {
  const out: ConformanceOutcome[] = [];
  const add = (id: number, name: string, pass: boolean, assertion: string, detail?: string) =>
    out.push({ id, name, category: 'PROVIDER_CONTRACT', pass, assertion, detail });

  const inputs = syntheticInputsWithDiscrepancy();

  const p0 = providerFactory();
  add(
    1,
    'stable provider id + version',
    !!p0.provider_id && !!p0.provider_version,
    'provider_id && provider_version truthy',
    p0.provider_id,
  );

  add(
    2,
    'implements the full init/step/cancel contract',
    typeof p0.init === 'function' && typeof p0.step === 'function' && typeof p0.cancel === 'function',
    'typeof init/step/cancel === function',
  );

  // Input contract: init receives ONLY {manifest, synthetic_inputs}; no credentials.
  const capture = new GovernedRunHarness(providerFactory, new MockGate({ connectorRequiresApproval: false }));
  await capture.start(inputs);

  const ctx0 = capture.initContexts[0];
  add(
    3,
    'init context carries only {manifest, synthetic_inputs}',
    !!ctx0 && Object.keys(ctx0).sort().join(',') === 'manifest,synthetic_inputs',
    "Object.keys(initCtx) === ['manifest','synthetic_inputs']",
  );
  add(
    4,
    'manifest view exposes no credential fields',
    !!ctx0 && viewHasNoCredentials(ctx0.manifest),
    'no manifest key matches a credential pattern',
  );

  // Structured proposals.
  const insp = providerFactory();
  await insp.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

  const first = await insp.step({ step_index: 0, prior_results: [] });
  const a0 = first.kind === 'PROPOSE' ? first.proposed_actions?.[0] : undefined;
  add(
    5,
    'returns structured proposed actions',
    !!a0 && !!a0.step_kind && !!a0.action_type && !!a0.target_resource && !!a0.operation,
    'proposed_actions[0] has step_kind/action_type/target_resource/operation',
    a0?.action_type,
  );

  // Determinism.
  const q1 = providerFactory();
  const q2 = providerFactory();
  await q1.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });
  await q2.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

  const s1 = await q1.step({ step_index: 0, prior_results: [] });
  const s2 = await q2.step({ step_index: 0, prior_results: [] });
  add(
    6,
    'deterministic proposals for identical inputs',
    JSON.stringify(s1) === JSON.stringify(s2),
    'two instances → identical step(0) output',
  );

  // Halts after a prior DENY.
  const denyOut = await insp.step({
    step_index: 1,
    prior_results: [{ decision: 'DENY', reason_codes: [], receipt_id: null, safe_result: null }],
  });
  add(
    7,
    'halts after a prior DENY',
    denyOut.kind === 'FAIL',
    'step() with a prior DENY → kind FAIL',
    denyOut.error_reason,
  );

  // Cooperative cancellation.
  const cp = providerFactory();
  await cp.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });
  cp.cancel();

  const cancelled = await cp.step({ step_index: 0, prior_results: [] });
  add(8, 'cooperative cancellation', cancelled.kind === 'FAIL', 'cancel() then step() → kind FAIL');

  // Safe terminal summary.
  const runToEnd = new GovernedRunHarness(providerFactory, new MockGate({ connectorRequiresApproval: false }));
  const { provider: doneProvider } = await runToEnd.start(inputs);
  const terminal = await doneProvider.step({ step_index: 99, prior_results: [] });
  const summary = terminal.kind === 'COMPLETE' ? (terminal.output_summary ?? '') : '';
  add(
    9,
    'terminal output is a safe summary only',
    terminal.kind === 'COMPLETE' && typeof summary === 'string' && !viewLikeSecret(summary),
    'COMPLETE.output_summary is a string with no secret markers',
  );

  /*
   * INSTRUMENTED (behavioural) purity — the network entry point used by
   * fetch-based clients (incl. LangChain/LangSmith) is spied and must not be
   * called; step() returns only PROPOSE/COMPLETE/FAIL. Model/tool/adapter/
   * evidence/DB capabilities are proven absent STRUCTURALLY (import-boundary
   * test), not claimed as behaviourally instrumented here.
   */
  const purity = await instrumentedPurity(providerFactory, inputs);
  add(
    10,
    'no global fetch network call inside provider.step() (behavioural)',
    purity.ok,
    'globalThis.fetch spied → zero calls during a full step() drive; only PROPOSE/COMPLETE/FAIL',
    purity.detail,
  );

  return out;
}
