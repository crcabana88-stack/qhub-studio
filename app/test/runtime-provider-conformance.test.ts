/**
 * QHUB Agent Framework — runtime provider conformance + integration tests
 * app/test/runtime-provider-conformance.test.ts
 *
 * HONEST scoping:
 *   - "provider conformance" counts ONLY genuine provider-level responsibilities,
 *     each backed by an executed behavioural assertion (no hard-coded outcomes).
 *   - Orchestrator / Gate 04 / Gate 05 behaviours are exercised as separate
 *     INTEGRATION tests using the production `reconstructForResume` guard, not
 *     counted in the provider score.
 */

import { describe, it, expect } from 'vitest';
import {
  providerContractConformance,
  instrumentedPurity,
  GovernedRunHarness,
  MockGate,
  ToolProposingProvider,
  referenceManifestView,
  syntheticInputsWithDiscrepancy,
  inputHashOf,
  type ConformanceOutcome,
} from '~/lib/qhub/agent/runtime/runtime-provider-conformance';
import {
  LocalSimulationProvider,
  LOCAL_SIMULATION_PROVIDER_ID,
} from '~/lib/qhub/agent/runtime/local-simulation-provider';
import { selectRuntimeProvider } from '~/lib/qhub/agent/runtime/provider-registry.server';
import {
  reconstructForResume,
  type RunIdentity,
  type StoredRunStep,
} from '~/lib/qhub/agent/runtime/run-reconstruction';

const localFactory = () => new LocalSimulationProvider();

// ── STRUCTURAL exclusion: provider modules cannot import prohibited capabilities ─

describe('A0. PROVIDER CONTRACT CONFORMANCE — structural capability exclusion', () => {
  const providerModules = [
    'app/lib/qhub/agent/runtime/provider.ts',
    'app/lib/qhub/agent/runtime/local-simulation-provider.ts',
    'app/lib/qhub/agent/reference/commission-reconciliation.ts',
  ];

  /*
   * A provider must not be able to reach a DB client, a Gate/adapter/evidence
   * executor, a model/connector client, the network, or the filesystem.
   */
  const PROHIBITED = [
    /from ['"][^'"]*\.server['"]/, // any server-only executor (Gate 04, stores, adapters, evidence)
    /@supabase/, // database client
    /node:http\b/,
    /node:https\b/,
    /node:net\b/,
    /node:dns\b/,
    /node:fs\b/,
    /node:child_process\b/,
    /openai|anthropic|@ai-sdk|langchain|langgraph|langsmith/i, // model/connector clients
  ];

  for (const mod of providerModules) {
    it(`${mod} imports no prohibited capability`, async () => {
      const fs = await import('node:fs');
      const src = fs.readFileSync(mod, 'utf8');
      const importLines = src.split('\n').filter((l) => /^\s*import\b/.test(l) || /require\(/.test(l));
      const violations = importLines.filter((l) => PROHIBITED.some((re) => re.test(l)));
      expect(violations).toEqual([]);
    });
  }
});

// ── A. PROVIDER CONTRACT CONFORMANCE (only what the provider itself proves) ───

describe('A. PROVIDER CONTRACT CONFORMANCE — local deterministic provider', () => {
  let outcomes: ConformanceOutcome[];

  it('reports honest provider-contract properties (all PROVIDER_CONTRACT, each with an assertion)', async () => {
    outcomes = await providerContractConformance(localFactory);
    expect(outcomes.length).toBe(10);
    expect(outcomes.every((o) => o.category === 'PROVIDER_CONTRACT')).toBe(true);
    expect(outcomes.every((o) => typeof o.assertion === 'string' && o.assertion.length > 0)).toBe(true);
  });

  it('passes every provider-contract property with a real assertion', async () => {
    outcomes = outcomes ?? (await providerContractConformance(localFactory));

    const failed = outcomes.filter((o) => !o.pass);
    expect(failed.map((f) => `#${f.id} ${f.name}${f.detail ? ` (${f.detail})` : ''}`)).toEqual([]);
  });

  it('instrumented purity is real: it FAILS for a provider that makes a network call', async () => {
    class ImpureProvider {
      readonly provider_id = 'qhub.runtime.test.impure';
      readonly provider_version = '1.0.0';
      async init() {
        return undefined;
      }
      async step() {
        await fetch('https://example.invalid/x');
        return { kind: 'COMPLETE' as const, output_summary: 'done' };
      }
      cancel() {
        /* no-op */
      }
    }

    const impure = await instrumentedPurity(() => new ImpureProvider());
    expect(impure.ok).toBe(false);

    // …and PASSES for the pure local provider.
    const pure = await instrumentedPurity(() => new LocalSimulationProvider());
    expect(pure.ok).toBe(true);
  });
});

// ── TOOL ROUTING (Codex A) ───────────────────────────────────────────────────

describe('tool routing — provider proposes, only the gate executes', () => {
  const toolFactory = () => new ToolProposingProvider();

  it('ALLOW: tool routed through the gate; provider never executes it', async () => {
    const gate = new MockGate({ connectorRequiresApproval: false });
    const harness = new GovernedRunHarness(toolFactory, gate);
    const { state } = await harness.start({});
    expect(state.state).toBe('COMPLETED');
    expect(gate.counters.toolCalls).toBe(1);
    expect(gate.counters.adapterExecutions).toBe(1); // the gate executed exactly once
    expect(gate.counters.receipts).toBe(1);
    expect(state.steps.filter((s) => s.action_type === 'DATABASE_MUTATION')).toHaveLength(1);
  });

  it('DENY: zero adapter executions, run fails closed', async () => {
    const gate = new MockGate({ denyTargetSubstring: 'qhub.tool' });
    const harness = new GovernedRunHarness(toolFactory, gate);
    const { state } = await harness.start({});
    expect(state.state).toBe('FAILED');
    expect(state.reason).toBe('GOVERNED_ACTION_DENIED');
    expect(gate.counters.adapterExecutions).toBe(0);
    expect(gate.counters.receipts).toBe(0);
  });
});

// ── ORCHESTRATOR / GATE 04 INTEGRATION (real reconstructForResume) ────────────

describe('orchestrator integration — Gate 04 pause / resume / no-replay', () => {
  const inputs = syntheticInputsWithDiscrepancy();

  it('DENY on the connector stops the run', async () => {
    const gate = new MockGate({ denyTargetSubstring: '.invalid' });
    const { state } = await new GovernedRunHarness(localFactory, gate).start(inputs);
    expect(state.state).toBe('FAILED');
    expect(state.reason).toBe('GOVERNED_ACTION_DENIED');
  });

  it('REQUIRE_APPROVAL pauses; exact-E2 resume completes with one receipt', async () => {
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(localFactory, gate);
    const { state: paused } = await harness.start(inputs);
    expect(paused.state).toBe('AWAITING_APPROVAL');

    const receiptsBefore = gate.counters.receipts;
    const { reconstruction, state: done } = await harness.restartAndResume(paused, inputs);
    expect(reconstruction.ok).toBe(true);
    expect(done.state).toBe('COMPLETED');
    expect(gate.counters.receipts).toBe(receiptsBefore + 1); // no duplicate
    expect(done.steps.filter((s) => s.action_type === 'EXTERNAL_DATA_TRANSMISSION')).toHaveLength(1);
  });

  it('RESTART reconstructs from stored steps and re-executes NOTHING completed', async () => {
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(localFactory, gate);
    const { state: paused } = await harness.start(inputs);

    const before = { ...gate.counters };
    const { reconstruction, state: done } = await harness.restartAndResume(paused, inputs);

    expect(reconstruction.ok).toBe(true);
    expect(done.state).toBe('COMPLETED');

    // Completed model step (step 0) NOT re-run; no extra approval request.
    expect(gate.counters.modelCalls).toBe(before.modelCalls);
    expect(gate.counters.approvalRequests).toBe(before.approvalRequests);

    // Exactly one new submission (the approved E2) + one new receipt.
    expect(gate.counters.submissions).toBe(before.submissions + 1);
    expect(gate.counters.adapterExecutions).toBe(before.adapterExecutions + 1);
    expect(gate.counters.receipts).toBe(before.receipts + 1);
  });

  it('tampered prior result fails closed — no execution', async () => {
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(localFactory, gate);
    const { state: paused } = await harness.start(inputs);
    const tampered = {
      ...paused,
      steps: paused.steps.map((s) => (s.step_index === 0 ? { ...s, input_hash: 'deadbeef' } : s)),
    };
    const before = gate.counters.receipts;
    const { reconstruction } = await harness.restartAndResume(tampered, inputs);
    expect(reconstruction.ok).toBe(false);
    expect(reconstruction.reason).toBe('PRIOR_RESULT_TAMPERED');
    expect(gate.counters.receipts).toBe(before);
  });

  it('missing prior step fails closed rather than replaying', async () => {
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(localFactory, gate);
    const { state: paused } = await harness.start(inputs);
    const missing = { ...paused, steps: paused.steps.filter((s) => s.step_index !== 0) };
    const before = gate.counters.receipts;
    const { reconstruction } = await harness.restartAndResume(missing, inputs);
    expect(reconstruction.ok).toBe(false);
    expect(['MISSING_PRIOR_STEP', 'DUPLICATE_TERMINAL_RECEIPT']).toContain(reconstruction.reason);
    expect(gate.counters.receipts).toBe(before);
  });

  it('wrong-action approval cannot resume; no receipt is produced (Codex B)', async () => {
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(localFactory, gate);
    const { state: paused } = await harness.start(inputs);
    const before = gate.counters.receipts;

    // Supply an approval/evaluation for a DIFFERENT action.
    const { reconstruction } = await harness.restartAndResume(paused, inputs, 'eval-for-action-B');
    expect(reconstruction.ok).toBe(false);
    expect(reconstruction.reason).toBe('PENDING_EVALUATION_MISMATCH');
    expect(gate.counters.receipts).toBe(before);
  });
});

// ── LIMITS + KILL SWITCH (real attempted counts / controllable clock) ────────

describe('run limits + kill switch (integration)', () => {
  const inputs = syntheticInputsWithDiscrepancy();

  it('max actions per run enforced by actual attempted action count', async () => {
    const gate = new MockGate({ connectorRequiresApproval: false });
    const harness = new GovernedRunHarness(localFactory, gate, {
      limits: { max_actions_per_run: 1, max_model_calls_per_run: 4, max_runtime_seconds: 60 },
    });
    const { state } = await harness.start(inputs);
    expect(state.state).toBe('FAILED');
    expect(state.reason).toBe('ACTION_LIMIT_EXCEEDED');
  });

  it('max model calls enforced by actual attempted model-call count', async () => {
    const gate = new MockGate({ connectorRequiresApproval: false });
    const harness = new GovernedRunHarness(localFactory, gate, {
      limits: { max_actions_per_run: 8, max_model_calls_per_run: 0, max_runtime_seconds: 60 },
    });
    const { state } = await harness.start(inputs);
    expect(state.state).toBe('FAILED');
    expect(state.reason).toBe('MODEL_CALL_LIMIT_EXCEEDED');
  });

  it('runtime duration limit stops the run via a controllable clock (Codex E)', async () => {
    let t = 0;
    const clock = () => t;
    const gate = new MockGate({ connectorRequiresApproval: false });
    const harness = new GovernedRunHarness(localFactory, gate, {
      limits: { max_actions_per_run: 8, max_model_calls_per_run: 4, max_runtime_seconds: 30 },
      now: () => {
        const v = t;
        t += 60_000;

        // each read jumps 60s → exceeds the 30s deadline immediately
        return v;
      },
    });
    const { state } = await harness.start(inputs);
    expect(state.state).toBe('FAILED');
    expect(state.reason).toBe('RUNTIME_TIMEOUT');

    // No action was proposed/executed after timeout.
    expect(gate.counters.submissions).toBe(0);
    expect(gate.counters.receipts).toBe(0);
    void clock;
  });

  it('kill switch suspends execution before any action', async () => {
    const gate = new MockGate({ connectorRequiresApproval: false });
    const harness = new GovernedRunHarness(localFactory, gate, { killSwitch: () => true });
    const { state } = await harness.start(inputs);
    expect(state.state).toBe('SUSPENDED');
    expect(gate.counters.adapterExecutions).toBe(0);
  });
});

// ── PRODUCTION reconstructForResume — direct fail-closed unit checks ──────────

describe('reconstructForResume — direct fail-closed unit checks', () => {
  const run: RunIdentity = {
    run_id: 'r1',
    org_id: 'o1',
    agent_id: 'a1',
    agent_version_id: 'v1',
    release_candidate_hash: 'rc1',
    qhub_app_id: 'app1',
    current_state: 'AWAITING_APPROVAL',
    current_step: 1,
    pending_evaluation_id: 'E1',
  };
  const inputs = syntheticInputsWithDiscrepancy();

  async function planHashes() {
    const p = new LocalSimulationProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    return p.plan().map(inputHashOf);
  }

  function steps(over: Partial<StoredRunStep>[] = []): StoredRunStep[] {
    const base: StoredRunStep[] = [
      {
        run_id: 'r1',
        org_id: 'o1',
        step_index: 0,
        action_type: 'AI_MODEL_INVOCATION',
        decision: 'SIMULATED',
        reason_codes: [],
        receipt_id: 'rM',
        input_hash: '',
        evaluation_id: 'Emodel',
      },
      {
        run_id: 'r1',
        org_id: 'o1',
        step_index: 1,
        action_type: 'EXTERNAL_DATA_TRANSMISSION',
        decision: 'REQUIRE_APPROVAL',
        reason_codes: [],
        receipt_id: null,
        input_hash: '',
        evaluation_id: 'E1',
      },
    ];
    return base.map((s, i) => ({ ...s, ...(over[i] ?? {}) }));
  }

  it('happy path reconstructs and returns the exact paused action', async () => {
    const h = await planHashes();
    const s = steps([{ input_hash: h[0] }, { input_hash: h[1] }]);
    const p = new LocalSimulationProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    const r = await reconstructForResume({ provider: p, run, steps: s, approvedEvaluationId: 'E1' });
    expect(r.ok).toBe(true);
    expect(r.paused_action?.action_type).toBe('EXTERNAL_DATA_TRANSMISSION');
    expect(inputHashOf(r.paused_action!)).toBe(h[1]);
  });

  it('cross-tenant step ownership fails closed', async () => {
    const h = await planHashes();
    const s = steps([{ input_hash: h[0], org_id: 'EVIL' }, { input_hash: h[1] }]);
    const p = new LocalSimulationProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    const r = await reconstructForResume({ provider: p, run, steps: s, approvedEvaluationId: 'E1' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('STEP_OWNERSHIP_MISMATCH');
  });

  it('altered paused-step evaluation reference fails closed', async () => {
    const h = await planHashes();
    const s = steps([{ input_hash: h[0] }, { input_hash: h[1], evaluation_id: 'E-OTHER' }]);
    const p = new LocalSimulationProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    const r = await reconstructForResume({ provider: p, run, steps: s, approvedEvaluationId: 'E1' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('PAUSED_STEP_MISMATCH');
  });

  it('completed run cannot resume', async () => {
    const h = await planHashes();
    const s = steps([{ input_hash: h[0] }, { input_hash: h[1] }]);
    const p = new LocalSimulationProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

    const r = await reconstructForResume({
      provider: p,
      run: { ...run, current_state: 'COMPLETED' },
      steps: s,
      approvedEvaluationId: 'E1',
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('RUN_NOT_RESUMABLE');
  });
});

// ── REGISTRY FAIL-CLOSED ─────────────────────────────────────────────────────

describe('provider registry fail-closed', () => {
  it('selects the known local provider', () => {
    const sel = selectRuntimeProvider(LOCAL_SIMULATION_PROVIDER_ID);
    expect(sel.ok).toBe(true);
    expect(sel.provider?.provider_id).toBe(LOCAL_SIMULATION_PROVIDER_ID);
  });

  it('fails closed on an unknown provider', () => {
    expect(selectRuntimeProvider('qhub.runtime.evil').reason).toBe('UNKNOWN_PROVIDER');
  });

  it('fails closed on a version mismatch', () => {
    expect(selectRuntimeProvider(LOCAL_SIMULATION_PROVIDER_ID, '9.9.9').reason).toBe('VERSION_MISMATCH');
  });
});
