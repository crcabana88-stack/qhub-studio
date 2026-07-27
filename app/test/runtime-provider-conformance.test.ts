/**
 * QHUB Agent Framework — runtime provider conformance + no-replay tests
 * app/test/runtime-provider-conformance.test.ts
 *
 * Proves the local simulation provider and the LangGraph provider both obey the
 * governance contract (30 properties) and the no-replay recovery rule: restart
 * never re-executes a completed consequential node, and a tampered/missing prior
 * result fails closed instead of replaying.
 */

/* eslint-disable @typescript-eslint/naming-convention -- destructures the snake_case governed_plan from the graph result */

import { describe, it, expect } from 'vitest';
import {
  conformanceProperties,
  GovernedRunHarness,
  MockGate,
  referenceManifestView,
  syntheticInputsWithDiscrepancy,
  inputHashOf,
  type ConformanceOutcome,
} from '~/lib/qhub/agent/runtime/runtime-provider-conformance';
import { LocalSimulationProvider } from '~/lib/qhub/agent/runtime/local-simulation-provider';
import { LangGraphRuntimeProvider } from '~/lib/qhub/agent/runtime/langgraph-runtime-provider';
import { selectRuntimeProvider } from '~/lib/qhub/agent/runtime/provider-registry.server';
import { reconstructRunState } from '~/lib/qhub/agent/runtime/run-reconstruction';
import { computeGovernedPlan } from '~/lib/qhub/agent/reference/commission-reconciliation-graph';

const PROVIDERS: Array<{ label: string; factory: () => LocalSimulationProvider | LangGraphRuntimeProvider }> = [
  { label: 'LocalSimulationProvider', factory: () => new LocalSimulationProvider() },
  { label: 'LangGraphRuntimeProvider', factory: () => new LangGraphRuntimeProvider() },
];

describe('runtime provider conformance suite (30 properties)', () => {
  for (const { label, factory } of PROVIDERS) {
    describe(label, () => {
      let outcomes: ConformanceOutcome[];

      it('runs the full suite', async () => {
        outcomes = await conformanceProperties(factory);
        expect(outcomes).toHaveLength(30);
      });

      it('passes every property', async () => {
        outcomes = outcomes ?? (await conformanceProperties(factory));

        const failed = outcomes.filter((o) => !o.pass);
        expect(failed.map((f) => `#${f.id} ${f.name}${f.detail ? ` (${f.detail})` : ''}`)).toEqual([]);
      });
    });
  }
});

describe('provider registry fail-closed', () => {
  it('selects a known provider', () => {
    const sel = selectRuntimeProvider('qhub.runtime.langgraph');
    expect(sel.ok).toBe(true);
    expect(sel.provider?.provider_id).toBe('qhub.runtime.langgraph');
  });

  it('fails closed on an unknown provider', () => {
    const sel = selectRuntimeProvider('qhub.runtime.evil');
    expect(sel.ok).toBe(false);
    expect(sel.reason).toBe('UNKNOWN_PROVIDER');
  });

  it('fails closed on a version mismatch', () => {
    const sel = selectRuntimeProvider('qhub.runtime.langgraph', '9.9.9');
    expect(sel.ok).toBe(false);
    expect(sel.reason).toBe('VERSION_MISMATCH');
  });
});

describe('LangGraph graph produces the same governed plan as the local provider', () => {
  it('model + connector actions with identical material', async () => {
    const inputs = syntheticInputsWithDiscrepancy();
    const view = referenceManifestView();
    const { governed_plan, trace } = await computeGovernedPlan(view, inputs);

    // Same shape/business result as the local plan.
    expect(governed_plan.map((a) => a.action_type)).toEqual(['AI_MODEL_INVOCATION', 'EXTERNAL_DATA_TRANSMISSION']);
    expect(trace).toEqual([
      'VALIDATE_SYNTHETIC_INPUT',
      'COMPARE_RECORDS',
      'ANALYZE_DISCREPANCY',
      'PROPOSE_RECONCILIATION',
    ]);

    const local = new LocalSimulationProvider();
    await local.init({ manifest: view, synthetic_inputs: inputs });
    expect(governed_plan.map(inputHashOf)).toEqual(local.plan().map(inputHashOf));
  });

  it('no discrepancy → model-only plan (no connector write)', async () => {
    const inputs = {
      ledger: [{ broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 100 }],
      statement: [{ broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 100 }],
    };
    const { governed_plan } = await computeGovernedPlan(referenceManifestView(), inputs);
    expect(governed_plan.map((a) => a.action_type)).toEqual(['AI_MODEL_INVOCATION']);
  });
});

describe('no-replay recovery (restart never re-executes a completed node)', () => {
  for (const { label, factory } of PROVIDERS) {
    it(`${label}: restart resumes without repeating model/gate/approval/adapter/receipt`, async () => {
      const inputs = syntheticInputsWithDiscrepancy();
      const gate = new MockGate({ connectorRequiresApproval: true });
      const harness = new GovernedRunHarness(factory, gate);

      const { state: paused } = await harness.start(inputs);
      expect(paused.state).toBe('AWAITING_APPROVAL');

      // Snapshot counters at the pause point.
      const modelBefore = gate.counters.modelCalls;
      const submissionsBefore = gate.counters.submissions;
      const approvalsBefore = gate.counters.approvalRequests;
      const adapterBefore = gate.counters.adapterExecutions;
      const receiptsBefore = gate.counters.receipts;

      // RESTART: brand-new provider instances, state only from stored steps.
      const { reconstruction, state: resumed } = await harness.restartAndResume(paused, inputs);

      expect(reconstruction.ok).toBe(true);
      expect(reconstruction.terminal).toBe('AWAITING_APPROVAL');
      expect(resumed.state).toBe('COMPLETED');

      // The model call (step 0) was NOT repeated on restart.
      expect(gate.counters.modelCalls).toBe(modelBefore);

      // No additional approval request was created.
      expect(gate.counters.approvalRequests).toBe(approvalsBefore);

      // Exactly one new submission (the approved E2) and one new receipt.
      expect(gate.counters.submissions).toBe(submissionsBefore + 1);
      expect(gate.counters.adapterExecutions).toBe(adapterBefore + 1);
      expect(gate.counters.receipts).toBe(receiptsBefore + 1);

      // Exactly one connector receipt overall (no duplicate).
      const connectorSteps = resumed.steps.filter((s) => s.action_type === 'EXTERNAL_DATA_TRANSMISSION');
      expect(connectorSteps).toHaveLength(1);
      expect(connectorSteps[0].decision).toBe('SIMULATED');
    });

    it(`${label}: reconstructed state matches stored run state`, async () => {
      const inputs = syntheticInputsWithDiscrepancy();
      const gate = new MockGate({ connectorRequiresApproval: true });
      const harness = new GovernedRunHarness(factory, gate);
      const { state: paused } = await harness.start(inputs);

      const provider = factory();
      await provider.init({ manifest: referenceManifestView(), synthetic_inputs: inputs });

      const plan = provider.plan();
      const recon = reconstructRunState(paused.steps, (i) => (plan[i] ? inputHashOf(plan[i]) : null));

      expect(recon.ok).toBe(true);
      expect(recon.terminal).toBe('AWAITING_APPROVAL');
      expect(recon.next_step_index).toBe(paused.current_step);

      // Only the executed model step is in prior_results; the connector is pending.
      expect(recon.prior_results).toHaveLength(1);
      expect(recon.prior_results[0].decision).toBe('SIMULATED');
    });

    it(`${label}: tampered prior result fails closed (no replay)`, async () => {
      const inputs = syntheticInputsWithDiscrepancy();
      const gate = new MockGate({ connectorRequiresApproval: true });
      const harness = new GovernedRunHarness(factory, gate);
      const { state: paused } = await harness.start(inputs);

      // Tamper with the stored model step's input hash.
      const tampered = {
        ...paused,
        steps: paused.steps.map((s) => (s.step_index === 0 ? { ...s, input_hash: 'deadbeef' } : s)),
      };

      const receiptsBefore = gate.counters.receipts;
      const adapterBefore = gate.counters.adapterExecutions;
      const { reconstruction } = await harness.restartAndResume(tampered, inputs);

      expect(reconstruction.ok).toBe(false);
      expect(reconstruction.reason).toBe('PRIOR_RESULT_TAMPERED');

      // Fail closed: no consequential action executed.
      expect(gate.counters.receipts).toBe(receiptsBefore);
      expect(gate.counters.adapterExecutions).toBe(adapterBefore);
    });

    it(`${label}: missing prior result fails closed rather than replaying`, async () => {
      const inputs = syntheticInputsWithDiscrepancy();
      const gate = new MockGate({ connectorRequiresApproval: true });
      const harness = new GovernedRunHarness(factory, gate);
      const { state: paused } = await harness.start(inputs);

      const missing = { ...paused, steps: paused.steps.filter((s) => s.step_index !== 0) };
      const receiptsBefore = gate.counters.receipts;
      const { reconstruction } = await harness.restartAndResume(missing, inputs);

      expect(reconstruction.ok).toBe(false);
      expect(reconstruction.reason).toBe('MISSING_PRIOR_STEP');
      expect(gate.counters.receipts).toBe(receiptsBefore);
    });
  }
});
