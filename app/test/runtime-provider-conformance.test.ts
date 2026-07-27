/**
 * QHUB Agent Framework — runtime provider conformance + no-replay tests
 * app/test/runtime-provider-conformance.test.ts
 *
 * Proves the local deterministic provider obeys the governance contract (30
 * properties) and the no-replay recovery rule: restart never re-executes a
 * completed consequential node, and a tampered/missing prior result fails closed
 * instead of replaying. The suite is provider-neutral and reusable for any future
 * runtime provider.
 */

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
import {
  LocalSimulationProvider,
  LOCAL_SIMULATION_PROVIDER_ID,
} from '~/lib/qhub/agent/runtime/local-simulation-provider';
import { selectRuntimeProvider } from '~/lib/qhub/agent/runtime/provider-registry.server';
import { reconstructRunState } from '~/lib/qhub/agent/runtime/run-reconstruction';

const PROVIDERS: Array<{ label: string; factory: () => LocalSimulationProvider }> = [
  { label: 'LocalSimulationProvider', factory: () => new LocalSimulationProvider() },
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
  it('selects the known local provider', () => {
    const sel = selectRuntimeProvider(LOCAL_SIMULATION_PROVIDER_ID);
    expect(sel.ok).toBe(true);
    expect(sel.provider?.provider_id).toBe(LOCAL_SIMULATION_PROVIDER_ID);
  });

  it('fails closed on an unknown provider', () => {
    const sel = selectRuntimeProvider('qhub.runtime.evil');
    expect(sel.ok).toBe(false);
    expect(sel.reason).toBe('UNKNOWN_PROVIDER');
  });

  it('fails closed on a version mismatch', () => {
    const sel = selectRuntimeProvider(LOCAL_SIMULATION_PROVIDER_ID, '9.9.9');
    expect(sel.ok).toBe(false);
    expect(sel.reason).toBe('VERSION_MISMATCH');
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

      const modelBefore = gate.counters.modelCalls;
      const submissionsBefore = gate.counters.submissions;
      const approvalsBefore = gate.counters.approvalRequests;
      const adapterBefore = gate.counters.adapterExecutions;
      const receiptsBefore = gate.counters.receipts;

      const { reconstruction, state: resumed } = await harness.restartAndResume(paused, inputs);

      expect(reconstruction.ok).toBe(true);
      expect(reconstruction.terminal).toBe('AWAITING_APPROVAL');
      expect(resumed.state).toBe('COMPLETED');

      expect(gate.counters.modelCalls).toBe(modelBefore);
      expect(gate.counters.approvalRequests).toBe(approvalsBefore);
      expect(gate.counters.submissions).toBe(submissionsBefore + 1);
      expect(gate.counters.adapterExecutions).toBe(adapterBefore + 1);
      expect(gate.counters.receipts).toBe(receiptsBefore + 1);

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
      expect(recon.prior_results).toHaveLength(1);
      expect(recon.prior_results[0].decision).toBe('SIMULATED');
    });

    it(`${label}: tampered prior result fails closed (no replay)`, async () => {
      const inputs = syntheticInputsWithDiscrepancy();
      const gate = new MockGate({ connectorRequiresApproval: true });
      const harness = new GovernedRunHarness(factory, gate);
      const { state: paused } = await harness.start(inputs);

      const tampered = {
        ...paused,
        steps: paused.steps.map((s) => (s.step_index === 0 ? { ...s, input_hash: 'deadbeef' } : s)),
      };

      const receiptsBefore = gate.counters.receipts;
      const adapterBefore = gate.counters.adapterExecutions;
      const { reconstruction } = await harness.restartAndResume(tampered, inputs);

      expect(reconstruction.ok).toBe(false);
      expect(reconstruction.reason).toBe('PRIOR_RESULT_TAMPERED');
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
