/**
 * QHUB Agent Framework — LangGraph provider no-network + tracing-off tests
 * app/test/langgraph-no-network.test.ts
 *
 * Proves the LangGraph runtime provider makes NO network activity during init +
 * step (no fetch / HTTP / HTTPS), and that no LangSmith / hosted-tracing env is
 * silently enabled. LangGraph coordinates the workflow in-process only.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import https from 'node:https';
import { LangGraphRuntimeProvider } from '~/lib/qhub/agent/runtime/langgraph-runtime-provider';
import {
  GovernedRunHarness,
  MockGate,
  referenceManifestView,
  syntheticInputsWithDiscrepancy,
} from '~/lib/qhub/agent/runtime/runtime-provider-conformance';

describe('LangGraph provider — tracing disabled by default', () => {
  it('no LangSmith/LangChain tracing env is enabled', () => {
    const tracing = process.env.LANGCHAIN_TRACING_V2 ?? process.env.LANGSMITH_TRACING ?? '';
    expect(['', 'false', '0']).toContain(String(tracing).toLowerCase());

    // No LangSmith API key should be present in the test/runtime env.
    expect(process.env.LANGSMITH_API_KEY ?? '').toBe('');
    expect(process.env.LANGCHAIN_API_KEY ?? '').toBe('');
  });
});

describe('LangGraph provider — no network during init + step', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  const origFetch = globalThis.fetch;

  const boom = () => {
    throw new Error('NETWORK_FORBIDDEN: network call during provider execution');
  };

  beforeEach(() => {
    fetchSpy = vi.fn(() => {
      throw new Error('NETWORK_FORBIDDEN: fetch called during provider execution');
    });
    (globalThis as unknown as { fetch: unknown }).fetch = fetchSpy;

    vi.spyOn(http, 'request').mockImplementation(boom as never);
    vi.spyOn(http, 'get').mockImplementation(boom as never);
    vi.spyOn(https, 'request').mockImplementation(boom as never);
    vi.spyOn(https, 'get').mockImplementation(boom as never);
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = origFetch;
    vi.restoreAllMocks();
  });

  it('drives a full governed run with zero network calls', async () => {
    const inputs = syntheticInputsWithDiscrepancy();
    const gate = new MockGate({ connectorRequiresApproval: true });
    const harness = new GovernedRunHarness(() => new LangGraphRuntimeProvider(), gate);

    const { state: paused } = await harness.start(inputs);
    expect(paused.state).toBe('AWAITING_APPROVAL');

    const { state: resumed } = await harness.restartAndResume(paused, inputs);
    expect(resumed.state).toBe('COMPLETED');

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(vi.mocked(http.request)).not.toHaveBeenCalled();
    expect(vi.mocked(http.get)).not.toHaveBeenCalled();
    expect(vi.mocked(https.request)).not.toHaveBeenCalled();
    expect(vi.mocked(https.get)).not.toHaveBeenCalled();
  });

  it('init alone performs the pure planning graph with no network', async () => {
    const p = new LangGraphRuntimeProvider();
    await p.init({ manifest: referenceManifestView(), synthetic_inputs: syntheticInputsWithDiscrepancy() });
    expect(p.plan().length).toBe(2);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(vi.mocked(https.request)).not.toHaveBeenCalled();
  });
});
