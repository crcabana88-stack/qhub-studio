/**
 * QHUB Agent Framework Foundation — Runtime provider registry (SERVER ONLY)
 * app/lib/qhub/agent/runtime/provider-registry.server.ts
 *
 * Server-authoritative selection of a runtime provider. The browser can never
 * choose a provider; selection is by the manifest's server-set runtime_provider.
 * Unknown providers FAIL CLOSED. Only the local deterministic simulation provider
 * exists in this phase (no managed/external runtime).
 */

import type { AgentRuntimeProvider } from './provider';
import {
  LocalSimulationProvider,
  LOCAL_SIMULATION_PROVIDER_ID,
  LOCAL_SIMULATION_PROVIDER_VERSION,
} from './local-simulation-provider';
import { LangGraphRuntimeProvider, LANGGRAPH_PROVIDER_ID } from './langgraph-runtime-provider';

/**
 * Known providers this build is allowed to run. Add future adapters here.
 * The local deterministic simulation provider is the default verified baseline;
 * the LangGraph provider is present for controlled evaluation only (selected
 * server-side by a manifest's runtime_provider, never the default).
 */
const PROVIDER_FACTORIES: Record<string, () => AgentRuntimeProvider> = {
  [LOCAL_SIMULATION_PROVIDER_ID]: () => new LocalSimulationProvider(),
  [LANGGRAPH_PROVIDER_ID]: () => new LangGraphRuntimeProvider(),
};

export const DEFAULT_RUNTIME_PROVIDER_ID = LOCAL_SIMULATION_PROVIDER_ID;

export interface ProviderSelection {
  ok: boolean;
  provider?: AgentRuntimeProvider;
  reason?: 'UNKNOWN_PROVIDER' | 'VERSION_MISMATCH';
}

/**
 * Select a provider by its server-authoritative id. Fail-closed on unknown id.
 * When expectedVersion is given, the resolved provider version must match.
 */
export function selectRuntimeProvider(providerId: string, expectedVersion?: string): ProviderSelection {
  const factory = PROVIDER_FACTORIES[providerId];

  if (!factory) {
    return { ok: false, reason: 'UNKNOWN_PROVIDER' };
  }

  const provider = factory();

  if (expectedVersion && provider.provider_version !== expectedVersion) {
    return { ok: false, reason: 'VERSION_MISMATCH' };
  }

  return { ok: true, provider };
}

export function knownProviderIds(): string[] {
  return Object.keys(PROVIDER_FACTORIES);
}

export const LOCAL_SIMULATION = {
  id: LOCAL_SIMULATION_PROVIDER_ID,
  version: LOCAL_SIMULATION_PROVIDER_VERSION,
};
