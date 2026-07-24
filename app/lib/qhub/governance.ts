/**
 * QHUB Governance — Public API (re-exports)
 * app/lib/qhub/governance.ts
 *
 * This module previously contained both client-side signing logic AND
 * browser-accessible functions. After the P0-A security remediation,
 * the architecture is split:
 *
 *   Browser code  → governance-client.ts  (no secrets, no signing)
 *   Server code   → governance-service.server.ts  (secret, signing, AWS POST)
 *
 * This file re-exports the browser-safe client API so that existing imports
 * of '~/lib/qhub/governance' continue to work without modification.
 *
 * NOTE: getQhubCredentials() is removed — the HMAC secret is no longer
 * passed through the session or client code. Server code that needs
 * the secret should use getHmacSecret() from ~/lib/auth/session directly.
 */

export {
  notifyProjectCreated,
  notifyAiModelUsed,
  assertDeploymentGate,
} from './governance-client';

export type {
  GenesisIntent,
  AiBomIntent,
  GateCheckIntent,
  GateState,
  GovernanceResponse,
} from './governance-client';

// Legacy type aliases for any code that referenced the old param types
// These can be removed in a later cleanup pass.
export type GenesisParams = import('./governance-client').GenesisIntent & { userId?: string; orgId?: string; hmacSecret?: never };
export type AiBomParams = import('./governance-client').AiBomIntent & { userId?: string; orgId?: string; hmacSecret?: never };
export type GateParams = import('./governance-client').GateCheckIntent & { userId?: string; orgId?: string; hmacSecret?: never };
