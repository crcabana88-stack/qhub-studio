/**
 * QHUB Governance Client — browser-safe
 * app/lib/qhub/governance-client.ts
 *
 * Thin browser-side client that sends governance intents to the
 * QHUB server action (/api/governance).
 *
 * SECURITY:
 *   - No HMAC secret. No signing. No direct AWS calls.
 *   - The browser posts an INTENT (what happened + app context).
 *   - The server asserts identity, constructs the canonical event,
 *     signs with the HMAC secret, and POSTs to AWS.
 *   - This module is safe to import in client code.
 *
 * GATE STATE:
 *   - assertDeploymentGate() returns an explicit GateState.
 *   - Only 'APPROVED' authorizes production deployment.
 *   - 'UNKNOWN', 'ERROR', 'BLOCKED' are all fail-closed.
 */

export type GateState = 'APPROVED' | 'BLOCKED' | 'UNKNOWN' | 'ERROR';

export interface GovernanceResponse {
  ok: boolean;
  gateState?: GateState;
  error?: string;
}

/**
 * Internal: POST a governance intent to the server action.
 * Fire-and-forget for non-gate events; awaited for gate checks.
 */
async function postIntent(body: Record<string, unknown>): Promise<GovernanceResponse> {
  try {
    const res = await fetch('/api/governance', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (res.status === 401) {
      console.warn('[QHUB] Governance: unauthenticated — skipping');
      return { ok: false, gateState: 'UNKNOWN', error: 'Unauthenticated' };
    }

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error(`[QHUB] Governance: server error ${res.status}`, text);

      return { ok: false, gateState: 'ERROR', error: `Server error ${res.status}` };
    }

    return (await res.json()) as GovernanceResponse;
  } catch (err) {
    console.error('[QHUB] Governance: network error', err);
    return { ok: false, gateState: 'ERROR', error: 'Network error' };
  }
}

// ─── Hook 1: Project Created (GENESIS) ───────────────────────────────────────

export interface GenesisIntent {
  conversationId: string;
  appId: string;
  projectTitle: string;
}

/**
 * Notify the governance server that a new project has been created.
 * Fire-and-forget — never blocks the builder UI.
 */
export function notifyProjectCreated(intent: GenesisIntent): void {
  postIntent({
    action: 'PROJECT_CREATED',
    ...intent,
  }).catch((err) => console.error('[QHUB] GENESIS intent failed:', err));
}

// ─── Hook 2: AI Model Used (AI_BOM) ──────────────────────────────────────────

export interface AiBomIntent {
  conversationId: string;
  appId: string;
  provider: string;
  model: string;
}

/**
 * Notify the governance server that an AI model was invoked.
 * Hook 2 is primarily handled server-side in stream-text.ts.
 * This client function is available for cases where the caller
 * is on the client side.
 * Fire-and-forget — never blocks the builder UI.
 */
export function notifyAiModelUsed(intent: AiBomIntent): void {
  postIntent({
    action: 'AI_MODEL_USED',
    ...intent,
  }).catch((err) => console.error('[QHUB] AI_BOM intent failed:', err));
}

// ─── Hook 3: Deployment Gate Check ───────────────────────────────────────────

export interface GateCheckIntent {
  conversationId: string;
  appId: string;
}

/**
 * Check whether this project may be deployed.
 *
 * Returns an explicit GateState:
 *   'APPROVED'  — human attestation confirmed → deployment may proceed
 *   'BLOCKED'   — attestation required but not completed → block deployment
 *   'UNKNOWN'   — governance API unreachable → block production deployment
 *   'ERROR'     — server error → block production deployment
 *
 * NEVER treats anything other than 'APPROVED' as a pass.
 */
export async function assertDeploymentGate(intent: GateCheckIntent): Promise<GateState> {
  const result = await postIntent({
    action: 'DEPLOYMENT_GATE_CHECK',
    ...intent,
  });

  // Only explicit APPROVED passes — everything else blocks
  return result.gateState === 'APPROVED' ? 'APPROVED' : (result.gateState ?? 'ERROR');
}

// ─── Gate 02: Classification ─────────────────────────────────────────────────

import type { ClassificationResult, RiskTier } from './classification';
import type { PolicyProfile } from './policy';

export interface ClassificationProposal {
  classification: ClassificationResult;

  /** Opaque server reference; must be passed back on confirm (Gate 03 Phase 0). */
  proposalId: string | null;
}

/**
 * Ask the server to analyze the app description and PROPOSE a classification
 * (deterministic floor + AI). Does NOT write to the ledger. The server persists
 * the provisional result and returns an opaque proposalId; confirmation binds to
 * that id so the browser can never rewrite the authoritative signals.
 * Throws on failure so the caller can block the build until classification runs.
 */
export async function requestClassification(
  description: string,
  conversationId: string,
): Promise<ClassificationProposal> {
  const res = await fetch('/api/classify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ description, conversationId }),
  });

  if (!res.ok) {
    throw new Error(`Classification request failed (${res.status})`);
  }

  const data = (await res.json()) as {
    ok: boolean;
    classification?: ClassificationResult;
    proposalId?: string | null;
    error?: string;
  };

  if (!data.ok || !data.classification) {
    throw new Error(data.error ?? 'Classification failed');
  }

  return { classification: data.classification, proposalId: data.proposalId ?? null };
}

export interface ConfirmClassificationResult {
  ok: boolean;
  riskTier?: RiskTier;
  error?: string;
}

/**
 * Confirm (or correct) a proposed classification. The server reloads the
 * authoritative signals from the persisted proposal, re-derives the
 * deterministic floor, and emits the CLASSIFICATION_ASSIGNED ledger event with
 * server-authoritative identity. The confirmed tier can raise but never lower
 * below the floor.
 */
export async function confirmClassification(intent: {
  conversationId: string;
  proposalId: string;
  confirmedTier: RiskTier;
  projectTitle?: string;
  builderProjectId?: string;
}): Promise<ConfirmClassificationResult> {
  const result = (await postIntent({
    action: 'CLASSIFICATION_CONFIRMED',
    ...intent,
  })) as ConfirmClassificationResult & { gateState?: GateState };

  return { ok: result.ok, riskTier: result.riskTier, error: result.error };
}

// ─── Gate 03: Policy ─────────────────────────────────────────────────────────

export interface PolicyAssignResult {
  ok: boolean;
  policyProfile?: PolicyProfile;
  policyStatus?: string;
  riskTier?: RiskTier;
  error?: string;
}

/**
 * Assign the deterministic policy profile for the confirmed classification.
 * The server builds it from the versioned catalog (never the browser), writes a
 * compact POLICY_PROFILE_ASSIGNED event to the chain, and persists the full
 * profile snapshot. Returns the browser-safe profile for display.
 */
export async function assignPolicy(intent: {
  conversationId: string;
  builderProjectId?: string;
}): Promise<PolicyAssignResult> {
  const result = (await postIntent({
    action: 'POLICY_ASSIGN',
    ...intent,
  })) as PolicyAssignResult;

  return result;
}

/**
 * Acknowledge the assigned policy controls. Flips ASSIGNED → ACKNOWLEDGED,
 * which the build gate requires before code generation.
 */
export async function acknowledgePolicy(intent: {
  conversationId: string;
  builderProjectId?: string;
}): Promise<PolicyAssignResult> {
  const result = (await postIntent({
    action: 'POLICY_ACKNOWLEDGE',
    ...intent,
  })) as PolicyAssignResult;

  return result;
}
