/**
 * QHUB Agent Framework Foundation — Lifecycle & operating-mode engine (PURE)
 * app/lib/qhub/agent/agent-lifecycle.ts
 *
 * Deterministic, fail-closed transition rules for agent lifecycle state. No I/O.
 * Server code consults these guards before ANY state change; unknown or
 * disallowed transitions are rejected (closed by default).
 */

import type { AgentOperatingMode } from './agent-manifest';

export type AgentLifecycleState =
  | 'DRAFT' // manifest incomplete or not frozen
  | 'SIMULATION' // synthetic/test data + simulation adapters only
  | 'SUPERVISED' // human approval + Gate 04 enforcement
  | 'ACTIVE' // only where Gate 05 approval + policy permit
  | 'SUSPENDED' // all new consequential execution blocked
  | 'RETIRED'; // historical only; cannot run

/** States from which an agent run may be initiated at all. */
export const RUNNABLE_STATES: AgentLifecycleState[] = ['SIMULATION', 'SUPERVISED', 'ACTIVE'];

/** Reason codes for a rejected transition or run (compact, closed enum). */
export type LifecycleReasonCode =
  | 'INVALID_TRANSITION'
  | 'MANIFEST_NOT_FROZEN'
  | 'MISSING_GOVERNANCE_INPUTS'
  | 'RELEASE_NOT_APPROVED'
  | 'RELEASE_STALE'
  | 'MANIFEST_CHANGED'
  | 'NO_VALID_SUPERVISOR'
  | 'POLICY_DISALLOWS_ACTIVE'
  | 'UNRESOLVED_EXCEPTION'
  | 'NOT_RUNNABLE_STATE'
  | 'PRODUCTION_AUTONOMY_DISABLED'
  | 'SUSPENDED'
  | 'RETIRED';

/** Preconditions the server must supply for a guarded transition. */
export interface TransitionContext {
  manifest_frozen: boolean;
  has_classification: boolean;
  has_policy_profile: boolean;
  has_enforcement_plan: boolean;
  release_approved: boolean; // current DEPLOYMENT_APPROVED for exact manifest hash
  release_stale: boolean; // policy/plan/classification drift since freeze
  manifest_matches_release: boolean; // manifest hash == approved release's bound hash
  has_valid_supervisor: boolean;
  policy_allows_active: boolean;
  unresolved_exceptions: boolean;
  operating_mode: AgentOperatingMode;
}

/** Static allowed edges. SUSPENDED is reachable from every runnable/preparing state. */
const ALLOWED_EDGES: Record<AgentLifecycleState, AgentLifecycleState[]> = {
  DRAFT: ['SIMULATION', 'RETIRED', 'SUSPENDED'],
  SIMULATION: ['SUPERVISED', 'SUSPENDED', 'RETIRED'],
  SUPERVISED: ['ACTIVE', 'SUSPENDED', 'RETIRED'],
  ACTIVE: ['SUSPENDED', 'RETIRED'],
  SUSPENDED: ['SIMULATION', 'SUPERVISED', 'ACTIVE', 'RETIRED'],
  RETIRED: [], // terminal
};

export interface TransitionResult {
  ok: boolean;
  reason?: LifecycleReasonCode;
}

/**
 * Evaluate a proposed lifecycle transition. Fail-closed: any edge not explicitly
 * allowed is rejected, and each guarded target enforces its own preconditions.
 * SUSPENDED and RETIRED are always reachable (kill-switch / owner action) and
 * carry no positive preconditions.
 */
export function evaluateTransition(
  from: AgentLifecycleState,
  to: AgentLifecycleState,
  ctx: TransitionContext,
): TransitionResult {
  if (from === to) {
    return { ok: false, reason: 'INVALID_TRANSITION' };
  }

  if (!ALLOWED_EDGES[from]?.includes(to)) {
    return { ok: false, reason: 'INVALID_TRANSITION' };
  }

  // Always-permitted safety transitions (no positive preconditions).
  if (to === 'SUSPENDED' || to === 'RETIRED') {
    return { ok: true };
  }

  switch (to) {
    case 'SIMULATION': {
      /*
       * DRAFT→SIMULATION or SUSPENDED→SIMULATION: needs a complete, frozen manifest
       * with classification/policy/plan. Simulation never needs a release approval.
       */
      if (!ctx.manifest_frozen) {
        return { ok: false, reason: 'MANIFEST_NOT_FROZEN' };
      }

      if (!ctx.has_classification || !ctx.has_policy_profile || !ctx.has_enforcement_plan) {
        return { ok: false, reason: 'MISSING_GOVERNANCE_INPUTS' };
      }

      return { ok: true };
    }

    case 'SUPERVISED': {
      if (!ctx.manifest_frozen) {
        return { ok: false, reason: 'MANIFEST_NOT_FROZEN' };
      }

      if (!ctx.release_approved) {
        return { ok: false, reason: 'RELEASE_NOT_APPROVED' };
      }

      if (ctx.release_stale) {
        return { ok: false, reason: 'RELEASE_STALE' };
      }

      if (!ctx.manifest_matches_release) {
        return { ok: false, reason: 'MANIFEST_CHANGED' };
      }

      if (!ctx.has_valid_supervisor) {
        return { ok: false, reason: 'NO_VALID_SUPERVISOR' };
      }

      return { ok: true };
    }

    case 'ACTIVE': {
      if (!ctx.policy_allows_active) {
        return { ok: false, reason: 'POLICY_DISALLOWS_ACTIVE' };
      }

      if (!ctx.release_approved) {
        return { ok: false, reason: 'RELEASE_NOT_APPROVED' };
      }

      if (ctx.release_stale) {
        return { ok: false, reason: 'RELEASE_STALE' };
      }

      if (!ctx.manifest_matches_release) {
        return { ok: false, reason: 'MANIFEST_CHANGED' };
      }

      if (ctx.unresolved_exceptions) {
        return { ok: false, reason: 'UNRESOLVED_EXCEPTION' };
      }

      // Production autonomy stays disabled in this phase.
      if (ctx.operating_mode === 'BOUNDED_AUTONOMOUS_AGENT') {
        return { ok: false, reason: 'PRODUCTION_AUTONOMY_DISABLED' };
      }

      return { ok: true };
    }

    default:
      return { ok: false, reason: 'INVALID_TRANSITION' };
  }
}

/** Whether an agent in this state may start a run at all (before per-run checks). */
export function canRunInState(state: AgentLifecycleState): TransitionResult {
  if (state === 'SUSPENDED') {
    return { ok: false, reason: 'SUSPENDED' };
  }

  if (state === 'RETIRED') {
    return { ok: false, reason: 'RETIRED' };
  }

  if (!RUNNABLE_STATES.includes(state)) {
    return { ok: false, reason: 'NOT_RUNNABLE_STATE' };
  }

  return { ok: true };
}
