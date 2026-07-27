/**
 * QHUB Agent Framework Foundation — lifecycle transition tests (pure)
 * app/test/agent-lifecycle.test.ts
 */

import { describe, it, expect } from 'vitest';
import { evaluateTransition, canRunInState, type TransitionContext } from '~/lib/qhub/agent/agent-lifecycle';

function ctx(over: Partial<TransitionContext> = {}): TransitionContext {
  return {
    manifest_frozen: true,
    has_classification: true,
    has_policy_profile: true,
    has_enforcement_plan: true,
    release_approved: true,
    release_stale: false,
    manifest_matches_release: true,
    has_valid_supervisor: true,
    policy_allows_active: true,
    unresolved_exceptions: false,
    operating_mode: 'SUPERVISED_ACTION_AGENT',
    ...over,
  };
}

describe('agent lifecycle transitions (tests 8-14)', () => {
  it('DRAFT→SIMULATION requires frozen manifest + governance inputs (test 8)', () => {
    expect(evaluateTransition('DRAFT', 'SIMULATION', ctx()).ok).toBe(true);
    expect(evaluateTransition('DRAFT', 'SIMULATION', ctx({ manifest_frozen: false })).reason).toBe(
      'MANIFEST_NOT_FROZEN',
    );
    expect(evaluateTransition('DRAFT', 'SIMULATION', ctx({ has_policy_profile: false })).reason).toBe(
      'MISSING_GOVERNANCE_INPUTS',
    );
  });

  it('SIMULATION→SUPERVISED requires an approved release + supervisor (test 12)', () => {
    expect(evaluateTransition('SIMULATION', 'SUPERVISED', ctx()).ok).toBe(true);
    expect(evaluateTransition('SIMULATION', 'SUPERVISED', ctx({ release_approved: false })).reason).toBe(
      'RELEASE_NOT_APPROVED',
    );
    expect(evaluateTransition('SIMULATION', 'SUPERVISED', ctx({ has_valid_supervisor: false })).reason).toBe(
      'NO_VALID_SUPERVISOR',
    );
  });

  it('changed manifest invalidates the release binding (test 13)', () => {
    expect(evaluateTransition('SIMULATION', 'SUPERVISED', ctx({ manifest_matches_release: false })).reason).toBe(
      'MANIFEST_CHANGED',
    );
  });

  it('stale release blocks SUPERVISED (test 14)', () => {
    expect(evaluateTransition('SIMULATION', 'SUPERVISED', ctx({ release_stale: true })).reason).toBe('RELEASE_STALE');
  });

  it('SUPERVISED→ACTIVE requires explicit policy permission (test 12)', () => {
    expect(evaluateTransition('SUPERVISED', 'ACTIVE', ctx()).ok).toBe(true);
    expect(evaluateTransition('SUPERVISED', 'ACTIVE', ctx({ policy_allows_active: false })).reason).toBe(
      'POLICY_DISALLOWS_ACTIVE',
    );
  });

  it('ACTIVE is refused for BOUNDED_AUTONOMOUS_AGENT (production autonomy disabled)', () => {
    expect(evaluateTransition('SUPERVISED', 'ACTIVE', ctx({ operating_mode: 'BOUNDED_AUTONOMOUS_AGENT' })).reason).toBe(
      'PRODUCTION_AUTONOMY_DISABLED',
    );
  });

  it('rejects an invalid edge DRAFT→ACTIVE (test 9)', () => {
    expect(evaluateTransition('DRAFT', 'ACTIVE', ctx()).reason).toBe('INVALID_TRANSITION');
  });

  it('RETIRED is terminal (test 11)', () => {
    expect(evaluateTransition('RETIRED', 'ACTIVE', ctx()).reason).toBe('INVALID_TRANSITION');
    expect(evaluateTransition('RETIRED', 'SIMULATION', ctx()).reason).toBe('INVALID_TRANSITION');
  });

  it('ANY→SUSPENDED is always permitted (kill switch / owner action)', () => {
    expect(evaluateTransition('ACTIVE', 'SUSPENDED', ctx()).ok).toBe(true);
    expect(evaluateTransition('SIMULATION', 'SUSPENDED', ctx()).ok).toBe(true);
    expect(evaluateTransition('DRAFT', 'SUSPENDED', ctx()).ok).toBe(true);
  });

  it('SUSPENDED→ACTIVE re-evaluates current authority', () => {
    expect(evaluateTransition('SUSPENDED', 'ACTIVE', ctx()).ok).toBe(true);
    expect(evaluateTransition('SUSPENDED', 'ACTIVE', ctx({ release_approved: false })).reason).toBe(
      'RELEASE_NOT_APPROVED',
    );
  });

  it('canRunInState blocks SUSPENDED/RETIRED/DRAFT (tests 10/11)', () => {
    expect(canRunInState('SUSPENDED').reason).toBe('SUSPENDED');
    expect(canRunInState('RETIRED').reason).toBe('RETIRED');
    expect(canRunInState('DRAFT').reason).toBe('NOT_RUNNABLE_STATE');
    expect(canRunInState('SIMULATION').ok).toBe(true);
    expect(canRunInState('SUPERVISED').ok).toBe(true);
    expect(canRunInState('ACTIVE').ok).toBe(true);
  });
});
