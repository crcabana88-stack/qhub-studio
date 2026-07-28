/**
 * QHUB Agent Framework — complete pre-Gate-04 paused-action binding tests
 * app/test/run-binding.test.ts
 *
 * Proves verifyPausedActionBinding validates the FULL persisted authorization
 * identity against the server-owned Gate 04 evaluation and fails closed on every
 * field/failure mode — with the re-derived action's recomputed action_digest as
 * the canonical anchor.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  verifyPausedActionBinding,
  stableStringify,
  type PersistedEvaluation,
  type ResumeBindingRun,
  type ResumeBindingVersion,
} from '~/lib/qhub/agent/runtime/run-reconstruction';
import { canonicalActionRequestString } from '~/lib/qhub/enforcement-plan';
import type { ProposedAction } from '~/lib/qhub/agent/runtime/provider';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const CONV = 'conv-app-1';

const pausedAction: ProposedAction = {
  step_kind: 'CONNECTOR_ACTION',
  action_type: 'EXTERNAL_DATA_TRANSMISSION',
  target_resource: 'https://commission-recon-brk-002.invalid/reconcile',
  operation: 'write_simulation',
  material_parameters: { synthetic: true, broker_id: 'BRK-002', adjustment_minor: -17500 },
  summary: 'reconcile',
};

/** Compute the exact Gate 04 digest for the paused action under given policy/plan. */
function digestFor(
  over: Partial<{ ppv: number; pph: string; epv: number; eph: string; env: string; conv: string }> = {},
) {
  return sha256(
    canonicalActionRequestString({
      tenant_id: 'org-1',
      qhub_app_id: 'app-1',
      action_request_id: 'areq-1',
      action_type: pausedAction.action_type,
      target_resource: pausedAction.target_resource,
      operation: pausedAction.operation,
      material_parameters_hash: sha256(stableStringify(pausedAction.material_parameters ?? null)),
      model_identity: null,
      provider_identity: null,
      tool_identity: null,
      environment: (over.env ?? 'INTERNAL') as 'PREVIEW' | 'INTERNAL' | 'PRODUCTION',
      app_version_ref: over.conv ?? CONV,
      policy_profile_id: '',
      policy_profile_version: over.ppv ?? 3,
      policy_profile_hash: over.pph ?? 'PPHASH',
      enforcement_plan_id: '',
      enforcement_plan_version: over.epv ?? 5,
      enforcement_plan_hash: over.eph ?? 'EPHASH',
    }),
  );
}

const run: ResumeBindingRun = {
  org_id: 'org-1',
  qhub_app_id: 'app-1',
  run_id: 'run-1',
  agent_id: 'agent-1',
  agent_version_id: 'ver-1',
  release_candidate_hash: 'RC1',
  runtime_provider: 'qhub.runtime.local-simulation',
  runtime_provider_version: '1.0.0',
  policy_profile_hash: 'PPHASH',
  enforcement_plan_hash: 'EPHASH',
};
const version: ResumeBindingVersion = {
  agent_version_id: 'ver-1',
  manifest_hash: 'MH1',
  execution_environment: 'STAGING', // → INTERNAL
  release_candidate_hash: 'RC1',
};
const provider = { provider_id: 'qhub.runtime.local-simulation', provider_version: '1.0.0' };

function evalRow(over: Partial<PersistedEvaluation> = {}): PersistedEvaluation {
  return {
    evaluation_id: 'E1',
    action_request_id: 'areq-1',
    action_digest: digestFor(),
    decision: 'REQUIRE_APPROVAL',
    org_id: 'org-1',
    qhub_app_id: 'app-1',
    policy_profile_id: 'pp-1',
    policy_profile_version: 3,
    policy_profile_hash: 'PPHASH',
    enforcement_plan_id: 'ep-1',
    enforcement_plan_version: 5,
    enforcement_plan_hash: 'EPHASH',
    ...over,
  };
}

const base = { run, version, provider, pausedAction, approvedEvaluationId: 'E1', conversationId: CONV };

describe('verifyPausedActionBinding — complete pre-Gate-04 binding', () => {
  it('passes when every persisted binding matches and the digest re-derives exactly', () => {
    const r = verifyPausedActionBinding({ ...base, evaluation: evalRow() });
    expect(r.ok).toBe(true);
    expect(r.recomputed_action_digest).toBe(digestFor());
  });

  it('fails when the evaluation is not pending approval', () => {
    expect(verifyPausedActionBinding({ ...base, evaluation: evalRow({ decision: 'ALLOW' }) }).reason).toBe(
      'EVALUATION_NOT_PENDING',
    );
  });

  it('fails when the approved evaluation id does not match', () => {
    expect(verifyPausedActionBinding({ ...base, approvedEvaluationId: 'OTHER', evaluation: evalRow() }).reason).toBe(
      'EVALUATION_MISMATCH',
    );
  });

  it('fails when action_request_id is missing', () => {
    expect(verifyPausedActionBinding({ ...base, evaluation: evalRow({ action_request_id: null }) }).reason).toBe(
      'MISSING_ACTION_REQUEST_ID',
    );
  });

  it('fails when the evaluation belongs to another tenant/app', () => {
    expect(verifyPausedActionBinding({ ...base, evaluation: evalRow({ org_id: 'EVIL' }) }).reason).toBe(
      'EVALUATION_TENANT_APP_MISMATCH',
    );
  });

  it('fails when the loaded version is not the run version', () => {
    expect(
      verifyPausedActionBinding({
        ...base,
        version: { ...version, agent_version_id: 'ver-OTHER' },
        evaluation: evalRow(),
      }).reason,
    ).toBe('RUN_VERSION_MISMATCH');
  });

  it('fails when the policy profile hash changed', () => {
    expect(verifyPausedActionBinding({ ...base, evaluation: evalRow({ policy_profile_hash: 'DIFF' }) }).reason).toBe(
      'POLICY_PROFILE_MISMATCH',
    );
  });

  it('fails when the enforcement plan hash changed', () => {
    expect(verifyPausedActionBinding({ ...base, evaluation: evalRow({ enforcement_plan_hash: 'DIFF' }) }).reason).toBe(
      'ENFORCEMENT_PLAN_MISMATCH',
    );
  });

  it('fails when the provider id/version does not match the run', () => {
    expect(
      verifyPausedActionBinding({
        ...base,
        provider: { provider_id: 'qhub.runtime.evil', provider_version: '1.0.0' },
        evaluation: evalRow(),
      }).reason,
    ).toBe('PROVIDER_IDENTITY_MISMATCH');
  });

  it('fails when the release hash changed/superseded', () => {
    expect(
      verifyPausedActionBinding({
        ...base,
        version: { ...version, release_candidate_hash: 'RC-NEW' },
        evaluation: evalRow(),
      }).reason,
    ).toBe('RELEASE_HASH_MISMATCH');
  });

  it('fails closed when the re-derived action digest does not match the persisted anchor', () => {
    // A materially different action (changed params) → different digest.
    const tampered = {
      ...pausedAction,
      material_parameters: { synthetic: true, broker_id: 'BRK-002', adjustment_minor: -1 },
    };
    expect(verifyPausedActionBinding({ ...base, pausedAction: tampered, evaluation: evalRow() }).reason).toBe(
      'ACTION_DIGEST_MISMATCH',
    );
  });

  it('fails closed when policy VERSION changed even if hash-string matches loosely', () => {
    // Evaluation persisted a different policy version than the digest was scoped to.
    const ev = evalRow({ policy_profile_version: 999, action_digest: digestFor({ ppv: 3 }) });
    expect(verifyPausedActionBinding({ ...base, evaluation: ev }).reason).toBe('ACTION_DIGEST_MISMATCH');
  });
});
