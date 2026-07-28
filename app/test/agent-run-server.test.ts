/**
 * QHUB Agent Framework Foundation — run orchestrator tests (integration/adversarial)
 * app/test/agent-run-server.test.ts
 *
 * Uses the REAL local simulation provider + provider registry, a mocked Gate 04
 * enforcement path, mocked registry/release-binding reads, and an in-memory fake
 * Supabase for run/step writes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { syntheticCommissionDatasets } from '~/lib/qhub/agent/reference/commission-reconciliation';
import { LOCAL_SIMULATION_PROVIDER_ID } from '~/lib/qhub/agent/runtime/local-simulation-provider';

// ── In-memory fake Supabase (backs run/step writes) ──
const STORE: { runs: any[]; steps: any[]; failStepInsert: boolean } = { runs: [], steps: [], failStepInsert: false };
const tableKey = (t: string) => (t === 'qhub_agent_runs' ? 'runs' : 'steps');

function fakeClient() {
  const from = (table: string) => {
    const key = tableKey(table) as 'runs' | 'steps';
    const filters: [string, unknown][] = [];
    let mode: 'select' | 'insert' | 'update' | null = null;
    let payload: any = null;
    const match = (r: any) => filters.every(([c, v]) => r[c] === v);
    const exec = () => {
      const rows = STORE[key];

      if (mode === 'insert') {
        if (key === 'steps' && STORE.failStepInsert) {
          return Promise.resolve({ data: null, error: { message: 'forced step insert failure' } });
        }

        const arr = Array.isArray(payload) ? payload : [payload];
        arr.forEach((r) => rows.push({ ...r }));

        return Promise.resolve({ data: arr, error: null });
      }

      if (mode === 'update') {
        const upd = rows.filter(match);
        upd.forEach((r) => Object.assign(r, payload));

        return Promise.resolve({ data: upd, error: null });
      }

      return Promise.resolve({ data: rows.filter(match), error: null });
    };
    const b: any = {
      select() {
        mode = 'select';
        return b;
      },
      insert(r: any) {
        mode = 'insert';
        payload = r;

        return exec();
      },
      upsert(r: any) {
        if (key === 'steps' && STORE.failStepInsert) {
          return Promise.resolve({ data: null, error: { message: 'forced step upsert failure' } });
        }

        const arr = Array.isArray(r) ? r : [r];

        for (const row of arr) {
          const idx = STORE[key].findIndex((x) => x.run_id === row.run_id && x.step_index === row.step_index);

          if (idx >= 0) {
            STORE[key][idx] = { ...row };
          } else {
            STORE[key].push({ ...row });
          }
        }

        return Promise.resolve({ data: arr, error: null });
      },
      update(p: any) {
        mode = 'update';
        payload = p;

        return b;
      },
      eq(c: string, v: unknown) {
        filters.push([c, v]);
        return b;
      },
      is(c: string, v: unknown) {
        filters.push([c, v]);
        return b;
      },
      order() {
        return b;
      },
      maybeSingle() {
        return Promise.resolve({ data: STORE[key].filter(match)[0] ?? null, error: null });
      },
      then(res: any, rej: any) {
        return exec().then(res, rej);
      },
    };

    return b;
  };

  return { from };
}

const H = vi.hoisted(() => ({
  getAgent: vi.fn(),
  getAgentVersion: vi.fn(),
  checkReleaseBinding: vi.fn(),
  enforce: vi.fn(),
  assertSchema: vi.fn(),
}));

vi.mock('@supabase/supabase-js', () => ({ createClient: () => fakeClient() }));
vi.mock('~/lib/qhub/agent/agent-registry.server', () => ({ getAgent: H.getAgent, getAgentVersion: H.getAgentVersion }));
vi.mock('~/lib/qhub/agent/agent-release-binding.server', () => ({ checkReleaseBinding: H.checkReleaseBinding }));
vi.mock('~/lib/qhub/enforcement.server', () => ({ enforceGovernedAction: H.enforce }));
vi.mock('~/lib/qhub/agent/agent-schema-check.server', () => ({ assertAgentSchemaReady: H.assertSchema }));

const ENV = { SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };
const SESSION = { userId: 'user-1', orgId: 'client-smoke', role: 'owner' };

function makeVersion(over: any = {}) {
  const { manifest: manifestOver, ...rest } = over;

  return {
    agent_version_id: 'ver-1',
    agent_id: 'agent-1',
    org_id: 'client-smoke',
    qhub_app_id: 'app-1',
    manifest_hash: 'MH',
    manifest_version: 'agent-manifest-1.0.0',
    operating_mode: 'SUPERVISED_ACTION_AGENT',
    autonomy_level: 'HUMAN_IN_LOOP',
    risk_tier: 'T2',
    policy_profile_hash: 'PPHASH',
    enforcement_plan_hash: 'EPHASH',
    release_candidate_id: 'rc-1',
    release_candidate_hash: 'RCHASH',
    deployment_decision_id: 'dd-1',
    frozen: true,
    ...rest,
    manifest: {
      agent_id: 'agent-1',
      agent_version_id: 'ver-1',
      operating_mode: 'SUPERVISED_ACTION_AGENT',
      autonomy_level: 'HUMAN_IN_LOOP',
      primary_model: 'anthropic:claude-sonnet-5',
      approved_models: ['anthropic:claude-sonnet-5'],
      approved_tools: [],
      approved_connectors: [],
      goal_definition: 'reconcile',
      execution_environment: 'STAGING',
      runtime_provider: LOCAL_SIMULATION_PROVIDER_ID,
      runtime_provider_version: '1.0.0',
      action_limits: {
        max_actions_per_run: 5,
        max_model_calls_per_run: 3,
        max_runtime_seconds: 60,
        max_approval_wait_seconds: 3600,
      },
      ...(manifestOver ?? {}),
    },
  };
}

function makeAgent(over: any = {}) {
  return {
    agent_id: 'agent-1',
    org_id: 'client-smoke',
    qhub_app_id: 'app-1',
    name: 'Recon',
    owner_user_id: 'user-1',
    current_version_id: 'ver-1',
    current_lifecycle_state: 'SIMULATION',
    current_operating_mode: 'SUPERVISED_ACTION_AGENT',
    risk_tier: 'T2',
    kill_switch_active: false,
    ...over,
  };
}

/** Default Gate 04 mock: model ALLOW(SIM); transmission E1 REQUIRE_APPROVAL, E2 ALLOW(SIM). */
function defaultEnforce() {
  H.enforce.mockImplementation(async (inp: any) => {
    if (inp.action.action_type === 'AI_MODEL_INVOCATION') {
      return {
        decision: 'ALLOW',
        reason_codes: [],
        evaluation_id: 'Emodel',
        execution_mode: 'SIMULATION',
        side_effect_performed: false,
        execution_status: 'SIMULATED_SUCCESS',
        receipt: { receipt_id: 'rM', execution_status: 'SIMULATED_SUCCESS' },
      };
    }

    if (inp.parentEvaluationId) {
      return {
        decision: 'ALLOW',
        reason_codes: [],
        evaluation_id: 'E2',
        execution_mode: 'SIMULATION',
        side_effect_performed: false,
        execution_status: 'SIMULATED_SUCCESS',
        receipt: { receipt_id: 'rT', execution_status: 'SIMULATED_SUCCESS' },
      };
    }

    return {
      decision: 'REQUIRE_APPROVAL',
      reason_codes: ['OWNER_ATTESTATION_REQUIRED'],
      evaluation_id: 'E1',
      execution_mode: null,
      side_effect_performed: false,
      execution_status: null,
      receipt: null,
    };
  });
}

const run = async (over: any = {}) => {
  const { runAgent } = await import('~/lib/qhub/agent/agent-run.server');

  return runAgent({
    session: SESSION,
    conversationId: 'conv-1',
    agent_id: 'agent-1',
    idempotency_key: over.key ?? 'idem-1',
    synthetic_inputs: over.inputs ?? syntheticCommissionDatasets(),
    sessionId: 's',
    env: ENV,
  });
};

beforeEach(() => {
  vi.clearAllMocks();
  STORE.runs = [];
  STORE.steps = [];
  STORE.failStepInsert = false;
  H.assertSchema.mockResolvedValue(undefined);
  H.getAgent.mockResolvedValue(makeAgent());
  H.getAgentVersion.mockResolvedValue(makeVersion());
  H.checkReleaseBinding.mockResolvedValue({
    release_approved: true,
    release_stale: false,
    manifest_matches_release: true,
    reason: [],
  });
  defaultEnforce();
});

describe('agent run orchestrator — Gate 04 routing (tests 17-31)', () => {
  it('routes the model action through Gate 04 (test 17)', async () => {
    const r = await run();
    const modelCall = H.enforce.mock.calls.find((c) => c[0].action.action_type === 'AI_MODEL_INVOCATION');
    expect(modelCall).toBeTruthy();
    expect(r.ok).toBe(true);
  });

  it('routes the connector action through Gate 04 and pauses on REQUIRE_APPROVAL (tests 18/20)', async () => {
    const r = await run();
    const connCall = H.enforce.mock.calls.find((c) => c[0].action.action_type === 'EXTERNAL_DATA_TRANSMISSION');
    expect(connCall).toBeTruthy();
    expect(r.state).toBe('AWAITING_APPROVAL');
    expect(r.pending_evaluation_id).toBe('E1');
  });

  it('DENY yields no adapter execution and fails the run (test 19)', async () => {
    H.enforce.mockImplementation(async () => ({
      decision: 'DENY',
      reason_codes: ['MODEL_NOT_APPROVED'],
      evaluation_id: 'Ed',
      execution_mode: null,
      side_effect_performed: false,
      execution_status: null,
      receipt: null,
    }));

    const r = await run();
    expect(r.state).toBe('FAILED');
    expect(r.reason_codes).toContain('GOVERNED_ACTION_DENIED');
    expect(r.denied_action_count).toBe(1);
  });

  it('REQUIRE_APPROVAL persists AWAITING_APPROVAL with the pending evaluation (test 20)', async () => {
    await run();

    const row = STORE.runs[0];
    expect(row.current_state).toBe('AWAITING_APPROVAL');
    expect(row.pending_evaluation_id).toBe('E1');
  });

  it('resume with the exact approved evaluation resumes only that action → COMPLETED (test 21)', async () => {
    await run();

    const { resumeAgentRun } = await import('~/lib/qhub/agent/agent-run.server');
    const runId = STORE.runs[0].run_id;
    const r = await resumeAgentRun({
      session: SESSION,
      run_id: runId,
      approved_evaluation_id: 'E1',
      synthetic_inputs: syntheticCommissionDatasets(),
      sessionId: 's',
      env: ENV,
    });
    expect(r.state).toBe('COMPLETED');

    // The resumed transmission was governed with a parent evaluation (E2 path).
    const e2 = H.enforce.mock.calls.find((c) => c[0].parentEvaluationId === 'E1');
    expect(e2).toBeTruthy();
  });

  it('resume with a wrong evaluation id fails closed (test 21)', async () => {
    await run();

    const { resumeAgentRun } = await import('~/lib/qhub/agent/agent-run.server');
    const r = await resumeAgentRun({
      session: SESSION,
      run_id: STORE.runs[0].run_id,
      approved_evaluation_id: 'WRONG',
      synthetic_inputs: syntheticCommissionDatasets(),
      sessionId: 's',
      env: ENV,
    });
    expect(r.state).toBe('BLOCKED');
  });

  it('replay with the same idempotency key returns the existing run — no duplicate (test 22)', async () => {
    const first = await run({ key: 'idem-X' });
    const again = await run({ key: 'idem-X' });
    expect(again.run_id).toBe(first.run_id);
    expect(STORE.runs.length).toBe(1);
  });

  it('kill switch active at entry blocks the run (test 23)', async () => {
    H.getAgent.mockResolvedValue(makeAgent({ kill_switch_active: true }));

    const r = await run();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('KILL_SWITCH_ACTIVE');
  });

  it('kill switch flipped mid-run suspends the run (test 23)', async () => {
    H.getAgent.mockResolvedValueOnce(makeAgent({ kill_switch_active: false })); // entry
    H.getAgent.mockResolvedValue(makeAgent({ kill_switch_active: true })); // driveRun re-check

    const r = await run();
    expect(r.state).toBe('SUSPENDED');
    expect(r.reason_codes).toContain('KILL_SWITCH_ACTIVE');
  });

  it('enforces the maximum action limit (test 24)', async () => {
    H.getAgentVersion.mockResolvedValue(
      makeVersion({
        manifest: {
          action_limits: {
            max_actions_per_run: 1,
            max_model_calls_per_run: 3,
            max_runtime_seconds: 60,
            max_approval_wait_seconds: 10,
          },
        },
      }),
    );

    const r = await run();
    expect(r.state).toBe('FAILED');
    expect(r.reason_codes).toContain('ACTION_LIMIT_EXCEEDED');
  });

  it('enforces the maximum model-call limit (test 25)', async () => {
    H.getAgentVersion.mockResolvedValue(
      makeVersion({
        manifest: {
          action_limits: {
            max_actions_per_run: 5,
            max_model_calls_per_run: 0,
            max_runtime_seconds: 60,
            max_approval_wait_seconds: 10,
          },
        },
      }),
    );

    const r = await run();
    expect(r.state).toBe('FAILED');
    expect(r.reason_codes).toContain('MODEL_CALL_LIMIT_EXCEEDED');
  });

  it('enforces the runtime timeout (test 26)', async () => {
    H.getAgentVersion.mockResolvedValue(
      makeVersion({
        manifest: {
          action_limits: {
            max_actions_per_run: 5,
            max_model_calls_per_run: 3,
            max_runtime_seconds: -1,
            max_approval_wait_seconds: 10,
          },
        },
      }),
    );

    const r = await run();
    expect(r.state).toBe('FAILED');
    expect(r.reason_codes).toContain('RUNTIME_TIMEOUT');
  });

  it('fails closed when a step evidence write fails (test 27)', async () => {
    STORE.failStepInsert = true;

    const r = await run();
    expect(r.state).toBe('FAILED');
    expect(r.reason_codes).toContain('EVIDENCE_WRITE_FAILED');
  });

  it('fails closed on an unknown runtime provider (test 16)', async () => {
    H.getAgentVersion.mockResolvedValue(makeVersion({ manifest: { runtime_provider: 'nope.unknown' } }));

    const r = await run();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('UNKNOWN_PROVIDER');
  });

  it('SUPERVISED requires a current approved release binding (tests 12/14)', async () => {
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'SUPERVISED' }));
    H.checkReleaseBinding.mockResolvedValue({
      release_approved: false,
      release_stale: false,
      manifest_matches_release: true,
      reason: ['RELEASE_NOT_APPROVED'],
    });

    const r = await run();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('RELEASE_NOT_APPROVED');
  });

  it('suspended agent cannot run (test 10)', async () => {
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'SUSPENDED' }));
    expect((await run()).reason_codes).toContain('SUSPENDED');
  });

  it('retired agent cannot run (test 11)', async () => {
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'RETIRED' }));
    expect((await run()).reason_codes).toContain('RETIRED');
  });

  it('commission reconciliation reference agent completes in simulation with no real effect (tests 29/30)', async () => {
    const started = await run();
    expect(started.state).toBe('AWAITING_APPROVAL');

    const { resumeAgentRun } = await import('~/lib/qhub/agent/agent-run.server');
    const done = await resumeAgentRun({
      session: SESSION,
      run_id: STORE.runs[0].run_id,
      approved_evaluation_id: 'E1',
      synthetic_inputs: syntheticCommissionDatasets(),
      sessionId: 's',
      env: ENV,
    });
    expect(done.state).toBe('COMPLETED');

    // No governed action reported a real external effect (all SIMULATION).
    const anyRealEffect = H.enforce.mock.results.some((res: any) => res.value?.side_effect_performed === true);
    expect(anyRealEffect).toBe(false);

    // The paused transmission step was updated IN PLACE to its SIMULATED receipt.
    const txSteps = STORE.steps.filter((s) => s.action_type === 'EXTERNAL_DATA_TRANSMISSION');
    expect(txSteps.length).toBe(1);
    expect(txSteps[0].decision).toBe('SIMULATED');
    expect(txSteps[0].receipt_id).toBe('rT');

    // Resume used a DISTINCT E2 idempotency key (not the paused E1 key).
    const e2call = H.enforce.mock.calls.find((c) => c[0].parentEvaluationId === 'E1');
    expect(e2call?.[0].idempotencyKey).toMatch(/:e2$/);
  });

  it('Agent Run fails closed when schema is not ready — no run row, no Gate 04 action (tests 14/15/16)', async () => {
    H.assertSchema.mockRejectedValueOnce(new Error('SchemaNotReadyError'));

    const r = await run();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('SCHEMA_NOT_READY');
    expect(H.enforce).not.toHaveBeenCalled(); // no Gate 04 action
    expect(STORE.runs.length).toBe(0); // no partial run record
    expect(STORE.steps.length).toBe(0);
  });

  it('run + step records contain hashes only — no raw params/secrets (test 31)', async () => {
    await run();

    for (const s of STORE.steps) {
      expect(s.input_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(s).not.toHaveProperty('material_parameters');
      expect(JSON.stringify(s)).not.toMatch(/SUPABASE_SERVICE_ROLE_KEY|secret|password/i);
    }
    expect(STORE.runs[0]).not.toHaveProperty('material_parameters');
  });

  it('build-integrity mismatch in an enforced env fails closed — no run, no Gate 04', async () => {
    const { runAgent } = await import('~/lib/qhub/agent/agent-run.server');
    const r = await runAgent({
      session: SESSION,
      conversationId: 'conv-1',
      agent_id: 'agent-1',
      idempotency_key: 'idem-bi',
      synthetic_inputs: syntheticCommissionDatasets(),
      sessionId: 's',
      env: {
        ...ENV,
        QHUB_DEPLOY_ENV: 'staging',
        QHUB_BUILD_SOURCE_COMMIT: 'c',
        QHUB_BUILD_ARTIFACT_HASH: 'a',
        QHUB_BUILD_LOCKFILE_HASH: 'l',
        QHUB_IMAGE_SOURCE_COMMIT: 'DIFFERENT',
        QHUB_IMAGE_ARTIFACT_HASH: 'a',
        QHUB_IMAGE_LOCKFILE_HASH: 'l',
      },
    });
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('BUILD_INTEGRITY_FAILED');
    expect(H.enforce).not.toHaveBeenCalled();
    expect(STORE.runs.length).toBe(0);
  });

  // ── Production no-replay reconstruction on resume (Blocker 1) ──────────────

  const resume = async (over: any = {}) => {
    const { resumeAgentRun } = await import('~/lib/qhub/agent/agent-run.server');

    return resumeAgentRun({
      session: SESSION,
      run_id: STORE.runs[0].run_id,
      approved_evaluation_id: over.eval ?? 'E1',
      synthetic_inputs: over.inputs ?? syntheticCommissionDatasets(),
      sessionId: 's',
      env: ENV,
    });
  };

  it('resume fails closed when a stored prior step is tampered — no E2, no receipt', async () => {
    await run();
    STORE.steps.find((s) => s.step_index === 0)!.input_hash = 'deadbeef'; // tamper the model step

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('RECONSTRUCTION_FAILED');

    // No approved-action (E2) submission was made.
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();

    // The paused step was not turned into a receipt.
    expect(STORE.steps.find((s) => s.step_index === 1)!.receipt_id).toBeNull();
  });

  it('resume fails closed when a prior step is missing (non-contiguous)', async () => {
    await run();
    STORE.steps = STORE.steps.filter((s) => s.step_index !== 0); // drop the model step

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('RECONSTRUCTION_FAILED');
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();
  });

  it('suspended agent cannot resume', async () => {
    await run();
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'SUSPENDED' }));

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('SUSPENDED');
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();
  });

  it('SUPERVISED resume re-checks Gate 05 binding and fails closed when unapproved', async () => {
    await run();
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'SUPERVISED' }));
    H.checkReleaseBinding.mockResolvedValue({
      release_approved: false,
      release_stale: false,
      manifest_matches_release: true,
      reason: ['RELEASE_NOT_APPROVED'],
    });

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('RELEASE_NOT_APPROVED');
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();
  });

  it('SUPERVISED resume fails closed when the manifest no longer matches the release', async () => {
    await run();
    H.getAgent.mockResolvedValue(makeAgent({ current_lifecycle_state: 'SUPERVISED' }));
    H.checkReleaseBinding.mockResolvedValue({
      release_approved: true,
      release_stale: false,
      manifest_matches_release: false,
      reason: ['MANIFEST_CHANGED'],
    });

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('MANIFEST_CHANGED');
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();
  });
});
