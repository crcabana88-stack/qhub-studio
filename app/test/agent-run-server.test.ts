/**
 * QHUB Agent Framework Foundation — run orchestrator tests (integration/adversarial)
 * app/test/agent-run-server.test.ts
 *
 * Uses the REAL local simulation provider + provider registry, a mocked Gate 04
 * enforcement path, mocked registry/release-binding reads, and an in-memory fake
 * Supabase for run/step writes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { syntheticCommissionDatasets } from '~/lib/qhub/agent/reference/commission-reconciliation';
import {
  LOCAL_SIMULATION_PROVIDER_ID,
  LocalSimulationProvider,
} from '~/lib/qhub/agent/runtime/local-simulation-provider';
import { stableStringify } from '~/lib/qhub/agent/runtime/run-reconstruction';
import { computeStepResultHash } from '~/lib/qhub/agent/runtime/step-result-hash';
import { canonicalActionRequestString } from '~/lib/qhub/enforcement-plan';

/**
 * Build the persisted Gate 04 evaluation the resume path will load — with the exact
 * server-owned action_digest the re-derived connector action reproduces. Mirrors
 * how resumeAgentRun resolves conversationId (falls back to qhub_app_id) + env.
 */
async function pausedEvalForConnector(inputs: any) {
  const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
  const p = new LocalSimulationProvider();
  await p.init({
    manifest: {
      agent_id: 'agent-1',
      agent_version_id: 'ver-1',
      operating_mode: 'SUPERVISED_ACTION_AGENT',
      autonomy_level: 'HUMAN_IN_LOOP',
      primary_model: 'anthropic:claude-sonnet-5',
      approved_models: ['anthropic:claude-sonnet-5'],
      approved_tool_ids: [],
      approved_connector_ids: [],
      goal_definition: 'reconcile',
      execution_environment: 'STAGING',
    },
    synthetic_inputs: inputs,
  });

  const connector = p.plan()[1]; // [model, connector]
  const actionDigest = sha256(
    canonicalActionRequestString({
      tenant_id: 'client-smoke',
      qhub_app_id: 'app-1',
      action_request_id: 'areq-1',
      action_type: connector.action_type,
      target_resource: connector.target_resource,
      operation: connector.operation,
      material_parameters_hash: sha256(stableStringify(connector.material_parameters ?? null)),
      model_identity: connector.model_identity ?? null,
      provider_identity: null,
      tool_identity: null,
      environment: 'INTERNAL', // STAGING → INTERNAL
      app_version_ref: 'app-1', // resumeAgentRun falls back to qhub_app_id
      policy_profile_id: '',
      policy_profile_version: 1,
      policy_profile_hash: 'PPHASH',
      enforcement_plan_id: '',
      enforcement_plan_version: 1,
      enforcement_plan_hash: 'EPHASH',
    }),
  );

  return {
    evaluation_id: 'E1',
    action_request_id: 'areq-1',
    action_digest: actionDigest,
    decision: 'REQUIRE_APPROVAL',
    org_id: 'client-smoke',
    qhub_app_id: 'app-1',
    policy_profile_id: 'pp-1',
    policy_profile_version: 1,
    policy_profile_hash: 'PPHASH',
    enforcement_plan_id: 'ep-1',
    enforcement_plan_version: 1,
    enforcement_plan_hash: 'EPHASH',
  };
}

// ── In-memory fake Supabase (backs run/step writes) ──
const STORE: { runs: any[]; steps: any[]; evals: any[]; failStepInsert: boolean } = {
  runs: [],
  steps: [],
  evals: [],
  failStepInsert: false,
};
const MANIFEST_HASH = 'MH'; // matches makeVersion().manifest_hash
const tableKey = (t: string): 'runs' | 'steps' | 'evals' =>
  t === 'qhub_agent_runs' ? 'runs' : t === 'qhub_control_evaluations' ? 'evals' : 'steps';

function fakeClient() {
  const from = (table: string) => {
    const key = tableKey(table);
    const filters: [string, unknown][] = [];
    const inFilters: [string, unknown[]][] = [];
    let mode: 'select' | 'insert' | 'update' | null = null;
    let payload: any = null;
    const match = (r: any) =>
      filters.every(([c, v]) => r[c] === v) && inFilters.every(([c, arr]) => arr.includes(r[c]));
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
      in(c: string, arr: unknown[]) {
        inFilters.push([c, arr]);
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

  /**
   * Simulates the two service-role-only write RPCs. Direct table writes are denied
   * to service_role in the real schema; here the RPC is the only write path.
   * qhub_finalize computes the REAL canonical result_hash (so the resume-time
   * recompute matches) chained onto the prior finalized step. Honors failStepInsert.
   */
  const evalFor = (evaluationId: string | null, orgId: string) => {
    if (!evaluationId) {
      return undefined;
    }

    let ev = STORE.evals.find((e) => e.evaluation_id === evaluationId);

    if (!ev) {
      ev = {
        evaluation_id: evaluationId,
        org_id: orgId,
        action_request_id: null,
        action_digest: null,
        policy_profile_id: null,
        policy_profile_version: null,
        policy_profile_hash: null,
        enforcement_plan_id: null,
        enforcement_plan_version: null,
        enforcement_plan_hash: null,
      };
      STORE.evals.push(ev);
    }

    return ev;
  };

  const rpc = (fn: string, args: any) => {
    if (fn === 'qhub_create_agent_run_step_pending') {
      if (STORE.failStepInsert) {
        return Promise.resolve({ data: null, error: { message: 'forced create failure' } });
      }

      const row = {
        run_id: args.p_run_id,
        org_id: args.p_org_id,
        step_index: args.p_step_index,
        step_kind: args.p_step_kind,
        action_type: args.p_action_type,
        evaluation_id: args.p_evaluation_id,
        decision: 'REQUIRE_APPROVAL',
        reason_codes: args.p_reason_codes ?? [],
        receipt_id: null,
        input_hash: args.p_input_hash,
        summary: args.p_summary,
        result_hash: null,
        safe_result: null,
        previous_step_hash: null,
      };
      const idx = STORE.steps.findIndex((x) => x.run_id === row.run_id && x.step_index === row.step_index);

      if (idx >= 0) {
        STORE.steps[idx] = { ...STORE.steps[idx], ...row };
      } else {
        STORE.steps.push(row);
      }

      return Promise.resolve({ data: { recorded: true }, error: null });
    }

    if (fn === 'qhub_finalize_agent_run_step') {
      if (STORE.failStepInsert) {
        return Promise.resolve({ data: null, error: { message: 'forced finalize failure' } });
      }

      const run = STORE.runs.find((r) => r.run_id === args.p_run_id);
      const ev = evalFor(args.p_evaluation_id ?? null, args.p_org_id);
      const prev =
        args.p_step_index === 0
          ? null
          : (STORE.steps.find((s) => s.run_id === args.p_run_id && s.step_index === args.p_step_index - 1)
              ?.result_hash ?? null);
      const resultHash = computeStepResultHash({
        org_id: run.org_id,
        qhub_app_id: run.qhub_app_id,
        agent_id: run.agent_id,
        agent_version_id: run.agent_version_id,
        release_candidate_id: run.release_candidate_id ?? null,
        release_candidate_hash: run.release_candidate_hash ?? null,
        manifest_hash: MANIFEST_HASH,
        run_id: args.p_run_id,
        runtime_provider_id: run.runtime_provider,
        runtime_provider_version: run.runtime_provider_version,
        step_index: args.p_step_index,
        step_kind: args.p_step_kind,
        action_type: args.p_action_type,
        input_hash: args.p_input_hash,
        decision: args.p_decision,
        evaluation_id: args.p_evaluation_id ?? null,
        action_request_id: ev?.action_request_id ?? null,
        action_digest: ev?.action_digest ?? null,
        policy_profile_id: ev?.policy_profile_id ?? null,
        policy_profile_version: ev?.policy_profile_version ?? null,
        policy_profile_hash: ev?.policy_profile_hash ?? null,
        enforcement_plan_id: ev?.enforcement_plan_id ?? null,
        enforcement_plan_version: ev?.enforcement_plan_version ?? null,
        enforcement_plan_hash: ev?.enforcement_plan_hash ?? null,
        receipt_id: args.p_receipt_id ?? null,
        safe_result: args.p_safe_result,
        previous_step_hash: prev,
      });
      const row = {
        run_id: args.p_run_id,
        org_id: args.p_org_id,
        step_index: args.p_step_index,
        step_kind: args.p_step_kind,
        action_type: args.p_action_type,
        evaluation_id: args.p_evaluation_id,
        decision: args.p_decision,
        reason_codes: args.p_reason_codes ?? [],
        receipt_id: args.p_receipt_id,
        input_hash: args.p_input_hash,
        summary: args.p_summary,
        safe_result: args.p_safe_result,
        previous_step_hash: prev,
        result_hash: resultHash,
        result_hash_schema_version: 'agent-step-result-1.0.0',
        finalized_at: new Date().toISOString(),
      };
      const idx = STORE.steps.findIndex((x) => x.run_id === row.run_id && x.step_index === row.step_index);

      if (idx >= 0) {
        STORE.steps[idx] = { ...STORE.steps[idx], ...row };
      } else {
        STORE.steps.push(row);
      }

      return Promise.resolve({ data: { finalized: true, result_hash: resultHash }, error: null });
    }

    return Promise.resolve({ data: null, error: { message: `unknown rpc ${fn}` } });
  };

  return { from, rpc };
}

const H = vi.hoisted(() => ({
  getAgent: vi.fn(),
  getAgentVersion: vi.fn(),
  checkReleaseBinding: vi.fn(),
  enforce: vi.fn(),
  assertSchema: vi.fn(),
  getEval: vi.fn(),
  gather: vi.fn(),
  plan: vi.fn(),
}));

vi.mock('@supabase/supabase-js', () => ({ createClient: () => fakeClient() }));
vi.mock('~/lib/qhub/agent/agent-registry.server', () => ({ getAgent: H.getAgent, getAgentVersion: H.getAgentVersion }));
vi.mock('~/lib/qhub/agent/agent-release-binding.server', () => ({ checkReleaseBinding: H.checkReleaseBinding }));
vi.mock('~/lib/qhub/enforcement.server', () => ({ enforceGovernedAction: H.enforce }));
vi.mock('~/lib/qhub/agent/agent-schema-check.server', () => ({ assertAgentSchemaReady: H.assertSchema }));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({
  getEvaluationById: H.getEval,
  gatherApprovals: H.gather,
  getActivePlan: H.plan,
}));

const OWNER_REQ = {
  requirement_id: 'REQ-OWNER',
  attestation_type: 'OWNER_ATTESTATION',
  applies_to: ['EXTERNAL_DATA_TRANSMISSION'],
  min_approvals: 1,
  distinct_approvers: false,
  roles: ['owner'],
};

/** Configure a valid resume: matching evaluation + active plan + a valid approval. */
async function setupValidResume(inputs: any) {
  const ev: any = await pausedEvalForConnector(inputs);
  ev.required_attestations = ['OWNER_ATTESTATION'];
  H.getEval.mockResolvedValue(ev);
  H.plan.mockResolvedValue({
    policy_profile_hash: 'PPHASH',
    enforcement_plan_hash: 'EPHASH',
    plan: { approval_requirements: [OWNER_REQ] },
  });
  H.gather.mockResolvedValue([
    {
      attestation_type: 'OWNER_ATTESTATION',
      approver_id: 'owner-9',
      approver_role: 'owner',
      scoped_action_digest: ev.action_digest,
      scoped_policy_profile_hash: 'PPHASH',
      scoped_enforcement_plan_hash: 'EPHASH',
      status: 'GRANTED',
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    },
  ]);

  return ev;
}

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
  STORE.evals = [];
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
    await setupValidResume(syntheticCommissionDatasets());

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
    await setupValidResume(syntheticCommissionDatasets());

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

  it('resume fails closed with NO valid approval — zero E2 submission, zero receipt', async () => {
    await run();
    await setupValidResume(syntheticCommissionDatasets());
    H.gather.mockResolvedValue([]); // binding is valid, but there is no valid approval

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
    expect(r.reason_codes).toContain('RECONSTRUCTION_FAILED');

    // No E2 Gate 04 submission was made, and the paused step has no receipt.
    expect(H.enforce.mock.calls.find((c) => c[0].parentEvaluationId)).toBeUndefined();
    expect(STORE.steps.find((s) => s.step_index === 1)!.receipt_id).toBeNull();
  });

  it('resume fails closed when an approval is scoped to a DIFFERENT action digest', async () => {
    await run();
    await setupValidResume(syntheticCommissionDatasets());
    H.gather.mockResolvedValue([
      {
        attestation_type: 'OWNER_ATTESTATION',
        approver_id: 'owner-9',
        approver_role: 'owner',
        scoped_action_digest: 'digest-for-a-different-action',
        scoped_policy_profile_hash: 'PPHASH',
        scoped_enforcement_plan_hash: 'EPHASH',
        status: 'GRANTED',
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
    ]);

    const r = await resume();
    expect(r.state).toBe('BLOCKED');
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
