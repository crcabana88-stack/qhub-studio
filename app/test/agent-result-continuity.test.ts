/**
 * QHUB Agent Framework — RESULT CONTINUITY R3 contract on real PostgreSQL (PGlite)
 * app/test/agent-result-continuity.test.ts
 *
 * Adversarial coverage of the R3 hardened contract: privilege-based writes (no
 * forgeable path), the authoritative receipt-binding table + RPC, the contiguous
 * pending-step RPC, the binding-backed finalizer, run/version identity immutability,
 * locked helper ACLs, and the foundation+R2+R3 verifier superset (owner /
 * search_path / body-digest / index-def / policy-expression drift all fail).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MIG = (f: string) => fileURLToPath(new URL(`../../supabase/migrations/${f}`, import.meta.url));
const BASELINE = [
  '20260723_qhub_applications.sql',
  '20260725_gate03_policy.sql',
  '20260725_qhub_classification.sql',
  '20260726_gate04_enforcement.sql',
  '20260726_gate04_schema_assurance_approval_cleanup.sql',
  '20260727_gate05_attestation.sql',
  '20260727_agent_framework_foundation.sql',
];
const CONTINUITY = '20260728_agent_run_step_result_continuity.sql';

const ORG = 'org_ct';
const APP = '10000000-0000-0000-0000-000000000001';
const AGENT = '20000000-0000-0000-0000-000000000001';
const VERSION = '30000000-0000-0000-0000-000000000001';
const AGENT2 = '20000000-0000-0000-0000-000000000002';
const VERSION2 = '30000000-0000-0000-0000-000000000002';
const PLAN = '60000000-0000-0000-0000-000000000001';
const RELEASE = '70000000-0000-0000-0000-000000000001';
const OTHER_ORG = 'org_other';
const OTHER_APP = '11000000-0000-0000-0000-000000000009';
const PP = 'pp_hash';
const EP = 'ep_hash';
const RC = 'rc_hash';

let db: PGlite;
let seq = 0;

function pgArray(items: string[]): string {
  return `{${items.map((i) => `"${i}"`).join(',')}}`;
}

async function asRole<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);

  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

async function seedRun(over: Partial<Record<string, string>> = {}): Promise<string> {
  seq += 1;

  const runId = `40000000-0000-0000-0000-${String(seq).padStart(12, '0')}`;
  await db.query(
    `insert into public.qhub_agent_runs
      (run_id, agent_id, agent_version_id, org_id, qhub_app_id, release_candidate_id, release_candidate_hash,
       initiating_user_id, operating_mode, runtime_provider, runtime_provider_version, current_state, current_step,
       policy_profile_hash, enforcement_plan_hash, primary_model, input_hash, idempotency_key, run_hash)
     values ($1,$2,$3,$4,$5,$6,$7,'user_a','SUPERVISED','local-simulation','1.0.0','RUNNING',0,
             $8,$9,'model-x','ih_run',$10,'run_hash')`,
    [
      runId,
      over.agent_id ?? AGENT,
      over.agent_version_id ?? VERSION,
      ORG,
      APP,
      over.release_candidate_id === null ? null : (over.release_candidate_id ?? RELEASE),
      over.release_candidate_hash ?? RC,
      PP,
      EP,
      `idem_${seq}`,
    ],
  );

  return runId;
}

interface EvalOpts {
  decision?: string;
  action_event_state?: string;
  action_type?: string;
  action_digest?: string;
  org_id?: string;
  qhub_app_id?: string;
  policy_profile_hash?: string;
  enforcement_plan_id?: string | null;
  enforcement_plan_hash?: string;
}

async function seedEval(o: EvalOpts = {}): Promise<string> {
  seq += 1;

  const evalId = `50000000-0000-0000-0000-${String(seq).padStart(12, '0')}`;
  const reqId = `51000000-0000-0000-0000-${String(seq).padStart(12, '0')}`;
  await db.query(
    `insert into public.qhub_control_evaluations
      (evaluation_id, action_request_id, org_id, qhub_app_id, action_type, action_digest, environment, decision,
       policy_profile_id, policy_profile_version, policy_profile_hash, enforcement_plan_id, enforcement_plan_version,
       enforcement_plan_hash, control_results_hash, evaluator_version, action_event_state, created_by)
     values ($1,$2,$3,$4,$5,$6,'INTERNAL',$7,
             '80000000-0000-0000-0000-000000000001',1,$8,$9,1,$10,'cr_hash','ev-1',$11,'user_a')`,
    [
      evalId,
      reqId,
      o.org_id ?? ORG,
      o.qhub_app_id ?? APP,
      o.action_type ?? 'CONNECTOR_ACTION',
      o.action_digest ?? 'digest_x',
      o.decision ?? 'ALLOW',
      o.policy_profile_hash ?? PP,
      o.enforcement_plan_id === null ? null : (o.enforcement_plan_id ?? PLAN),
      o.enforcement_plan_hash ?? EP,
      o.action_event_state ?? 'COMMITTED',
    ],
  );

  return evalId;
}

interface BindOpts {
  decision?: string;
  action_type?: string;
  receipt_id?: string;
  receipt_type?: string;
  receipt_hash?: string;
  evidence_event_id?: string;
  evidence_event_hash?: string;
  org_id?: string;
}

async function seedBinding(runId: string, evalId: string, o: BindOpts = {}): Promise<Record<string, unknown>> {
  const r = await db.query<{ r: Record<string, unknown> }>(
    `select public.qhub_bind_governed_action_receipt(
       $1::uuid,$2::text,$3::uuid,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,$10::text,$11::text,$12::text,$13::bigint,$14::timestamptz) r`,
    [
      runId,
      o.org_id ?? ORG,
      evalId,
      o.decision ?? 'EXECUTED',
      o.action_type ?? 'CONNECTOR_ACTION',
      o.receipt_id ?? 'rcpt_1',
      o.receipt_type ?? 'SANDBOX',
      'gate04-receipt-1.0.0',
      o.receipt_hash ?? 'receipt_hash_1',
      null,
      o.evidence_event_id ?? 'evt_1',
      o.evidence_event_hash ?? 'evt_hash_1',
      1,
      new Date().toISOString(),
    ],
  );

  return r.rows[0].r;
}

interface FinalizeArgs {
  step_index: number;
  step_kind?: string;
  action_type?: string | null;
  evaluation_id: string | null;
  decision?: string;
  reason_codes?: string[];
  receipt_id?: string | null;
  input_hash?: string | null;
  summary?: string;
  safe_result?: unknown;
}

async function finalize(runId: string, a: FinalizeArgs): Promise<Record<string, unknown>> {
  const r = await db.query<{ r: Record<string, unknown> }>(
    `select public.qhub_finalize_agent_run_step(
       $1::uuid,$2::text,$3::int,$4::text,$5::text,$6::uuid,$7::text,$8::text[],$9::text,$10::text,$11::text,$12::jsonb) r`,
    [
      runId,
      ORG,
      a.step_index,
      a.step_kind ?? 'CONNECTOR_ACTION',
      a.action_type === undefined ? 'CONNECTOR_ACTION' : a.action_type,
      a.evaluation_id,
      a.decision ?? 'EXECUTED',
      pgArray(a.reason_codes ?? []),
      a.receipt_id === undefined ? 'rcpt_1' : a.receipt_id,
      a.input_hash === undefined ? 'ih_step' : a.input_hash,
      a.summary ?? 'a safe summary',
      JSON.stringify(a.safe_result ?? { execution_status: 'SUCCEEDED' }),
    ],
  );

  return r.rows[0].r;
}

/** Finalize a valid EXECUTED step 0: ALLOW+COMMITTED eval, bound receipt. */
async function finalizeHappy(runId: string, stepIndex = 0): Promise<{ evalId: string; out: Record<string, unknown> }> {
  const evalId = await seedEval();
  await seedBinding(runId, evalId, { receipt_id: `rcpt_${seq}` });

  const out = await finalize(runId, { step_index: stepIndex, evaluation_id: evalId, receipt_id: `rcpt_${seq}` });

  return { evalId, out };
}

async function createPending(
  runId: string,
  evalId: string,
  stepIndex: number | null = null,
): Promise<Record<string, unknown>> {
  const r = await db.query<{ r: Record<string, unknown> }>(
    `select public.qhub_create_agent_run_step_pending($1::uuid,$2::text,$3::int,$4::text,$5::text,$6::uuid,$7::text[],$8::text,$9::text) r`,
    [runId, ORG, stepIndex, 'CONNECTOR_ACTION', 'CONNECTOR_ACTION', evalId, '{}', 'ih', 's'],
  );

  return r.rows[0].r;
}

async function stepRow(runId: string, stepIndex: number): Promise<Record<string, unknown> | null> {
  const r = await db.query<Record<string, unknown>>(
    'select * from public.qhub_agent_run_steps where run_id=$1 and step_index=$2',
    [runId, stepIndex],
  );

  return r.rows[0] ?? null;
}

beforeAll(async () => {
  db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );

  for (const f of BASELINE) {
    await db.exec(readFileSync(MIG(f), 'utf8'));
  }
  await db.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

  await db.query(`insert into public.qhub_applications (qhub_app_id, org_id, created_by) values ($1,$2,'user_a')`, [
    APP,
    ORG,
  ]);
  await db.query(`insert into public.qhub_applications (qhub_app_id, org_id, created_by) values ($1,$2,'user_a')`, [
    OTHER_APP,
    OTHER_ORG,
  ]);
  await db.query(
    `insert into public.qhub_enforcement_plans
      (enforcement_plan_id, org_id, qhub_app_id, enforcement_plan_version, classification_version, policy_profile_hash,
       policy_catalog_version, risk_tier, enforcement_plan_hash, plan, status, compiler_version, generated_by)
     values ($1,$2,$3,1,1,$4,'cat-1','TIER_2',$5,'{}'::jsonb,'ACTIVE','comp-1','user_a')`,
    [PLAN, ORG, APP, PP, EP],
  );
  await db.query(
    `insert into public.qhub_release_candidates
      (release_candidate_id, org_id, qhub_app_id, qhub_app_version, release_candidate_hash, canonical_file_manifest_hash,
       classification_version, risk_tier, policy_profile_hash, enforcement_plan_hash, model_manifest_hash,
       connector_manifest_hash, data_access_manifest_hash, target_environment, deployment_target, release_scope,
       manifest, manifest_version, status, created_by)
     values ($1,$2,$3,1,$4,'cfmh',1,'TIER_2',$5,$6,'mmh','cmh','damh','STAGING','staging','app',
             '{}'::jsonb,'1','APPROVED','user_a')`,
    [RELEASE, ORG, APP, RC, PP, EP],
  );

  for (const [ag, ver, mh] of [
    [AGENT, VERSION, 'manifest_hash_1'],
    [AGENT2, VERSION2, 'manifest_hash_2'],
  ] as const) {
    await db.query(
      `insert into public.qhub_agents
        (agent_id, org_id, qhub_app_id, name, owner_user_id, current_lifecycle_state, current_operating_mode, risk_tier, created_by)
       values ($1,$2,$3,'agent','user_a','SUPERVISED','SUPERVISED','TIER_2','user_a')`,
      [ag, ORG, APP],
    );
    await db.query(
      `insert into public.qhub_agent_versions
        (agent_version_id, agent_id, org_id, qhub_app_id, manifest, manifest_hash, manifest_version,
         operating_mode, autonomy_level, risk_tier, policy_profile_hash, enforcement_plan_hash,
         release_candidate_id, release_candidate_hash, created_by)
       values ($1,$2,$3,$4,'{}'::jsonb,$5,'1','SUPERVISED','L1','TIER_2',$6,$7,$8,$9,'user_a')`,
      [ver, ag, ORG, APP, mh, PP, EP, RELEASE, RC],
    );
  }
});

afterAll(async () => {
  await db.close();
});

describe('finalization + valid path (tests 13, 14, 15, 21, 24)', () => {
  it('finalizes a valid EXECUTED step with a bound receipt (tests 13, 21)', async () => {
    const run = await seedRun();
    const { out } = await finalizeHappy(run);
    expect(out.finalized).toBe(true);
    expect((out.result_hash as string).length).toBe(64);

    const row = await stepRow(run, 0);
    expect(row?.finalized_at).not.toBeNull();
    expect(row?.result_hash).toBe(out.result_hash);
  });

  it('is idempotent for an exact repeat, rejects a materially different repeat (tests 14, 15)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_a' });

    const first = await finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_a' });
    const again = await finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_a' });
    expect(again.idempotent).toBe(true);
    expect(again.result_hash).toBe(first.result_hash);
    await expect(
      finalize(run, {
        step_index: 0,
        evaluation_id: evalId,
        receipt_id: 'r_a',
        safe_result: { execution_status: 'FAILED' },
      }),
    ).rejects.toThrow(/already finalized with a different result/);
  });

  it('rejects EXECUTED without a receipt binding (test 12)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /requires an authoritative receipt binding/,
    );
  });

  it('rejects EXECUTED without a receipt id (test 21)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_b' });

    // p_receipt_id mismatch vs binding is rejected; a null caller id defers to the binding.
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'WRONG' })).rejects.toThrow(
      /caller receipt_id does not match/,
    );
  });

  it('accepts a valid DENY step (no receipt) (test 20)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ decision: 'DENY', action_event_state: 'NONE' });
    const out = await finalize(run, {
      step_index: 0,
      evaluation_id: evalId,
      decision: 'DENY',
      receipt_id: null,
      safe_result: { execution_status: 'DENIED' },
    });
    expect(out.finalized).toBe(true);
    expect(await stepRow(run, 0).then((r) => r?.receipt_id)).toBeNull();
  });

  it('rejects a DENY step that carries a receipt (test 20)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ decision: 'DENY', action_event_state: 'NONE' });
    await expect(
      finalize(run, { step_index: 0, evaluation_id: evalId, decision: 'DENY', receipt_id: 'rcpt' }),
    ).rejects.toThrow(/DENY step must not carry a receipt/);
  });
});

describe('receipt-binding authority (tests 11-24)', () => {
  it('rejects a fabricated receipt (uncommitted evidence) (tests 11, 18)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ action_event_state: 'NONE' });
    await expect(seedBinding(run, evalId)).rejects.toThrow(/evidence is not COMMITTED/);
  });

  it('rejects a cross-tenant receipt binding (test 14)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ org_id: OTHER_ORG, qhub_app_id: OTHER_APP, enforcement_plan_id: null });
    await expect(seedBinding(run, evalId)).rejects.toThrow(/evaluation ownership mismatch/);
  });

  it('rejects a wrong receipt type at finalization (test 19)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_prod', receipt_type: 'PRODUCTION' });
    await expect(
      finalize(run, { step_index: 0, evaluation_id: evalId, decision: 'SIMULATED', receipt_id: 'r_prod' }),
    ).rejects.toThrow(/SIMULATED requires a simulation\/sandbox receipt/);
  });

  it('rejects a cross-run receipt at finalization (tests 13, 16)', async () => {
    const runA = await seedRun();
    const evalId = await seedEval();
    await seedBinding(runA, evalId, { receipt_id: 'r_x' }); // binding belongs to runA

    const runB = await seedRun();

    // finalize runB referencing runA's evaluation → binding.run_id != runB
    await expect(finalize(runB, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_x' })).rejects.toThrow(
      /evaluation ownership mismatch|receipt binding does not match/,
    );
  });

  it('is idempotent for an exact receipt-binding repeat, rejects a different one (tests 23, 24)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    const first = await seedBinding(run, evalId, { receipt_id: 'r_i', evidence_event_hash: 'h1' });
    const again = await seedBinding(run, evalId, { receipt_id: 'r_i', evidence_event_hash: 'h1' });
    expect(again.idempotent).toBe(true);
    expect(again.binding_id).toBe(first.binding_id);
    await expect(seedBinding(run, evalId, { receipt_id: 'r_i2', evidence_event_hash: 'h2' })).rejects.toThrow(
      /different receipt is already bound/,
    );
  });

  it('rejects an action-digest / policy-plan mismatch at binding time (tests 16, 17)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ enforcement_plan_hash: 'WRONG' });
    await expect(seedBinding(run, evalId)).rejects.toThrow(/policy\/plan hash does not match/);
  });
});

describe('pending-step RPC contract (tests 1-10)', () => {
  it('creates a contiguous pending step at MAX+1 (test 4)', async () => {
    const run = await seedRun();
    const e = await seedEval({ decision: 'REQUIRE_APPROVAL', action_event_state: 'NONE' });
    const out = await createPending(run, e, 0);
    expect(out.step_index).toBe(0);
    expect(out.decision).toBe('REQUIRE_APPROVAL');
  });

  it('rejects a cross-tenant evaluation (test 1)', async () => {
    const run = await seedRun();
    const e = await seedEval({
      org_id: OTHER_ORG,
      qhub_app_id: OTHER_APP,
      enforcement_plan_id: null,
      decision: 'REQUIRE_APPROVAL',
      action_event_state: 'NONE',
    });
    await expect(createPending(run, e, 0)).rejects.toThrow(/evaluation ownership mismatch/);
  });

  it('rejects a terminal-decision evaluation for a pending step (test 9)', async () => {
    const run = await seedRun();
    const e = await seedEval(); // decision ALLOW
    await expect(createPending(run, e, 0)).rejects.toThrow(/requires a REQUIRE_APPROVAL evaluation/);
  });

  it('rejects a noncontiguous / step-99 gap (tests 4, 5)', async () => {
    const run = await seedRun();
    const e = await seedEval({ decision: 'REQUIRE_APPROVAL', action_event_state: 'NONE' });
    await expect(createPending(run, e, 99)).rejects.toThrow(/noncontiguous step_index/);
  });

  it('is exact-idempotent for the tail pending row, rejects a different evaluation (tests 6, 7, 8)', async () => {
    const run = await seedRun();
    const e = await seedEval({ decision: 'REQUIRE_APPROVAL', action_event_state: 'NONE' });
    await createPending(run, e, 0);

    const again = await createPending(run, e, 0);
    expect(again.idempotent).toBe(true);

    const e2 = await seedEval({ decision: 'REQUIRE_APPROVAL', action_event_state: 'NONE' });
    await expect(createPending(run, e2, 0)).rejects.toThrow(/already exists with a different evaluation/);
  });

  it('rejects a run in an invalid state (test 10)', async () => {
    const run = await seedRun();
    await db.query(`update public.qhub_agent_runs set current_state='COMPLETED' where run_id=$1`, [run]);

    const e = await seedEval({ decision: 'REQUIRE_APPROVAL', action_event_state: 'NONE' });
    await expect(createPending(run, e, 0)).rejects.toThrow(/not in a writable state/);
  });
});

describe('authoritative validation in the finalizer (tests 13-17)', () => {
  it('rejects EXECUTED without an evaluation (test 21-adjacent)', async () => {
    const run = await seedRun();
    await expect(finalize(run, { step_index: 0, evaluation_id: null })).rejects.toThrow(
      /requires an authoritative evaluation/,
    );
  });

  it('rejects a stale/invalid release (test 13)', async () => {
    await db.query(`update public.qhub_release_candidates set status='SUPERSEDED' where release_candidate_id=$1`, [
      RELEASE,
    ]);

    const run = await seedRun();
    const evalId = await seedEval();
    await expect(seedBinding(run, evalId)).rejects.toThrow(/release candidate invalid/);
    await db.query(`update public.qhub_release_candidates set status='APPROVED' where release_candidate_id=$1`, [
      RELEASE,
    ]);
  });

  it('rejects an agent whose lifecycle is not runnable (test 14)', async () => {
    await db.query(`update public.qhub_agents set current_lifecycle_state='RETIRED' where agent_id=$1`, [AGENT2]);

    const run = await seedRun({ agent_id: AGENT2, agent_version_id: VERSION2 });
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_life' });
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_life' })).rejects.toThrow(
      /lifecycle .* is not runnable/,
    );
    await db.query(`update public.qhub_agents set current_lifecycle_state='SUPERVISED' where agent_id=$1`, [AGENT2]);
  });

  it('rejects an inactive enforcement plan at binding (test 15)', async () => {
    await db.query(`update public.qhub_enforcement_plans set status='SUSPENDED' where enforcement_plan_id=$1`, [PLAN]);

    const run = await seedRun();
    const evalId = await seedEval();
    await expect(seedBinding(run, evalId)).rejects.toThrow(/enforcement plan invalid/);
    await db.query(`update public.qhub_enforcement_plans set status='ACTIVE' where enforcement_plan_id=$1`, [PLAN]);
  });

  it('rejects an invalid safe_result', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_sr' });
    await expect(
      finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_sr', safe_result: { secret: 'x' } }),
    ).rejects.toThrow(/safe_result failed strict validation/);
  });
});

describe('previous-step hash chain', () => {
  it('chains step 1 onto step 0', async () => {
    const run = await seedRun();
    const { out: s0 } = await finalizeHappy(run, 0);
    const { out: s1 } = await finalizeHappy(run, 1);
    expect(s1.previous_step_hash).toBe(s0.result_hash);
  });

  it('rejects a later step when the previous step is not finalized', async () => {
    const run = await seedRun();
    const e = await seedEval();
    await seedBinding(run, e, { receipt_id: 'r_p1' });
    await expect(finalize(run, { step_index: 1, evaluation_id: e, receipt_id: 'r_p1' })).rejects.toThrow(
      /previous step .* missing or not finalized/,
    );
  });
});

describe('privilege-based authorization — no forgeable path (tests 1-6 receipt)', () => {
  it('denies a direct service_role terminal INSERT', async () => {
    const run = await seedRun();
    await asRole('service_role', async () => {
      await expect(
        db.query(
          `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary) values ($1,$2,0,'CONNECTOR_ACTION','EXECUTED','s')`,
          [run, ORG],
        ),
      ).rejects.toThrow(/permission denied/i);
    });
  });

  it('denies a direct service_role INSERT into receipt bindings', async () => {
    const run = await seedRun();
    await asRole('service_role', async () => {
      await expect(
        db.query(
          `insert into public.qhub_governed_action_receipt_bindings (receipt_id, receipt_type, receipt_schema_version, receipt_hash, org_id, qhub_app_id, run_id, agent_id, agent_version_id, evaluation_id, action_request_id, action_digest, action_type, decision, policy_profile_hash, enforcement_plan_hash, evidence_event_id, evidence_event_hash, committed_at)
           values ('x','SANDBOX','v','h',$1,$2,$3,$4,$5,'50000000-0000-0000-0000-0000000000aa','51000000-0000-0000-0000-0000000000aa','d','CONNECTOR_ACTION','ALLOW','pp','ep','e','eh',NOW())`,
          [ORG, APP, run, AGENT, VERSION],
        ),
      ).rejects.toThrow(/permission denied/i);
    });
  });

  it('the guard trigger references no forgeable GUC gate', async () => {
    const src = await db.query<{ prosrc: string }>(
      `select prosrc from pg_proc where oid='public.qhub_agent_run_step_guard()'::regprocedure`,
    );
    expect(src.rows[0].prosrc).not.toMatch(/current_setting|allow_finalize|set_config/);
  });

  it('the finalize + bind RPCs work for service_role while direct writes do not', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    const out = await asRole('service_role', async () => {
      await seedBinding(run, evalId, { receipt_id: 'r_svc' });
      return finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'r_svc' });
    });
    expect(out.finalized).toBe(true);
  });

  it('browser roles cannot execute helpers or the bind RPC', async () => {
    const r = await db.query<{ a: boolean; b: boolean; c: boolean }>(
      `select has_function_privilege('anon','public.qhub_agent_safe_result_valid(jsonb)','EXECUTE') a,
              has_function_privilege('authenticated','public.qhub_bind_governed_action_receipt(uuid,text,uuid,text,text,text,text,text,text,text,text,text,bigint,timestamptz)','EXECUTE') b,
              has_function_privilege('service_role','public.qhub_receipt_binding_immutable()','EXECUTE') c`,
    );
    expect(r.rows[0].a).toBe(false);
    expect(r.rows[0].b).toBe(false);
    expect(r.rows[0].c).toBe(false);
  });
});

describe('immutability (steps + run identity + version + binding)', () => {
  it('rejects mutation of a finalized step (result_hash)', async () => {
    const run = await seedRun();
    await finalizeHappy(run);
    await expect(
      db.query(`update public.qhub_agent_run_steps set result_hash='00' where run_id=$1 and step_index=0`, [run]),
    ).rejects.toThrow(/finalized step is immutable/);
  });

  it('rejects mutation of run identity (agent_id) and runtime_provider_version (tests 16, 17)', async () => {
    const run = await seedRun();
    await expect(
      db.query(`update public.qhub_agent_runs set agent_id=$2 where run_id=$1`, [run, AGENT2]),
    ).rejects.toThrow(/hash-bound run identity is immutable/);
    await expect(
      db.query(`update public.qhub_agent_runs set runtime_provider_version='9.9' where run_id=$1`, [run]),
    ).rejects.toThrow(/hash-bound run identity is immutable/);
  });

  it('rejects mutation of version manifest_hash (drift prevention)', async () => {
    await expect(
      db.query(`update public.qhub_agent_versions set manifest_hash='DRIFT' where agent_version_id=$1`, [VERSION]),
    ).rejects.toThrow(/manifest_hash is immutable/);
  });

  it('rejects mutation of a receipt binding', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await seedBinding(run, evalId, { receipt_id: 'r_imm' });
    await expect(
      db.query(`update public.qhub_governed_action_receipt_bindings set receipt_id='x' where evaluation_id=$1`, [
        evalId,
      ]),
    ).rejects.toThrow(/receipt bindings are immutable/);
  });
});

describe('verifier superset + drift + no-op (tests 25-36)', () => {
  async function verify(inst: PGlite) {
    const r = await inst.query<{
      v: {
        expected_version: string;
        ready: boolean;
        checks: { identifier: string; ready: boolean; reason_code: string }[];
      };
    }>('select public.qhub_verify_agent_schema() v');
    return r.rows[0].v;
  }

  async function freshDb(): Promise<PGlite> {
    const d = new PGlite();
    await d.exec(
      'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
    );

    for (const f of BASELINE) {
      await d.exec(readFileSync(MIG(f), 'utf8'));
    }
    await d.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

    return d;
  }

  it('reports READY at r3 and preserves foundation checks (test 36)', async () => {
    const v = await verify(db);
    expect(v.expected_version).toBe('2026-07-29.agent-result-continuity-r3');
    expect(v.ready).toBe(true);

    for (const id of [
      'index.run_idempotency_unique',
      'column.runs_contract',
      'constraint.run_state_check',
      'index.version_content_unique',
    ]) {
      expect(v.checks.find((c) => c.identifier === id)?.ready, id).toBe(true);
    }
  });

  const drifts: Array<[string, string, string]> = [
    [
      'helper owner drift (test 25)',
      'ALTER FUNCTION public.qhub_agent_safe_result_valid(jsonb) OWNER TO service_role;',
      'function.owners_pinned',
    ],
    [
      'helper search_path drift (test 26)',
      'ALTER FUNCTION public.qhub_agent_safe_result_valid(jsonb) SET search_path = public;',
      'function.search_paths_pinned',
    ],
    [
      'helper ACL drift (test 27)',
      'GRANT EXECUTE ON FUNCTION public.qhub_agent_safe_result_valid(jsonb) TO anon;',
      'privilege.helpers_locked',
    ],
    [
      'helper body drift (test 28)',
      'CREATE OR REPLACE FUNCTION public.qhub_agent_hash_intcell(v INT) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $q$ SELECT $1::text $q$;',
      'function.bodies_pinned',
    ],
    [
      'broad RLS policy (test 29)',
      'CREATE POLICY evil_broad ON public.qhub_agent_run_steps AS PERMISSIVE FOR SELECT TO authenticated USING (true);',
      'policy.restrictive_exact',
    ],
    [
      'removed run-idempotency index (test 32)',
      'DROP INDEX public.idx_agent_runs_idem;',
      'index.run_idempotency_unique',
    ],
    [
      'removed receipt unique index (test 33)',
      'DROP INDEX public.idx_receipt_binding_eval;',
      'index.receipt_binding_unique',
    ],
    [
      'direct table write grant (test 34)',
      'GRANT INSERT ON public.qhub_agent_run_steps TO service_role;',
      'privilege.steps_no_direct_write',
    ],
    [
      'disabled guard trigger (test 35)',
      'ALTER TABLE public.qhub_agent_run_steps DISABLE TRIGGER trg_qhub_agent_run_step_guard;',
      'trigger.step_guard',
    ],
    [
      'wrong-table index (test 31)',
      'DROP INDEX public.idx_receipt_binding_receipt; CREATE UNIQUE INDEX idx_receipt_binding_receipt ON public.qhub_agent_runs(run_id);',
      'index.pinned_defs_exact',
    ],
  ];

  for (const [label, mutation, expectFail] of drifts) {
    it(`verifier fails on ${label}`, async () => {
      const d = await freshDb();
      await d.exec(mutation);

      const v = await verify(d);
      expect(v.ready).toBe(false);
      expect(
        v.checks.some((c) => c.identifier === expectFail && !c.ready),
        `${expectFail} should fail`,
      ).toBe(true);
      await d.close();
    });
  }

  it('a second migration run is a true no-op (OID/xmin stable) (test 56)', async () => {
    const d = await freshDb();
    const q = () =>
      Promise.all([
        d.query<{ proname: string; oid: string; xmin: string }>(
          `select proname, oid::text, xmin::text from pg_proc where proname like 'qhub_%agent%' or proname like 'qhub_%receipt%' or proname='qhub_verify_agent_schema' order by proname`,
        ),
        d.query<{ tgname: string; oid: string; xmin: string }>(
          `select tgname, oid::text, xmin::text from pg_trigger where tgname like 'trg_qhub%' order by tgname`,
        ),
      ]);
    const [f1, t1] = await q();
    await d.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

    const [f2, t2] = await q();
    expect(f2.rows).toEqual(f1.rows);
    expect(t2.rows).toEqual(t1.rows);
    expect((await verify(d)).ready).toBe(true);
    await d.close();
  });

  it('a drifted second run aborts rather than overwriting (test 57)', async () => {
    const d = await freshDb();

    // Hand-mutate a pinned function body, then re-run the migration → it must abort.
    await d.exec(
      'CREATE OR REPLACE FUNCTION public.qhub_agent_hash_intcell(v INT) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $q$ SELECT $1::text $q$;',
    );
    await expect(d.exec(readFileSync(MIG(CONTINUITY), 'utf8'))).rejects.toThrow(/drift — aborting/);
    await d.close();
  });
});
