/**
 * QHUB Agent Framework — RESULT CONTINUITY contract on real PostgreSQL (PGlite)
 * app/test/agent-result-continuity.test.ts
 *
 * Adversarial coverage of the hardened, PRIVILEGE-BASED terminalization contract:
 * service_role holds no direct write on qhub_agent_run_steps (SELECT only); all
 * writes flow through the SECURITY DEFINER RPCs; no caller-settable GUC is trusted;
 * the finalizer validates every authoritative record; run/version identity is
 * immutable; helpers are browser+service_role denied; the verifier proves it all;
 * and a second migration run is a true no-op.
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

const OTHER_ORG = 'org_other';
const OTHER_APP = '11000000-0000-0000-0000-000000000009';

interface EvalOpts {
  decision?: string;
  action_event_state?: string;
  action_type?: string;
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
     values ($1,$2,$3,$4,$5,'digest_x','INTERNAL',$6,
             '80000000-0000-0000-0000-000000000001',1,$7,$8,1,$9,'cr_hash','ev-1',$10,'user_a')`,
    [
      evalId,
      reqId,
      o.org_id ?? ORG,
      o.qhub_app_id ?? APP,
      o.action_type ?? 'CONNECTOR_ACTION',
      o.decision ?? 'ALLOW',
      o.policy_profile_hash ?? PP,
      o.enforcement_plan_id === null ? null : (o.enforcement_plan_id ?? PLAN),
      o.enforcement_plan_hash ?? EP,
      o.action_event_state ?? 'COMMITTED',
    ],
  );

  return evalId;
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

/** Finalize a valid EXECUTED step 0 with a fresh ALLOW/COMMITTED evaluation. */
async function finalizeHappy(runId: string): Promise<{ evalId: string; out: Record<string, unknown> }> {
  const evalId = await seedEval();
  const out = await finalize(runId, { step_index: 0, evaluation_id: evalId });

  return { evalId, out };
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

describe('finalization RPC — valid path + idempotency (tests 13, 14, 15, 24)', () => {
  it('finalizes a valid EXECUTED step and returns the authoritative hash', async () => {
    const run = await seedRun();
    const { out } = await finalizeHappy(run);
    expect(out.finalized).toBe(true);
    expect(out.previous_step_hash).toBeNull();
    expect((out.result_hash as string).length).toBe(64);

    const row = await stepRow(run, 0);
    expect(row?.result_hash).toBe(out.result_hash);
    expect(row?.finalized_at).not.toBeNull();
  });

  it('is idempotent for an exact repeat, rejects a materially different repeat (tests 14, 15)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    const first = await finalize(run, { step_index: 0, evaluation_id: evalId });
    const again = await finalize(run, { step_index: 0, evaluation_id: evalId });
    expect(again.idempotent).toBe(true);
    expect(again.result_hash).toBe(first.result_hash);

    await expect(finalize(run, { step_index: 0, evaluation_id: evalId, receipt_id: 'DIFFERENT' })).rejects.toThrow(
      /already finalized with a different result/,
    );
  });

  it('chains step 1 onto step 0', async () => {
    const run = await seedRun();
    const { out: s0 } = await finalizeHappy(run);
    const e1 = await seedEval();
    const s1 = await finalize(run, { step_index: 1, evaluation_id: e1 });
    expect(s1.previous_step_hash).toBe(s0.result_hash);
  });
});

describe('authoritative validation in the finalizer (tests 8-15)', () => {
  it('rejects EXECUTED without an evaluation (test 8)', async () => {
    const run = await seedRun();
    await expect(finalize(run, { step_index: 0, evaluation_id: null })).rejects.toThrow(
      /requires an authoritative evaluation/,
    );
  });

  it('rejects EXECUTED with an arbitrary receipt (evaluation not COMMITTED) (test 9)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ action_event_state: 'NONE' });
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(/not COMMITTED/);
  });

  it('rejects a DENY step that carries a receipt (test 10)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ decision: 'DENY', action_event_state: 'NONE' });
    await expect(
      finalize(run, { step_index: 0, evaluation_id: evalId, decision: 'DENY', receipt_id: 'rcpt' }),
    ).rejects.toThrow(/DENY step must not carry a receipt/);
  });

  it('accepts a valid DENY step (no receipt)', async () => {
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
  });

  it('rejects a cross-tenant evaluation (tests 11, 12)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ org_id: OTHER_ORG, qhub_app_id: OTHER_APP, enforcement_plan_id: null });
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /evaluation ownership mismatch/,
    );
  });

  it('rejects a stale/invalid release (test 13)', async () => {
    await db.query(`update public.qhub_release_candidates set status='SUPERSEDED' where release_candidate_id=$1`, [
      RELEASE,
    ]);

    const run = await seedRun();
    const evalId = await seedEval();
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /release candidate status .* is not valid/,
    );
    await db.query(`update public.qhub_release_candidates set status='APPROVED' where release_candidate_id=$1`, [
      RELEASE,
    ]);
  });

  it('rejects a run whose agent lifecycle is not runnable (test 14)', async () => {
    await db.query(`update public.qhub_agents set current_lifecycle_state='RETIRED' where agent_id=$1`, [AGENT2]);

    const run = await seedRun({ agent_id: AGENT2, agent_version_id: VERSION2 });
    const evalId = await seedEval();
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /lifecycle .* is not runnable/,
    );
    await db.query(`update public.qhub_agents set current_lifecycle_state='SUPERVISED' where agent_id=$1`, [AGENT2]);
  });

  it('rejects a policy/plan mismatch (test 15)', async () => {
    const run = await seedRun();
    const evalId = await seedEval({ enforcement_plan_hash: 'WRONG' });
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /policy\/plan hash does not match/,
    );
  });

  it('rejects an inactive enforcement plan', async () => {
    await db.query(`update public.qhub_enforcement_plans set status='SUSPENDED' where enforcement_plan_id=$1`, [PLAN]);

    const run = await seedRun();
    const evalId = await seedEval();
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId })).rejects.toThrow(
      /plan status .* is not ACTIVE/,
    );
    await db.query(`update public.qhub_enforcement_plans set status='ACTIVE' where enforcement_plan_id=$1`, [PLAN]);
  });

  it('rejects an invalid safe_result', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    await expect(finalize(run, { step_index: 0, evaluation_id: evalId, safe_result: { secret: 'x' } })).rejects.toThrow(
      /safe_result failed strict validation/,
    );
  });
});

describe('previous-step hash chain (tests 4, 5, 6, 7)', () => {
  it('rejects a later step when the previous step is not finalized (test 5)', async () => {
    const run = await seedRun();
    const e = await seedEval();
    await expect(finalize(run, { step_index: 1, evaluation_id: e })).rejects.toThrow(
      /previous step .* missing or not finalized/,
    );
  });

  it('rejects a transplanted prior hash on a later step (tests 4, 6, 7)', async () => {
    const runA = await seedRun();
    const { out: a0 } = await finalizeHappy(runA);
    const runB = await seedRun();
    await finalizeHappy(runB);

    const e = await seedEval();

    // A crafted finalized INSERT (as the owner/superuser) with a transplanted prev hash must still be rejected by the trigger.
    await expect(
      db.exec(`INSERT INTO public.qhub_agent_run_steps
        (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, receipt_id,
         input_hash, summary, safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
        VALUES ('${runB}','${ORG}',1,'CONNECTOR_ACTION','CONNECTOR_ACTION','${e}','EXECUTED','{}','rcpt','ih','s',
          '{"execution_status":"SUCCEEDED"}'::jsonb,'${a0.result_hash}','x','agent-step-result-1.0.0',NOW())`),
    ).rejects.toThrow(/previous_step_hash does not match/);
  });
});

describe('privilege-based authorization — no forgeable path (tests 1-6)', () => {
  it('denies a direct service_role terminal INSERT (test 1)', async () => {
    const run = await seedRun();
    await asRole('service_role', async () => {
      await expect(
        db.query(
          `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary)
           values ($1,$2,0,'CONNECTOR_ACTION','EXECUTED','s')`,
          [run, ORG],
        ),
      ).rejects.toThrow(/permission denied/i);
    });
  });

  it('denies a direct service_role UPDATE (test 2)', async () => {
    const run = await seedRun();
    await finalizeHappy(run);
    await asRole('service_role', async () => {
      await expect(
        db.query(`update public.qhub_agent_run_steps set summary='x' where run_id=$1 and step_index=0`, [run]),
      ).rejects.toThrow(/permission denied/i);
    });
  });

  it('a custom GUC cannot authorize terminalization — and the trigger references none (tests 3, 4)', async () => {
    const run = await seedRun();
    await asRole('service_role', async () => {
      await db.exec(`SELECT set_config('qhub.allow_finalize','1',true)`);
      await expect(
        db.query(
          `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary, result_hash)
           values ($1,$2,0,'CONNECTOR_ACTION','EXECUTED','s','forged')`,
          [run, ORG],
        ),
      ).rejects.toThrow(/permission denied/i);
    });

    // The guard trigger contains NO GUC gate at all.
    const src = await db.query<{ prosrc: string }>(
      `select prosrc from pg_proc where oid='public.qhub_agent_run_step_guard()'::regprocedure`,
    );
    expect(src.rows[0].prosrc).not.toMatch(/current_setting|allow_finalize|set_config/);
  });

  it('a nested SECURITY DEFINER wrapper owned by service_role cannot bypass (test 5)', async () => {
    const run = await seedRun();
    await db.exec(`CREATE FUNCTION public._evil_write(p_run uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $f$
      BEGIN INSERT INTO public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary)
        VALUES (p_run, '${ORG}', 0, 'CONNECTOR_ACTION', 'EXECUTED', 's'); END $f$;`);
    await db.exec('ALTER FUNCTION public._evil_write(uuid) OWNER TO service_role');
    await asRole('service_role', async () => {
      await expect(db.query(`select public._evil_write($1)`, [run])).rejects.toThrow(/permission denied/i);
    });
  });

  it('the finalize RPC works for service_role while direct writes do not (privilege model holds)', async () => {
    const run = await seedRun();
    const evalId = await seedEval();
    const out = await asRole('service_role', () => finalize(run, { step_index: 0, evaluation_id: evalId }));
    expect(out.finalized).toBe(true);
  });

  it('browser roles cannot execute the hash/validator helpers (test 6)', async () => {
    const r = await db.query<{ a: boolean; b: boolean; c: boolean }>(
      `select has_function_privilege('anon','public.qhub_agent_safe_result_valid(jsonb)','EXECUTE') a,
              has_function_privilege('service_role','public.qhub_agent_safe_result_valid(jsonb)','EXECUTE') b,
              has_function_privilege('authenticated','public.qhub_agent_run_step_guard()','EXECUTE') c`,
    );
    expect(r.rows[0].a).toBe(false);
    expect(r.rows[0].b).toBe(false);
    expect(r.rows[0].c).toBe(false);
  });
});

describe('malformed terminal rows are impossible (test 7)', () => {
  it('rejects a terminal decision with NULL continuity (owner path)', async () => {
    const run = await seedRun();
    await expect(
      db.query(
        `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary)
         values ($1,$2,0,'CONNECTOR_ACTION','EXECUTED','s')`,
        [run, ORG],
      ),
    ).rejects.toThrow(/non-finalized row must be REQUIRE_APPROVAL/);
  });

  it('rejects a pending row that carries continuity fields', async () => {
    const run = await seedRun();
    await expect(
      db.query(
        `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary, safe_result)
         values ($1,$2,0,'CONNECTOR_ACTION','REQUIRE_APPROVAL','s','{"execution_status":"SUCCEEDED"}'::jsonb)`,
        [run, ORG],
      ),
    ).rejects.toThrow(/continuity fields require finalization/);
  });

  it('rejects an arbitrary caller-supplied result_hash (owner path)', async () => {
    const run = await seedRun();
    const e = await seedEval();
    await expect(
      db.exec(`INSERT INTO public.qhub_agent_run_steps
        (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, receipt_id,
         input_hash, summary, safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
        VALUES ('${run}','${ORG}',0,'CONNECTOR_ACTION','CONNECTOR_ACTION','${e}','EXECUTED','{}','rcpt','ih','s',
          '{"execution_status":"SUCCEEDED"}'::jsonb,NULL,'deadbeef','agent-step-result-1.0.0',NOW())`),
    ).rejects.toThrow(/not the authoritative canonical hash/);
  });
});

describe('immutability of terminal + run identity (tests 16, 17, 20)', () => {
  const stepUpdates: Array<[string, string]> = [
    ['step_index', `update public.qhub_agent_run_steps set step_index=99 where run_id=$1 and step_index=0`],
    [
      'evaluation_id',
      `update public.qhub_agent_run_steps set evaluation_id='50000000-0000-0000-0000-0000000000ff' where run_id=$1 and step_index=0`,
    ],
    ['receipt_id', `update public.qhub_agent_run_steps set receipt_id='other' where run_id=$1 and step_index=0`],
    [
      'safe_result',
      `update public.qhub_agent_run_steps set safe_result='{"execution_status":"DENIED"}'::jsonb where run_id=$1 and step_index=0`,
    ],
    ['result_hash', `update public.qhub_agent_run_steps set result_hash='00' where run_id=$1 and step_index=0`],
  ];

  for (const [field, sql] of stepUpdates) {
    it(`rejects mutation of terminal ${field} (test 20)`, async () => {
      const run = await seedRun();
      await finalizeHappy(run);
      await expect(db.query(sql, [run])).rejects.toThrow(/finalized step is immutable/);
    });
  }

  it('rejects mutation of run identity org_id/agent_id (test 16)', async () => {
    const run = await seedRun();
    await expect(
      db.query(`update public.qhub_agent_runs set agent_id=$2 where run_id=$1`, [run, AGENT2]),
    ).rejects.toThrow(/hash-bound run identity is immutable/);
  });

  it('rejects mutation of runtime_provider_version (test 17)', async () => {
    const run = await seedRun();
    await expect(
      db.query(`update public.qhub_agent_runs set runtime_provider_version='9.9.9' where run_id=$1`, [run]),
    ).rejects.toThrow(/hash-bound run identity is immutable/);
  });

  it('rejects mutation of a version manifest_hash (test 18 — drift prevention)', async () => {
    await expect(
      db.query(`update public.qhub_agent_versions set manifest_hash='DRIFT' where agent_version_id=$1`, [VERSION]),
    ).rejects.toThrow(/manifest_hash is immutable/);
  });
});

describe('cross-agent binding (test 8-adjacent)', () => {
  it('identical inputs under a different agent/version produce a different hash', async () => {
    const runA = await seedRun();
    const runB = await seedRun({ agent_id: AGENT2, agent_version_id: VERSION2 });
    const eA = await seedEval();
    const eB = await seedEval();
    const a = await finalize(runA, { step_index: 0, evaluation_id: eA, input_hash: 'same', receipt_id: 'same' });
    const b = await finalize(runB, { step_index: 0, evaluation_id: eB, input_hash: 'same', receipt_id: 'same' });
    expect(a.result_hash).not.toBe(b.result_hash);
  });
});

describe('verifier + true no-op (tests 19-24)', () => {
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

  it('reports READY at the r2 version with all helper ACLs locked (test 19)', async () => {
    const v = await verify(db);
    expect(v.expected_version).toBe('2026-07-28.agent-result-continuity-r2');
    expect(v.ready).toBe(true);
    expect(v.checks.find((c) => c.identifier === 'privilege.helpers_locked')?.ready).toBe(true);
    expect(v.checks.find((c) => c.identifier === 'privilege.steps_no_direct_write')?.ready).toBe(true);
  });

  it('verifier fails on direct table privilege broadening (test 20)', async () => {
    const d = await freshDb();
    await d.exec('GRANT INSERT ON public.qhub_agent_run_steps TO service_role;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'privilege.steps_no_direct_write' && !c.ready)).toBe(true);
    await d.close();
  });

  it('verifier fails on helper PUBLIC execution (test 21)', async () => {
    const d = await freshDb();
    await d.exec('GRANT EXECUTE ON FUNCTION public.qhub_agent_safe_result_valid(jsonb) TO anon;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'privilege.helpers_locked' && !c.ready)).toBe(true);
    await d.close();
  });

  it('verifier fails on a disabled guard trigger (test 22)', async () => {
    const d = await freshDb();
    await d.exec('ALTER TABLE public.qhub_agent_run_steps DISABLE TRIGGER trg_qhub_agent_run_step_guard;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'trigger.step_guard' && !c.ready)).toBe(true);
    await d.close();
  });

  it('verifier fails without the run-identity guard', async () => {
    const d = await freshDb();
    await d.exec('ALTER TABLE public.qhub_agent_runs DISABLE TRIGGER trg_qhub_agent_run_identity_guard;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'trigger.run_identity_guard' && !c.ready)).toBe(true);
    await d.close();
  });

  it('a second migration run is a true no-op (function + trigger OID/xmin stable) (tests 23, 24)', async () => {
    const d = await freshDb();
    const before = await d.query<{ proname: string; oid: string; xmin: string }>(
      `select proname, oid::text, xmin::text from pg_proc where proname like 'qhub_%agent%' or proname='qhub_verify_agent_schema'`,
    );
    const trgBefore = await d.query<{ tgname: string; oid: string; xmin: string }>(
      `select tgname, oid::text, xmin::text from pg_trigger where tgname like 'trg_qhub_agent%'`,
    );
    await d.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

    const after = await d.query<{ proname: string; oid: string; xmin: string }>(
      `select proname, oid::text, xmin::text from pg_proc where proname like 'qhub_%agent%' or proname='qhub_verify_agent_schema'`,
    );
    const trgAfter = await d.query<{ tgname: string; oid: string; xmin: string }>(
      `select tgname, oid::text, xmin::text from pg_trigger where tgname like 'trg_qhub_agent%'`,
    );
    expect(after.rows).toEqual(before.rows);
    expect(trgAfter.rows).toEqual(trgBefore.rows);
    expect((await verify(d)).ready).toBe(true);
    await d.close();
  });
});
