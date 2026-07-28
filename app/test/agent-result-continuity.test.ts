/**
 * QHUB Agent Framework — RESULT CONTINUITY contract on real PostgreSQL (PGlite)
 * app/test/agent-result-continuity.test.ts
 *
 * Exercises the database-enforced, server-owned terminalization + continuity
 * contract end to end: the qhub_finalize_agent_run_step RPC, the defensive +
 * immutability trigger, the previous-step hash chain, and the extended verifier.
 *
 * Required DB tests covered here: 1 (arbitrary caller hash), 4 (step-0 prev), 5
 * (null prev on later step), 6 (arbitrary prior hash), 7 (cross-run transplant),
 * 8 (cross-agent binding), 12 (terminalization without continuity), 13 (valid
 * first transition), 14 (idempotent repeat), 15 (materially different repeat),
 * 16-20 (immutability), 21 (guard fn not executable by browser roles), 22
 * (finalize RPC service-role-only), 23 (legacy non-resumable coexists), 24 (new
 * terminal writes), 25 (verifier failure modes), 26 (first migration), 27 (second
 * migration true no-op). Tests 2, 3, 9, 10, 11 live in the parity suites.
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

let db: PGlite;
let runCounter = 0;

function pgArray(items: string[]): string {
  return `{${items.map((i) => `"${i}"`).join(',')}}`;
}

async function seedRun(agentId = AGENT, versionId = VERSION): Promise<string> {
  runCounter += 1;

  const runId = `40000000-0000-0000-0000-${String(runCounter).padStart(12, '0')}`;
  await db.query(
    `insert into public.qhub_agent_runs
      (run_id, agent_id, agent_version_id, org_id, qhub_app_id, initiating_user_id, operating_mode,
       runtime_provider, runtime_provider_version, current_state, current_step, policy_profile_hash,
       enforcement_plan_hash, primary_model, input_hash, idempotency_key, run_hash)
     values ($1,$2,$3,$4,$5,'user_a','SUPERVISED','local-simulation','1.0.0','RUNNING',0,
             'pp_hash','ep_hash','model-x','ih_run',$6,'run_hash')`,
    [runId, agentId, versionId, ORG, APP, `idem_${runCounter}`],
  );

  return runId;
}

async function seedEvaluation(): Promise<string> {
  const evalId = `50000000-0000-0000-0000-${String(runCounter).padStart(12, '0')}`;
  const reqId = `51000000-0000-0000-0000-${String(runCounter).padStart(12, '0')}`;
  await db.query(
    `insert into public.qhub_control_evaluations
      (evaluation_id, action_request_id, org_id, qhub_app_id, action_type, action_digest, environment,
       decision, policy_profile_hash, enforcement_plan_hash, control_results_hash, evaluator_version, created_by)
     values ($1,$2,$3,$4,'CONNECTOR_ACTION','digest_x','INTERNAL','ALLOW','pp_hash','ep_hash','cr_hash','ev-1','user_a')`,
    [evalId, reqId, ORG, APP],
  );

  return evalId;
}

interface FinalizeArgs {
  step_index: number;
  step_kind?: string;
  action_type?: string | null;
  evaluation_id?: string | null;
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
      a.evaluation_id ?? null,
      a.decision ?? 'EXECUTED',
      pgArray(a.reason_codes ?? []),
      a.receipt_id === undefined ? 'rcpt_1' : a.receipt_id,
      a.input_hash === undefined ? 'ih_step' : a.input_hash,
      a.summary ?? 'a safe summary',
      JSON.stringify(a.safe_result ?? { execution_status: 'COMPLETED' }),
    ],
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
  await db.exec('CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;');

  for (const f of BASELINE) {
    await db.exec(readFileSync(MIG(f), 'utf8'));
  }
  await db.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

  // Minimal tenant graph: app → agent(+version) ×2.
  await db.query(`insert into public.qhub_applications (qhub_app_id, org_id, created_by) values ($1,$2,'user_a')`, [
    APP,
    ORG,
  ]);

  for (const [ag, ver, mh] of [
    [AGENT, VERSION, 'manifest_hash_1'],
    [AGENT2, VERSION2, 'manifest_hash_2'],
  ] as const) {
    await db.query(
      `insert into public.qhub_agents
        (agent_id, org_id, qhub_app_id, name, owner_user_id, current_operating_mode, risk_tier, created_by)
       values ($1,$2,$3,'agent','user_a','SUPERVISED','TIER_2','user_a')`,
      [ag, ORG, APP],
    );
    await db.query(
      `insert into public.qhub_agent_versions
        (agent_version_id, agent_id, org_id, qhub_app_id, manifest, manifest_hash, manifest_version,
         operating_mode, autonomy_level, risk_tier, policy_profile_hash, enforcement_plan_hash, created_by)
       values ($1,$2,$3,$4,'{}'::jsonb,$5,'1','SUPERVISED','L1','TIER_2','pp_hash','ep_hash','user_a')`,
      [ver, ag, ORG, APP, mh],
    );
  }
});

afterAll(async () => {
  await db.close();
});

describe('result-continuity: finalization RPC (tests 13, 14, 15, 24)', () => {
  it('finalizes a valid first terminal step and returns the authoritative hash (tests 13, 24)', async () => {
    const run = await seedRun();
    const out = await finalize(run, { step_index: 0 });
    expect(out.finalized).toBe(true);
    expect(out.idempotent).toBe(false);
    expect(out.previous_step_hash).toBeNull();
    expect(typeof out.result_hash).toBe('string');
    expect((out.result_hash as string).length).toBe(64);

    const row = await stepRow(run, 0);
    expect(row?.result_hash).toBe(out.result_hash);
    expect(row?.finalized_at).not.toBeNull();
    expect(row?.result_hash_schema_version).toBe('agent-step-result-1.0.0');
  });

  it('chains step 1 onto step 0 via previous_step_hash', async () => {
    const run = await seedRun();
    const s0 = await finalize(run, { step_index: 0 });
    const s1 = await finalize(run, { step_index: 1 });
    expect(s1.previous_step_hash).toBe(s0.result_hash);
  });

  it('is idempotent for an EXACT repeat finalization (test 14)', async () => {
    const run = await seedRun();
    const first = await finalize(run, { step_index: 0 });
    const again = await finalize(run, { step_index: 0 });
    expect(again.idempotent).toBe(true);
    expect(again.result_hash).toBe(first.result_hash);

    const count = await db.query<{ n: number }>(
      'select count(*)::int n from public.qhub_agent_run_steps where run_id=$1 and step_index=0',
      [run],
    );
    expect(count.rows[0].n).toBe(1);
  });

  it('rejects a materially different second finalization (test 15)', async () => {
    const run = await seedRun();
    await finalize(run, { step_index: 0, decision: 'EXECUTED' });
    await expect(finalize(run, { step_index: 0, decision: 'DENY', receipt_id: null })).rejects.toThrow(
      /already finalized with a different result/,
    );
  });

  it('rejects an invalid safe_result at the RPC boundary', async () => {
    const run = await seedRun();
    await expect(finalize(run, { step_index: 0, safe_result: { secret_token: 'x' } })).rejects.toThrow(
      /safe_result failed strict validation/,
    );
  });

  it('binds a valid Gate 04 evaluation and enforces its ownership', async () => {
    const run = await seedRun();
    const evalId = await seedEvaluation();
    const out = await finalize(run, { step_index: 0, evaluation_id: evalId });
    expect(out.finalized).toBe(true);

    const row = await stepRow(run, 0);
    expect(row?.evaluation_id).toBe(evalId);
  });
});

describe('result-continuity: previous-step hash chain (tests 4, 5, 6, 7)', () => {
  it('rejects a later step when the previous step is not finalized (test 5)', async () => {
    const run = await seedRun();
    await expect(finalize(run, { step_index: 1 })).rejects.toThrow(/previous step .* is missing or not finalized/);
  });

  it('step 0 must have a NULL previous_step_hash (test 4)', async () => {
    const run = await seedRun();

    // Craft a finalizing write (flag set) that violates the step-0 rule.
    await expect(
      db.exec(`DO $$
        BEGIN
          PERFORM set_config('qhub.allow_finalize','1',true);
          INSERT INTO public.qhub_agent_run_steps
            (run_id, org_id, step_index, step_kind, decision, reason_codes, receipt_id, input_hash, summary,
             safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
          VALUES ('${run}','${ORG}',0,'CONNECTOR_ACTION','EXECUTED','{}','rcpt','ih','s',
             '{"execution_status":"OK"}'::jsonb, 'deadbeef', 'x', 'agent-step-result-1.0.0', NOW());
        END $$;`),
    ).rejects.toThrow(/step 0 must have NULL previous_step_hash/);
  });

  it('rejects an arbitrary / transplanted prior hash on a later step (tests 6, 7)', async () => {
    const runA = await seedRun();
    const a0 = await finalize(runA, { step_index: 0 });
    const runB = await seedRun();
    await finalize(runB, { step_index: 0 });

    // Craft step 1 in run B whose previous_step_hash is run A's step-0 hash (transplant).
    await expect(
      db.exec(`DO $$
        BEGIN
          PERFORM set_config('qhub.allow_finalize','1',true);
          INSERT INTO public.qhub_agent_run_steps
            (run_id, org_id, step_index, step_kind, decision, reason_codes, receipt_id, input_hash, summary,
             safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
          VALUES ('${runB}','${ORG}',1,'CONNECTOR_ACTION','EXECUTED','{}','rcpt','ih','s',
             '{"execution_status":"OK"}'::jsonb, '${a0.result_hash}', 'x', 'agent-step-result-1.0.0', NOW());
        END $$;`),
    ).rejects.toThrow(/previous_step_hash does not match the prior finalized step/);
  });
});

describe('result-continuity: cross-agent binding (test 8)', () => {
  it('identical step inputs under a different agent/version produce a different hash', async () => {
    const runA = await seedRun(AGENT, VERSION);
    const runB = await seedRun(AGENT2, VERSION2);
    const a = await finalize(runA, { step_index: 0, input_hash: 'same', receipt_id: 'same', summary: 'same' });
    const b = await finalize(runB, { step_index: 0, input_hash: 'same', receipt_id: 'same', summary: 'same' });
    expect(a.result_hash).not.toBe(b.result_hash);
  });
});

describe('result-continuity: defensive trigger (tests 1, 12)', () => {
  it('rejects an arbitrary caller-supplied result_hash outside the RPC path (test 1)', async () => {
    const run = await seedRun();
    await db.query(
      `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary)
       values ($1,$2,0,'CONNECTOR_ACTION','REQUIRE_APPROVAL','pending')`,
      [run, ORG],
    );
    await expect(
      db.query(`update public.qhub_agent_run_steps set result_hash='deadbeef' where run_id=$1 and step_index=0`, [run]),
    ).rejects.toThrow(/terminalization is only permitted via qhub_finalize_agent_run_step/);
  });

  it('rejects continuity fields on a non-finalizing write (test 12)', async () => {
    const run = await seedRun();
    await expect(
      db.query(
        `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary, safe_result)
         values ($1,$2,0,'CONNECTOR_ACTION','ALLOW','s','{"execution_status":"OK"}'::jsonb)`,
        [run, ORG],
      ),
    ).rejects.toThrow(/continuity fields require finalization/);
  });

  it('allows a legacy / pending step with no continuity fields (test 23 coexistence)', async () => {
    const run = await seedRun();
    await db.query(
      `insert into public.qhub_agent_run_steps (run_id, org_id, step_index, step_kind, decision, summary)
       values ($1,$2,0,'CONNECTOR_ACTION','REQUIRE_APPROVAL','pending')`,
      [run, ORG],
    );

    const row = await stepRow(run, 0);
    expect(row?.result_hash).toBeNull();
    expect(row?.safe_result).toBeNull();
  });
});

describe('result-continuity: terminal immutability (tests 16-20)', () => {
  const protectedUpdates: Array<[string, string]> = [
    ['step_index', 'update public.qhub_agent_run_steps set step_index=99 where run_id=$1 and step_index=0'],
    [
      'run_id',
      `update public.qhub_agent_run_steps set run_id='40000000-0000-0000-0000-000000009999' where run_id=$1 and step_index=0`,
    ],
    [
      'evaluation_id',
      `update public.qhub_agent_run_steps set evaluation_id='50000000-0000-0000-0000-0000000000ff' where run_id=$1 and step_index=0`,
    ],
    ['receipt_id', `update public.qhub_agent_run_steps set receipt_id='other' where run_id=$1 and step_index=0`],
    [
      'safe_result',
      `update public.qhub_agent_run_steps set safe_result='{"execution_status":"TAMPERED"}'::jsonb where run_id=$1 and step_index=0`,
    ],
    ['result_hash', `update public.qhub_agent_run_steps set result_hash='00' where run_id=$1 and step_index=0`],
    [
      'previous_step_hash',
      `update public.qhub_agent_run_steps set previous_step_hash='00' where run_id=$1 and step_index=0`,
    ],
  ];

  for (const [field, sql] of protectedUpdates) {
    it(`rejects mutation of terminal ${field} (tests 16-20)`, async () => {
      const run = await seedRun();
      await finalize(run, { step_index: 0 });
      await expect(db.query(sql, [run])).rejects.toThrow(/finalized step is immutable/);
    });
  }
});

describe('result-continuity: privileges (tests 21, 22)', () => {
  it('the guard trigger function is not executable by browser roles (test 21)', async () => {
    const r = await db.query<{ anon: boolean; auth: boolean }>(
      `select has_function_privilege('anon','public.qhub_agent_run_step_guard()','EXECUTE') anon,
              has_function_privilege('authenticated','public.qhub_agent_run_step_guard()','EXECUTE') auth`,
    );
    expect(r.rows[0].anon).toBe(false);
    expect(r.rows[0].auth).toBe(false);
  });

  it('the finalization RPC is service-role-only (test 22)', async () => {
    const sig = 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)';
    const r = await db.query<{ anon: boolean; auth: boolean; svc: boolean }>(
      `select has_function_privilege('anon','${sig}','EXECUTE') anon,
              has_function_privilege('authenticated','${sig}','EXECUTE') auth,
              has_function_privilege('service_role','${sig}','EXECUTE') svc`,
    );
    expect(r.rows[0].anon).toBe(false);
    expect(r.rows[0].auth).toBe(false);
    expect(r.rows[0].svc).toBe(true);
  });
});

describe('result-continuity: verifier failure modes + no-op (tests 25, 26, 27)', () => {
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
    await d.exec('CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;');

    for (const f of BASELINE) {
      await d.exec(readFileSync(MIG(f), 'utf8'));
    }
    await d.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

    return d;
  }

  it('reports READY at the continuity version on a correct install (test 26)', async () => {
    const v = await verify(db);
    expect(v.expected_version).toBe('2026-07-28.agent-result-continuity');
    expect(v.ready).toBe(true);
  });

  it('fails readiness when the guard trigger is disabled (test 25)', async () => {
    const d = await freshDb();
    await d.exec('ALTER TABLE public.qhub_agent_run_steps DISABLE TRIGGER trg_qhub_agent_run_step_guard;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'trigger.step_guard' && !c.ready)).toBe(true);
    await d.close();
  });

  it('fails readiness when the finalize RPC is exposed to a browser role (test 25)', async () => {
    const d = await freshDb();
    await d.exec(
      `GRANT EXECUTE ON FUNCTION public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb) TO anon;`,
    );

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'function.finalize_rpc' && !c.ready)).toBe(true);
    await d.close();
  });

  it('fails readiness when the unique result-hash index is dropped (test 25)', async () => {
    const d = await freshDb();
    await d.exec('DROP INDEX public.idx_agent_run_steps_run_result;');

    const v = await verify(d);
    expect(v.ready).toBe(false);
    expect(v.checks.some((c) => c.identifier === 'index.step_result_unique' && !c.ready)).toBe(true);
    await d.close();
  });

  it('a second migration run is a true no-op with a stable trigger identity (test 27)', async () => {
    const d = await freshDb();
    const before = await d.query<{ oid: number }>(
      `select oid from pg_trigger where tgname='trg_qhub_agent_run_step_guard'`,
    );
    await d.exec(readFileSync(MIG(CONTINUITY), 'utf8'));

    const after = await d.query<{ oid: number }>(
      `select oid from pg_trigger where tgname='trg_qhub_agent_run_step_guard'`,
    );
    expect(after.rows[0].oid).toBe(before.rows[0].oid);

    const v = await verify(d);
    expect(v.ready).toBe(true);
    await d.close();
  });
});
