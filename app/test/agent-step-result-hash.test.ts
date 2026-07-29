/**
 * QHUB Agent Framework — canonical STEP RESULT HASH: TS↔SQL parity + sensitivity
 * app/test/agent-step-result-hash.test.ts
 *
 * Proves the TypeScript canonical hash (step-result-hash.ts) is byte-identical to
 * the PostgreSQL qhub_agent_step_result_hash(...) for shared fixtures, and that
 * changing ANY material field changes the hash. Runs on real PostgreSQL (PGlite).
 *
 * Covers required DB tests 2 (TS/PG parity) and 3 (per-field sensitivity).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  canonicalStepResultString,
  computeStepResultHash,
  type StepResultHashInput,
} from '~/lib/qhub/agent/runtime/step-result-hash';
import { canonicalSafeResult, type SafeResult } from '~/lib/qhub/agent/runtime/safe-result';

const MIG = (f: string) => fileURLToPath(new URL(`../../supabase/migrations/${f}`, import.meta.url));
const MIGRATIONS = [
  '20260723_qhub_applications.sql',
  '20260725_gate03_policy.sql',
  '20260725_qhub_classification.sql',
  '20260726_gate04_enforcement.sql',
  '20260726_gate04_schema_assurance_approval_cleanup.sql',
  '20260727_gate05_attestation.sql',
  '20260727_agent_framework_foundation.sql',
  '20260728_agent_run_step_result_continuity.sql',
];

let db: PGlite;

beforeAll(async () => {
  db = new PGlite();
  await db.exec('CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;');

  for (const f of MIGRATIONS) {
    await db.exec(readFileSync(MIG(f), 'utf8'));
  }
});

afterAll(async () => {
  await db.close();
});

/** Call the SQL canonical hash with EXACTLY the TS field set. */
async function sqlHash(f: StepResultHashInput): Promise<string> {
  const r = await db.query<{ h: string }>(
    `select qhub_private.qhub_agent_step_result_hash(
       $1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,$10::text,
       $11::int,$12::text,$13::text,$14::text,$15::text,$16::text,$17::text,$18::text,$19::text,$20::int,
       $21::text,$22::text,$23::int,$24::text,$25::text,$26::jsonb,$27::text) h`,
    [
      f.org_id,
      f.qhub_app_id,
      f.agent_id,
      f.agent_version_id,
      f.release_candidate_id,
      f.release_candidate_hash,
      f.manifest_hash,
      f.run_id,
      f.runtime_provider_id,
      f.runtime_provider_version,
      f.step_index,
      f.step_kind,
      f.action_type,
      f.input_hash,
      f.decision,
      f.evaluation_id,
      f.action_request_id,
      f.action_digest,
      f.policy_profile_id,
      f.policy_profile_version,
      f.policy_profile_hash,
      f.enforcement_plan_id,
      f.enforcement_plan_version,
      f.enforcement_plan_hash,
      f.receipt_id,
      f.safe_result === null ? null : JSON.stringify(f.safe_result),
      f.previous_step_hash,
    ],
  );

  return r.rows[0].h;
}

const fullSafe: SafeResult = {
  execution_status: 'COMPLETED',
  safe_metadata: { outcome: 'OK', record_count: 3, truncated: false },
};

const base: StepResultHashInput = {
  org_id: 'org_alpha',
  qhub_app_id: '11111111-1111-1111-1111-111111111111',
  agent_id: '22222222-2222-2222-2222-222222222222',
  agent_version_id: '33333333-3333-3333-3333-333333333333',
  release_candidate_id: '44444444-4444-4444-4444-444444444444',
  release_candidate_hash: 'rc_hash_aaa',
  manifest_hash: 'manifest_hash_bbb',
  run_id: '55555555-5555-5555-5555-555555555555',
  runtime_provider_id: 'local-simulation',
  runtime_provider_version: '1.0.0',
  step_index: 1,
  step_kind: 'CONNECTOR_ACTION',
  action_type: 'CONNECTOR_ACTION',
  input_hash: 'input_hash_ccc',
  decision: 'EXECUTED',
  evaluation_id: '66666666-6666-6666-6666-666666666666',
  action_request_id: '77777777-7777-7777-7777-777777777777',
  action_digest: 'digest_ddd',
  policy_profile_id: '88888888-8888-8888-8888-888888888888',
  policy_profile_version: 2,
  policy_profile_hash: 'pp_hash_eee',
  enforcement_plan_id: '99999999-9999-9999-9999-999999999999',
  enforcement_plan_version: 5,
  enforcement_plan_hash: 'ep_hash_fff',
  receipt_id: 'receipt_ggg',
  safe_result: fullSafe,
  previous_step_hash: 'a'.repeat(64),
};

// A fixture that exercises the null branches of every optional field + step 0.
const nullsAtStepZero: StepResultHashInput = {
  ...base,
  step_index: 0,
  action_type: null,
  input_hash: null,
  decision: 'DENY',
  evaluation_id: null,
  action_request_id: null,
  action_digest: null,
  policy_profile_id: null,
  policy_profile_version: null,
  policy_profile_hash: null,
  enforcement_plan_id: null,
  enforcement_plan_version: null,
  enforcement_plan_hash: null,
  receipt_id: null,
  release_candidate_id: null,
  release_candidate_hash: null,
  safe_result: { execution_status: null },
  previous_step_hash: null,
};

describe('canonical step-result hash — TS↔SQL parity (tests 2, 3)', () => {
  it('TS and PostgreSQL agree on a fully-populated fixture (test 2)', async () => {
    expect(await sqlHash(base)).toBe(computeStepResultHash(base));
  });

  it('TS and PostgreSQL agree on the all-nulls / step-0 fixture (test 2)', async () => {
    expect(await sqlHash(nullsAtStepZero)).toBe(computeStepResultHash(nullsAtStepZero));
  });

  it('changing ANY material field changes the hash — TS and SQL both (test 3)', async () => {
    const baseHash = computeStepResultHash(base);
    expect(await sqlHash(base)).toBe(baseHash);

    const mutations: Array<Partial<StepResultHashInput>> = [
      { org_id: 'org_beta' },
      { qhub_app_id: '11111111-1111-1111-1111-111111111112' },
      { agent_id: '22222222-2222-2222-2222-222222222223' },
      { agent_version_id: '33333333-3333-3333-3333-333333333334' },
      { release_candidate_id: null },
      { release_candidate_hash: 'rc_hash_zzz' },
      { manifest_hash: 'manifest_hash_zzz' },
      { run_id: '55555555-5555-5555-5555-555555555556' },
      { runtime_provider_id: 'langgraph' },
      { runtime_provider_version: '2.0.0' },
      { step_index: 2 },
      { step_kind: 'TOOL_ACTION' },
      { action_type: 'TOOL_ACTION' },
      { input_hash: 'input_hash_zzz' },
      { decision: 'ALLOW' },
      { evaluation_id: '66666666-6666-6666-6666-666666666667' },
      { action_request_id: '77777777-7777-7777-7777-777777777778' },
      { action_digest: 'digest_zzz' },
      { policy_profile_id: '88888888-8888-8888-8888-888888888889' },
      { policy_profile_version: 3 },
      { policy_profile_hash: 'pp_hash_zzz' },
      { enforcement_plan_id: '99999999-9999-9999-9999-999999999990' },
      { enforcement_plan_version: 6 },
      { enforcement_plan_hash: 'ep_hash_zzz' },
      { receipt_id: 'receipt_zzz' },
      {
        safe_result: {
          execution_status: 'COMPLETED',
          safe_metadata: { outcome: 'OK', record_count: 4, truncated: false },
        },
      },
      { previous_step_hash: 'b'.repeat(64) },
    ];

    for (const m of mutations) {
      const mutated = { ...base, ...m };
      const tsHash = computeStepResultHash(mutated);
      expect(tsHash, `TS: mutation ${JSON.stringify(m)} did not change the hash`).not.toBe(baseHash);
      expect(await sqlHash(mutated), `SQL parity for mutation ${JSON.stringify(m)}`).toBe(tsHash);
    }
  });

  it('a present-null metadata key differs from an absent key (canonical safe result)', async () => {
    const withNull: SafeResult = { execution_status: 'COMPLETED', safe_metadata: { truncated: null } };
    const withAbsent: SafeResult = { execution_status: 'COMPLETED' };
    expect(canonicalSafeResult(withNull)).not.toBe(canonicalSafeResult(withAbsent));

    const a = { ...base, safe_result: withNull };
    const b = { ...base, safe_result: withAbsent };
    expect(computeStepResultHash(a)).not.toBe(computeStepResultHash(b));
    expect(await sqlHash(a)).toBe(computeStepResultHash(a));
    expect(await sqlHash(b)).toBe(computeStepResultHash(b));
  });

  it('exposes the canonical preimage for auditing', () => {
    expect(canonicalStepResultString(nullsAtStepZero)).toContain('-1:;');
    expect(canonicalStepResultString(base).startsWith('23:agent-step-result-1.0.0;')).toBe(true);
  });
});
