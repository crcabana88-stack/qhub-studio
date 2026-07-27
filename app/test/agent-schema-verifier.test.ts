/**
 * QHUB Agent Framework — metadata verifier (SQL) tests on real PostgreSQL (PGlite)
 * app/test/agent-schema-verifier.test.ts
 *
 * Proves qhub_verify_agent_schema() detects a missing table, unvalidated FK,
 * missing constraint/index, disabled RLS, missing policy, and broadened
 * browser-role privileges — and that Gate 04's verifier contract is unchanged.
 */

import { describe, it, expect } from 'vitest';
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

async function buildDb(mutation?: string): Promise<PGlite> {
  const db = new PGlite();
  await db.exec('CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;');

  for (const f of BASELINE) {
    await db.exec(readFileSync(MIG(f), 'utf8'));
  }

  if (mutation) {
    await db.exec(mutation);
  }

  return db;
}

async function verify(db: PGlite): Promise<{ ready: boolean; version: string; failing: string[] }> {
  const r = await db.query<{
    v: {
      expected_version: string;
      ready: boolean;
      checks: { identifier: string; ready: boolean; reason_code: string }[];
    };
  }>('select public.qhub_verify_agent_schema() v');
  const v = r.rows[0].v;

  return {
    ready: v.ready,
    version: v.expected_version,
    failing: v.checks.filter((c) => !c.ready).map((c) => `${c.identifier}:${c.reason_code}`),
  };
}

describe('qhub_verify_agent_schema (SQL / PGlite)', () => {
  it('reports READY with the expected version on a correct install (tests 1-11)', async () => {
    const db = await buildDb();
    const v = await verify(db);
    expect(v.version).toBe('2026-07-27.agent-foundation');
    expect(v.ready).toBe(true);
    expect(v.failing).toEqual([]);
  });

  it('fails readiness when a table is missing (tests 1-4)', async () => {
    const db = await buildDb('DROP TABLE public.qhub_agent_run_steps CASCADE;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.startsWith('table.qhub_agent_run_steps'))).toBe(true);
  });

  it('fails readiness when a foreign key is dropped (test 5)', async () => {
    const db = await buildDb('ALTER TABLE public.qhub_agent_versions DROP CONSTRAINT fk_av_agent;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.includes('foreign_keys_validated'))).toBe(true);
  });

  it('fails readiness when the idempotency index is dropped (test 7)', async () => {
    const db = await buildDb('DROP INDEX public.idx_agent_runs_idem;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.includes('run_idempotency_unique'))).toBe(true);
  });

  it('fails readiness when RLS is disabled (test 9)', async () => {
    const db = await buildDb('ALTER TABLE public.qhub_agents DISABLE ROW LEVEL SECURITY;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.includes('rls.enabled_all'))).toBe(true);
  });

  it('fails readiness when a restrictive policy is dropped (test 10)', async () => {
    const db = await buildDb('DROP POLICY qhub_agents_service_only ON public.qhub_agents;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.includes('policy.restrictive_service_only'))).toBe(true);
  });

  it('fails readiness when a browser role is granted access (test 11)', async () => {
    const db = await buildDb('GRANT SELECT ON public.qhub_agents TO anon;');
    const v = await verify(db);
    expect(v.ready).toBe(false);
    expect(v.failing.some((f) => f.includes('browser_roles_denied'))).toBe(true);
  });

  it('leaves the Gate 04 governance verifier contract unchanged (test 20)', async () => {
    const db = await buildDb();
    const g4 = await db.query<{ v: { expected_version: string; ready: boolean } }>(
      'select public.qhub_verify_governance_schema() v',
    );
    expect(g4.rows[0].v.expected_version).toBe('2026-07-26.gate04');
    expect(g4.rows[0].v.ready).toBe(true);
  });
});
