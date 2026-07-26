import { readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const baselineMigrationUrls = [
  new URL('../../supabase/migrations/20260723_qhub_applications.sql', import.meta.url),
  new URL('../../supabase/migrations/20260725_qhub_classification.sql', import.meta.url),
  new URL('../../supabase/migrations/20260725_gate03_policy.sql', import.meta.url),
  new URL('../../supabase/migrations/20260726_gate04_enforcement.sql', import.meta.url),
];
const migrationUrl = new URL(
  '../../supabase/migrations/20260726_gate04_schema_assurance_approval_cleanup.sql',
  import.meta.url,
);
const sql = readFileSync(migrationUrl, 'utf8');

describe('Gate 04 schema-assurance migration', () => {
  it('compiles every DO/function body and completes self-verification in PostgreSQL', async () => {
    const db = new PGlite();

    try {
      await db.exec(`
          CREATE ROLE anon NOLOGIN;
          CREATE ROLE authenticated NOLOGIN;
          CREATE ROLE service_role NOLOGIN BYPASSRLS;
        `);

      for (const migration of baselineMigrationUrls) {
        await db.exec(readFileSync(migration, 'utf8'));
      }

      await expect(
        db.exec(`
            DO $$
            BEGIN
              SELECT '{}'::jsonb INTO undeclared_readiness;
            END
            $$;
          `),
      ).rejects.toThrow(/not a known variable/i);

      await expect(db.exec(sql)).resolves.toBeDefined();
      await expect(db.exec(sql)).resolves.toBeDefined();

      const result = await db.query<{
        expected_version: string;
        ready: boolean;
      }>(`
          SELECT
            verification->>'expected_version' AS expected_version,
            (verification->>'ready')::boolean AS ready
          FROM (
            SELECT public.qhub_verify_governance_schema() AS verification
          ) verified
        `);

      expect(result.rows).toEqual([
        {
          expected_version: '2026-07-26.gate04',
          ready: true,
        },
      ]);
    } finally {
      await db.close();
    }
  }, 60_000);

  it('contains only the explicitly authorized two-row cleanup', () => {
    const deleteStatements = sql.match(/^\s*DELETE\s+FROM\b.*$/gim) ?? [];
    expect(deleteStatements).toHaveLength(1);
    expect(deleteStatements[0]).toMatch(/DELETE FROM public\.qhub_control_approvals approval/i);
    expect(sql).toContain('623f674d-c58f-47fc-a385-faa4f758ae69');
    expect(sql).toContain('89b48d61-c70e-44bc-9fe2-cfe0189cf73a');
    expect(sql).toContain('expected to delete exactly two rows');
    expect(sql).toContain('present_count NOT IN (0, 2)');
    expect(sql).not.toMatch(/^\s*(DROP|TRUNCATE)\b/im);
    expect(sql).not.toMatch(/ALTER\s+(TABLE|TYPE)[\s\S]{0,120}\b(DROP|RENAME|TYPE\s+)\b/i);
    expect(sql).not.toMatch(
      /^\s*UPDATE\s+(?!public\.qhub_(enforcement_plans|control_evaluations|control_approvals))/im,
    );
  });

  it('repairs only exact plan identity mismatches and proves zero orphans', () => {
    const repair = sql.slice(0, sql.indexOf('-- ─── Ownership and state integrity'));
    expect(repair).toContain("SET enforcement_plan_id = (ep.plan->>'enforcement_plan_id')::uuid");
    expect(sql).toContain('orphan_count <> mapped_orphan_count');
    expect(sql).toContain('orphan enforcement plan reference remains');
    expect(repair).not.toMatch(/UPDATE\s+public\.qhub_control_evaluations/i);
    expect(sql).toMatch(/\bBEGIN;\s*[\s\S]*\bCOMMIT;/i);
  });

  it('fails closed on cleanup provenance, ownership, consumption, side-effect, and dependency drift', () => {
    for (const assertion of [
      "approval.org_id <> 'other-org-live'",
      "approval.attestation_type <> 'OWNER_ATTESTATION'",
      "approval.status <> 'GRANTED'",
      "approval.created_by <> 'seed'",
      'approval.consumed_by_evaluation IS NOT NULL',
      'approval.consumed_at IS NOT NULL',
      'approval.expires_at >= clock_timestamp()',
      "app.org_id = 'client-smoke'",
      "app.org_id = 'other-org-live'",
      'authorized approval may precede a successful action',
      "fk.confrelid = 'public.qhub_control_approvals'::regclass",
      'approval identifier appears in %.%.%',
      'approval tenant/app orphans remain',
    ]) {
      expect(sql).toContain(assertion);
    }
  });

  it('aborts on dependent old ids, ambiguous mappings, collisions, or provenance mismatch', () => {
    expect(sql).toContain("fk.confrelid = 'public.qhub_enforcement_plans'::regclass");
    expect(sql).toContain("column_name = 'enforcement_plan_id'");
    expect(sql).toContain('orphan does not have exactly one candidate plan');
    expect(sql).toContain('intended enforcement plan id already exists');
    expect(sql).toContain('tenant, app, policy, hash, version, or compiler binding mismatch');
    expect(sql).toContain("ep.plan->>'compiler_version' <> repair.compiler_version");
    expect(sql).toContain("ep.plan->>'policy_catalog_version' <> repair.policy_catalog_version");
  });

  it('defines a metadata-only verifier with a fixed search path', () => {
    const start = sql.indexOf('CREATE OR REPLACE FUNCTION public.qhub_verify_governance_schema');
    const end = sql.indexOf('REVOKE ALL ON FUNCTION public.qhub_verify_governance_schema');
    const verifier = sql.slice(start, end);
    expect(verifier).toContain('RETURNS JSONB');
    expect(verifier).toContain('LANGUAGE sql');
    expect(verifier).toContain('STABLE');
    expect(verifier).toContain('SET search_path = pg_catalog, public');
    expect(verifier).not.toMatch(/^\s*(INSERT|UPDATE|DELETE|TRUNCATE|DROP)\b/im);
    expect(verifier).not.toContain('EXECUTE ');
  });

  it('keeps verifier and transition functions service-role-only', () => {
    for (const signature of [
      'qhub_verify_governance_schema()',
      'qhub_claim_control_evaluation(UUID, TEXT)',
      'qhub_consume_control_approvals(UUID, TEXT, TEXT, UUID)',
    ]) {
      expect(sql).toContain(`REVOKE ALL ON FUNCTION public.${signature} FROM PUBLIC`);
      expect(sql).toContain(`REVOKE ALL ON FUNCTION public.${signature} FROM anon`);
      expect(sql).toContain(`REVOKE ALL ON FUNCTION public.${signature} FROM authenticated`);
      expect(sql).toContain(`GRANT EXECUTE ON FUNCTION public.${signature} TO service_role`);
    }
  });

  it('certifies constraints, exact index shapes, RLS, policies, and required functions', () => {
    for (const category of ['CONSTRAINT', 'INDEX', 'RLS_ENABLED', 'RLS_POLICY', 'FUNCTION']) {
      expect(sql).toContain(`'${category}'`);
    }
    expect(sql).toContain('pg_get_expr(i.indpred, i.indrelid)');
    expect(sql).toContain('ck_ce_claim_consistency');
    expect(sql).toContain('ck_ca_consumption_consistency');
    expect(sql).toContain('policy.no_broad_client_access');
    expect(sql).toContain("'expected_version', '2026-07-26.gate04'");
    expect(sql).toContain('VALIDATE CONSTRAINT fk_ca_tenant_app');
    expect(sql).toContain('metadata self-verification is not ready');
  });
});
