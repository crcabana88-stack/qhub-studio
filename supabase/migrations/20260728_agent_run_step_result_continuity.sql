-- QHUB Agent Framework — authoritative run-step RESULT CONTINUITY (additive)
-- supabase/migrations/20260728_agent_run_step_result_continuity.sql
--
-- Persists the authoritative safe result, result hash, and prior-step hash chain
-- for each completed run step, so resume reconstruction uses PERSISTED result
-- continuity (not a deterministic re-derivation placeholder). Additive and
-- idempotent: safe to re-run; existing (legacy) rows keep NULLs and are treated
-- as non-resumable-for-continuity by the runtime (fail closed) — no backfill of
-- fabricated results. Service-role-only access + RESTRICTIVE RLS are inherited
-- from the base table and re-asserted. No DROP/TRUNCATE/DELETE/destructive ALTER.

BEGIN;

-- 1. Additive columns (no defaults that rewrite the table; nullable for legacy).
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS result_hash        TEXT;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS safe_result        JSONB;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS previous_step_hash TEXT;

-- 2. Immutability: once a step reaches a TERMINAL decision, its result-continuity
--    fields (and receipt) may never be altered. Prevents post-terminal tampering.
CREATE OR REPLACE FUNCTION public.qhub_agent_run_step_result_immutable()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.decision IN ('ALLOW','DENY','SIMULATED','EXECUTED') THEN
    IF NEW.result_hash        IS DISTINCT FROM OLD.result_hash
       OR NEW.safe_result        IS DISTINCT FROM OLD.safe_result
       OR NEW.previous_step_hash IS DISTINCT FROM OLD.previous_step_hash
       OR NEW.receipt_id         IS DISTINCT FROM OLD.receipt_id
       OR NEW.decision           IS DISTINCT FROM OLD.decision
       OR NEW.input_hash         IS DISTINCT FROM OLD.input_hash THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: terminal step result is immutable (step_id=%)', OLD.step_id;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_agent_run_step_result_immutable ON public.qhub_agent_run_steps;
CREATE TRIGGER trg_agent_run_step_result_immutable
  BEFORE UPDATE ON public.qhub_agent_run_steps
  FOR EACH ROW EXECUTE FUNCTION public.qhub_agent_run_step_result_immutable();

-- 3. Index to walk the per-run hash chain efficiently.
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_prev_hash
  ON public.qhub_agent_run_steps (run_id, previous_step_hash);

-- 4. Re-assert RESTRICTIVE service-only RLS + grants (inherited; idempotent).
ALTER TABLE public.qhub_agent_run_steps ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_agent_run_steps'::regclass
      AND polname = 'qhub_agent_run_steps_service_only'
  ) THEN
    CREATE POLICY qhub_agent_run_steps_service_only ON public.qhub_agent_run_steps
      AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
END $$;
REVOKE ALL ON TABLE public.qhub_agent_run_steps FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agent_run_steps TO service_role;

-- 5. Schema verifier: EXTEND the base verifier — every base check is preserved;
--    the run-step contract now requires the 3 result-continuity columns (count 14)
--    plus the immutability trigger, and the expected version is bumped so the
--    runtime/predeploy readiness check fails closed until this migration applies.
CREATE OR REPLACE FUNCTION public.qhub_verify_agent_schema()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
WITH agent_tables(name) AS (
  VALUES ('qhub_agents'), ('qhub_agent_versions'), ('qhub_agent_runs'), ('qhub_agent_run_steps')
),
fk_count AS (
  SELECT count(*) AS n
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
  WHERE c.contype = 'f' AND n.nspname = 'public'
    AND t.relname IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
    AND c.convalidated
),
checks(identifier, category, ready, reason_code) AS (
  VALUES
    ('table.qhub_agents', 'TABLE', to_regclass('public.qhub_agents') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_versions', 'TABLE', to_regclass('public.qhub_agent_versions') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_runs', 'TABLE', to_regclass('public.qhub_agent_runs') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_run_steps', 'TABLE', to_regclass('public.qhub_agent_run_steps') IS NOT NULL, 'TABLE_MISSING'),

    ('column.agents_contract', 'COLUMN', (
      SELECT count(*) = 14 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agents'
        AND column_name = ANY(ARRAY['agent_id','org_id','qhub_app_id','name','owner_user_id','owning_team',
          'current_version_id','current_lifecycle_state','current_operating_mode','risk_tier',
          'kill_switch_active','created_by','created_at','updated_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.versions_contract', 'COLUMN', (
      SELECT count(*) = 17 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_versions'
        AND column_name = ANY(ARRAY['agent_version_id','agent_id','org_id','qhub_app_id','manifest','manifest_hash',
          'manifest_version','operating_mode','autonomy_level','risk_tier','policy_profile_hash','enforcement_plan_hash',
          'release_candidate_id','release_candidate_hash','deployment_decision_id','frozen','created_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.runs_contract', 'COLUMN', (
      SELECT count(*) = 24 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_runs'
        AND column_name = ANY(ARRAY['run_id','agent_id','agent_version_id','org_id','qhub_app_id','release_candidate_id',
          'release_candidate_hash','initiating_user_id','operating_mode','runtime_provider','runtime_provider_version',
          'current_state','current_step','policy_profile_hash','enforcement_plan_hash','primary_model','input_hash',
          'output_hash','proposed_action_count','idempotency_key','pending_evaluation_id','error_reference','run_hash','started_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    -- Run-step contract now REQUIRES the 3 result-continuity columns (14 named).
    ('column.steps_contract', 'COLUMN', (
      SELECT count(*) = 14 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND column_name = ANY(ARRAY['step_id','run_id','org_id','step_index','step_kind','action_type',
          'evaluation_id','decision','reason_codes','input_hash','summary',
          'result_hash','safe_result','previous_step_hash'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),

    ('constraint.foreign_keys_validated', 'CONSTRAINT', (SELECT n = 13 FROM fk_count), 'FK_MISSING_OR_UNVALIDATED'),

    ('constraint.lifecycle_state_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agents' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_lifecycle_state%'
    ), 'CONSTRAINT_MISSING'),
    ('constraint.run_state_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_runs' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_state%'
    ), 'CONSTRAINT_MISSING'),
    ('constraint.step_decision_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_run_steps' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%decision%'
    ), 'CONSTRAINT_MISSING'),
    -- New: terminal-step result immutability trigger must exist.
    ('trigger.step_result_immutable', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname = 'trg_agent_run_step_result_immutable'
    ), 'TRIGGER_MISSING'),

    ('index.version_content_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_versions_hash' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.run_idempotency_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_runs_idem' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_index_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_run_steps_run_index' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),

    ('rls.enabled_all', 'RLS_ENABLED', (
      SELECT count(*) = 4 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      JOIN agent_tables a ON a.name = t.relname
      WHERE n.nspname='public' AND t.relrowsecurity
    ), 'RLS_DISABLED'),

    ('policy.restrictive_service_only', 'RLS_POLICY', (
      SELECT count(*) = 4 FROM pg_policy p JOIN pg_class t ON t.oid=p.polrelid
      JOIN agent_tables a ON a.name = t.relname
      WHERE p.polpermissive = FALSE
    ), 'POLICY_MISSING_OR_PERMISSIVE'),

    ('privilege.browser_roles_denied', 'FUNCTION', (
      SELECT count(*) = 0 FROM information_schema.role_table_grants
      WHERE table_schema='public' AND grantee IN ('PUBLIC','anon','authenticated')
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
    ), 'BROWSER_PRIVILEGE_BROADENED'),
    ('privilege.service_role_scoped', 'FUNCTION', (
      SELECT count(*) = 12 FROM information_schema.role_table_grants
      WHERE table_schema='public' AND grantee='service_role'
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
        AND privilege_type IN ('SELECT','INSERT','UPDATE')
    ), 'SERVICE_ROLE_PRIVILEGE_MISMATCH'),

    ('function.agent_verifier', 'FUNCTION',
      to_regprocedure('public.qhub_verify_agent_schema()') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid = 'public.qhub_verify_agent_schema()'::regprocedure)
      AND NOT has_function_privilege('anon', 'public.qhub_verify_agent_schema()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'public.qhub_verify_agent_schema()', 'EXECUTE')
      AND has_function_privilege('service_role', 'public.qhub_verify_agent_schema()', 'EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED')
),
normalized AS (
  SELECT identifier, category, ready, CASE WHEN ready THEN 'OK' ELSE reason_code END AS reason_code
  FROM checks
)
SELECT jsonb_build_object(
  'expected_version', '2026-07-28.agent-result-continuity',
  'ready', bool_and(ready),
  'checks', jsonb_agg(
    jsonb_build_object('identifier', identifier, 'category', category, 'ready', ready, 'reason_code', reason_code)
    ORDER BY category, identifier
  )
)
FROM normalized
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_agent_schema() TO service_role;

COMMIT;
