-- QHUB Agent Framework Foundation — durable agent registry, versions, runs, steps
-- Migration: 20260727_agent_framework_foundation
--
-- Additive + idempotent. Introduces the minimum durable foundation for governed
-- agents. Mutable lifecycle state (qhub_agents) is separated from immutable
-- version content (qhub_agent_versions). Runs + steps are the observable,
-- Gate-04-governed execution record. Security invariants are DB-enforced:
--   - one immutable version per (agent, manifest_hash) — content identity
--   - one run per (agent_version, idempotency_key) — replay safety
--   - one step per (run, step_index)
--   - tenant/app + release-candidate foreign keys, all validated
--   - service-role-only: browser roles (anon, authenticated) denied by a
--     RESTRICTIVE RLS policy and hold no table grants
--
-- Does NOT modify or weaken any Gate 01–05 object. Run ONCE in the Supabase SQL
-- editor (project jsjsanmaahvmynblmzkq).

BEGIN;

-- ─── 0. Required parents ─────────────────────────────────────────────────────
DO $$
BEGIN
  IF to_regclass('public.qhub_applications') IS NULL
     OR to_regclass('public.qhub_enforcement_plans') IS NULL
     OR to_regclass('public.qhub_release_candidates') IS NULL THEN
    RAISE EXCEPTION 'Agent foundation aborted: a required Gate 01–05 parent table is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relname = 'idx_qhub_apps_org_app' AND i.indisunique
  ) THEN
    RAISE EXCEPTION 'Agent foundation aborted: unique (org_id, qhub_app_id) index on qhub_applications is missing';
  END IF;
END
$$;

-- ─── 1. Agents (mutable lifecycle + identity) ────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_agents (
  agent_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                  TEXT NOT NULL,
  qhub_app_id             UUID NOT NULL,
  name                    TEXT NOT NULL,
  owner_user_id           TEXT NOT NULL,
  owning_team             TEXT,
  current_version_id      UUID,
  current_lifecycle_state TEXT NOT NULL DEFAULT 'DRAFT'
                          CHECK (current_lifecycle_state IN ('DRAFT','SIMULATION','SUPERVISED','ACTIVE','SUSPENDED','RETIRED')),
  current_operating_mode  TEXT NOT NULL,
  risk_tier               TEXT NOT NULL,
  kill_switch_active      BOOLEAN NOT NULL DEFAULT FALSE,
  created_by              TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agents_org ON qhub_agents (org_id);
CREATE INDEX IF NOT EXISTS idx_agents_org_app ON qhub_agents (org_id, qhub_app_id);
CREATE INDEX IF NOT EXISTS idx_agents_current_version ON qhub_agents (current_version_id);
-- Tenant-scoped identity used as a composite FK target for children.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_org_agent ON qhub_agents (org_id, agent_id);

-- ─── 2. Agent versions (immutable content) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_agent_versions (
  agent_version_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id                UUID NOT NULL,
  org_id                  TEXT NOT NULL,
  qhub_app_id             UUID NOT NULL,
  manifest                JSONB NOT NULL,
  manifest_hash           TEXT NOT NULL,
  manifest_version        TEXT NOT NULL,
  operating_mode          TEXT NOT NULL,
  autonomy_level          TEXT NOT NULL,
  risk_tier               TEXT NOT NULL,
  policy_profile_hash     TEXT NOT NULL,
  enforcement_plan_hash   TEXT NOT NULL,
  release_candidate_id    UUID,
  release_candidate_hash  TEXT,
  deployment_decision_id  UUID,
  frozen                  BOOLEAN NOT NULL DEFAULT FALSE,
  created_by              TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_versions_agent ON qhub_agent_versions (agent_id);
-- Content identity: one immutable version per (agent, manifest_hash).
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_versions_hash ON qhub_agent_versions (agent_id, manifest_hash);
-- Tenant-scoped identity used as a composite FK target for runs.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_versions_org_version ON qhub_agent_versions (org_id, agent_version_id);

-- ─── 3. Agent runs ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_agent_runs (
  run_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id                 UUID NOT NULL,
  agent_version_id         UUID NOT NULL,
  org_id                   TEXT NOT NULL,
  qhub_app_id              UUID NOT NULL,
  release_candidate_id     UUID,
  release_candidate_hash   TEXT,
  initiating_user_id       TEXT NOT NULL,
  operating_mode           TEXT NOT NULL,
  runtime_provider         TEXT NOT NULL,
  runtime_provider_version TEXT NOT NULL,
  current_state            TEXT NOT NULL DEFAULT 'CREATED'
                           CHECK (current_state IN ('CREATED','RUNNING','AWAITING_APPROVAL','COMPLETED','FAILED','CANCELLED','SUSPENDED')),
  current_step             INT NOT NULL DEFAULT 0,
  policy_profile_hash      TEXT NOT NULL,
  enforcement_plan_hash    TEXT NOT NULL,
  primary_model            TEXT NOT NULL,
  input_hash               TEXT NOT NULL,
  output_hash              TEXT,
  proposed_action_count    INT NOT NULL DEFAULT 0,
  approved_action_count    INT NOT NULL DEFAULT 0,
  denied_action_count      INT NOT NULL DEFAULT 0,
  idempotency_key          TEXT NOT NULL,
  pending_evaluation_id    UUID,
  error_reference          TEXT,
  run_hash                 TEXT NOT NULL,
  started_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at             TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent ON qhub_agent_runs (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_org_state ON qhub_agent_runs (org_id, current_state);
-- Replay safety: one run per (agent_version, idempotency_key).
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_runs_idem ON qhub_agent_runs (agent_version_id, idempotency_key);
-- Tenant-scoped identity used as a composite FK target for steps.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_runs_org_run ON qhub_agent_runs (org_id, run_id);

-- ─── 4. Agent run steps ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_agent_run_steps (
  step_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id        UUID NOT NULL,
  org_id        TEXT NOT NULL,
  step_index    INT  NOT NULL,
  step_kind     TEXT NOT NULL,
  action_type   TEXT,
  evaluation_id UUID,
  decision      TEXT CHECK (decision IN ('ALLOW','DENY','REQUIRE_APPROVAL','SIMULATED','EXECUTED')),
  reason_codes  TEXT[] NOT NULL DEFAULT '{}',
  receipt_id    TEXT,
  input_hash    TEXT,
  summary       TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_run ON qhub_agent_run_steps (run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_run_steps_run_index ON qhub_agent_run_steps (run_id, step_index);

-- ─── 5. Referential-integrity preflight (empty on fresh install) ─────────────
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.qhub_agents c
    LEFT JOIN public.qhub_applications p ON p.org_id = c.org_id AND p.qhub_app_id = c.qhub_app_id
    WHERE p.qhub_app_id IS NULL
  ) THEN RAISE EXCEPTION 'Agent foundation preflight aborted: agent tenant/app orphan'; END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_agent_versions c
    LEFT JOIN public.qhub_agents p ON p.org_id = c.org_id AND p.agent_id = c.agent_id
    WHERE p.agent_id IS NULL
  ) THEN RAISE EXCEPTION 'Agent foundation preflight aborted: version tenant/agent orphan'; END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_agent_versions c
    LEFT JOIN public.qhub_release_candidates p ON p.release_candidate_id = c.release_candidate_id
    WHERE c.release_candidate_id IS NOT NULL AND p.release_candidate_id IS NULL
  ) THEN RAISE EXCEPTION 'Agent foundation preflight aborted: version release orphan'; END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_agent_runs c
    LEFT JOIN public.qhub_agent_versions p ON p.org_id = c.org_id AND p.agent_version_id = c.agent_version_id
    WHERE p.agent_version_id IS NULL
  ) THEN RAISE EXCEPTION 'Agent foundation preflight aborted: run tenant/version orphan'; END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_agent_run_steps c
    LEFT JOIN public.qhub_agent_runs p ON p.org_id = c.org_id AND p.run_id = c.run_id
    WHERE p.run_id IS NULL
  ) THEN RAISE EXCEPTION 'Agent foundation preflight aborted: step tenant/run orphan'; END IF;
END
$$;

-- ─── 6. Foreign keys (staged NOT VALID, then validated) ──────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_agent_qhub_app') THEN
    ALTER TABLE public.qhub_agents ADD CONSTRAINT fk_agent_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_agent_tenant_app') THEN
    ALTER TABLE public.qhub_agents ADD CONSTRAINT fk_agent_tenant_app
      FOREIGN KEY (org_id, qhub_app_id) REFERENCES public.qhub_applications(org_id, qhub_app_id) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_av_agent') THEN
    ALTER TABLE public.qhub_agent_versions ADD CONSTRAINT fk_av_agent
      FOREIGN KEY (agent_id) REFERENCES public.qhub_agents(agent_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_av_tenant_agent') THEN
    ALTER TABLE public.qhub_agent_versions ADD CONSTRAINT fk_av_tenant_agent
      FOREIGN KEY (org_id, agent_id) REFERENCES public.qhub_agents(org_id, agent_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_av_qhub_app') THEN
    ALTER TABLE public.qhub_agent_versions ADD CONSTRAINT fk_av_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_av_release') THEN
    ALTER TABLE public.qhub_agent_versions ADD CONSTRAINT fk_av_release
      FOREIGN KEY (release_candidate_id) REFERENCES public.qhub_release_candidates(release_candidate_id) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_run_agent') THEN
    ALTER TABLE public.qhub_agent_runs ADD CONSTRAINT fk_run_agent
      FOREIGN KEY (agent_id) REFERENCES public.qhub_agents(agent_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_run_version') THEN
    ALTER TABLE public.qhub_agent_runs ADD CONSTRAINT fk_run_version
      FOREIGN KEY (agent_version_id) REFERENCES public.qhub_agent_versions(agent_version_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_run_tenant_version') THEN
    ALTER TABLE public.qhub_agent_runs ADD CONSTRAINT fk_run_tenant_version
      FOREIGN KEY (org_id, agent_version_id) REFERENCES public.qhub_agent_versions(org_id, agent_version_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_run_qhub_app') THEN
    ALTER TABLE public.qhub_agent_runs ADD CONSTRAINT fk_run_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_run_release') THEN
    ALTER TABLE public.qhub_agent_runs ADD CONSTRAINT fk_run_release
      FOREIGN KEY (release_candidate_id) REFERENCES public.qhub_release_candidates(release_candidate_id) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_step_run') THEN
    ALTER TABLE public.qhub_agent_run_steps ADD CONSTRAINT fk_step_run
      FOREIGN KEY (run_id) REFERENCES public.qhub_agent_runs(run_id) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_step_tenant_run') THEN
    ALTER TABLE public.qhub_agent_run_steps ADD CONSTRAINT fk_step_tenant_run
      FOREIGN KEY (org_id, run_id) REFERENCES public.qhub_agent_runs(org_id, run_id) NOT VALID;
  END IF;
END
$$;

ALTER TABLE public.qhub_agents          VALIDATE CONSTRAINT fk_agent_qhub_app;
ALTER TABLE public.qhub_agents          VALIDATE CONSTRAINT fk_agent_tenant_app;
ALTER TABLE public.qhub_agent_versions  VALIDATE CONSTRAINT fk_av_agent;
ALTER TABLE public.qhub_agent_versions  VALIDATE CONSTRAINT fk_av_tenant_agent;
ALTER TABLE public.qhub_agent_versions  VALIDATE CONSTRAINT fk_av_qhub_app;
ALTER TABLE public.qhub_agent_versions  VALIDATE CONSTRAINT fk_av_release;
ALTER TABLE public.qhub_agent_runs      VALIDATE CONSTRAINT fk_run_agent;
ALTER TABLE public.qhub_agent_runs      VALIDATE CONSTRAINT fk_run_version;
ALTER TABLE public.qhub_agent_runs      VALIDATE CONSTRAINT fk_run_tenant_version;
ALTER TABLE public.qhub_agent_runs      VALIDATE CONSTRAINT fk_run_qhub_app;
ALTER TABLE public.qhub_agent_runs      VALIDATE CONSTRAINT fk_run_release;
ALTER TABLE public.qhub_agent_run_steps VALIDATE CONSTRAINT fk_step_run;
ALTER TABLE public.qhub_agent_run_steps VALIDATE CONSTRAINT fk_step_tenant_run;

-- ─── 7. Explicit service-only RLS posture ────────────────────────────────────
ALTER TABLE public.qhub_agents          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_agent_versions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_agent_runs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_agent_run_steps ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_agents'::regclass AND polname = 'qhub_agents_service_only') THEN
    CREATE POLICY qhub_agents_service_only ON public.qhub_agents AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_agent_versions'::regclass AND polname = 'qhub_agent_versions_service_only') THEN
    CREATE POLICY qhub_agent_versions_service_only ON public.qhub_agent_versions AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_agent_runs'::regclass AND polname = 'qhub_agent_runs_service_only') THEN
    CREATE POLICY qhub_agent_runs_service_only ON public.qhub_agent_runs AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_agent_run_steps'::regclass AND polname = 'qhub_agent_run_steps_service_only') THEN
    CREATE POLICY qhub_agent_run_steps_service_only ON public.qhub_agent_run_steps AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
END
$$;

REVOKE ALL ON TABLE public.qhub_agents          FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_agent_versions  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_agent_runs      FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_agent_run_steps FROM PUBLIC, anon, authenticated;

GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agents          TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agent_versions  TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agent_runs      TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agent_run_steps TO service_role;

COMMENT ON TABLE qhub_agents IS
  'Agent Framework: mutable agent identity + lifecycle state. Immutable content lives in qhub_agent_versions.';
COMMENT ON TABLE qhub_agent_versions IS
  'Agent Framework: immutable agent versions. manifest_hash is server-computed; SUPERVISED/ACTIVE require a bound APPROVED Gate 05 release.';
COMMENT ON TABLE qhub_agent_runs IS
  'Agent Framework: governed run records. Every action routes through Gate 04; no DEPLOYMENT_EXECUTED is fabricated.';

-- ─── 8. Metadata-only Agent Framework verifier (service-role only) ────────────
-- Separate from qhub_verify_governance_schema() so Gate 04's verified contract
-- stays stable. Reads ONLY pg_catalog / information_schema metadata and returns a
-- compact, non-sensitive readiness result (no raw SQL, RLS predicates, secrets,
-- or customer data). Missing-safe: joins by relname so a dropped table yields
-- ready=false instead of raising.
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
    ('column.steps_contract', 'COLUMN', (
      SELECT count(*) = 11 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND column_name = ANY(ARRAY['step_id','run_id','org_id','step_index','step_kind','action_type',
          'evaluation_id','decision','reason_codes','input_hash','summary'])
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
  'expected_version', '2026-07-27.agent-foundation',
  'ready', bool_and(ready),
  'checks', jsonb_agg(
    jsonb_build_object('identifier', identifier, 'category', category, 'ready', ready, 'reason_code', reason_code)
    ORDER BY category, identifier
  )
)
FROM normalized
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM anon;
REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_agent_schema() TO service_role;

COMMIT;
