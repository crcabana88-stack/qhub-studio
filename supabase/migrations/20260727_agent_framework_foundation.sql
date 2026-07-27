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

COMMIT;
