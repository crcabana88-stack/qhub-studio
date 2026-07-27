-- QHUB Gate 05 — Exact-version attestation & deployment authorization
-- Migration: 20260727_gate05_attestation
--
-- Additive + idempotent. Provides the authoritative records for release
-- candidates, human attestations bound to an exact release hash, and deployment
-- decisions. Security invariants are DB-enforced, not only in app code:
--   - unique release_candidate_id / attestation_id / decision_id
--   - one release candidate row per (app, release_candidate_hash) — content identity
--   - one VALID attestation per (release_candidate_id, purpose, signer)
--   - at most one executed deployment per release candidate
--   - every row is tenant/app-scoped with validated foreign keys to the Gate 04
--     application, enforcement-plan, and release-candidate parents
--   - tables are service-role-only: browser roles (anon, authenticated) are
--     denied by a RESTRICTIVE RLS policy and hold no table grants
--
-- This migration does NOT return customer data, credentials, SQL definitions, or
-- RLS predicates, and does not grant table/function access to browser roles.
--
-- Run ONCE in the Supabase SQL editor (project jsjsanmaahvmynblmzkq).

BEGIN;

-- ─── 0. Required Gate 04 parents ─────────────────────────────────────────────
-- The release/attestation records are meaningful only relative to an existing
-- application and enforcement plan. Abort early with a clear message rather than
-- failing on a foreign key later.
DO $$
BEGIN
  IF to_regclass('public.qhub_applications') IS NULL
     OR to_regclass('public.qhub_enforcement_plans') IS NULL THEN
    RAISE EXCEPTION 'Gate 05 aborted: required Gate 04 parent table is missing';
  END IF;

  -- The tenant composite FK below targets (org_id, qhub_app_id); that pair must
  -- be uniquely indexed on the parent (installed by the Gate 04 migration).
  IF NOT EXISTS (
    SELECT 1
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relname = 'idx_qhub_apps_org_app'
      AND i.indisunique
  ) THEN
    RAISE EXCEPTION 'Gate 05 aborted: unique (org_id, qhub_app_id) index on qhub_applications is missing';
  END IF;
END
$$;

-- ─── 1. Release candidates ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_release_candidates (
  release_candidate_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                        TEXT NOT NULL,
  qhub_app_id                   UUID NOT NULL,
  qhub_app_version              INT  NOT NULL,
  conversation_id               TEXT,
  release_candidate_hash        TEXT NOT NULL,
  canonical_file_manifest_hash  TEXT NOT NULL,
  file_count                    INT  NOT NULL DEFAULT 0,
  dependency_lockfile_hash      TEXT,
  build_artifact_digest         TEXT,
  classification_version        INT  NOT NULL,
  classification_reference      TEXT,
  risk_tier                     TEXT NOT NULL,
  policy_profile_id             UUID,
  policy_profile_version        INT,
  policy_profile_hash           TEXT NOT NULL,
  enforcement_plan_id           UUID,
  enforcement_plan_version      INT,
  enforcement_plan_hash         TEXT NOT NULL,
  model_manifest_hash           TEXT NOT NULL,
  connector_manifest_hash       TEXT NOT NULL,
  data_access_manifest_hash     TEXT NOT NULL,
  target_environment            TEXT NOT NULL,
  deployment_target             TEXT NOT NULL,
  release_scope                 TEXT NOT NULL,
  manifest                      JSONB NOT NULL,
  manifest_version              TEXT NOT NULL,
  status                        TEXT NOT NULL DEFAULT 'DRAFT'
                                CHECK (status IN ('DRAFT','FROZEN','AWAITING_ATTESTATION','APPROVED','REJECTED','SUPERSEDED','DEPLOYED')),
  supersedes_release_candidate_id UUID,
  created_by                    TEXT NOT NULL,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  frozen_at                     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_rc_app ON qhub_release_candidates (qhub_app_id);
CREATE INDEX IF NOT EXISTS idx_rc_org_app_status ON qhub_release_candidates (org_id, qhub_app_id, status);
-- Content identity: one RC row per app + exact release hash (freeze is idempotent).
CREATE UNIQUE INDEX IF NOT EXISTS idx_rc_hash ON qhub_release_candidates (qhub_app_id, release_candidate_hash);
-- Tenant-scoped identity used as a composite FK target for children.
CREATE UNIQUE INDEX IF NOT EXISTS idx_rc_org_rc ON qhub_release_candidates (org_id, release_candidate_id);

-- ─── 2. Attestations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_attestations (
  attestation_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                        TEXT NOT NULL,
  qhub_app_id                   UUID NOT NULL,
  release_candidate_id          UUID NOT NULL,
  release_candidate_hash        TEXT NOT NULL,
  qhub_app_version              INT  NOT NULL,
  signer_user_id                TEXT NOT NULL,
  signer_org_id                 TEXT NOT NULL,
  signer_role                   TEXT NOT NULL,
  authority_source              TEXT NOT NULL,
  attestation_purpose           TEXT NOT NULL,
  attestation_scope             TEXT NOT NULL,
  target_environment            TEXT NOT NULL,
  policy_profile_id             UUID,
  policy_profile_version        INT,
  policy_profile_hash           TEXT NOT NULL,
  enforcement_plan_id           UUID,
  enforcement_plan_version      INT,
  enforcement_plan_hash         TEXT NOT NULL,
  attestation_statement_version TEXT NOT NULL,
  attestation_statement_hash    TEXT NOT NULL,
  signed_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at                    TIMESTAMPTZ,
  status                        TEXT NOT NULL DEFAULT 'VALID'
                                CHECK (status IN ('VALID','SUPERSEDED','REVOKED','EXPIRED','INVALIDATED')),
  supersedes_attestation_id     UUID,
  evidence_reference            TEXT,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_att_rc ON qhub_attestations (release_candidate_id);
CREATE INDEX IF NOT EXISTS idx_att_org_app ON qhub_attestations (org_id, qhub_app_id);
-- One VALID attestation per (release candidate, purpose, signer) — no double-sign.
CREATE UNIQUE INDEX IF NOT EXISTS idx_att_valid_unique
  ON qhub_attestations (release_candidate_id, attestation_purpose, signer_user_id) WHERE status = 'VALID';

-- ─── 3. Deployment decisions ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_deployment_decisions (
  decision_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                  TEXT NOT NULL,
  qhub_app_id             UUID NOT NULL,
  release_candidate_id    UUID NOT NULL,
  release_candidate_hash  TEXT NOT NULL,
  decision                TEXT NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  reason_codes            TEXT[] NOT NULL DEFAULT '{}',
  satisfied_requirements  TEXT[] NOT NULL DEFAULT '{}',
  missing_requirements    TEXT[] NOT NULL DEFAULT '{}',
  target_environment      TEXT NOT NULL,
  deployed                BOOLEAN NOT NULL DEFAULT FALSE,
  deployment_receipt      JSONB,
  decided_by              TEXT NOT NULL,
  decided_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dd_rc ON qhub_deployment_decisions (release_candidate_id);
CREATE INDEX IF NOT EXISTS idx_dd_org_app ON qhub_deployment_decisions (org_id, qhub_app_id);
-- At most one EXECUTED deployment per release candidate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dd_deployed_once
  ON qhub_deployment_decisions (release_candidate_id) WHERE deployed = TRUE;

-- ─── 4. Referential-integrity preflight ──────────────────────────────────────
-- On a fresh install these tables are empty and every check trivially passes.
-- On a rerun over existing data, discover any orphan before staging a foreign
-- key rather than one constraint at a time.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.qhub_release_candidates child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: release candidate tenant/app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_release_candidates child
    LEFT JOIN public.qhub_enforcement_plans parent
      ON parent.enforcement_plan_id = child.enforcement_plan_id
    WHERE child.enforcement_plan_id IS NOT NULL
      AND parent.enforcement_plan_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: release candidate enforcement-plan orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_release_candidates child
    LEFT JOIN public.qhub_release_candidates parent
      ON parent.release_candidate_id = child.supersedes_release_candidate_id
    WHERE child.supersedes_release_candidate_id IS NOT NULL
      AND parent.release_candidate_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: release candidate supersede orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_attestations child
    LEFT JOIN public.qhub_release_candidates parent
      ON parent.org_id = child.org_id AND parent.release_candidate_id = child.release_candidate_id
    WHERE parent.release_candidate_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: attestation tenant/release orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_attestations child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: attestation tenant/app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_deployment_decisions child
    LEFT JOIN public.qhub_release_candidates parent
      ON parent.org_id = child.org_id AND parent.release_candidate_id = child.release_candidate_id
    WHERE parent.release_candidate_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: deployment decision tenant/release orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_deployment_decisions child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 05 preflight aborted: deployment decision tenant/app orphan';
  END IF;
END
$$;

-- ─── 5. Foreign keys (staged NOT VALID, then validated) ──────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rc_qhub_app') THEN
    ALTER TABLE public.qhub_release_candidates
      ADD CONSTRAINT fk_rc_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rc_tenant_app') THEN
    ALTER TABLE public.qhub_release_candidates
      ADD CONSTRAINT fk_rc_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rc_enforcement_plan') THEN
    ALTER TABLE public.qhub_release_candidates
      ADD CONSTRAINT fk_rc_enforcement_plan
      FOREIGN KEY (enforcement_plan_id) REFERENCES public.qhub_enforcement_plans(enforcement_plan_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rc_supersedes') THEN
    ALTER TABLE public.qhub_release_candidates
      ADD CONSTRAINT fk_rc_supersedes
      FOREIGN KEY (supersedes_release_candidate_id) REFERENCES public.qhub_release_candidates(release_candidate_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_att_release') THEN
    ALTER TABLE public.qhub_attestations
      ADD CONSTRAINT fk_att_release
      FOREIGN KEY (release_candidate_id) REFERENCES public.qhub_release_candidates(release_candidate_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_att_tenant_release') THEN
    ALTER TABLE public.qhub_attestations
      ADD CONSTRAINT fk_att_tenant_release
      FOREIGN KEY (org_id, release_candidate_id)
      REFERENCES public.qhub_release_candidates(org_id, release_candidate_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_att_tenant_app') THEN
    ALTER TABLE public.qhub_attestations
      ADD CONSTRAINT fk_att_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_dd_release') THEN
    ALTER TABLE public.qhub_deployment_decisions
      ADD CONSTRAINT fk_dd_release
      FOREIGN KEY (release_candidate_id) REFERENCES public.qhub_release_candidates(release_candidate_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_dd_tenant_release') THEN
    ALTER TABLE public.qhub_deployment_decisions
      ADD CONSTRAINT fk_dd_tenant_release
      FOREIGN KEY (org_id, release_candidate_id)
      REFERENCES public.qhub_release_candidates(org_id, release_candidate_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_dd_tenant_app') THEN
    ALTER TABLE public.qhub_deployment_decisions
      ADD CONSTRAINT fk_dd_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;
END
$$;

ALTER TABLE public.qhub_release_candidates   VALIDATE CONSTRAINT fk_rc_qhub_app;
ALTER TABLE public.qhub_release_candidates   VALIDATE CONSTRAINT fk_rc_tenant_app;
ALTER TABLE public.qhub_release_candidates   VALIDATE CONSTRAINT fk_rc_enforcement_plan;
ALTER TABLE public.qhub_release_candidates   VALIDATE CONSTRAINT fk_rc_supersedes;
ALTER TABLE public.qhub_attestations         VALIDATE CONSTRAINT fk_att_release;
ALTER TABLE public.qhub_attestations         VALIDATE CONSTRAINT fk_att_tenant_release;
ALTER TABLE public.qhub_attestations         VALIDATE CONSTRAINT fk_att_tenant_app;
ALTER TABLE public.qhub_deployment_decisions VALIDATE CONSTRAINT fk_dd_release;
ALTER TABLE public.qhub_deployment_decisions VALIDATE CONSTRAINT fk_dd_tenant_release;
ALTER TABLE public.qhub_deployment_decisions VALIDATE CONSTRAINT fk_dd_tenant_app;

-- ─── 6. Explicit service-only RLS posture ────────────────────────────────────
ALTER TABLE public.qhub_release_candidates   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_attestations         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_deployment_decisions ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_release_candidates'::regclass
      AND polname = 'qhub_release_candidates_service_only'
  ) THEN
    CREATE POLICY qhub_release_candidates_service_only
      ON public.qhub_release_candidates
      AS RESTRICTIVE FOR ALL TO anon, authenticated
      USING (FALSE) WITH CHECK (FALSE);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_attestations'::regclass
      AND polname = 'qhub_attestations_service_only'
  ) THEN
    CREATE POLICY qhub_attestations_service_only
      ON public.qhub_attestations
      AS RESTRICTIVE FOR ALL TO anon, authenticated
      USING (FALSE) WITH CHECK (FALSE);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_deployment_decisions'::regclass
      AND polname = 'qhub_deployment_decisions_service_only'
  ) THEN
    CREATE POLICY qhub_deployment_decisions_service_only
      ON public.qhub_deployment_decisions
      AS RESTRICTIVE FOR ALL TO anon, authenticated
      USING (FALSE) WITH CHECK (FALSE);
  END IF;
END
$$;

REVOKE ALL ON TABLE public.qhub_release_candidates   FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_attestations         FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_deployment_decisions FROM PUBLIC, anon, authenticated;

GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_release_candidates   TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_attestations         TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_deployment_decisions TO service_role;

COMMENT ON TABLE qhub_release_candidates IS
  'Gate 05: frozen exact-version release candidates. release_candidate_hash is server-computed; attestations and deployment decisions bind to it.';
COMMENT ON TABLE qhub_attestations IS
  'Gate 05: human attestations bound to an exact release_candidate_hash. Server-authoritative signer role; unique VALID per (release, purpose, signer).';
COMMENT ON TABLE qhub_deployment_decisions IS
  'Gate 05: deployment authorization decisions. deployed=TRUE only after a real deployment; at most one executed deployment per release candidate.';

COMMIT;
