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
--
-- Run ONCE in the Supabase SQL editor (project jsjsanmaahvmynblmzkq).

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
-- Content identity: one RC row per app + exact release hash (freeze is idempotent).
CREATE UNIQUE INDEX IF NOT EXISTS idx_rc_hash ON qhub_release_candidates (qhub_app_id, release_candidate_hash);
ALTER TABLE qhub_release_candidates ENABLE ROW LEVEL SECURITY;

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
-- One VALID attestation per (release candidate, purpose, signer) — no double-sign.
CREATE UNIQUE INDEX IF NOT EXISTS idx_att_valid_unique
  ON qhub_attestations (release_candidate_id, attestation_purpose, signer_user_id) WHERE status = 'VALID';
ALTER TABLE qhub_attestations ENABLE ROW LEVEL SECURITY;

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
-- At most one EXECUTED deployment per release candidate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dd_deployed_once
  ON qhub_deployment_decisions (release_candidate_id) WHERE deployed = TRUE;
ALTER TABLE qhub_deployment_decisions ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE qhub_release_candidates IS
  'Gate 05: frozen exact-version release candidates. release_candidate_hash is server-computed; attestations and deployment decisions bind to it.';
