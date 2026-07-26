-- QHUB Gate 04 — Control Enforcement persistence
-- Migration: 20260726_gate04_enforcement
--
-- Additive + idempotent. Provides the authoritative records enforcement needs:
--   1. qhub_enforcement_plans   — compiled, versioned plans (hash-bound to policy)
--   2. qhub_control_evaluations — every ALLOW/DENY/REQUIRE_APPROVAL decision
--   3. qhub_control_approvals   — scoped, single-use, expiring approval grants
--   4. kill_switch_active flag  — server-authoritative kill switch per app
--
-- Security invariants are enforced by DB constraints/indexes, not only app code:
--   - unique evaluation_id (PK) and unique action_request_id
--   - one idempotent evaluation per (org, app, idempotency_key)
--   - the ALLOW claim is a single conditional UPDATE (claimed false->true)
--   - one consumption per single-use approval (status transition GRANTED->CONSUMED)
--
-- Run this ONCE in the Supabase SQL editor (project jsjsanmaahvmynblmzkq).

-- ─── 1. Enforcement plans ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_enforcement_plans (
  enforcement_plan_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                   TEXT NOT NULL,
  qhub_app_id              UUID NOT NULL,
  enforcement_plan_version INT  NOT NULL,
  classification_version   INT  NOT NULL,
  policy_profile_id        UUID,
  policy_profile_version   INT,
  policy_profile_hash      TEXT NOT NULL,
  policy_catalog_version   TEXT NOT NULL,
  risk_tier                TEXT NOT NULL,
  enforcement_plan_hash    TEXT NOT NULL,
  plan                     JSONB NOT NULL,
  status                   TEXT NOT NULL DEFAULT 'ACTIVE'
                           CHECK (status IN ('ACTIVE','SUPERSEDED','SUSPENDED')),
  compiler_version         TEXT NOT NULL,
  generated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  generated_by             TEXT NOT NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ep_app        ON qhub_enforcement_plans (qhub_app_id);
-- At most one ACTIVE plan per app.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ep_active_one
  ON qhub_enforcement_plans (qhub_app_id) WHERE status = 'ACTIVE';
ALTER TABLE qhub_enforcement_plans ENABLE ROW LEVEL SECURITY;

-- ─── 2. Control evaluations (the decisions) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS qhub_control_evaluations (
  evaluation_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action_request_id        UUID NOT NULL UNIQUE,
  parent_evaluation_id     UUID,
  org_id                   TEXT NOT NULL,
  qhub_app_id              UUID NOT NULL,
  action_type              TEXT NOT NULL,
  action_digest            TEXT NOT NULL,
  environment              TEXT NOT NULL,
  decision                 TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY','REQUIRE_APPROVAL')),
  reason_codes             TEXT[] NOT NULL DEFAULT '{}',
  policy_profile_id        UUID,
  policy_profile_version   INT,
  policy_profile_hash      TEXT NOT NULL,
  enforcement_plan_id      UUID,
  enforcement_plan_version INT,
  enforcement_plan_hash    TEXT NOT NULL,
  control_results          JSONB NOT NULL DEFAULT '[]',
  control_results_hash     TEXT NOT NULL,
  required_attestations    TEXT[] NOT NULL DEFAULT '{}',
  evaluator_version        TEXT NOT NULL,
  enforcement_mode         TEXT NOT NULL DEFAULT 'FAIL_CLOSED',
  idempotency_key          TEXT,
  -- The single-use ALLOW claim: flips false->true exactly once (side-effect gate).
  claimed                  BOOLEAN NOT NULL DEFAULT FALSE,
  claimed_at               TIMESTAMPTZ,
  -- Post-action evidence outbox state.
  action_event_state       TEXT NOT NULL DEFAULT 'NONE'
                           CHECK (action_event_state IN ('NONE','PENDING','COMMITTED','FAILED')),
  evaluated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by               TEXT NOT NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ce_app     ON qhub_control_evaluations (qhub_app_id);
CREATE INDEX IF NOT EXISTS idx_ce_digest  ON qhub_control_evaluations (action_digest);
-- Idempotency: at most one evaluation per (org, app, idempotency_key).
CREATE UNIQUE INDEX IF NOT EXISTS idx_ce_idem
  ON qhub_control_evaluations (org_id, qhub_app_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
ALTER TABLE qhub_control_evaluations ENABLE ROW LEVEL SECURITY;

-- ─── 3. Control approvals (scoped, single-use, expiring) ──────────────────────
CREATE TABLE IF NOT EXISTS qhub_control_approvals (
  approval_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                       TEXT NOT NULL,
  qhub_app_id                  UUID NOT NULL,
  attestation_type             TEXT NOT NULL,
  action_digest                TEXT NOT NULL,
  scoped_policy_profile_hash   TEXT NOT NULL,
  scoped_enforcement_plan_hash TEXT NOT NULL,
  approver_id                  TEXT NOT NULL,
  approver_role                TEXT NOT NULL,
  single_use                   BOOLEAN NOT NULL DEFAULT TRUE,
  status                       TEXT NOT NULL DEFAULT 'GRANTED'
                               CHECK (status IN ('GRANTED','CONSUMED','REVOKED','EXPIRED')),
  expires_at                   TIMESTAMPTZ NOT NULL,
  consumed_by_evaluation       UUID,
  created_by                   TEXT NOT NULL,
  created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  consumed_at                  TIMESTAMPTZ,
  -- One approval per (app, digest, attestation_type, approver) — no double-grant.
  UNIQUE (qhub_app_id, action_digest, attestation_type, approver_id)
);
CREATE INDEX IF NOT EXISTS idx_ca_lookup
  ON qhub_control_approvals (qhub_app_id, action_digest, status);
ALTER TABLE qhub_control_approvals ENABLE ROW LEVEL SECURITY;

-- ─── 4. Kill switch (server-authoritative) ────────────────────────────────────
ALTER TABLE qhub_applications
  ADD COLUMN IF NOT EXISTS kill_switch_active   BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS kill_switch_reason   TEXT,
  ADD COLUMN IF NOT EXISTS kill_switch_set_by   TEXT,
  ADD COLUMN IF NOT EXISTS kill_switch_set_at   TIMESTAMPTZ;

COMMENT ON TABLE qhub_control_evaluations IS
  'Gate 04: authoritative CONTROL_DECISION_RECORDED evidence. The single-use ALLOW claim (claimed false->true) gates the protected side effect.';
