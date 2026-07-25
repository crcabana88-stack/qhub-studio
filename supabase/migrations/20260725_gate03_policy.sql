-- QHUB Gate 03 — Policy stage + Phase-0 classification hardening
-- Migration: 20260725_gate03_policy
--
-- 1. qhub_classification_proposals — server-persisted provisional classifications.
--    Closes the Gate 02 signal-integrity gap: on confirmation the server loads the
--    authoritative proposal (never trusting browser-rewritten signals), re-derives
--    the floor, and marks the proposal consumed.
-- 2. Policy snapshot columns on qhub_applications (current operational snapshot;
--    the immutable ledger remains the historical authority).
--
-- Run this in your Supabase SQL editor (project dashboard → SQL editor → New query).

CREATE TABLE IF NOT EXISTS qhub_classification_proposals (
  proposal_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             TEXT NOT NULL,
  conversation_id    TEXT,
  qhub_app_id        UUID,
  description_hash   TEXT NOT NULL,
  provisional        JSONB NOT NULL,   -- full provisional ClassificationResult (authoritative signals)
  risk_floor         TEXT NOT NULL,
  ai_proposed_tier   TEXT NOT NULL,
  classifier_version TEXT NOT NULL,
  created_by         TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL,
  status             TEXT NOT NULL DEFAULT 'PENDING'
                     CHECK (status IN ('PENDING', 'CONSUMED', 'EXPIRED'))
);

CREATE INDEX IF NOT EXISTS idx_proposals_org        ON qhub_classification_proposals (org_id);
CREATE INDEX IF NOT EXISTS idx_proposals_conv       ON qhub_classification_proposals (conversation_id);

ALTER TABLE qhub_classification_proposals ENABLE ROW LEVEL SECURITY;
-- Service role (SUPABASE_SERVICE_ROLE_KEY) bypasses RLS; GovernanceService uses it.

-- Policy snapshot on the app record (current operational snapshot).
ALTER TABLE qhub_applications
  ADD COLUMN IF NOT EXISTS policy_profile_id      UUID,
  ADD COLUMN IF NOT EXISTS policy_profile_version INT,
  ADD COLUMN IF NOT EXISTS policy_catalog_version TEXT,
  ADD COLUMN IF NOT EXISTS policy_profile         JSONB,
  ADD COLUMN IF NOT EXISTS policy_profile_hash    TEXT,
  ADD COLUMN IF NOT EXISTS policy_status          TEXT,
  ADD COLUMN IF NOT EXISTS policy_assigned_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS policy_assigned_by     TEXT;

COMMENT ON TABLE qhub_classification_proposals IS
  'Gate 03 Phase 0: server-persisted provisional classifications. Confirmation binds to a proposal_id; browser cannot rewrite authoritative signals.';
