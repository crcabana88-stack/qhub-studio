-- QHUB Gate 02 — Classification persistence
-- Migration: 20260725_qhub_classification
--
-- Adds a JSONB column holding the CURRENT classification for each app.
-- The authoritative, immutable classification HISTORY lives in the WORM ledger
-- (CLASSIFICATION_ASSIGNED events); this column is a fast-read snapshot only.
--
-- risk_tier (T0–T3) and governance_status ('classified') already exist from
-- the 20260723_qhub_applications migration.
--
-- Run this in your Supabase SQL editor (project dashboard → SQL editor → New query).

ALTER TABLE qhub_applications
  ADD COLUMN IF NOT EXISTS classification JSONB;

COMMENT ON COLUMN qhub_applications.classification IS
  'Gate 02: current CLASSIFICATION_ASSIGNED payload (risk_tier, risk_floor, signals, rationale, confirmed_by, version). Immutable history is in the WORM ledger.';
