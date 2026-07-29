-- ============================================================================
-- QHUB Commercial Launch Foundation
-- Migration: 20260729_commercial_launch_foundation
--
-- PURPOSE: Additive commercial-tier tables for Builder Beta + Guided Builder —
-- plans, entitlement reference, billing customers, subscriptions, webhook events
-- (idempotency), usage credits + ledger, project entitlements, onboarding state,
-- acknowledgments, manual-review queue, and entitlement-change audit.
--
-- SAFETY:
--   * ADDITIVE ONLY — no ALTER/DROP of existing objects, no data mutation.
--   * Idempotent — every statement is guarded; a second run is a no-op.
--   * Tenant-scoped + server-authoritative — RESTRICTIVE RLS denies anon/
--     authenticated entirely; only the service role (used by the server store)
--     holds table grants. Billing writes are service-role only.
--   * NO secrets. NO production application in this pass.
--
-- Run this in the Supabase SQL editor at the human checkpoint. Do NOT apply
-- automatically.
-- ============================================================================

-- ─── Tables ─────────────────────────────────────────────────────────────────

-- Reference: plan catalog (code in plans.ts is authoritative for entitlements;
-- this mirrors identity/active-state for auditing and joins).
CREATE TABLE IF NOT EXISTS public.qhub_commercial_plans (
  plan_id       TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reference: entitlement snapshot rows (optional, for audit/inspection).
CREATE TABLE IF NOT EXISTS public.qhub_plan_entitlements (
  plan_id            TEXT NOT NULL REFERENCES public.qhub_commercial_plans (plan_id),
  entitlement_key    TEXT NOT NULL,
  entitlement_value  JSONB NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (plan_id, entitlement_key)
);

-- Billing customer mapping (org ↔ provider customer).
CREATE TABLE IF NOT EXISTS public.qhub_billing_customers (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                TEXT NOT NULL,
  provider              TEXT NOT NULL,
  provider_customer_id  TEXT NOT NULL,
  email                 TEXT NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, provider)
);

-- Subscription state (snapshot source for entitlement resolution).
CREATE TABLE IF NOT EXISTS public.qhub_subscriptions (
  id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                         TEXT NOT NULL,
  plan_id                        TEXT NOT NULL,
  status                         TEXT NOT NULL DEFAULT 'none'
                                 CHECK (status IN ('active','trialing','past_due','canceled','incomplete','none')),
  provider                       TEXT NOT NULL,
  provider_customer_id           TEXT,
  provider_subscription_id       TEXT,
  current_period_end             BIGINT,
  override_sensitive_data_review BOOLEAN NOT NULL DEFAULT FALSE,
  override_bonus_credits         INTEGER NOT NULL DEFAULT 0,
  created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, provider)
);

-- Webhook events (idempotency / replay protection).
CREATE TABLE IF NOT EXISTS public.qhub_billing_webhook_events (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider           TEXT NOT NULL,
  provider_event_id  TEXT NOT NULL,
  event_type         TEXT NOT NULL,
  received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at       TIMESTAMPTZ,
  UNIQUE (provider, provider_event_id)
);

-- Monthly build-credit accounting (one row per org per period).
CREATE TABLE IF NOT EXISTS public.qhub_usage_credits (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  period_key    TEXT NOT NULL,
  period_start  TIMESTAMPTZ NOT NULL,
  period_end    TIMESTAMPTZ NOT NULL,
  allotted      INTEGER NOT NULL DEFAULT 0 CHECK (allotted >= 0),
  used          INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, period_key),
  CHECK (used <= allotted)
);

-- Append-only usage ledger (audit of credit movements).
CREATE TABLE IF NOT EXISTS public.qhub_usage_ledger (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         TEXT NOT NULL,
  event_type     TEXT NOT NULL,
  credits_delta  INTEGER NOT NULL,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-project entitlement snapshot.
CREATE TABLE IF NOT EXISTS public.qhub_project_entitlements (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID NOT NULL,
  org_id        TEXT NOT NULL,
  risk_tier     TEXT NOT NULL DEFAULT 'UNCLASSIFIED'
                CHECK (risk_tier IN ('UNCLASSIFIED','T0','T1','T2','T3')),
  publish_state TEXT NOT NULL DEFAULT 'draft'
                CHECK (publish_state IN ('draft','review_requested','review_approved','published','export_only')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id)
);

-- Onboarding state (one per org).
CREATE TABLE IF NOT EXISTS public.qhub_onboarding_state (
  org_id                       TEXT PRIMARY KEY,
  plan_selected                TEXT NOT NULL DEFAULT 'none',
  acknowledged_terms           BOOLEAN NOT NULL DEFAULT FALSE,
  acknowledged_prohibited_data BOOLEAN NOT NULL DEFAULT FALSE,
  first_project_created        BOOLEAN NOT NULL DEFAULT FALSE,
  guided_customer              BOOLEAN NOT NULL DEFAULT FALSE,
  completed                    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Terms / acceptable-use / prohibited-data acknowledgments (append-only).
CREATE TABLE IF NOT EXISTS public.qhub_acknowledgments (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  ack_type         TEXT NOT NULL
                   CHECK (ack_type IN ('terms','privacy','acceptable_use','prohibited_data')),
  ack_version      TEXT NOT NULL,
  acknowledged_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Manual Quantex review queue.
CREATE TABLE IF NOT EXISTS public.qhub_manual_review_requests (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  project_id       UUID,
  request_type     TEXT NOT NULL,
  reason           TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','approved','rejected')),
  decided_by       TEXT,
  decision_reason  TEXT,
  decided_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit of plan / entitlement changes.
CREATE TABLE IF NOT EXISTS public.qhub_entitlement_audit (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  actor         TEXT NOT NULL,
  change_type   TEXT NOT NULL,
  before_state  JSONB,
  after_state   JSONB,
  reason        TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Indexes ────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_qhub_subscriptions_org        ON public.qhub_subscriptions (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_billing_customers_org     ON public.qhub_billing_customers (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_usage_credits_org         ON public.qhub_usage_credits (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_usage_ledger_org          ON public.qhub_usage_ledger (org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_qhub_project_entitlements_org  ON public.qhub_project_entitlements (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_ack_org                   ON public.qhub_acknowledgments (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_manual_review_status      ON public.qhub_manual_review_requests (status, created_at);
CREATE INDEX IF NOT EXISTS idx_qhub_entitlement_audit_org     ON public.qhub_entitlement_audit (org_id, created_at);

-- ─── updated_at trigger (shared, guarded) ───────────────────────────────────

CREATE OR REPLACE FUNCTION public.qhub_commercial_touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_billing_customers',
    'qhub_subscriptions',
    'qhub_usage_credits',
    'qhub_project_entitlements',
    'qhub_onboarding_state'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger
      WHERE tgname = 'trg_' || t || '_updated_at'
        AND tgrelid = ('public.' || t)::regclass
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER trg_%1$s_updated_at BEFORE UPDATE ON public.%1$s '
        || 'FOR EACH ROW EXECUTE FUNCTION public.qhub_commercial_touch_updated_at()',
        t
      );
    END IF;
  END LOOP;
END;
$$;

-- ─── Atomic build-credit consume RPC (service-role only) ─────────────────────
-- Increments used by 1 only while credits remain; returns remaining, or NULL
-- when exhausted / no current-period row. SECURITY DEFINER so the definer's
-- privileges apply; search_path pinned; EXECUTE granted to service_role only.

CREATE OR REPLACE FUNCTION public.qhub_consume_build_credit(p_org_id TEXT, p_period_key TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_remaining INTEGER;
BEGIN
  UPDATE public.qhub_usage_credits
     SET used = used + 1,
         updated_at = NOW()
   WHERE org_id = p_org_id
     AND period_key = p_period_key
     AND used < allotted
  RETURNING (allotted - used) INTO v_remaining;

  RETURN v_remaining; -- NULL when no row matched (exhausted / missing period)
END;
$$;

-- ─── RLS: RESTRICTIVE service-only on every commercial table ─────────────────

DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans',
    'qhub_plan_entitlements',
    'qhub_billing_customers',
    'qhub_subscriptions',
    'qhub_billing_webhook_events',
    'qhub_usage_credits',
    'qhub_usage_ledger',
    'qhub_project_entitlements',
    'qhub_onboarding_state',
    'qhub_acknowledgments',
    'qhub_manual_review_requests',
    'qhub_entitlement_audit'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);

    -- RESTRICTIVE policy denying anon + authenticated any access.
    IF NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service_only'
    ) THEN
      EXECUTE format(
        'CREATE POLICY %1$s_service_only ON public.%1$s '
        || 'AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false) WITH CHECK (false)',
        t
      );
    END IF;

    -- Least privilege: browser roles hold no grants; service role only.
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon, authenticated', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE public.%I TO service_role', t);
  END LOOP;
END;
$$;

-- Credit-consume RPC: deny browser roles, allow service role only.
REVOKE ALL ON FUNCTION public.qhub_consume_build_credit(TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_consume_build_credit(TEXT, TEXT) TO service_role;

-- ─── Seed plan identity (idempotent; entitlements authoritative in code) ─────

INSERT INTO public.qhub_commercial_plans (plan_id, display_name, active)
VALUES
  ('builder_beta',   'QHub Builder Beta',   TRUE),
  ('guided_builder', 'QHub Guided Builder', TRUE)
ON CONFLICT (plan_id) DO NOTHING;
