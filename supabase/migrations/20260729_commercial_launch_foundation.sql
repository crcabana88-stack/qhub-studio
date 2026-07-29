-- ============================================================================
-- QHUB Commercial Launch Foundation — R2 HARDENING
-- Migration: 20260729_commercial_launch_foundation  (replaces the rejected
--            2ff6ab3a… contents IN PLACE — one authoritative commercial migration)
-- Schema version: 2026-07-29.commercial-launch-r2
--
-- Adds authoritative identity/membership, a recoverable Stripe webhook inbox,
-- mode/account/price-bound subscriptions, an atomic idempotent build-credit RPC,
-- persisted Governance Essentials, staff-authorized manual review, hardened
-- constraints, and a qhub_verify_commercial_schema() readiness contract.
--
-- SAFETY: wrapped in a single transaction (BEGIN/COMMIT — full rollback on any
-- failure). Additive only: no DROP / DELETE / TRUNCATE / destructive type change /
-- fabricated backfill. Idempotent: a healthy rerun is a no-op. Tenant-scoped +
-- server-authoritative: RESTRICTIVE RLS denies anon/authenticated; only the
-- service role holds table grants; the credit RPC is service-role only.
--
-- Run in the Supabase SQL editor at the human checkpoint. Do NOT apply here.
-- ============================================================================

BEGIN;

-- ─── Reference: plan catalog ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.qhub_commercial_plans (
  plan_id       TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Authoritative identity / tenancy ───────────────────────────────────────

-- Organization membership. THE authority for org_id + org role — never
-- user_metadata. A protected request resolves membership from here.
CREATE TABLE IF NOT EXISTS public.qhub_org_members (
  user_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'builder'
              CHECK (role IN ('owner','admin','billing_admin','builder','viewer')),
  status      TEXT NOT NULL DEFAULT 'active'
              CHECK (status IN ('active','invited','suspended','removed')),
  invited_by  TEXT,
  accepted_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, org_id)
);

-- Internal Quantex staff. THE authority for internal override/review/dev access.
CREATE TABLE IF NOT EXISTS public.qhub_quantex_staff (
  user_id     TEXT PRIMARY KEY,
  staff_role  TEXT NOT NULL DEFAULT 'reviewer'
              CHECK (staff_role IN ('reviewer','admin','engineer')),
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Invitations (acceptance flow).
CREATE TABLE IF NOT EXISTS public.qhub_org_invitations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       TEXT NOT NULL,
  email        TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'builder'
               CHECK (role IN ('owner','admin','billing_admin','builder','viewer')),
  token_hash   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'invited'
               CHECK (status IN ('invited','accepted','revoked','expired')),
  expires_at   TIMESTAMPTZ NOT NULL,
  accepted_by  TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Billing customers (mode/account bound, unique both directions) ──────────
CREATE TABLE IF NOT EXISTS public.qhub_billing_customers (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                TEXT NOT NULL,
  provider              TEXT NOT NULL,
  provider_customer_id  TEXT NOT NULL,
  email                 TEXT NOT NULL DEFAULT '',
  livemode              BOOLEAN NOT NULL DEFAULT FALSE,
  stripe_account        TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, provider),
  UNIQUE (provider, provider_customer_id)
);

-- ─── Subscriptions (mode/account/price bound; out-of-order guarded) ──────────
CREATE TABLE IF NOT EXISTS public.qhub_subscriptions (
  id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                         TEXT NOT NULL,
  plan_id                        TEXT NOT NULL REFERENCES public.qhub_commercial_plans (plan_id),
  status                         TEXT NOT NULL DEFAULT 'none'
                                 CHECK (status IN ('active','trialing','past_due','canceled','incomplete','none')),
  provider                       TEXT NOT NULL,
  provider_customer_id           TEXT,
  provider_subscription_id       TEXT,
  provider_price_id              TEXT,
  livemode                       BOOLEAN NOT NULL DEFAULT FALSE,
  stripe_account                 TEXT,
  current_period_end             BIGINT,
  last_event_created             BIGINT NOT NULL DEFAULT 0,
  override_sensitive_data_review BOOLEAN NOT NULL DEFAULT FALSE,
  override_bonus_credits         INTEGER NOT NULL DEFAULT 0,
  override_actor                 TEXT,
  override_reason                TEXT,
  override_start                 TIMESTAMPTZ,
  override_end                   TIMESTAMPTZ,
  created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, provider),
  UNIQUE (provider, provider_subscription_id)
);

-- ─── Webhook inbox (recoverable state machine) ──────────────────────────────
CREATE TABLE IF NOT EXISTS public.qhub_billing_webhook_events (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider           TEXT NOT NULL,
  provider_event_id  TEXT NOT NULL,
  event_type         TEXT NOT NULL,
  state              TEXT NOT NULL DEFAULT 'RECEIVED'
                     CHECK (state IN ('RECEIVED','PROCESSING','PROCESSED','FAILED_RETRYABLE','FAILED_PERMANENT')),
  livemode           BOOLEAN NOT NULL DEFAULT FALSE,
  stripe_account     TEXT,
  event_created      BIGINT,
  payload_hash       TEXT,
  attempts           INTEGER NOT NULL DEFAULT 0,
  last_error_code    TEXT,
  received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at       TIMESTAMPTZ,
  UNIQUE (provider, provider_event_id)
);

-- ─── Usage credits + immutable ledger ───────────────────────────────────────
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

CREATE TABLE IF NOT EXISTS public.qhub_usage_ledger (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  project_id       UUID,
  event_type       TEXT NOT NULL,
  credits_delta    INTEGER NOT NULL,
  idempotency_key  TEXT,
  request_hash     TEXT,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, idempotency_key)
);

-- ─── Project entitlements (ownership + one-active-guided rule) ───────────────
CREATE TABLE IF NOT EXISTS public.qhub_project_entitlements (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID NOT NULL,
  org_id        TEXT NOT NULL,
  plan_id       TEXT NOT NULL DEFAULT 'none',
  risk_tier     TEXT NOT NULL DEFAULT 'UNCLASSIFIED'
                CHECK (risk_tier IN ('UNCLASSIFIED','T0','T1','T2','T3')),
  publish_state TEXT NOT NULL DEFAULT 'draft'
                CHECK (publish_state IN ('draft','review_requested','review_approved','published','export_only')),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id)
);
-- One ACTIVE guided-plan launch project per org (product = exactly one).
CREATE UNIQUE INDEX IF NOT EXISTS uq_qhub_guided_one_active_project
  ON public.qhub_project_entitlements (org_id)
  WHERE (active AND plan_id = 'guided_builder');

-- ─── Onboarding + acknowledgments ───────────────────────────────────────────
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

CREATE TABLE IF NOT EXISTS public.qhub_acknowledgments (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  ack_type         TEXT NOT NULL
                   CHECK (ack_type IN ('terms','privacy','acceptable_use','prohibited_data')),
  ack_version      TEXT NOT NULL,
  acknowledged_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Governance Essentials (persisted server workflow) ──────────────────────
CREATE TABLE IF NOT EXISTS public.qhub_governance_essentials (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id             UUID NOT NULL,
  org_id                 TEXT NOT NULL,
  purpose                TEXT,
  use_case               TEXT,
  data_classes           JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_tier              TEXT NOT NULL DEFAULT 'UNCLASSIFIED'
                         CHECK (risk_tier IN ('UNCLASSIFIED','T0','T1','T2','T3')),
  model_declaration      TEXT,
  connector_declaration  JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_card_version    TEXT,
  acknowledgment_version TEXT,
  disposition            TEXT NOT NULL DEFAULT 'incomplete'
                         CHECK (disposition IN ('incomplete','proceed','manual_review','blocked','prohibited')),
  declaration_complete   BOOLEAN NOT NULL DEFAULT FALSE,
  acknowledged           BOOLEAN NOT NULL DEFAULT FALSE,
  review_state           TEXT NOT NULL DEFAULT 'none'
                         CHECK (review_state IN ('none','requested','approved','rejected')),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id)
);

-- ─── Manual review (staff-authorized) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.qhub_manual_review_requests (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  project_id       UUID,
  request_type     TEXT NOT NULL,
  category         TEXT,
  reason           TEXT NOT NULL,
  request_hash     TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','approved','rejected')),
  decided_by       TEXT REFERENCES public.qhub_quantex_staff (user_id),
  decision_reason  TEXT,
  policy_version   TEXT,
  decided_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, request_hash)
);

-- ─── Entitlement / override audit ───────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_qhub_org_members_org         ON public.qhub_org_members (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_subscriptions_org        ON public.qhub_subscriptions (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_billing_customers_org     ON public.qhub_billing_customers (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_usage_credits_org         ON public.qhub_usage_credits (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_usage_ledger_org          ON public.qhub_usage_ledger (org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_qhub_project_entitlements_org  ON public.qhub_project_entitlements (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_ack_org                   ON public.qhub_acknowledgments (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_manual_review_status      ON public.qhub_manual_review_requests (status, created_at);
CREATE INDEX IF NOT EXISTS idx_qhub_gov_essentials_org        ON public.qhub_governance_essentials (org_id);
CREATE INDEX IF NOT EXISTS idx_qhub_webhook_state             ON public.qhub_billing_webhook_events (state, received_at);
CREATE INDEX IF NOT EXISTS idx_qhub_entitlement_audit_org     ON public.qhub_entitlement_audit (org_id, created_at);

-- ─── Shared updated_at trigger ──────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_commercial_touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_org_members','qhub_billing_customers','qhub_subscriptions','qhub_usage_credits',
    'qhub_project_entitlements','qhub_onboarding_state','qhub_governance_essentials'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname = 'trg_' || t || '_updated_at'
        AND tgrelid = ('public.' || t)::regclass
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER trg_%1$s_updated_at BEFORE UPDATE ON public.%1$s '
        || 'FOR EACH ROW EXECUTE FUNCTION public.qhub_commercial_touch_updated_at()', t);
    END IF;
  END LOOP;
END;
$$;

-- Acknowledgment immutability: no UPDATE/DELETE of a recorded acknowledgment.
CREATE OR REPLACE FUNCTION public.qhub_acknowledgment_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'qhub_acknowledgments rows are immutable';
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_qhub_ack_immutable'
      AND tgrelid = 'public.qhub_acknowledgments'::regclass
  ) THEN
    EXECUTE 'CREATE TRIGGER trg_qhub_ack_immutable BEFORE UPDATE OR DELETE ON public.qhub_acknowledgments '
         || 'FOR EACH ROW EXECUTE FUNCTION public.qhub_acknowledgment_immutable()';
  END IF;
END;
$$;

-- Usage-ledger immutability: append-only.
CREATE OR REPLACE FUNCTION public.qhub_usage_ledger_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'qhub_usage_ledger rows are immutable';
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_qhub_usage_ledger_immutable'
      AND tgrelid = 'public.qhub_usage_ledger'::regclass
  ) THEN
    EXECUTE 'CREATE TRIGGER trg_qhub_usage_ledger_immutable BEFORE UPDATE OR DELETE ON public.qhub_usage_ledger '
         || 'FOR EACH ROW EXECUTE FUNCTION public.qhub_usage_ledger_immutable()';
  END IF;
END;
$$;

-- ─── Atomic, idempotent build-credit consume RPC ────────────────────────────
-- One transaction: idempotency check → lock credit row → validate remaining →
-- decrement → append immutable ledger row → return remaining. Materially
-- different reuse of an idempotency key (different request_hash) fails.
CREATE OR REPLACE FUNCTION public.qhub_consume_build_credit(
  p_org_id TEXT, p_period_key TEXT, p_idempotency_key TEXT, p_request_hash TEXT
) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_existing_hash TEXT;
  v_remaining     INTEGER;
BEGIN
  -- Idempotency: a prior ledger row for this key returns the prior result.
  SELECT request_hash INTO v_existing_hash
    FROM public.qhub_usage_ledger
   WHERE org_id = p_org_id AND idempotency_key = p_idempotency_key
   LIMIT 1;

  IF FOUND THEN
    IF v_existing_hash IS DISTINCT FROM p_request_hash THEN
      RAISE EXCEPTION 'qhub_consume_build_credit: idempotency key reused with a different request';
    END IF;

    SELECT (allotted - used) INTO v_remaining
      FROM public.qhub_usage_credits
     WHERE org_id = p_org_id AND period_key = p_period_key;

    RETURN v_remaining; -- no second decrement
  END IF;

  -- Lock the current-period credit row and decrement only while credits remain.
  UPDATE public.qhub_usage_credits
     SET used = used + 1, updated_at = NOW()
   WHERE org_id = p_org_id AND period_key = p_period_key AND used < allotted
  RETURNING (allotted - used) INTO v_remaining;

  IF NOT FOUND THEN
    RETURN NULL; -- exhausted / no period row
  END IF;

  INSERT INTO public.qhub_usage_ledger (org_id, event_type, credits_delta, idempotency_key, request_hash)
  VALUES (p_org_id, 'BUILD_CREDIT_CONSUMED', -1, p_idempotency_key, p_request_hash);

  RETURN v_remaining;
END;
$$;

-- ─── Atomic webhook-event claim RPC ─────────────────────────────────────────
-- Inserts a RECEIVED row (or claims a retryable one) and transitions to
-- PROCESSING atomically. Returns: CLAIMED | DUPLICATE | IN_PROGRESS.
CREATE OR REPLACE FUNCTION public.qhub_claim_webhook_event(
  p_provider TEXT, p_event_id TEXT, p_event_type TEXT,
  p_livemode BOOLEAN, p_account TEXT, p_event_created BIGINT, p_payload_hash TEXT
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_state TEXT;
BEGIN
  INSERT INTO public.qhub_billing_webhook_events
    (provider, provider_event_id, event_type, state, livemode, stripe_account, event_created, payload_hash, attempts)
  VALUES
    (p_provider, p_event_id, p_event_type, 'PROCESSING', p_livemode, p_account, p_event_created, p_payload_hash, 1)
  ON CONFLICT (provider, provider_event_id) DO NOTHING;

  IF FOUND THEN
    RETURN 'CLAIMED';
  END IF;

  -- Existing row: claim it only if it is retryable.
  SELECT state INTO v_state
    FROM public.qhub_billing_webhook_events
   WHERE provider = p_provider AND provider_event_id = p_event_id
   FOR UPDATE;

  IF v_state IN ('PROCESSED','FAILED_PERMANENT') THEN
    RETURN 'DUPLICATE';
  ELSIF v_state = 'PROCESSING' THEN
    RETURN 'IN_PROGRESS';
  ELSE
    UPDATE public.qhub_billing_webhook_events
       SET state = 'PROCESSING', attempts = attempts + 1
     WHERE provider = p_provider AND provider_event_id = p_event_id;
    RETURN 'CLAIMED';
  END IF;
END;
$$;

-- ─── RLS: RESTRICTIVE service-only on every commercial table ─────────────────
DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans','qhub_org_members','qhub_quantex_staff','qhub_org_invitations',
    'qhub_billing_customers','qhub_subscriptions','qhub_billing_webhook_events','qhub_usage_credits',
    'qhub_usage_ledger','qhub_project_entitlements','qhub_onboarding_state','qhub_acknowledgments',
    'qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);

    IF NOT EXISTS (
      SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname=t||'_service_only'
    ) THEN
      EXECUTE format(
        'CREATE POLICY %1$s_service_only ON public.%1$s '
        || 'AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false) WITH CHECK (false)', t);
    END IF;

    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon, authenticated', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE public.%I TO service_role', t);
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION public.qhub_consume_build_credit(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_consume_build_credit(TEXT, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_claim_webhook_event(TEXT, TEXT, TEXT, BOOLEAN, TEXT, BIGINT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_claim_webhook_event(TEXT, TEXT, TEXT, BOOLEAN, TEXT, BIGINT, TEXT) TO service_role;

-- ─── Seed plan identity (idempotent) ────────────────────────────────────────
INSERT INTO public.qhub_commercial_plans (plan_id, display_name, active)
VALUES ('builder_beta','QHub Builder Beta',TRUE), ('guided_builder','QHub Guided Builder',TRUE)
ON CONFLICT (plan_id) DO NOTHING;

-- ─── Readiness verifier ─────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema()
RETURNS JSONB
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_failed TEXT[] := ARRAY[]::TEXT[];
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans','qhub_org_members','qhub_quantex_staff','qhub_org_invitations',
    'qhub_billing_customers','qhub_subscriptions','qhub_billing_webhook_events','qhub_usage_credits',
    'qhub_usage_ledger','qhub_project_entitlements','qhub_onboarding_state','qhub_acknowledgments',
    'qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit'
  ];
BEGIN
  -- Every table must exist, have RLS enabled, a RESTRICTIVE service-only policy,
  -- and no anon/authenticated privileges.
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      v_failed := v_failed || ('missing_table:'||t); CONTINUE;
    END IF;
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      v_failed := v_failed || ('rls_disabled:'||t);
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t
        AND policyname=t||'_service_only' AND permissive='RESTRICTIVE'
    ) THEN
      v_failed := v_failed || ('policy_missing:'||t);
    END IF;
    IF has_table_privilege('anon', ('public.'||t)::regclass, 'SELECT')
       OR has_table_privilege('authenticated', ('public.'||t)::regclass, 'INSERT') THEN
      v_failed := v_failed || ('browser_grant:'||t);
    END IF;
    IF NOT has_table_privilege('service_role', ('public.'||t)::regclass, 'INSERT') THEN
      v_failed := v_failed || ('service_grant_missing:'||t);
    END IF;
  END LOOP;

  -- Critical unique constraints / indexes.
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='uq_qhub_guided_one_active_project') THEN
    v_failed := v_failed || 'missing_index:guided_one_active'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_billing_customers'::regclass AND contype='u'
      AND conkey @> (SELECT ARRAY[attnum] FROM pg_attribute WHERE attrelid='public.qhub_billing_customers'::regclass AND attname='provider_customer_id')
  ) THEN
    v_failed := v_failed || 'missing_unique:customer_mapping'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_subscriptions'::regclass AND contype='u'
      AND conkey @> (SELECT ARRAY[attnum] FROM pg_attribute WHERE attrelid='public.qhub_subscriptions'::regclass AND attname='provider_subscription_id')
  ) THEN
    v_failed := v_failed || 'missing_unique:subscription_mapping'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_usage_ledger'::regclass AND contype='u'
  ) THEN
    v_failed := v_failed || 'missing_unique:ledger_idempotency'::text;
  END IF;

  -- FK: subscription.plan_id → plans, manual review decided_by → staff.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_subscriptions'::regclass AND contype='f'
  ) THEN
    v_failed := v_failed || 'missing_fk:subscription_plan'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass AND contype='f'
  ) THEN
    v_failed := v_failed || 'missing_fk:review_staff'::text;
  END IF;

  -- Credit + webhook RPCs: exist, SECURITY DEFINER, fixed search_path, service-only.
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_consume_build_credit'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'credit_rpc_contract'::text; END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_claim_webhook_event'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'webhook_rpc_contract'::text; END IF;

  IF has_function_privilege('anon','public.qhub_consume_build_credit(text,text,text,text)','EXECUTE')
     OR has_function_privilege('authenticated','public.qhub_consume_build_credit(text,text,text,text)','EXECUTE') THEN
    v_failed := v_failed || 'credit_rpc_browser_exec'::text;
  END IF;

  -- Webhook inbox state contract present.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_billing_webhook_events'::regclass
      AND contype='c' AND pg_get_constraintdef(oid) LIKE '%FAILED_RETRYABLE%'
  ) THEN
    v_failed := v_failed || 'webhook_state_contract'::text;
  END IF;

  RETURN jsonb_build_object(
    'expected_version', '2026-07-29.commercial-launch-r2',
    'ready', (cardinality(v_failed) = 0),
    'failed', to_jsonb(v_failed)
  );
END;
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_commercial_schema() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role;

COMMIT;
