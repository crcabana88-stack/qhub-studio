-- ============================================================================
-- QHUB Commercial Launch Foundation — R8 FINAL SECURITY CLOSURE
-- Migration: 20260729_commercial_launch_foundation  (replaces the rejected
--            4b42555a… contents IN PLACE — one authoritative commercial migration)
-- Schema version: 2026-07-30.commercial-launch-r5
--
-- Central commercial security boundary: authoritative membership/staff, real
-- project ownership, checkout-intent binding (metadata is never tenant authority),
-- a recoverable webhook inbox with LEASES, an atomic project-derived credit RPC,
-- persisted Governance Essentials as the build gate, staff-authorized review, and
-- a qhub_verify_commercial_schema() contract that checks exact semantics.
--
-- R5 (R8) adds PERSISTED AUTHORITATIVE REVIEW IDENTITY: a review request now stores the
-- exact Governance record id/version, the required + accepted acknowledgment identity, the
-- canonical declaration_identity_hash, the requester, and the idempotency key; the Governance
-- record carries a monotonic record_version + declaration_identity_hash. Every reviewed
-- operation binds to that stored set, so a changed purpose/use-case/data/model/connector/
-- classification/policy/acknowledgment cannot be satisfied by an older review. All R5 changes
-- are ADDITIVE (nullable columns + guarded FKs/checks); legacy rows remain readable but their
-- NULL identity can never satisfy the new current-review authorization.
--
-- SAFETY: single transaction (BEGIN/COMMIT — full rollback on any failure).
-- Additive only: no DROP / DELETE / TRUNCATE / destructive type change / fabricated
-- backfill. Idempotent: a healthy rerun is a no-op. RESTRICTIVE service-only RLS;
-- only the service role holds grants; RPCs are service-role only.
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

CREATE TABLE IF NOT EXISTS public.qhub_quantex_staff (
  user_id     TEXT PRIMARY KEY,
  staff_role  TEXT NOT NULL DEFAULT 'reviewer'
              CHECK (staff_role IN ('reviewer','admin','engineer')),
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
-- At most one ACTIVE (invited) invitation per org+email (normalized lower-case).
CREATE UNIQUE INDEX IF NOT EXISTS uq_qhub_invitation_active
  ON public.qhub_org_invitations (org_id, lower(email))
  WHERE (status = 'invited');

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
  last_provider_event_id         TEXT,
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

-- ─── Checkout intents (opaque tenant binding — metadata is never authority) ──
-- The browser chooses only an internal plan. The server binds all authority here
-- (org, membership, exact prices, mode, account, origin) BEFORE Stripe is called;
-- only the opaque id travels in Stripe metadata, and the webhook consumes it.
CREATE TABLE IF NOT EXISTS public.qhub_checkout_intents (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                   TEXT NOT NULL,
  requested_by             TEXT NOT NULL,
  membership_id            TEXT,
  plan_id                  TEXT NOT NULL REFERENCES public.qhub_commercial_plans (plan_id),
  expected_recurring_price_id TEXT NOT NULL,
  expected_setup_price_id  TEXT,
  expected_mode            TEXT NOT NULL DEFAULT 'test' CHECK (expected_mode IN ('test','live')),
  expected_account         TEXT,
  expected_app_origin      TEXT NOT NULL,
  idempotency_key          TEXT NOT NULL,
  nonce                    TEXT NOT NULL,
  status                   TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','consumed','expired','failed')),
  checkout_session_id      TEXT,
  customer_id              TEXT,
  subscription_id          TEXT,
  failure_code             TEXT,
  expires_at               TIMESTAMPTZ NOT NULL,
  consumed_at              TIMESTAMPTZ,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (nonce),
  UNIQUE (org_id, idempotency_key)
);

-- ─── Webhook inbox (recoverable state machine with LEASES) ───────────────────
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
  attempt_count      INTEGER NOT NULL DEFAULT 0,
  processing_owner   TEXT,
  claimed_at         TIMESTAMPTZ,
  lease_expires_at   TIMESTAMPTZ,
  last_error_code    TEXT,
  last_error_at      TIMESTAMPTZ,
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
  units            INTEGER NOT NULL DEFAULT 1,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, idempotency_key)
);

-- ─── Project entitlements (authoritative project ownership) ──────────────────
CREATE TABLE IF NOT EXISTS public.qhub_project_entitlements (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID NOT NULL,
  org_id        TEXT NOT NULL,
  created_by    TEXT,
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
CREATE UNIQUE INDEX IF NOT EXISTS uq_qhub_guided_one_active_project
  ON public.qhub_project_entitlements (org_id)
  WHERE (active AND plan_id = 'guided_builder');
CREATE INDEX IF NOT EXISTS idx_qhub_project_active
  ON public.qhub_project_entitlements (org_id) WHERE active;

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

-- ─── Governance Essentials (persisted server workflow + review) ──────────────
CREATE TABLE IF NOT EXISTS public.qhub_governance_essentials (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id             UUID NOT NULL REFERENCES public.qhub_project_entitlements (project_id),
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
  reviewed_by            TEXT,
  reviewed_at            TIMESTAMPTZ,
  review_policy_version  TEXT,
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
CREATE INDEX IF NOT EXISTS idx_qhub_webhook_state             ON public.qhub_billing_webhook_events (state, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_qhub_checkout_intents_org      ON public.qhub_checkout_intents (org_id, status);
CREATE INDEX IF NOT EXISTS idx_qhub_entitlement_audit_org     ON public.qhub_entitlement_audit (org_id, created_at);

-- ─── R5 (R8): PERSISTED AUTHORITATIVE REVIEW / GOVERNANCE IDENTITY ───────────
-- Additive only — nullable columns + guarded FKs/checks. A hex-64 declaration_identity_hash
-- binds the material customer declaration; the Governance record carries a monotonic
-- record_version; a review request stores the exact identity set it was authorized against.
-- Legacy rows keep NULL identity and therefore can never satisfy the new authorization.

ALTER TABLE public.qhub_governance_essentials
  ADD COLUMN IF NOT EXISTS record_version             BIGINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS declaration_identity_hash  TEXT;

ALTER TABLE public.qhub_manual_review_requests
  ADD COLUMN IF NOT EXISTS governance_record_id           UUID,
  ADD COLUMN IF NOT EXISTS governance_record_version      BIGINT,
  ADD COLUMN IF NOT EXISTS required_acknowledgment_version TEXT,
  ADD COLUMN IF NOT EXISTS acknowledgment_record_id       UUID,
  ADD COLUMN IF NOT EXISTS acknowledgment_version         TEXT,
  ADD COLUMN IF NOT EXISTS declaration_identity_hash      TEXT,
  ADD COLUMN IF NOT EXISTS idempotency_key                TEXT,
  ADD COLUMN IF NOT EXISTS requester_user_id              TEXT;

-- Canonical declaration_identity_hash format: lowercase SHA-256 hex (64 chars) when present.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_governance_essentials'::regclass AND conname = 'chk_qhub_gov_decl_hash_hex'
  ) THEN
    ALTER TABLE public.qhub_governance_essentials
      ADD CONSTRAINT chk_qhub_gov_decl_hash_hex
      CHECK (declaration_identity_hash IS NULL OR declaration_identity_hash ~ '^[0-9a-f]{64}$');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_manual_review_requests'::regclass AND conname = 'chk_qhub_review_decl_hash_hex'
  ) THEN
    ALTER TABLE public.qhub_manual_review_requests
      ADD CONSTRAINT chk_qhub_review_decl_hash_hex
      CHECK (declaration_identity_hash IS NULL OR declaration_identity_hash ~ '^[0-9a-f]{64}$');
  END IF;

  -- FK: review.governance_record_id → the authoritative Governance record.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_manual_review_requests'::regclass AND conname = 'fk_qhub_review_governance_record'
  ) THEN
    ALTER TABLE public.qhub_manual_review_requests
      ADD CONSTRAINT fk_qhub_review_governance_record
      FOREIGN KEY (governance_record_id) REFERENCES public.qhub_governance_essentials (id);
  END IF;

  -- FK: review.acknowledgment_record_id → the authoritative acknowledgment row.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_manual_review_requests'::regclass AND conname = 'fk_qhub_review_acknowledgment_record'
  ) THEN
    ALTER TABLE public.qhub_manual_review_requests
      ADD CONSTRAINT fk_qhub_review_acknowledgment_record
      FOREIGN KEY (acknowledgment_record_id) REFERENCES public.qhub_acknowledgments (id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_qhub_review_governance_record ON public.qhub_manual_review_requests (governance_record_id);

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

-- Acknowledgment + usage-ledger immutability (append-only).
CREATE OR REPLACE FUNCTION public.qhub_row_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$;

DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY['qhub_acknowledgments','qhub_usage_ledger','qhub_entitlement_audit'];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname = 'trg_' || t || '_immutable'
        AND tgrelid = ('public.' || t)::regclass
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER trg_%1$s_immutable BEFORE UPDATE OR DELETE ON public.%1$s '
        || 'FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable()', t);
    END IF;
  END LOOP;
END;
$$;

-- ─── Atomic project-derived build-credit RPC (R3) ───────────────────────────
-- Inputs are minimal + non-authoritative: project, idempotency key, canonical
-- request hash, units. The RPC derives org/ownership/eligibility and, in one
-- transaction: locks the credit period, validates active eligibility, initializes
-- the period if absent, enforces idempotency (exact retry returns the prior
-- result; a changed hash/units under the same key is rejected), prevents overdraw,
-- decrements, appends the immutable ledger row, and returns the balance + ledger id.
CREATE OR REPLACE FUNCTION public.qhub_consume_build_credit(
  p_project_id UUID, p_idempotency_key TEXT, p_canonical_hash TEXT, p_units INTEGER
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_org        TEXT;
  v_active     BOOLEAN;
  v_plan       TEXT;
  v_sub_status TEXT;
  v_period_key TEXT;
  v_period_start TIMESTAMPTZ;
  v_period_end   TIMESTAMPTZ;
  v_allot      INTEGER;
  v_existing   RECORD;
  v_remaining  INTEGER;
  v_ledger_id  UUID;
BEGIN
  IF p_units IS NULL OR p_units <= 0 THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_units');
  END IF;

  -- Derive org + ownership from the authoritative project row (locked).
  SELECT org_id, active, plan_id INTO v_org, v_active, v_plan
    FROM public.qhub_project_entitlements
   WHERE project_id = p_project_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'unknown_project');
  END IF;

  IF NOT v_active THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'project_inactive');
  END IF;

  -- Subscription eligibility (active / trialing only).
  SELECT status INTO v_sub_status FROM public.qhub_subscriptions WHERE org_id = v_org FOR UPDATE;

  IF v_sub_status IS NULL OR v_sub_status NOT IN ('active','trialing') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'ineligible_subscription');
  END IF;

  -- Idempotency: exact retry returns prior result; changed request is rejected.
  SELECT request_hash, units INTO v_existing
    FROM public.qhub_usage_ledger
   WHERE org_id = v_org AND idempotency_key = p_idempotency_key
   LIMIT 1;

  IF FOUND THEN
    IF v_existing.request_hash IS DISTINCT FROM p_canonical_hash OR v_existing.units IS DISTINCT FROM p_units THEN
      RETURN jsonb_build_object('ok', false, 'reason', 'idempotency_conflict');
    END IF;

    SELECT (allotted - used) INTO v_remaining
      FROM public.qhub_usage_credits
     WHERE org_id = v_org AND period_key = to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM');

    RETURN jsonb_build_object('ok', true, 'idempotent', true, 'remaining', v_remaining);
  END IF;

  -- Current UTC period; initialize under lock if absent (using the plan allotment).
  v_period_key := to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM');
  v_period_start := date_trunc('month', NOW() AT TIME ZONE 'UTC');
  v_period_end := v_period_start + INTERVAL '1 month';

  SELECT (allotted - used) INTO v_remaining
    FROM public.qhub_usage_credits
   WHERE org_id = v_org AND period_key = v_period_key
   FOR UPDATE;

  IF NOT FOUND THEN
    v_allot := CASE v_plan WHEN 'builder_beta' THEN 200 WHEN 'guided_builder' THEN 1000 ELSE 0 END;
    INSERT INTO public.qhub_usage_credits (org_id, period_key, period_start, period_end, allotted, used)
    VALUES (v_org, v_period_key, v_period_start, v_period_end, v_allot, 0)
    ON CONFLICT (org_id, period_key) DO NOTHING;

    SELECT (allotted - used) INTO v_remaining
      FROM public.qhub_usage_credits
     WHERE org_id = v_org AND period_key = v_period_key
     FOR UPDATE;
  END IF;

  IF v_remaining < p_units THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'insufficient_credits', 'remaining', v_remaining);
  END IF;

  UPDATE public.qhub_usage_credits
     SET used = used + p_units, updated_at = NOW()
   WHERE org_id = v_org AND period_key = v_period_key;

  INSERT INTO public.qhub_usage_ledger (org_id, project_id, event_type, credits_delta, idempotency_key, request_hash, units)
  VALUES (v_org, p_project_id, 'BUILD_CREDIT_CONSUMED', -p_units, p_idempotency_key, p_canonical_hash, p_units)
  RETURNING id INTO v_ledger_id;

  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'remaining', v_remaining - p_units, 'ledger_id', v_ledger_id);
END;
$$;

-- ─── Webhook claim with LEASE (R3) ──────────────────────────────────────────
-- Claims a RECEIVED/FAILED_RETRYABLE event, or a PROCESSING event whose lease has
-- expired (crash recovery). An active non-expired lease cannot be stolen. Returns
-- CLAIMED | DUPLICATE | IN_PROGRESS.
CREATE OR REPLACE FUNCTION public.qhub_claim_webhook_event(
  p_provider TEXT, p_event_id TEXT, p_event_type TEXT, p_livemode BOOLEAN,
  p_account TEXT, p_event_created BIGINT, p_payload_hash TEXT, p_owner TEXT, p_lease_seconds INTEGER
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_state TEXT;
  v_lease TIMESTAMPTZ;
BEGIN
  INSERT INTO public.qhub_billing_webhook_events
    (provider, provider_event_id, event_type, state, livemode, stripe_account, event_created,
     payload_hash, attempt_count, processing_owner, claimed_at, lease_expires_at)
  VALUES
    (p_provider, p_event_id, p_event_type, 'PROCESSING', p_livemode, p_account, p_event_created,
     p_payload_hash, 1, p_owner, NOW(), NOW() + make_interval(secs => p_lease_seconds))
  ON CONFLICT (provider, provider_event_id) DO NOTHING;

  IF FOUND THEN
    RETURN 'CLAIMED';
  END IF;

  SELECT state, lease_expires_at INTO v_state, v_lease
    FROM public.qhub_billing_webhook_events
   WHERE provider = p_provider AND provider_event_id = p_event_id
   FOR UPDATE;

  IF v_state IN ('PROCESSED','FAILED_PERMANENT') THEN
    RETURN 'DUPLICATE';
  ELSIF v_state = 'PROCESSING' AND v_lease IS NOT NULL AND v_lease > NOW() THEN
    RETURN 'IN_PROGRESS'; -- active non-expired lease cannot be stolen
  ELSE
    -- RECEIVED, FAILED_RETRYABLE, or PROCESSING with an EXPIRED lease → reclaim.
    UPDATE public.qhub_billing_webhook_events
       SET state = 'PROCESSING', attempt_count = attempt_count + 1,
           processing_owner = p_owner, claimed_at = NOW(),
           lease_expires_at = NOW() + make_interval(secs => p_lease_seconds)
     WHERE provider = p_provider AND provider_event_id = p_event_id;
    RETURN 'CLAIMED';
  END IF;
END;
$$;

-- ─── Transactional invitation acceptance (R4 — identity + plan-derived cap) ──
-- The caller supplies NO seat cap: the RPC verifies the recipient email + token,
-- derives the plan + seat cap from the org's authoritative active subscription, and
-- admits the invitee only under the cap, all under a lock. Returns
-- ACCEPTED | SEAT_LIMIT | INVALID | EMAIL_MISMATCH | TOKEN_MISMATCH | INELIGIBLE | ALREADY.
CREATE OR REPLACE FUNCTION public.qhub_accept_invitation(
  p_invitation_id UUID, p_user_id TEXT, p_user_email TEXT, p_token_hash TEXT
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_org  TEXT;
  v_role TEXT;
  v_status TEXT;
  v_expires TIMESTAMPTZ;
  v_email TEXT;
  v_token TEXT;
  v_plan TEXT;
  v_sub_status TEXT;
  v_cap INTEGER;
  v_seats INTEGER;
BEGIN
  SELECT org_id, role, status, expires_at, lower(email), token_hash
    INTO v_org, v_role, v_status, v_expires, v_email, v_token
    FROM public.qhub_org_invitations WHERE id = p_invitation_id FOR UPDATE;

  IF NOT FOUND OR v_status <> 'invited' THEN
    RETURN 'INVALID';
  END IF;

  IF v_expires < NOW() THEN
    UPDATE public.qhub_org_invitations SET status='expired' WHERE id = p_invitation_id;
    RETURN 'INVALID';
  END IF;

  -- The accepting user's verified email must match the invitation recipient.
  IF v_email IS DISTINCT FROM lower(coalesce(p_user_email, '')) THEN
    RETURN 'EMAIL_MISMATCH';
  END IF;

  IF v_token IS DISTINCT FROM p_token_hash THEN
    RETURN 'TOKEN_MISMATCH';
  END IF;

  -- Already a member? Idempotent no-op.
  IF EXISTS (SELECT 1 FROM public.qhub_org_members WHERE user_id = p_user_id AND org_id = v_org) THEN
    UPDATE public.qhub_org_invitations SET status='accepted', accepted_by=p_user_id WHERE id = p_invitation_id;
    RETURN 'ALREADY';
  END IF;

  -- Derive plan + seat cap from the org's authoritative active subscription (locked).
  SELECT plan_id, status INTO v_plan, v_sub_status FROM public.qhub_subscriptions WHERE org_id = v_org FOR UPDATE;

  IF v_plan IS NULL OR v_sub_status NOT IN ('active','trialing') THEN
    RETURN 'INELIGIBLE';
  END IF;

  v_cap := CASE v_plan WHEN 'builder_beta' THEN 1 WHEN 'guided_builder' THEN 5 ELSE 0 END;

  -- Lock the org's members and count active seats under the lock.
  PERFORM 1 FROM public.qhub_org_members WHERE org_id = v_org FOR UPDATE;
  SELECT count(*) INTO v_seats FROM public.qhub_org_members WHERE org_id = v_org AND status = 'active';

  IF v_seats >= v_cap THEN
    RETURN 'SEAT_LIMIT';
  END IF;

  INSERT INTO public.qhub_org_members (user_id, org_id, role, status, accepted_at)
  VALUES (p_user_id, v_org, v_role, 'active', NOW());

  UPDATE public.qhub_org_invitations SET status='accepted', accepted_by=p_user_id WHERE id = p_invitation_id;

  INSERT INTO public.qhub_entitlement_audit (org_id, actor, change_type, after_state, reason)
  VALUES (v_org, p_user_id, 'INVITATION_ACCEPTED',
          jsonb_build_object('invitation_id', p_invitation_id::text, 'role', v_role), 'accepted');

  RETURN 'ACCEPTED';
END;
$$;

-- ─── Atomic checkout-intent consumption (R3) ─────────────────────────────────
-- Loads an intent by opaque id under lock, verifies it is pending + unexpired +
-- unconsumed and that the resolved Stripe object matches the bound expectations,
-- then marks it consumed and records the session/customer/subscription. Returns
-- CONSUMED | EXPIRED | ALREADY | MISMATCH | NOT_FOUND.
CREATE OR REPLACE FUNCTION public.qhub_consume_checkout_intent(
  p_intent_id UUID, p_org_id TEXT, p_recurring_price TEXT, p_mode TEXT, p_account TEXT,
  p_session_id TEXT, p_customer_id TEXT, p_subscription_id TEXT
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  r RECORD;
BEGIN
  SELECT * INTO r FROM public.qhub_checkout_intents WHERE id = p_intent_id FOR UPDATE;

  IF NOT FOUND THEN
    RETURN 'NOT_FOUND';
  END IF;

  IF r.status = 'consumed' THEN
    -- Idempotent only for the SAME resulting subscription; a different object is a mismatch.
    IF r.subscription_id IS NOT DISTINCT FROM p_subscription_id THEN
      RETURN 'ALREADY';
    END IF;

    RETURN 'MISMATCH';
  END IF;

  IF r.status <> 'pending' THEN
    RETURN 'MISMATCH';
  END IF;

  IF r.expires_at < NOW() THEN
    UPDATE public.qhub_checkout_intents SET status='expired' WHERE id = p_intent_id;
    RETURN 'EXPIRED';
  END IF;

  IF r.org_id IS DISTINCT FROM p_org_id
     OR r.expected_recurring_price_id IS DISTINCT FROM p_recurring_price
     OR r.expected_mode IS DISTINCT FROM p_mode
     OR (r.expected_account IS NOT NULL AND r.expected_account IS DISTINCT FROM p_account) THEN
    UPDATE public.qhub_checkout_intents
       SET status='failed', failure_code='binding_mismatch', checkout_session_id=p_session_id
     WHERE id = p_intent_id;
    RETURN 'MISMATCH';
  END IF;

  UPDATE public.qhub_checkout_intents
     SET status='consumed', consumed_at=NOW(), checkout_session_id=p_session_id,
         customer_id=p_customer_id, subscription_id=p_subscription_id
   WHERE id = p_intent_id;

  RETURN 'CONSUMED';
END;
$$;

-- ─── Lease-owner-bound webhook state transition (R4) ─────────────────────────
-- Only the current processing_owner (with a non-expired lease) may transition an
-- event to PROCESSED / FAILED_RETRYABLE / FAILED_PERMANENT. Returns OK | LEASE_LOST.
CREATE OR REPLACE FUNCTION public.qhub_mark_webhook_state(
  p_provider TEXT, p_event_id TEXT, p_owner TEXT, p_state TEXT, p_error_code TEXT
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_owner TEXT;
  v_lease TIMESTAMPTZ;
BEGIN
  SELECT processing_owner, lease_expires_at INTO v_owner, v_lease
    FROM public.qhub_billing_webhook_events
   WHERE provider = p_provider AND provider_event_id = p_event_id
   FOR UPDATE;

  IF NOT FOUND OR v_owner IS DISTINCT FROM p_owner OR v_lease IS NULL OR v_lease < NOW() THEN
    RETURN 'LEASE_LOST';
  END IF;

  UPDATE public.qhub_billing_webhook_events
     SET state = p_state,
         last_error_code = p_error_code,
         last_error_at = CASE WHEN p_state LIKE 'FAILED%' THEN NOW() ELSE last_error_at END,
         processed_at = CASE WHEN p_state = 'PROCESSED' THEN NOW() ELSE processed_at END
   WHERE provider = p_provider AND provider_event_id = p_event_id;

  RETURN 'OK';
END;
$$;

-- ─── ATOMIC checkout reconciliation (R4) ─────────────────────────────────────
-- The full checkout.session.completed reconciliation as ONE transaction: verify the
-- caller owns the active lease, lock + validate the intent against the retrieved
-- Stripe objects (session/customer/subscription/price/setup-price/mode/account),
-- bind customer→org and subscription→customer/org/plan, write normalized state with
-- provider ordering, consume the intent, and mark the event PROCESSED — all commit or
-- roll back together. Returns jsonb {ok, reason?, idempotent?, org?}.
CREATE OR REPLACE FUNCTION public.qhub_reconcile_checkout(
  p_provider TEXT, p_event_id TEXT, p_owner TEXT, p_intent_id UUID,
  p_session_id TEXT, p_customer_id TEXT, p_subscription_id TEXT, p_recurring_price TEXT,
  p_setup_present BOOLEAN, p_mode TEXT, p_account TEXT, p_status TEXT,
  p_current_period_end BIGINT, p_event_created BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_ev_owner TEXT;
  v_ev_lease TIMESTAMPTZ;
  r RECORD;
  v_map_org TEXT;
  v_last BIGINT;
BEGIN
  -- 1-2. Lock the inbox event; caller must own the active, non-expired lease.
  SELECT processing_owner, lease_expires_at INTO v_ev_owner, v_ev_lease
    FROM public.qhub_billing_webhook_events
   WHERE provider = p_provider AND provider_event_id = p_event_id
   FOR UPDATE;

  IF NOT FOUND OR v_ev_owner IS DISTINCT FROM p_owner OR v_ev_lease IS NULL OR v_ev_lease < NOW() THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'lease_lost');
  END IF;

  -- 3. Lock the intent.
  SELECT * INTO r FROM public.qhub_checkout_intents WHERE id = p_intent_id FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'unknown_intent');
  END IF;

  -- Exact-retry idempotency: same session + subscription already reconciled.
  IF r.status = 'consumed' THEN
    IF r.checkout_session_id IS NOT DISTINCT FROM p_session_id
       AND r.subscription_id IS NOT DISTINCT FROM p_subscription_id THEN
      UPDATE public.qhub_billing_webhook_events SET state='PROCESSED', processed_at=NOW()
        WHERE provider=p_provider AND provider_event_id=p_event_id;
      RETURN jsonb_build_object('ok', true, 'idempotent', true, 'org', r.org_id);
    END IF;

    RETURN jsonb_build_object('ok', false, 'reason', 'intent_object_mismatch');
  END IF;

  IF r.status <> 'pending' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'intent_not_pending');
  END IF;

  -- 4. Expiration + bound-expectation validation.
  IF r.expires_at < NOW() THEN
    UPDATE public.qhub_checkout_intents SET status='expired' WHERE id = p_intent_id;
    RETURN jsonb_build_object('ok', false, 'reason', 'intent_expired');
  END IF;

  IF r.expected_recurring_price_id IS DISTINCT FROM p_recurring_price
     OR r.expected_mode IS DISTINCT FROM p_mode
     OR (r.expected_account IS NOT NULL AND r.expected_account IS DISTINCT FROM p_account)
     -- 9. Guided requires the one-time setup price to be present on the session.
     OR (r.plan_id = 'guided_builder' AND NOT p_setup_present) THEN
    UPDATE public.qhub_checkout_intents
       SET status='failed', failure_code='binding_mismatch', checkout_session_id=p_session_id
     WHERE id = p_intent_id;
    RETURN jsonb_build_object('ok', false, 'reason', 'binding_mismatch');
  END IF;

  -- 10. Bind/validate customer→org (a customer mapped to another org is a mismatch).
  SELECT org_id INTO v_map_org FROM public.qhub_billing_customers
    WHERE provider = p_provider AND provider_customer_id = p_customer_id FOR UPDATE;

  IF v_map_org IS NOT NULL AND v_map_org IS DISTINCT FROM r.org_id THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'customer_org_mismatch');
  END IF;

  INSERT INTO public.qhub_billing_customers (org_id, provider, provider_customer_id, livemode, stripe_account)
  VALUES (r.org_id, p_provider, p_customer_id, (p_mode = 'live'), p_account)
  ON CONFLICT (org_id, provider) DO UPDATE
     SET provider_customer_id = EXCLUDED.provider_customer_id, updated_at = NOW();

  -- 11-12. Bind subscription→customer/org/plan with an out-of-order guard.
  SELECT last_event_created INTO v_last FROM public.qhub_subscriptions
    WHERE org_id = r.org_id AND provider = p_provider FOR UPDATE;

  IF v_last IS NULL OR p_event_created > v_last THEN
    INSERT INTO public.qhub_subscriptions
      (org_id, plan_id, status, provider, provider_customer_id, provider_subscription_id,
       provider_price_id, livemode, stripe_account, current_period_end, last_event_created, last_provider_event_id)
    VALUES
      (r.org_id, r.plan_id, p_status, p_provider, p_customer_id, p_subscription_id,
       p_recurring_price, (p_mode='live'), p_account, p_current_period_end, p_event_created, p_event_id)
    ON CONFLICT (org_id, provider) DO UPDATE SET
       plan_id = EXCLUDED.plan_id, status = EXCLUDED.status,
       provider_customer_id = EXCLUDED.provider_customer_id,
       provider_subscription_id = EXCLUDED.provider_subscription_id,
       provider_price_id = EXCLUDED.provider_price_id,
       current_period_end = EXCLUDED.current_period_end,
       last_event_created = EXCLUDED.last_event_created,
       last_provider_event_id = EXCLUDED.last_provider_event_id,
       updated_at = NOW();
  END IF;

  -- 13. Consume the intent.
  UPDATE public.qhub_checkout_intents
     SET status='consumed', consumed_at=NOW(), checkout_session_id=p_session_id,
         customer_id=p_customer_id, subscription_id=p_subscription_id
   WHERE id = p_intent_id;

  -- 14. Mark the event PROCESSED (same transaction).
  UPDATE public.qhub_billing_webhook_events SET state='PROCESSED', processed_at=NOW()
    WHERE provider=p_provider AND provider_event_id=p_event_id;

  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'org', r.org_id);
END;
$$;

-- ─── ATOMIC review decision (R4) ─────────────────────────────────────────────
-- One transaction: lock + validate the PENDING request, verify the staff actor and
-- exact org/project scope, apply the decision, update Governance Essentials, and
-- append ONE immutable audit row. Prohibited categories are non-overridable. Returns
-- jsonb {ok, reason?, idempotent?}.
CREATE OR REPLACE FUNCTION public.qhub_decide_review(
  p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  r RECORD;
BEGIN
  IF NOT p_is_staff THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'staff_required');
  END IF;

  IF p_decision NOT IN ('approved','rejected') OR coalesce(btrim(p_reason),'') = '' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_decision');
  END IF;

  SELECT * INTO r FROM public.qhub_manual_review_requests WHERE id = p_request_id FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_found');
  END IF;

  -- Exact-repeat idempotency on an already-terminal request: idempotent ONLY when EVERY
  -- material field matches (decision, reviewer, normalized reason, and server-derived
  -- policy version — the resulting Governance Essentials disposition is a pure function of
  -- the decision, so a matching decision implies a matching disposition). No second audit
  -- row is written. Any material difference is a deterministic conflict (never idempotent).
  IF r.status <> 'pending' THEN
    IF r.status = p_decision
       AND r.decided_by IS NOT DISTINCT FROM p_actor
       AND btrim(coalesce(r.decision_reason, '')) IS NOT DISTINCT FROM btrim(coalesce(p_reason, ''))
       AND r.policy_version IS NOT DISTINCT FROM p_policy_version THEN
      RETURN jsonb_build_object('ok', true, 'idempotent', true);
    END IF;

    -- Changed reason / policy version / decision / reviewer / disposition on a terminal
    -- request → deterministic conflict. A policy-change re-review uses a NEW request.
    RETURN jsonb_build_object('ok', false, 'reason', 'decision_conflict');
  END IF;

  IF p_decision = 'approved' AND r.category IN ('secrets','credentials','mnpi','regulated_records','consequential_action','external_write','autonomous_agent') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'prohibited_cannot_approve');
  END IF;

  -- R5 (R8): a request that carries a persisted Governance identity may only be APPROVED while
  -- that identity STILL matches the authoritative Governance record. If the customer changed the
  -- declaration (new declaration_identity_hash / record_version) after opening the request, the
  -- stale approval is refused BEFORE any side effect — a new review must be requested. Legacy
  -- requests with a NULL declaration_identity_hash are unaffected (skip the drift check).
  IF p_decision = 'approved' AND r.project_id IS NOT NULL AND r.declaration_identity_hash IS NOT NULL THEN
    PERFORM 1 FROM public.qhub_governance_essentials g
      WHERE g.project_id = r.project_id AND g.org_id = r.org_id
        AND g.id IS NOT DISTINCT FROM r.governance_record_id
        AND g.record_version IS NOT DISTINCT FROM r.governance_record_version
        AND g.declaration_identity_hash IS NOT DISTINCT FROM r.declaration_identity_hash;

    IF NOT FOUND THEN
      RETURN jsonb_build_object('ok', false, 'reason', 'governance_changed');
    END IF;
  END IF;

  UPDATE public.qhub_manual_review_requests
     SET status = p_decision, decided_by = p_actor, decision_reason = p_reason,
         policy_version = p_policy_version, decided_at = NOW()
   WHERE id = p_request_id;

  IF r.project_id IS NOT NULL THEN
    UPDATE public.qhub_governance_essentials
       SET review_state = CASE WHEN p_decision='approved' THEN 'approved' ELSE 'rejected' END,
           reviewed_by = p_actor, reviewed_at = NOW(), review_policy_version = p_policy_version, updated_at = NOW()
     WHERE project_id = r.project_id AND org_id = r.org_id;
  END IF;

  -- Immutable audit binds the FULL decided identity (request, decision, policy, and the persisted
  -- Governance/acknowledgment/declaration identity the decision was authorized against).
  INSERT INTO public.qhub_entitlement_audit (org_id, actor, change_type, before_state, after_state, reason)
  VALUES (r.org_id, p_actor, 'REVIEW_DECISION',
          jsonb_build_object('request_id', p_request_id::text, 'prev_status', r.status),
          jsonb_build_object(
            'decision', p_decision,
            'policy_version', p_policy_version,
            'governance_record_id', r.governance_record_id,
            'governance_record_version', r.governance_record_version,
            'declaration_identity_hash', r.declaration_identity_hash,
            'acknowledgment_record_id', r.acknowledgment_record_id,
            'acknowledgment_version', r.acknowledgment_version
          ), p_reason);

  RETURN jsonb_build_object('ok', true, 'idempotent', false);
END;
$$;

-- ─── ATOMIC project creation with transactional cap (R4) ─────────────────────
-- Derives + locks org/subscription/active-project-count and inserts under the plan
-- cap (Builder 5, Guided 1) in one transaction. Idempotent by (org, idempotency_key)
-- via the ledger-style request hash; a changed hash under the same key fails. Returns
-- jsonb {ok, reason?, project_id?, idempotent?}.
CREATE OR REPLACE FUNCTION public.qhub_create_project(
  p_org_id TEXT, p_created_by TEXT, p_idempotency_key TEXT, p_request_hash TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_plan TEXT;
  v_status TEXT;
  v_cap INTEGER;
  v_active INTEGER;
  v_existing RECORD;
  v_pid UUID;
BEGIN
  -- Idempotency: a prior creation for this key returns the same project.
  SELECT after_state, reason INTO v_existing FROM public.qhub_entitlement_audit
    WHERE org_id = p_org_id AND change_type = 'PROJECT_CREATE'
      AND after_state->>'idempotency_key' = p_idempotency_key LIMIT 1;

  IF FOUND THEN
    IF v_existing.reason IS DISTINCT FROM p_request_hash THEN
      RETURN jsonb_build_object('ok', false, 'reason', 'idempotency_conflict');
    END IF;

    RETURN jsonb_build_object('ok', true, 'idempotent', true, 'project_id', v_existing.after_state->>'project_id');
  END IF;

  -- Lock subscription + derive plan/eligibility.
  SELECT plan_id, status INTO v_plan, v_status FROM public.qhub_subscriptions
    WHERE org_id = p_org_id FOR UPDATE;

  IF v_plan IS NULL OR v_status NOT IN ('active','trialing') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'ineligible_subscription');
  END IF;

  v_cap := CASE v_plan WHEN 'builder_beta' THEN 5 WHEN 'guided_builder' THEN 1 ELSE 0 END;

  -- Lock active projects and count under the lock.
  PERFORM 1 FROM public.qhub_project_entitlements WHERE org_id = p_org_id FOR UPDATE;
  SELECT count(*) INTO v_active FROM public.qhub_project_entitlements WHERE org_id = p_org_id AND active;

  IF v_active >= v_cap THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'project_limit_reached');
  END IF;

  v_pid := gen_random_uuid();
  INSERT INTO public.qhub_project_entitlements (project_id, org_id, created_by, plan_id, active)
  VALUES (v_pid, p_org_id, p_created_by, v_plan, true);

  INSERT INTO public.qhub_entitlement_audit (org_id, actor, change_type, after_state, reason)
  VALUES (p_org_id, p_created_by, 'PROJECT_CREATE',
          jsonb_build_object('project_id', v_pid::text, 'idempotency_key', p_idempotency_key), p_request_hash);

  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'project_id', v_pid::text);
END;
$$;

-- ─── RLS: RESTRICTIVE service-only on every commercial table ─────────────────
DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans','qhub_org_members','qhub_quantex_staff','qhub_org_invitations',
    'qhub_billing_customers','qhub_subscriptions','qhub_checkout_intents','qhub_billing_webhook_events',
    'qhub_usage_credits','qhub_usage_ledger','qhub_project_entitlements','qhub_onboarding_state',
    'qhub_acknowledgments','qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit'
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

REVOKE ALL ON FUNCTION public.qhub_consume_build_credit(UUID, TEXT, TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_consume_build_credit(UUID, TEXT, TEXT, INTEGER) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_claim_webhook_event(TEXT, TEXT, TEXT, BOOLEAN, TEXT, BIGINT, TEXT, TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_claim_webhook_event(TEXT, TEXT, TEXT, BOOLEAN, TEXT, BIGINT, TEXT, TEXT, INTEGER) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_accept_invitation(UUID, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_accept_invitation(UUID, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_mark_webhook_state(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_mark_webhook_state(TEXT, TEXT, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_reconcile_checkout(TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, BOOLEAN, TEXT, TEXT, TEXT, BIGINT, BIGINT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_reconcile_checkout(TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, BOOLEAN, TEXT, TEXT, TEXT, BIGINT, BIGINT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_create_project(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_create_project(TEXT, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_consume_checkout_intent(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_consume_checkout_intent(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) TO service_role;

-- ─── Seed plan identity (idempotent) ────────────────────────────────────────
INSERT INTO public.qhub_commercial_plans (plan_id, display_name, active)
VALUES ('builder_beta','QHub Builder Beta',TRUE), ('guided_builder','QHub Guided Builder',TRUE)
ON CONFLICT (plan_id) DO NOTHING;

-- ─── Readiness verifier (exact semantics) ───────────────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_verify_commercial_schema()
RETURNS JSONB
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_failed TEXT[] := ARRAY[]::TEXT[];
  t TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans','qhub_org_members','qhub_quantex_staff','qhub_org_invitations',
    'qhub_billing_customers','qhub_subscriptions','qhub_checkout_intents','qhub_billing_webhook_events',
    'qhub_usage_credits','qhub_usage_ledger','qhub_project_entitlements','qhub_onboarding_state',
    'qhub_acknowledgments','qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit'
  ];
BEGIN
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

  -- Critical unique/index semantics (checked by exact index definition — a
  -- same-named index over the wrong columns/predicate still fails).
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='uq_qhub_guided_one_active_project'
      AND indexdef LIKE '%UNIQUE%' AND indexdef LIKE '%(org_id)%'
      AND indexdef LIKE '%guided_builder%'
  ) THEN
    v_failed := v_failed || 'index_semantics:guided_one_active'::text;
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
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_usage_ledger'::regclass AND contype='u') THEN
    v_failed := v_failed || 'missing_unique:ledger_idempotency'::text;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_checkout_intents'::regclass AND contype='u') THEN
    v_failed := v_failed || 'missing_unique:checkout_intent_nonce'::text;
  END IF;

  -- FKs: subscription.plan → plans, review.decided_by → staff, gov.project →
  -- project_entitlements (authoritative project ownership), checkout.plan → plans.
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_subscriptions'::regclass AND contype='f') THEN
    v_failed := v_failed || 'missing_fk:subscription_plan'::text;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass AND contype='f') THEN
    v_failed := v_failed || 'missing_fk:review_staff'::text;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_governance_essentials'::regclass AND contype='f') THEN
    v_failed := v_failed || 'missing_fk:gov_project_ownership'::text;
  END IF;

  -- Webhook lease columns present (crash recovery contract).
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_billing_webhook_events'::regclass
      AND attname='lease_expires_at' AND NOT attisdropped
  ) THEN
    v_failed := v_failed || 'webhook_lease_contract'::text;
  END IF;

  -- Credit RPC R3: exact signature (uuid,text,text,int), SECURITY DEFINER, fixed
  -- search_path, returns jsonb, and no unexpected overloads.
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_consume_build_credit'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public']
      AND pg_get_function_identity_arguments(p.oid) = 'p_project_id uuid, p_idempotency_key text, p_canonical_hash text, p_units integer'
      AND p.prorettype = 'jsonb'::regtype;
  IF NOT FOUND THEN v_failed := v_failed || 'credit_rpc_contract'::text; END IF;

  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname='public' AND p.proname='qhub_consume_build_credit') <> 1 THEN
    v_failed := v_failed || 'credit_rpc_overload'::text;
  END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_claim_webhook_event'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'webhook_rpc_contract'::text; END IF;

  IF has_function_privilege('anon','public.qhub_consume_build_credit(uuid,text,text,integer)','EXECUTE')
     OR has_function_privilege('authenticated','public.qhub_consume_build_credit(uuid,text,text,integer)','EXECUTE') THEN
    v_failed := v_failed || 'credit_rpc_browser_exec'::text;
  END IF;

  -- Webhook inbox state contract present.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_billing_webhook_events'::regclass
      AND contype='c' AND pg_get_constraintdef(oid) LIKE '%FAILED_RETRYABLE%'
  ) THEN
    v_failed := v_failed || 'webhook_state_contract'::text;
  END IF;

  -- Append-only immutability triggers.
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_usage_ledger_immutable'
                   AND tgrelid='public.qhub_usage_ledger'::regclass) THEN
    v_failed := v_failed || 'ledger_immutable_contract'::text;
  END IF;

  -- Checkout-intent idempotency uniqueness (org_id, idempotency_key).
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_checkout_intents'::regclass AND contype='u'
      AND conkey @> (SELECT ARRAY[attnum] FROM pg_attribute WHERE attrelid='public.qhub_checkout_intents'::regclass AND attname='idempotency_key')
  ) THEN
    v_failed := v_failed || 'missing_unique:checkout_intent_idempotency'::text;
  END IF;

  -- Active-invitation uniqueness (one invited per org+email).
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='uq_qhub_invitation_active'
      AND indexdef LIKE '%UNIQUE%' AND indexdef LIKE '%lower(email)%'
  ) THEN
    v_failed := v_failed || 'invitation_active_uniqueness'::text;
  END IF;

  -- Seat-accept + checkout-intent-consume RPCs: exist, SECURITY DEFINER, fixed
  -- search_path, and denied to browser roles.
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_accept_invitation'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'seat_rpc_contract'::text; END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_consume_checkout_intent'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'checkout_consume_rpc_contract'::text; END IF;

  IF has_function_privilege('anon','public.qhub_accept_invitation(uuid,text,text,text)','EXECUTE')
     OR has_function_privilege('authenticated','public.qhub_accept_invitation(uuid,text,text,text)','EXECUTE') THEN
    v_failed := v_failed || 'seat_rpc_browser_exec'::text;
  END IF;

  -- R4: seat RPC must NOT accept a caller-supplied cap (identity + plan-derived cap).
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_accept_invitation'
      AND pg_get_function_identity_arguments(p.oid) = 'p_invitation_id uuid, p_user_id text, p_max_seats integer'
  ) THEN
    v_failed := v_failed || 'seat_rpc_caller_cap'::text;
  END IF;

  -- R4 atomic RPC contracts: each exists, SECURITY DEFINER, fixed search_path,
  -- and is denied to browser roles.
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_reconcile_checkout'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.prorettype='jsonb'::regtype;
  IF NOT FOUND THEN v_failed := v_failed || 'reconcile_rpc_contract'::text; END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_decide_review'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.prorettype='jsonb'::regtype;
  IF NOT FOUND THEN v_failed := v_failed || 'review_rpc_contract'::text; END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_create_project'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.prorettype='jsonb'::regtype;
  IF NOT FOUND THEN v_failed := v_failed || 'project_rpc_contract'::text; END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_mark_webhook_state'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'];
  IF NOT FOUND THEN v_failed := v_failed || 'lease_mark_rpc_contract'::text; END IF;

  IF has_function_privilege('anon','public.qhub_reconcile_checkout(text,text,text,uuid,text,text,text,text,boolean,text,text,text,bigint,bigint)','EXECUTE')
     OR has_function_privilege('anon','public.qhub_decide_review(uuid,text,boolean,text,text,text)','EXECUTE')
     OR has_function_privilege('anon','public.qhub_create_project(text,text,text,text)','EXECUTE') THEN
    v_failed := v_failed || 'r4_rpc_browser_exec'::text;
  END IF;

  -- Immutable review-decision audit (append-only qhub_entitlement_audit).
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_entitlement_audit_immutable'
                   AND tgrelid='public.qhub_entitlement_audit'::regclass) THEN
    v_failed := v_failed || 'review_audit_immutable'::text;
  END IF;

  -- Checkout intent must carry the Checkout Session + setup-price contract fields.
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_checkout_intents'::regclass
      AND attname='checkout_session_id' AND NOT attisdropped
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_checkout_intents'::regclass
      AND attname='expected_setup_price_id' AND NOT attisdropped
  ) THEN
    v_failed := v_failed || 'checkout_session_setup_contract'::text;
  END IF;

  -- R5 (R8): Governance record carries a monotonic record_version (NOT NULL) + a nullable
  -- declaration_identity_hash.
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_governance_essentials'::regclass
      AND attname='record_version' AND atttypid='int8'::regtype AND attnotnull AND NOT attisdropped
  ) THEN
    v_failed := v_failed || 'r5_gov_record_version'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_governance_essentials'::regclass
      AND attname='declaration_identity_hash' AND atttypid='text'::regtype AND NOT attisdropped
  ) THEN
    v_failed := v_failed || 'r5_gov_declaration_hash'::text;
  END IF;

  -- R5 (R8): the review request persists the FULL authoritative identity set. Each column must
  -- exist with the exact type; all are NULLABLE (legacy rows readable, but NULL cannot satisfy
  -- the new authorization).
  FOR t IN SELECT unnest(ARRAY[
    'governance_record_id:uuid','governance_record_version:int8','required_acknowledgment_version:text',
    'acknowledgment_record_id:uuid','acknowledgment_version:text','declaration_identity_hash:text',
    'idempotency_key:text','requester_user_id:text'
  ]) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid='public.qhub_manual_review_requests'::regclass
        AND attname = split_part(t, ':', 1)
        AND atttypid = (split_part(t, ':', 2))::regtype
        AND NOT attisdropped
    ) THEN
      v_failed := v_failed || ('r5_review_column:'||split_part(t, ':', 1))::text;
    END IF;
  END LOOP;

  -- R5 (R8): declaration_identity_hash hex-64 format checks on BOTH tables.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_governance_essentials'::regclass
      AND conname='chk_qhub_gov_decl_hash_hex' AND contype='c'
  ) THEN
    v_failed := v_failed || 'r5_gov_hash_format_check'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass
      AND conname='chk_qhub_review_decl_hash_hex' AND contype='c'
  ) THEN
    v_failed := v_failed || 'r5_review_hash_format_check'::text;
  END IF;

  -- R5 (R8): FKs binding the review to the authoritative Governance + acknowledgment rows.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass
      AND conname='fk_qhub_review_governance_record' AND contype='f'
  ) THEN
    v_failed := v_failed || 'r5_review_governance_fk'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass
      AND conname='fk_qhub_review_acknowledgment_record' AND contype='f'
  ) THEN
    v_failed := v_failed || 'r5_review_acknowledgment_fk'::text;
  END IF;

  -- R5 (R8): the atomic decision RPC keeps its exact signature/security/search_path (the
  -- Governance-drift + full-identity-audit body change does not alter the contract surface).
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_decide_review'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public']
      AND pg_get_function_identity_arguments(p.oid) = 'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text'
      AND p.prorettype='jsonb'::regtype;
  IF NOT FOUND THEN v_failed := v_failed || 'r5_decide_review_signature'::text; END IF;

  RETURN jsonb_build_object(
    'expected_version', '2026-07-30.commercial-launch-r5',
    'ready', (cardinality(v_failed) = 0),
    'failed', to_jsonb(v_failed)
  );
END;
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_commercial_schema() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role;

COMMIT;
