-- ============================================================================
-- QHUB Commercial Launch Foundation — R12 FINAL TWO-BLOCKER CLOSURE
--   (persisted + revalidated classification authority on review requests)
--   + R15.2 verifier exact dual-digest body pins (raw md5(prosrc) accepting exactly
--     the reviewed LF and reviewed CRLF encodings; NO normalization — supersedes the
--     withdrawn R15.1 CR-stripping, which allowed a false READY. No protected function
--     body, signature, owner, security mode, search_path, ACL or RLS setting changed.)
-- Migration: 20260729_commercial_launch_foundation  (replaces the rejected
--            4b42555a… contents IN PLACE — one authoritative commercial migration)
-- Schema version: 2026-07-30.commercial-launch-r8
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
  ADD COLUMN IF NOT EXISTS declaration_identity_hash  TEXT,
  ADD COLUMN IF NOT EXISTS acknowledgment_record_id   UUID;

ALTER TABLE public.qhub_manual_review_requests
  ADD COLUMN IF NOT EXISTS governance_record_id           UUID,
  ADD COLUMN IF NOT EXISTS governance_record_version      BIGINT,
  ADD COLUMN IF NOT EXISTS required_acknowledgment_version TEXT,
  ADD COLUMN IF NOT EXISTS acknowledgment_record_id       UUID,
  ADD COLUMN IF NOT EXISTS acknowledgment_version         TEXT,
  ADD COLUMN IF NOT EXISTS declaration_identity_hash      TEXT,
  ADD COLUMN IF NOT EXISTS idempotency_key                TEXT,
  ADD COLUMN IF NOT EXISTS requester_user_id              TEXT;

-- ─── R8 (R12): PERSISTED CLASSIFICATION AUTHORITY on review requests ─────────
-- Additive only — nullable columns so legacy rows stay readable/non-authorizing. A new review binds
-- the authoritative classification scheme id/version (from qhub_commercial_authority) + the risk tier
-- (from the Governance record) as INDEPENDENTLY REVALIDATABLE columns, so qhub_decide_review can reload
-- and compare current classification authority before ANY approval or terminal-repeat success — closing
-- the reproduced stale-classification false-approval (approved after the scheme advanced to v999).
ALTER TABLE public.qhub_manual_review_requests
  ADD COLUMN IF NOT EXISTS classification_scheme_id       TEXT,
  ADD COLUMN IF NOT EXISTS classification_scheme_version  TEXT,
  ADD COLUMN IF NOT EXISTS classification_risk_tier       TEXT;

-- ─── R6 (R10): AUTHORITATIVE ACKNOWLEDGMENT MODEL ────────────────────────────
-- Additive only. An acknowledgment gains a project/Governance scope, a required version, a
-- lifecycle status (ACTIVE / REVOKED / SUPERSEDED), and timestamps. Legacy rows keep NULL scope
-- and a NULL status (they are NON_AUTHORIZING_LEGACY_ACKNOWLEDGMENT — only status='ACTIVE' with a
-- full scope authorizes). A partial unique index enforces ONE ACTIVE acknowledgment per
-- (org, project, user, ack_type, ack_version) scope.
ALTER TABLE public.qhub_acknowledgments
  ADD COLUMN IF NOT EXISTS project_id                 UUID,
  ADD COLUMN IF NOT EXISTS governance_record_id       UUID,
  ADD COLUMN IF NOT EXISTS governance_record_version  BIGINT,
  ADD COLUMN IF NOT EXISTS required_version           TEXT,
  ADD COLUMN IF NOT EXISTS policy_version             TEXT,
  ADD COLUMN IF NOT EXISTS status                     TEXT,
  ADD COLUMN IF NOT EXISTS revoked_at                 TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS superseded_at              TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW();

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

  -- FK: governance.acknowledgment_record_id → the authoritative acknowledgment row (R9).
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_governance_essentials'::regclass AND conname = 'fk_qhub_gov_acknowledgment_record'
  ) THEN
    ALTER TABLE public.qhub_governance_essentials
      ADD CONSTRAINT fk_qhub_gov_acknowledgment_record
      FOREIGN KEY (acknowledgment_record_id) REFERENCES public.qhub_acknowledgments (id);
  END IF;

  /*
   * R9 NO NULL-BINDING TERMINALIZATION. A review may be PENDING with partial/legacy bindings,
   * but a TERMINAL (approved/rejected) row must carry EVERY authoritative binding field, valid.
   * Added NOT VALID so pre-existing legacy rows are not retro-invalidated (they can be READ but
   * never terminalized — qhub_decide_review refuses them as non_authorizing_legacy_review), while
   * every new insert/update IS checked.
   */
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_manual_review_requests'::regclass AND conname = 'chk_qhub_review_terminal_binding'
  ) THEN
    ALTER TABLE public.qhub_manual_review_requests
      ADD CONSTRAINT chk_qhub_review_terminal_binding
      CHECK (
        status = 'pending' OR (
          governance_record_id IS NOT NULL
          AND governance_record_version IS NOT NULL
          AND declaration_identity_hash IS NOT NULL
          AND declaration_identity_hash ~ '^[0-9a-f]{64}$'
          AND policy_version IS NOT NULL
          AND required_acknowledgment_version IS NOT NULL
          AND acknowledgment_record_id IS NOT NULL
          AND acknowledgment_version IS NOT NULL
          AND requester_user_id IS NOT NULL
          AND request_hash IS NOT NULL
        )
      ) NOT VALID;
  END IF;

  /*
   * R12 (R8) — TERMINAL CLASSIFICATION BINDING. A terminal (approved/rejected) review must also
   * carry the persisted classification authority (scheme id + version + risk tier). Added NOT VALID
   * so pre-existing legacy rows are readable but can never terminalize (qhub_decide_review refuses a
   * classification-unbound review as non_authorizing_legacy_review); every new terminal row IS checked.
   */
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_manual_review_requests'::regclass AND conname = 'chk_qhub_review_classification_binding'
  ) THEN
    ALTER TABLE public.qhub_manual_review_requests
      ADD CONSTRAINT chk_qhub_review_classification_binding
      CHECK (
        status = 'pending' OR (
          classification_scheme_id IS NOT NULL
          AND classification_scheme_version IS NOT NULL
          AND classification_risk_tier IS NOT NULL
        )
      ) NOT VALID;
  END IF;

  -- R6 (R10): acknowledgment lifecycle status is a fixed enum when present.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_acknowledgments'::regclass AND conname = 'chk_qhub_ack_status'
  ) THEN
    ALTER TABLE public.qhub_acknowledgments
      ADD CONSTRAINT chk_qhub_ack_status
      CHECK (status IS NULL OR status IN ('ACTIVE','REVOKED','SUPERSEDED'));
  END IF;

  -- R7 (R11): exact lifecycle timestamp consistency per status (belt-and-suspenders with the
  -- lifecycle trigger). NOT VALID so legacy status-less rows are readable.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_acknowledgments'::regclass AND conname = 'chk_qhub_ack_lifecycle'
  ) THEN
    ALTER TABLE public.qhub_acknowledgments
      ADD CONSTRAINT chk_qhub_ack_lifecycle
      CHECK (
        status IS NULL
        OR (status = 'ACTIVE'     AND revoked_at IS NULL     AND superseded_at IS NULL)
        OR (status = 'REVOKED'    AND revoked_at IS NOT NULL AND superseded_at IS NULL)
        OR (status = 'SUPERSEDED' AND superseded_at IS NOT NULL AND revoked_at IS NULL)
      ) NOT VALID;
  END IF;

  -- R6 (R10): FK — acknowledgment.governance_record_id → the authoritative Governance record.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.qhub_acknowledgments'::regclass AND conname = 'fk_qhub_ack_governance_record'
  ) THEN
    ALTER TABLE public.qhub_acknowledgments
      ADD CONSTRAINT fk_qhub_ack_governance_record
      FOREIGN KEY (governance_record_id) REFERENCES public.qhub_governance_essentials (id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_qhub_review_governance_record ON public.qhub_manual_review_requests (governance_record_id);

-- R6 (R10): ONE ACTIVE acknowledgment per (org, project, user, ack_type, required version) scope.
CREATE UNIQUE INDEX IF NOT EXISTS uq_qhub_ack_one_active
  ON public.qhub_acknowledgments (org_id, project_id, user_id, ack_type, required_version)
  WHERE status = 'ACTIVE';

-- ─── R7 (R11): DB-authoritative version/classification source ────────────────
-- A single-row config table is the DATABASE source of truth for the current review policy,
-- required acknowledgment version, policy-card version, and classification scheme identity/version.
-- The atomic RPCs resolve these INSIDE the locked transaction (they are never trusted RPC
-- parameters). The TS constants must match this seed (a parity test enforces it).
CREATE TABLE IF NOT EXISTS public.qhub_commercial_authority (
  id                             INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  review_policy_version          TEXT NOT NULL,
  required_acknowledgment_version TEXT NOT NULL,
  policy_card_version            TEXT NOT NULL,
  classification_scheme_id       TEXT NOT NULL,
  classification_scheme_version  TEXT NOT NULL,
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.qhub_commercial_authority
  (id, review_policy_version, required_acknowledgment_version, policy_card_version, classification_scheme_id, classification_scheme_version)
VALUES
  (1, '2026-07-30.governance-essentials.v1', '2026-07-30.acceptable-use.v1', '2026-07-30.policy-card.v1',
      'qhub-governance-essentials', '2026-07-30.classification.v1')
ON CONFLICT (id) DO NOTHING;

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
-- R7 (R11): qhub_acknowledgments protects EVERY authority field after insert and permits ONLY a
-- controlled lifecycle transition of the lifecycle-only fields (status/revoked_at/superseded_at/
-- updated_at). Enforced exactly:
--   ACTIVE     → revoked_at IS NULL AND superseded_at IS NULL
--   REVOKED    → revoked_at IS NOT NULL AND superseded_at IS NULL   (only from ACTIVE)
--   SUPERSEDED → superseded_at IS NOT NULL AND revoked_at IS NULL   (only from ACTIVE)
-- No transition back to ACTIVE; no REVOKED<->SUPERSEDED mutation; any authority-field edit or any
-- DELETE (and every other append-only table) stays fully immutable.
CREATE OR REPLACE FUNCTION public.qhub_row_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'qhub_acknowledgments' THEN
    -- ALL authority/identity/scope fields are immutable after insert.
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_id IS DISTINCT FROM OLD.org_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.ack_type IS DISTINCT FROM OLD.ack_type
       OR NEW.ack_version IS DISTINCT FROM OLD.ack_version
       OR NEW.governance_record_id IS DISTINCT FROM OLD.governance_record_id
       OR NEW.governance_record_version IS DISTINCT FROM OLD.governance_record_version
       OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
       OR NEW.required_version IS DISTINCT FROM OLD.required_version
       OR NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'qhub_acknowledgments authority fields are immutable';
    END IF;

    -- Only a forward ACTIVE→REVOKED / ACTIVE→SUPERSEDED transition, with exact timestamp consistency.
    IF OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED'
       AND NEW.revoked_at IS NOT NULL AND NEW.superseded_at IS NULL THEN
      RETURN NEW;
    END IF;

    IF OLD.status = 'ACTIVE' AND NEW.status = 'SUPERSEDED'
       AND NEW.superseded_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
      RETURN NEW;
    END IF;

    RAISE EXCEPTION 'qhub_acknowledgments rows permit only a controlled ACTIVE->REVOKED/SUPERSEDED lifecycle transition (immutable otherwise)';
  END IF;

  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$;

/*
 * R15.4 — EXPLICIT, PORTABLE, LEAST-PRIVILEGE ACL FOR THE TRIGGER HELPER.
 *
 * qhub_row_immutable() is an INTERNAL immutability trigger helper. It is never an
 * application-facing RPC: PostgreSQL refuses to invoke a trigger function directly
 * ("trigger functions can only be called as triggers") regardless of privilege.
 *
 * Stating no ACL is NOT portable. With no explicit statement the resulting ACL is
 * whatever the platform's default privileges produce, and the two environments this
 * project uses disagree:
 *   * plain PostgreSQL / PGlite      -> proacl IS NULL (owner + PUBLIC by default)
 *   * Supabase (ALTER DEFAULT PRIVILEGES ... GRANT EXECUTE ON FUNCTIONS TO
 *     anon, authenticated, service_role) -> five rows: PUBLIC, anon, authenticated,
 *     service_role and the owner
 * Both were reproduced from this exact migration. The Supabase result is the
 * platform's default, not a reviewed decision, and it is not the contract we want.
 *
 * The reviewed contract is therefore stated explicitly and is identical in both
 * environments: exactly ONE ACL row — the owner's own EXECUTE, not grantable.
 *
 * SAFETY OF THE REVOKES — verified, not assumed. PostgreSQL checks EXECUTE on a
 * trigger function at CREATE TRIGGER time, NOT at trigger fire time. With EXECUTE
 * revoked from service_role, anon, authenticated and PUBLIC, the triggers below
 * still fire correctly: a protected-field UPDATE is still rejected by the trigger,
 * the allowed ACTIVE->REVOKED lifecycle transition still succeeds, and DELETE is
 * still blocked. No application path depends on direct EXECUTE, so no service_role
 * or browser-role grant is required.
 *
 * The four REVOKEs alone already yield exactly {owner=X/owner}, because REVOKE
 * materializes proacl with the owner's default rights retained. The owner GRANT is
 * restated anyway so the reviewed contract is explicit for a reader rather than
 * implied by PostgreSQL's materialization behaviour. It derives the owner from the
 * catalog instead of naming a role, so it stays correct wherever this migration is
 * applied.
 */
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM anon;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM authenticated;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM service_role;

DO $qhub_row_immutable_owner_grant$
DECLARE
  v_owner name;
BEGIN
  SELECT pg_get_userbyid(p.proowner) INTO v_owner
    FROM pg_proc p WHERE p.oid = to_regprocedure('public.qhub_row_immutable()');

  IF v_owner IS NULL THEN
    RAISE EXCEPTION 'R15.4: cannot resolve the owner of public.qhub_row_immutable()';
  END IF;

  EXECUTE format('GRANT EXECUTE ON FUNCTION public.qhub_row_immutable() TO %I', v_owner);
END;
$qhub_row_immutable_owner_grant$;

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

-- ─── Canonical length-prefixed cell encoder (R10 §3) ─────────────────────────
-- Deterministic, unambiguous encoding: each cell is either '_' (explicit NULL) or
-- '<utf8-length>:<value>', joined in fixed order by '|'. The length prefix makes the join
-- delimiter safe (no ambiguous concatenation). Used to build canonical request identities.
CREATE OR REPLACE FUNCTION public.qhub_canon_cells(p_cells TEXT[])
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
  SELECT string_agg(
    CASE WHEN c IS NULL THEN '_' ELSE length(convert_to(c, 'UTF8'))::text || ':' || c END,
    '|' ORDER BY ord
  )
  FROM unnest(p_cells) WITH ORDINALITY AS t(c, ord);
$$;

-- ─── ATOMIC acknowledgment lifecycle (R11 §1) ────────────────────────────────
-- The ONE server-only authority path for acknowledgments. p_action ACKNOWLEDGE creates a new ACTIVE
-- ack (superseding any prior ACTIVE for the scope) and binds it onto the Governance record; REVOKE
-- transitions the current ACTIVE ack → REVOKED and unbinds it. All authoritative versions are
-- resolved from qhub_commercial_authority INSIDE the locked transaction; membership/type/version/
-- Governance identity are validated; exact repeats are idempotent; any error rolls the txn back.
CREATE OR REPLACE FUNCTION public.qhub_record_acknowledgment(
  p_org_id TEXT, p_project_id UUID, p_user_id TEXT, p_action TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  cfg RECORD;
  g RECORD;
  cur RECORD;
  v_has_active BOOLEAN;
  v_id UUID;
BEGIN
  IF p_org_id IS NULL OR p_project_id IS NULL OR p_user_id IS NULL OR p_action NOT IN ('ACKNOWLEDGE','REVOKE') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_arguments');
  END IF;

  SELECT * INTO cfg FROM public.qhub_commercial_authority WHERE id = 1;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'authority_config_missing'); END IF;

  PERFORM 1 FROM public.qhub_org_members m
    WHERE m.org_id = p_org_id AND m.user_id = p_user_id AND m.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_a_member'); END IF;

  SELECT * INTO g FROM public.qhub_governance_essentials
    WHERE project_id = p_project_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'no_governance_record'); END IF;

  SELECT * INTO cur FROM public.qhub_acknowledgments
    WHERE org_id = p_org_id AND project_id = p_project_id AND user_id = p_user_id
      AND ack_type = 'acceptable_use' AND status = 'ACTIVE'
      AND required_version = cfg.required_acknowledgment_version
    FOR UPDATE;
  v_has_active := FOUND;

  IF p_action = 'REVOKE' THEN
    IF NOT v_has_active THEN
      RETURN jsonb_build_object('ok', true, 'idempotent', true, 'reason', 'no_active_acknowledgment');
    END IF;

    UPDATE public.qhub_acknowledgments SET status='REVOKED', revoked_at=NOW(), updated_at=NOW() WHERE id = cur.id;
    UPDATE public.qhub_governance_essentials
       SET acknowledged=false, acknowledgment_record_id=NULL, acknowledgment_version=NULL, updated_at=NOW()
     WHERE id = g.id AND acknowledgment_record_id = cur.id;

    RETURN jsonb_build_object('ok', true, 'idempotent', false, 'record_id', cur.id::text, 'status', 'REVOKED');
  END IF;

  -- ACKNOWLEDGE.
  IF NOT g.declaration_complete THEN RETURN jsonb_build_object('ok', false, 'reason', 'declaration_incomplete'); END IF;
  IF g.disposition IN ('prohibited','blocked') THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_acknowledgeable'); END IF;
  IF g.policy_card_version IS DISTINCT FROM cfg.policy_card_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'governance_stale_policy_card');
  END IF;

  -- Idempotent: the ACTIVE ack already exists at the current version AND is the record's binding.
  IF v_has_active AND g.acknowledged AND g.acknowledgment_record_id = cur.id
     AND g.acknowledgment_version = cfg.required_acknowledgment_version THEN
    RETURN jsonb_build_object('ok', true, 'idempotent', true, 'record_id', cur.id::text, 'status', 'ACTIVE');
  END IF;

  -- Supersede a prior ACTIVE ack whose binding differs (e.g. the declaration/version changed).
  IF v_has_active THEN
    UPDATE public.qhub_acknowledgments SET status='SUPERSEDED', superseded_at=NOW(), updated_at=NOW() WHERE id = cur.id;
  END IF;

  v_id := gen_random_uuid();
  INSERT INTO public.qhub_acknowledgments
    (id, org_id, user_id, ack_type, ack_version, project_id, governance_record_id, governance_record_version,
     policy_version, required_version, status)
  VALUES
    (v_id, p_org_id, p_user_id, 'acceptable_use', cfg.required_acknowledgment_version, p_project_id, g.id, g.record_version,
     cfg.review_policy_version, cfg.required_acknowledgment_version, 'ACTIVE');

  UPDATE public.qhub_governance_essentials
     SET acknowledged=true, acknowledgment_version=cfg.required_acknowledgment_version, acknowledgment_record_id=v_id, updated_at=NOW()
   WHERE id = g.id;

  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'record_id', v_id::text, 'status', 'ACTIVE');
END;
$$;

-- ─── ATOMIC review CREATION (R11 §3) ─────────────────────────────────────────
-- One transaction: lock org membership + the current Governance record + the authoritative ACTIVE
-- acknowledgment; resolve ALL current authority (policy / required-ack / classification / Governance
-- versions) from qhub_commercial_authority + the locked rows INSIDE the transaction (NEVER from RPC
-- parameters); derive the category; compute a canonical length-prefixed SHA-256 request identity IN
-- the database (binding classification identity/version + risk tier); and insert ONE fully-bound
-- review. Exact identity → same request; same idempotency key + different identity → conflict; a new
-- Governance/policy/ack/declaration/classification version → a distinct identity (history preserved).
-- The caller supplies ONLY project/reason/idempotency-key.
CREATE OR REPLACE FUNCTION public.qhub_create_review_request(
  p_org_id TEXT, p_project_id UUID, p_requester TEXT, p_reason TEXT, p_idempotency_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  cfg RECORD;
  g RECORD;
  a RECORD;
  v_category TEXT;
  v_reason_hash TEXT;
  v_hash TEXT;
  v_existing RECORD;
  v_id UUID;
BEGIN
  IF p_org_id IS NULL OR p_project_id IS NULL OR p_requester IS NULL OR coalesce(btrim(p_reason),'') = '' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_arguments');
  END IF;

  -- DB-authoritative current versions (never trusted RPC parameters).
  SELECT * INTO cfg FROM public.qhub_commercial_authority WHERE id = 1;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'authority_config_missing'); END IF;

  PERFORM 1 FROM public.qhub_org_members m
    WHERE m.org_id = p_org_id AND m.user_id = p_requester AND m.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_a_member'); END IF;

  SELECT * INTO g FROM public.qhub_governance_essentials
    WHERE project_id = p_project_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'no_governance_record'); END IF;
  IF NOT g.declaration_complete THEN RETURN jsonb_build_object('ok', false, 'reason', 'declaration_incomplete'); END IF;
  IF g.disposition IS DISTINCT FROM 'manual_review' THEN RETURN jsonb_build_object('ok', false, 'reason', 'review_not_required'); END IF;
  IF g.record_version IS NULL OR g.declaration_identity_hash IS NULL OR g.acknowledgment_record_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'governance_binding_incomplete');
  END IF;
  IF g.policy_card_version IS DISTINCT FROM cfg.policy_card_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'governance_stale_policy_card');
  END IF;

  SELECT * INTO a FROM public.qhub_acknowledgments WHERE id = g.acknowledgment_record_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_not_found'); END IF;
  IF a.status IS DISTINCT FROM 'ACTIVE' THEN RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_not_active'); END IF;
  IF a.org_id <> p_org_id OR a.user_id <> p_requester OR a.ack_type <> 'acceptable_use'
     OR a.project_id IS DISTINCT FROM p_project_id THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_scope_mismatch');
  END IF;
  IF a.ack_version IS DISTINCT FROM cfg.required_acknowledgment_version
     OR a.required_version IS DISTINCT FROM cfg.required_acknowledgment_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_stale');
  END IF;

  SELECT elem INTO v_category FROM jsonb_array_elements_text(g.data_classes) elem
    WHERE elem IN ('personal','financial','restricted') LIMIT 1;
  IF v_category IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'no_review_eligible_category'); END IF;

  v_reason_hash := encode(sha256(convert_to(btrim(p_reason), 'UTF8')), 'hex');

  -- Canonical identity binds org/project/requester + Governance id/version + declaration hash +
  -- policy version + required-ack version + ack id/version/type/status + classification id/version +
  -- risk tier + material-reason hash + idempotency key (length-prefixed, explicit NULL, DB SHA-256).
  v_hash := encode(sha256(convert_to(public.qhub_canon_cells(ARRAY[
    p_org_id, p_project_id::text, p_requester, g.id::text, g.record_version::text,
    g.declaration_identity_hash, cfg.review_policy_version, cfg.required_acknowledgment_version,
    a.id::text, a.ack_version, a.ack_type, a.status,
    cfg.classification_scheme_id, cfg.classification_scheme_version, g.risk_tier,
    v_reason_hash, p_idempotency_key
  ]), 'UTF8')), 'hex');

  SELECT * INTO v_existing FROM public.qhub_manual_review_requests WHERE org_id = p_org_id AND request_hash = v_hash;
  IF FOUND THEN RETURN jsonb_build_object('ok', true, 'idempotent', true, 'request_id', v_existing.id::text); END IF;

  IF p_idempotency_key IS NOT NULL THEN
    PERFORM 1 FROM public.qhub_manual_review_requests
      WHERE org_id = p_org_id AND project_id = p_project_id
        AND requester_user_id = p_requester AND idempotency_key = p_idempotency_key;
    IF FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'idempotency_conflict'); END IF;
  END IF;

  v_id := gen_random_uuid();
  INSERT INTO public.qhub_manual_review_requests (
    id, org_id, project_id, request_type, category, reason, request_hash, status,
    governance_record_id, governance_record_version, declaration_identity_hash, policy_version,
    required_acknowledgment_version, acknowledgment_record_id, acknowledgment_version, requester_user_id, idempotency_key,
    classification_scheme_id, classification_scheme_version, classification_risk_tier
  ) VALUES (
    v_id, p_org_id, p_project_id, 'data_review', v_category, p_reason, v_hash, 'pending',
    g.id, g.record_version, g.declaration_identity_hash, cfg.review_policy_version,
    cfg.required_acknowledgment_version, a.id, a.ack_version, p_requester, p_idempotency_key,
    cfg.classification_scheme_id, cfg.classification_scheme_version, g.risk_tier
  );

  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'request_id', v_id::text);
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
  cfg RECORD;
  r RECORD;
  g RECORD;
  a RECORD;
BEGIN
  IF NOT p_is_staff THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'staff_required');
  END IF;

  IF p_decision NOT IN ('approved','rejected') OR coalesce(btrim(p_reason),'') = '' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_decision');
  END IF;

  /*
   * DB-authoritative current versions. R12 §3 — LOCK the authoritative config row FOR SHARE so the
   * classification/policy/ack authority it carries CANNOT change between revalidation and mutation
   * (a concurrent config UPDATE blocks until this decision commits). This is the first lock in the
   * deterministic order (config → review → Governance → ack → membership → staff).
   */
  SELECT * INTO cfg FROM public.qhub_commercial_authority WHERE id = 1 FOR SHARE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'reason', 'authority_config_missing'); END IF;

  /*
   * R11 §5 — LOCK all authoritative rows (deterministic order: review → Governance → ack → membership
   * → staff) FOR UPDATE, then FULLY REVALIDATE current authority BEFORE ANY return — including an exact
   * terminal repeat. A revoked/superseded acknowledgment (or any drift) after approval therefore makes
   * a later repeat FAIL rather than returning idempotent success.
   */
  SELECT * INTO r FROM public.qhub_manual_review_requests WHERE id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_found');
  END IF;

  -- FAIL CLOSED: the request must carry EVERY authoritative binding field (legacy/unbound never authorizes).
  IF r.project_id IS NULL
     OR r.governance_record_id IS NULL
     OR r.governance_record_version IS NULL
     OR r.declaration_identity_hash IS NULL
     OR r.declaration_identity_hash !~ '^[0-9a-f]{64}$'
     OR r.policy_version IS NULL
     OR r.required_acknowledgment_version IS NULL
     OR r.acknowledgment_record_id IS NULL
     OR r.acknowledgment_version IS NULL
     OR r.requester_user_id IS NULL
     OR r.request_hash IS NULL
     OR r.classification_scheme_id IS NULL
     OR r.classification_scheme_version IS NULL
     OR r.classification_risk_tier IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'non_authorizing_legacy_review');
  END IF;

  -- Reviewer must be an ACTIVE Quantex staff member (never trust the flag alone).
  PERFORM 1 FROM public.qhub_quantex_staff s WHERE s.user_id = p_actor AND s.active FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'staff_required');
  END IF;

  -- Requester membership must still be active (org/project ownership current).
  PERFORM 1 FROM public.qhub_org_members m
    WHERE m.org_id = r.org_id AND m.user_id = r.requester_user_id AND m.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'requester_not_a_member');
  END IF;

  -- Governance record: current, unchanged (version + declaration hash), and current policy-card.
  SELECT * INTO g FROM public.qhub_governance_essentials
    WHERE id = r.governance_record_id AND project_id = r.project_id AND org_id = r.org_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'governance_not_found');
  END IF;
  IF g.record_version IS DISTINCT FROM r.governance_record_version
     OR g.declaration_identity_hash IS DISTINCT FROM r.declaration_identity_hash
     OR g.policy_card_version IS DISTINCT FROM cfg.policy_card_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'governance_changed');
  END IF;

  -- Policy version must be current (config) and match the stored request policy.
  IF r.policy_version IS DISTINCT FROM cfg.review_policy_version
     OR p_policy_version IS DISTINCT FROM cfg.review_policy_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'policy_stale');
  END IF;

  /*
   * R12 §2 — CLASSIFICATION authority must be current, revalidated on EVERY invocation (incl. an exact
   * terminal repeat) BEFORE the terminal-repeat/first-decision branch. The persisted binding (scheme
   * id/version from config, risk tier from Governance) must exactly equal current authority; a changed
   * scheme/version/risk tier returns classification_changed with ZERO side effect — never approve, never
   * idempotent terminal success, no Governance/audit mutation, no downstream authorization.
   */
  IF r.classification_scheme_id IS DISTINCT FROM cfg.classification_scheme_id
     OR r.classification_scheme_version IS DISTINCT FROM cfg.classification_scheme_version
     OR r.classification_risk_tier IS DISTINCT FROM g.risk_tier THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'classification_changed');
  END IF;

  -- Acknowledgment: ACTIVE, correct scope, current version, and the record's binding.
  SELECT * INTO a FROM public.qhub_acknowledgments WHERE id = r.acknowledgment_record_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_not_found');
  END IF;
  IF a.status IS DISTINCT FROM 'ACTIVE' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_not_active');
  END IF;
  IF a.org_id IS DISTINCT FROM r.org_id
     OR a.user_id IS DISTINCT FROM r.requester_user_id
     OR a.project_id IS DISTINCT FROM r.project_id
     OR a.ack_type IS DISTINCT FROM 'acceptable_use'
     OR a.ack_version IS DISTINCT FROM r.acknowledgment_version
     OR r.acknowledgment_version IS DISTINCT FROM r.required_acknowledgment_version
     OR r.required_acknowledgment_version IS DISTINCT FROM cfg.required_acknowledgment_version THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_mismatch');
  END IF;
  IF NOT g.acknowledged
     OR g.acknowledgment_version IS DISTINCT FROM cfg.required_acknowledgment_version
     OR g.acknowledgment_record_id IS DISTINCT FROM r.acknowledgment_record_id THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'acknowledgment_stale');
  END IF;

  -- Prohibited use is non-overridable (applies to a first approval AND any approved terminal state).
  IF p_decision = 'approved' AND r.category IN ('secrets','credentials','mnpi','regulated_records','consequential_action','external_write','autonomous_agent') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'prohibited_cannot_approve');
  END IF;

  /*
   * Only AFTER full revalidation: an exact terminal repeat may return idempotent success (every
   * material field matches), a materially-different terminal repeat is a deterministic conflict, and
   * a still-PENDING request is terminalized atomically.
   */
  IF r.status <> 'pending' THEN
    IF r.status = p_decision
       AND r.decided_by IS NOT DISTINCT FROM p_actor
       AND btrim(coalesce(r.decision_reason, '')) IS NOT DISTINCT FROM btrim(coalesce(p_reason, ''))
       AND r.policy_version IS NOT DISTINCT FROM p_policy_version THEN
      RETURN jsonb_build_object('ok', true, 'idempotent', true);
    END IF;

    RETURN jsonb_build_object('ok', false, 'reason', 'decision_conflict');
  END IF;

  -- Atomic terminalization: request + Governance disposition + ONE immutable audit row.
  UPDATE public.qhub_manual_review_requests
     SET status = p_decision, decided_by = p_actor, decision_reason = p_reason,
         policy_version = p_policy_version, decided_at = NOW()
   WHERE id = p_request_id;

  UPDATE public.qhub_governance_essentials
     SET review_state = CASE WHEN p_decision='approved' THEN 'approved' ELSE 'rejected' END,
         reviewed_by = p_actor, reviewed_at = NOW(), review_policy_version = p_policy_version, updated_at = NOW()
   WHERE project_id = r.project_id AND org_id = r.org_id;

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
            'acknowledgment_version', r.acknowledgment_version,
            'requester_user_id', r.requester_user_id
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
    'qhub_acknowledgments','qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit','qhub_commercial_authority'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    -- R11 §6: FORCE RLS so even the table owner is subject to the RESTRICTIVE policy (service_role
    -- is BYPASSRLS by design and is the only writer).
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);

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
REVOKE ALL ON FUNCTION public.qhub_create_review_request(TEXT, UUID, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_create_review_request(TEXT, UUID, TEXT, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_record_acknowledgment(TEXT, UUID, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_record_acknowledgment(TEXT, UUID, TEXT, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.qhub_canon_cells(TEXT[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_canon_cells(TEXT[]) TO service_role;
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
  pv TEXT;
  tables TEXT[] := ARRAY[
    'qhub_commercial_plans','qhub_org_members','qhub_quantex_staff','qhub_org_invitations',
    'qhub_billing_customers','qhub_subscriptions','qhub_checkout_intents','qhub_billing_webhook_events',
    'qhub_usage_credits','qhub_usage_ledger','qhub_project_entitlements','qhub_onboarding_state',
    'qhub_acknowledgments','qhub_governance_essentials','qhub_manual_review_requests','qhub_entitlement_audit','qhub_commercial_authority'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      v_failed := v_failed || ('missing_table:'||t); CONTINUE;
    END IF;
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      v_failed := v_failed || ('rls_disabled:'||t);
    END IF;
    -- R10 §6: EXACT RESTRICTIVE service-only policy — role set + USING(false) + WITH CHECK(false).
    IF NOT EXISTS (
      SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t
        AND policyname=t||'_service_only' AND permissive='RESTRICTIVE'
        AND roles = ARRAY['anon','authenticated']::name[]
        AND coalesce(qual,'') = 'false' AND coalesce(with_check,'') = 'false'
    ) THEN
      v_failed := v_failed || ('policy_semantics:'||t);
    END IF;
    -- R10 §6: NO browser role may hold SELECT or ANY write privilege (inherited grants counted).
    IF has_table_privilege('anon', ('public.'||t)::regclass, 'SELECT')
       OR has_table_privilege('authenticated', ('public.'||t)::regclass, 'SELECT') THEN
      v_failed := v_failed || ('browser_select_grant:'||t);
    END IF;
    FOR pv IN SELECT unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) LOOP
      IF has_table_privilege('anon', ('public.'||t)::regclass, pv)
         OR has_table_privilege('authenticated', ('public.'||t)::regclass, pv) THEN
        v_failed := v_failed || ('browser_write_grant:'||t||':'||pv);
      END IF;
    END LOOP;
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

  -- R8 (R12): the review request persists the classification authority binding (scheme id/version +
  -- risk tier) as independently revalidatable columns. Each must exist with the exact type; all are
  -- NULLABLE (legacy rows readable) but required for terminal rows by chk_qhub_review_classification_binding.
  FOR t IN SELECT unnest(ARRAY[
    'classification_scheme_id:text','classification_scheme_version:text','classification_risk_tier:text'
  ]) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid='public.qhub_manual_review_requests'::regclass
        AND attname = split_part(t, ':', 1)
        AND atttypid = (split_part(t, ':', 2))::regtype
        AND NOT attisdropped
    ) THEN
      v_failed := v_failed || ('r8_review_classification_column:'||split_part(t, ':', 1))::text;
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

  -- R9: the governance record carries an authoritative acknowledgment_record_id (nullable),
  -- and a NOT-VALID terminal-binding CHECK forbids terminalizing an unbound review.
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_governance_essentials'::regclass
      AND attname='acknowledgment_record_id' AND atttypid='uuid'::regtype AND NOT attisdropped
  ) THEN
    v_failed := v_failed || 'r9_gov_ack_record_id'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_manual_review_requests'::regclass
      AND conname='chk_qhub_review_terminal_binding' AND contype='c'
  ) THEN
    v_failed := v_failed || 'r9_review_terminal_binding_check'::text;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid='public.qhub_governance_essentials'::regclass
      AND conname='fk_qhub_gov_acknowledgment_record' AND contype='f'
  ) THEN
    v_failed := v_failed || 'r9_gov_ack_fk'::text;
  END IF;

  /*
   * R9 §5 — EXECUTE-ACL DEPTH for EVERY privileged RPC. No browser role (anon/authenticated) and
   * no PUBLIC grant may hold EXECUTE (has_function_privilege reflects a PUBLIC grant on every
   * role, so anon+authenticated cover the PUBLIC case). This closes the reproduced drift where a
   * `GRANT EXECUTE ... TO authenticated` on qhub_decide_review still reported READY.
   */
  FOR t IN SELECT unnest(ARRAY[
    'public.qhub_consume_build_credit(uuid,text,text,integer)',
    'public.qhub_claim_webhook_event(text,text,text,boolean,text,bigint,text,text,integer)',
    'public.qhub_accept_invitation(uuid,text,text,text)',
    'public.qhub_mark_webhook_state(text,text,text,text,text)',
    'public.qhub_reconcile_checkout(text,text,text,uuid,text,text,text,text,boolean,text,text,text,bigint,bigint)',
    'public.qhub_decide_review(uuid,text,boolean,text,text,text)',
    'public.qhub_create_project(text,text,text,text)',
    'public.qhub_consume_checkout_intent(uuid,text,text,text,text,text,text,text)',
    'public.qhub_create_review_request(text,uuid,text,text,text)',
    'public.qhub_record_acknowledgment(text,uuid,text,text)',
    'public.qhub_canon_cells(text[])'
  ]) LOOP
    IF has_function_privilege('anon', t, 'EXECUTE') OR has_function_privilege('authenticated', t, 'EXECUTE') THEN
      v_failed := v_failed || ('rpc_execute_drift:'||split_part(t,'(',1))::text;
    END IF;
    -- R11 §6: the intended service_role EXECUTE grant must be PRESENT (a revoke → NOT READY).
    IF NOT has_function_privilege('service_role', t, 'EXECUTE') THEN
      v_failed := v_failed || ('rpc_service_execute_missing:'||split_part(t,'(',1))::text;
    END IF;
  END LOOP;

  /*
   * R9 §5 — qhub_decide_review deep ACL/identity pin: exactly ONE overload; SECURITY DEFINER;
   * owner matches the migration owner (the owner of a reference commercial table — detects owner
   * drift); PUBLIC has NO EXECUTE entry in the ACL; and an equivalent semantic body pin (the
   * fail-closed guard tokens must all be present, so a weakened body-replace is caught).
   */
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname='qhub_decide_review') <> 1 THEN
    v_failed := v_failed || 'decide_review_overload'::text;
  END IF;

  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_decide_review'
      AND p.proowner = (SELECT relowner FROM pg_class WHERE oid='public.qhub_manual_review_requests'::regclass);
  IF NOT FOUND THEN v_failed := v_failed || 'decide_review_owner_drift'::text; END IF;

  -- PUBLIC must not appear with EXECUTE in the function ACL (proacl grantee 0 = PUBLIC).
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
      LATERAL aclexplode(p.proacl) ae
    WHERE n.nspname='public' AND p.proname='qhub_decide_review'
      AND ae.grantee = 0 AND ae.privilege_type = 'EXECUTE'
  ) THEN
    v_failed := v_failed || 'decide_review_public_execute'::text;
  END IF;

  /*
   * R10 §6 — EXACT function body pin: md5 of prosrc (the verbatim body). A weakened body has a
   * different prosrc → different digest → NOT READY; retained marker text/comments cannot spoof it
   * (any change to the body text changes the digest). prosrc is stored verbatim, so the digest is
   * stable across PG versions.
   *
   * R15.2 — EXACT DUAL-DIGEST ACCEPTANCE (supersedes the withdrawn R15.1 normalization).
   *
   * Some application channels (a Windows clipboard paste into the SQL Editor) rewrite the migration's
   * LF line endings to CRLF; PostgreSQL stores that verbatim in prosrc, so the same reviewed body has
   * two possible raw encodings. R15.1 tried to absorb this with md5(replace(prosrc, chr(13), '')) —
   * that was UNSAFE and is withdrawn: deleting every CR also deletes a CR injected INSIDE executable
   * text, so a body containing e.g. 'staff'||chr(13)||'_required' hashed identically to the reviewed
   * body and produced a FALSE READY (independently reproduced).
   *
   * The pins therefore hash RAW prosrc — no replace/regexp_replace/translate/trim, no normalization of
   * any kind — and accept exactly TWO separately reviewed encodings of the same reviewed body: the LF
   * digest and the CRLF digest, each computed from the reviewed migration and verified. Any third byte
   * sequence, including a single injected or removed CR or LF, a mixed-ending body, or any executable
   * token change, yields a digest outside the two-value allowlist and is reported as drift.
   *
   * coalesce(..., FALSE) keeps the check fail-closed: a missing or renamed function makes the scalar
   * subquery NULL, `NULL IN (...)` is NULL, and the check reports drift rather than silently passing.
   */
  IF NOT coalesce(
       (SELECT md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_decide_review'
            AND pg_get_function_identity_arguments(p.oid) = 'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text')
       IN ('7e678f1e4bba0c540507cfe3743fbe54',   -- reviewed body, LF encoding
           'dac8abcd56d7fc804baac660059c14bf'),  -- reviewed body, CRLF encoding
     FALSE) THEN
    v_failed := v_failed || 'decide_review_body_drift'::text;
  END IF;

  /*
   * R11 §6 — atomic review-CREATE RPC: exact signature with NO authority parameters (only
   * org/project/requester/reason/idempotency-key), SECURITY DEFINER, fixed search_path, sole
   * overload, owner pinned, browser-denied, service_role EXECUTE present (ACL loop), and exact body pin.
   */
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_create_review_request'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.prorettype='jsonb'::regtype
      AND pg_get_function_identity_arguments(p.oid) = 'p_org_id text, p_project_id uuid, p_requester text, p_reason text, p_idempotency_key text';
  IF NOT FOUND THEN v_failed := v_failed || 'r7_create_review_signature'::text; END IF;
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname='qhub_create_review_request') <> 1 THEN
    v_failed := v_failed || 'r7_create_review_overload'::text;
  END IF;
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_create_review_request'
      AND p.proowner = (SELECT relowner FROM pg_class WHERE oid='public.qhub_manual_review_requests'::regclass);
  IF NOT FOUND THEN v_failed := v_failed || 'r7_create_review_owner_drift'::text; END IF;
  IF NOT coalesce(
       (SELECT md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_create_review_request'
            AND pg_get_function_identity_arguments(p.oid) = 'p_org_id text, p_project_id uuid, p_requester text, p_reason text, p_idempotency_key text')
       IN ('6b46c3d75636fd0c8b628b34a86f4084',   -- reviewed body, LF encoding
           '349b59554232ab7f3b9e4aa3a8cc2331'),  -- reviewed body, CRLF encoding
     FALSE) THEN
    v_failed := v_failed || 'r7_create_review_body_drift'::text;
  END IF;

  /*
   * R11 §1/§6 — atomic acknowledgment RPC: exact signature, SECURITY DEFINER, fixed search_path,
   * sole overload, owner pinned, and exact body pin (browser-denied + service_role present via ACL loop).
   */
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_record_acknowledgment'
      AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.prorettype='jsonb'::regtype
      AND pg_get_function_identity_arguments(p.oid) = 'p_org_id text, p_project_id uuid, p_user_id text, p_action text';
  IF NOT FOUND THEN v_failed := v_failed || 'r7_record_ack_signature'::text; END IF;
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname='qhub_record_acknowledgment') <> 1 THEN
    v_failed := v_failed || 'r7_record_ack_overload'::text;
  END IF;
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_record_acknowledgment'
      AND p.proowner = (SELECT relowner FROM pg_class WHERE oid='public.qhub_acknowledgments'::regclass);
  IF NOT FOUND THEN v_failed := v_failed || 'r7_record_ack_owner_drift'::text; END IF;
  IF NOT coalesce(
       (SELECT md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_record_acknowledgment')
       IN ('b6035e9a35f5ecc49369b68000c7b2a6',   -- reviewed body, LF encoding
           '09e053d93afb7aca96064b758d76213a'),  -- reviewed body, CRLF encoding
     FALSE) THEN
    v_failed := v_failed || 'r7_record_ack_body_drift'::text;
  END IF;

  /*
   * R11 §6 — qhub_canon_cells (canonical hash encoder): sole overload, owner pinned, IMMUTABLE, and
   * an exact body pin. A weakened encoding changes the digest → NOT READY.
   */
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname='qhub_canon_cells') <> 1 THEN
    v_failed := v_failed || 'r7_canon_cells_overload'::text;
  END IF;
  PERFORM 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='qhub_canon_cells'
      AND p.proowner = (SELECT relowner FROM pg_class WHERE oid='public.qhub_acknowledgments'::regclass)
      AND p.provolatile = 'i';
  IF NOT FOUND THEN v_failed := v_failed || 'r7_canon_cells_owner_or_volatility'::text; END IF;
  IF NOT coalesce(
       (SELECT md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_canon_cells')
       IN ('6151a5d4794e56fbc26fc891f8fefdb4',   -- reviewed body, LF encoding
           '2d569f42d1e95f2ffd38dc82e14d727c'),  -- reviewed body, CRLF encoding
     FALSE) THEN
    v_failed := v_failed || 'r7_canon_cells_body_drift'::text;
  END IF;

  /*
   * R11 §2/§6 — acknowledgment immutability trigger pinned exactly: table, BEFORE timing, UPDATE+DELETE
   * events, the qhub_row_immutable function, AND that function's exact body digest. Disabling/altering
   * the trigger or weakening the function body → NOT READY.
   */
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger tg
    WHERE tg.tgname = 'trg_qhub_acknowledgments_immutable'
      AND tg.tgrelid = 'public.qhub_acknowledgments'::regclass
      AND NOT tg.tgisinternal
      AND (tg.tgtype & 2) <> 0          -- BEFORE
      AND (tg.tgtype & 8) <> 0          -- DELETE
      AND (tg.tgtype & 16) <> 0         -- UPDATE
      AND tg.tgenabled = 'O'            -- enabled (origin/always)
      AND tg.tgfoid = 'public.qhub_row_immutable()'::regprocedure
  ) THEN
    v_failed := v_failed || 'r7_ack_immutable_trigger'::text;
  END IF;
  IF NOT coalesce(
       (SELECT md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_row_immutable')
       IN ('41ae59dde9a471b580d28e2cb45984f5',   -- reviewed body, LF encoding
           '4936e3f58627dde5abc10d2b0ecf5b4f'),  -- reviewed body, CRLF encoding
     FALSE) THEN
    v_failed := v_failed || 'r7_ack_immutable_body_drift'::text;
  END IF;

  /*
   * R10 §6 — EXACT constraint + FK semantics via normalized pg_get_constraintdef md5 + validation
   * state. A CHECK(true) substitution or a same-name wrong-expression / wrong-relationship changes
   * the def → NOT READY. Encoded as 'table:conname:defmd5:validated(t|f)'.
   */
  FOR t IN SELECT unnest(ARRAY[
    'public.qhub_manual_review_requests:chk_qhub_review_terminal_binding:96d317cd52870705f9f7defbdfec7326:f',
    'public.qhub_manual_review_requests:chk_qhub_review_classification_binding:6f804edb46b8ba63b345937c5b7a1d95:f',
    'public.qhub_manual_review_requests:chk_qhub_review_decl_hash_hex:6dfbd27d094d1fc5a4a4d0f11639d1ff:t',
    'public.qhub_governance_essentials:chk_qhub_gov_decl_hash_hex:6dfbd27d094d1fc5a4a4d0f11639d1ff:t',
    'public.qhub_acknowledgments:chk_qhub_ack_status:d02eacc726094f0045ad16688f9516c7:t',
    'public.qhub_acknowledgments:chk_qhub_ack_lifecycle:77eb697053f11d3fd061ea855e30b41a:f',
    'public.qhub_manual_review_requests:fk_qhub_review_governance_record:023c71ff41a866736ce25c495f1cc43a:t',
    'public.qhub_manual_review_requests:fk_qhub_review_acknowledgment_record:61bb98f0da57e4f852e0393d95f344b7:t',
    'public.qhub_governance_essentials:fk_qhub_gov_acknowledgment_record:61bb98f0da57e4f852e0393d95f344b7:t',
    'public.qhub_acknowledgments:fk_qhub_ack_governance_record:023c71ff41a866736ce25c495f1cc43a:t'
  ]) LOOP
    IF (SELECT md5(pg_get_constraintdef(c.oid)) FROM pg_constraint c
          WHERE c.conrelid = split_part(t,':',1)::regclass AND c.conname = split_part(t,':',2))
       IS DISTINCT FROM split_part(t,':',3)
       OR (SELECT c.convalidated FROM pg_constraint c
             WHERE c.conrelid = split_part(t,':',1)::regclass AND c.conname = split_part(t,':',2))
          IS DISTINCT FROM (split_part(t,':',4) = 't') THEN
      v_failed := v_failed || ('r6_constraint_semantics:'||split_part(t,':',2))::text;
    END IF;
  END LOOP;

  -- R10 §2/§6 — authoritative acknowledgment contract: lifecycle columns present + status enum
  -- check + one-active partial unique index (exact columns/predicate) + governance FK.
  FOR t IN SELECT unnest(ARRAY[
    'project_id:uuid','governance_record_id:uuid','governance_record_version:int8',
    'required_version:text','status:text','revoked_at:timestamptz','superseded_at:timestamptz'
  ]) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_acknowledgments'::regclass
        AND attname=split_part(t,':',1) AND atttypid=(split_part(t,':',2))::regtype AND NOT attisdropped
    ) THEN
      v_failed := v_failed || ('r6_ack_column:'||split_part(t,':',1))::text;
    END IF;
  END LOOP;
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='uq_qhub_ack_one_active'
      AND indexdef = 'CREATE UNIQUE INDEX uq_qhub_ack_one_active ON public.qhub_acknowledgments '
        || 'USING btree (org_id, project_id, user_id, ack_type, required_version) WHERE (status = ''ACTIVE''::text)'
  ) THEN
    v_failed := v_failed || 'r6_ack_one_active_index'::text;
  END IF;

  /*
   * R11 §6 — FORCED RLS + no extra broad policy. Every authority table must have relforcerowsecurity
   * (so even the owner is subject to the RESTRICTIVE policy), and must carry EXACTLY the single
   * service-only RESTRICTIVE policy — any additional (permissive or extra) policy → NOT READY.
   */
  FOREACH t IN ARRAY tables LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      CONTINUE;
    END IF;
    IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = ('public.'||t)::regclass) THEN
      v_failed := v_failed || ('rls_not_forced:'||t);
    END IF;
    IF (SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename=t) <> 1
       OR EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND permissive='PERMISSIVE') THEN
      v_failed := v_failed || ('extra_policy:'||t);
    END IF;
  END LOOP;

  -- R11 §3/§6 — the DB-authoritative version/classification config row must exist with all columns.
  FOR t IN SELECT unnest(ARRAY[
    'review_policy_version:text','required_acknowledgment_version:text','policy_card_version:text',
    'classification_scheme_id:text','classification_scheme_version:text'
  ]) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute WHERE attrelid='public.qhub_commercial_authority'::regclass
        AND attname=split_part(t,':',1) AND atttypid=(split_part(t,':',2))::regtype AND attnotnull AND NOT attisdropped
    ) THEN
      v_failed := v_failed || ('r7_authority_column:'||split_part(t,':',1))::text;
    END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM public.qhub_commercial_authority WHERE id = 1) THEN
    v_failed := v_failed || 'r7_authority_row_missing'::text;
  END IF;

  RETURN jsonb_build_object(
    'expected_version', '2026-07-30.commercial-launch-r8',
    'ready', (cardinality(v_failed) = 0),
    'failed', to_jsonb(v_failed)
  );
END;
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_commercial_schema() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_commercial_schema() TO service_role;

COMMIT;
