-- ============================================================================
-- QHUB R15.3 — 11 RESTORE REVIEWED PROTECTED BODIES
-- Schema version: 2026-07-30.commercial-launch-r8 (UNCHANGED)
--
-- Restores ONLY these two function bodies to their exact reviewed text:
--   public.qhub_decide_review(uuid,text,boolean,text,text,text)
--   public.qhub_row_immutable()
--
-- The two CREATE OR REPLACE statements below are VERBATIM extracts from
-- supabase/migrations/20260729_commercial_launch_foundation.sql at the reviewed
-- commit (migration SHA-256 b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf).
-- They were copied byte-for-byte, never retyped or reformatted, and a build-time
-- check proves that applying them alone reproduces the approved reviewed LF digests.
--
-- WHAT THIS FIXES. The 2026-07-30 apply passed the migration through a Windows
-- PowerShell clipboard command lacking -Encoding UTF8, so PowerShell 5.1 decoded
-- the BOM-less UTF-8 file as Windows-1252 and re-encoded it mangled (§ -> Â§,
-- — -> â€", → -> â†'). Only these two protected functions contain non-ASCII, and
-- only inside comments — executable text was byte-identical, but the raw digests
-- were not, which is why R15.2C's precheck correctly stopped.
--
-- THIS SCRIPT CHANGES NOTHING ELSE. No other function, no table, policy, RLS
-- setting, constraint, index, trigger, configuration row or data. It creates no
-- overload, mutates no data, contains no destructive statement, and never touches
-- cluster role memberships.
--
-- ACL / OWNER SCOPE:
--   * qhub_decide_review — the migration's exact ACL contract is restated verbatim
--     below, and the owner is restored from the owner of the migration-created
--     table public.qhub_manual_review_requests (derived, never guessed).
--   * qhub_row_immutable — the reviewed migration grants it NOTHING (proacl stays
--     NULL) and sets no owner explicitly. CREATE OR REPLACE preserves both, so this
--     script deliberately issues NO grant, revoke or owner change for it.
--
-- Run ONCE, as one transaction, only after 10_PRE_RESTORE_LIVE_BODY_VERIFY.sql
-- returns SAFE_TO_RESTORE_REVIEWED_BODIES. Idempotent: a second run is a no-op that
-- still passes both gates.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- Never PowerShell 5.1 Get-Content without -Encoding UTF8 — that is the exact
-- defect being repaired here, and it would silently reintroduce it.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- GATE 1 — FAIL-CLOSED PRECONDITION (runs BEFORE any change).
--
-- Both functions must exist at their exact reviewed identity, owner, security mode
-- and search_path, and each body must be EITHER the known mojibake digest (the
-- state this script repairs) OR already a reviewed digest (idempotent re-run).
-- Any third value is unexplained drift: raise and change nothing.
-- ---------------------------------------------------------------------------
DO $r15_3_pre$
DECLARE
  r          record;
  v_oid      oid;
  v_owner    oid;
  v_md5      text;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.qhub_decide_review(uuid,text,boolean,text,text,text)',
       'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
       'public.qhub_manual_review_requests', TRUE,  ARRAY['search_path=pg_catalog, public'],
       '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf', '9bc91d1671c5f65241ea22538c00d703'),
      ('public.qhub_row_immutable()',
       '',
       'public.qhub_acknowledgments',        FALSE, NULL::text[],
       '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f', '583882c1a9b203e278b27d1080065c9e')
    ) AS t(sig, args, owner_table, secdef, cfg, lf, crlf, moji)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: % is missing or not at its exact reviewed signature', r.sig;
    END IF;

    IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.proname = split_part(split_part(r.sig, '(', 1), '.', 2)) <> 1 THEN
      RAISE EXCEPTION 'R15.3 PRE: % has an unexpected overload', r.sig;
    END IF;

    IF pg_get_function_identity_arguments(v_oid) IS DISTINCT FROM r.args THEN
      RAISE EXCEPTION 'R15.3 PRE: % identity arguments differ from the reviewed signature', r.sig;
    END IF;

    SELECT c.relowner INTO v_owner FROM pg_class c WHERE c.oid = to_regclass(r.owner_table);
    IF v_owner IS NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: cannot resolve the contract owner from %', r.owner_table;
    END IF;
    IF (SELECT p.proowner FROM pg_proc p WHERE p.oid = v_oid) IS DISTINCT FROM v_owner THEN
      RAISE EXCEPTION 'R15.3 PRE: % owner drifted from the contract owner of %', r.sig, r.owner_table;
    END IF;

    IF (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = v_oid) IS DISTINCT FROM r.secdef THEN
      RAISE EXCEPTION 'R15.3 PRE: % security mode drifted', r.sig;
    END IF;
    IF (SELECT p.proconfig FROM pg_proc p WHERE p.oid = v_oid) IS DISTINCT FROM r.cfg THEN
      RAISE EXCEPTION 'R15.3 PRE: % search_path drifted', r.sig;
    END IF;

    SELECT md5(p.prosrc) INTO v_md5 FROM pg_proc p WHERE p.oid = v_oid;
    IF v_md5 NOT IN (r.moji, r.lf, r.crlf) THEN
      RAISE EXCEPTION 'R15.3 PRE: % carries an UNKNOWN body (md5=%). This is not the diagnosed mojibake and not a reviewed body. STOP and escalate — do not restore.', r.sig, v_md5;
    END IF;
  END LOOP;
END;
$r15_3_pre$;

-- ---------------------------------------------------------------------------
-- VERBATIM REVIEWED DEFINITION 1 of 2 — public.qhub_decide_review
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- VERBATIM REVIEWED DEFINITION 2 of 2 — public.qhub_row_immutable
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- EXACT OWNER + ACL for qhub_decide_review.
--
-- CREATE OR REPLACE preserves owner and ACL, so these are normally no-ops; they
-- are restated so the reviewed authority state is asserted rather than assumed.
-- The owner is derived from the migration-created table, never guessed. Nothing
-- here applies to qhub_row_immutable, whose reviewed contract is "no grants".
-- ---------------------------------------------------------------------------
DO $r15_3_owner$
DECLARE
  v_owner name;
BEGIN
  SELECT pg_get_userbyid(c.relowner) INTO v_owner
    FROM pg_class c WHERE c.oid = to_regclass('public.qhub_manual_review_requests');
  IF v_owner IS NULL THEN
    RAISE EXCEPTION 'R15.3: cannot resolve the intended owner from public.qhub_manual_review_requests';
  END IF;
  EXECUTE format(
    'ALTER FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) OWNER TO %I', v_owner);
END;
$r15_3_owner$;

REVOKE ALL ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) TO service_role;

-- ---------------------------------------------------------------------------
-- GATE 2 — FAIL-CLOSED VERIFICATION BEFORE COMMIT.
--
-- Both bodies must now hash to exactly one approved reviewed digest (LF or CRLF),
-- and must no longer hash to the mojibake value. If the transfer channel mangled
-- THIS file too, the restored body is not a reviewed body, this raises, and the
-- ENTIRE transaction rolls back leaving the database exactly as it was.
-- ---------------------------------------------------------------------------
DO $r15_3_post$
DECLARE
  r     record;
  v_oid oid;
  v_md5 text;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.qhub_decide_review(uuid,text,boolean,text,text,text)',
       '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf', '9bc91d1671c5f65241ea22538c00d703'),
      ('public.qhub_row_immutable()',
       '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f', '583882c1a9b203e278b27d1080065c9e')
    ) AS t(sig, lf, crlf, moji)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'R15.3 POST: % vanished during restoration', r.sig;
    END IF;

    SELECT md5(p.prosrc) INTO v_md5 FROM pg_proc p WHERE p.oid = v_oid;

    IF v_md5 = r.moji THEN
      RAISE EXCEPTION 'R15.3 POST: % is STILL the mojibake body (md5=%). The SQL was transferred through a non-UTF-8 channel. Rolling back. Re-copy with: Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard', r.sig, v_md5;
    END IF;

    IF v_md5 NOT IN (r.lf, r.crlf) THEN
      RAISE EXCEPTION 'R15.3 POST: % does not match either reviewed digest (md5=%). Rolling back.', r.sig, v_md5;
    END IF;
  END LOOP;
END;
$r15_3_post$;

COMMIT;
