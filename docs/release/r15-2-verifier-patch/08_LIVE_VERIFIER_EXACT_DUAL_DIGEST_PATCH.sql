-- ============================================================================
-- QHUB R15.2 — LIVE VERIFIER EXACT DUAL-DIGEST PATCH
-- Schema version: 2026-07-30.commercial-launch-r8 (UNCHANGED)
--
-- Replaces ONLY public.qhub_verify_commercial_schema() so its five function-body
-- pins hash RAW md5(prosrc) and accept exactly two separately reviewed encodings
-- of each reviewed body: the LF digest and the CRLF digest.
--
-- Supersedes the WITHDRAWN R15.1 patch, which hashed
-- md5(replace(prosrc, chr(13), '')). Deleting every CR also deleted a CR injected
-- INSIDE executable text, so a body containing 'staff'||chr(13)||'_required'
-- hashed identically to the reviewed body and produced a FALSE READY. No
-- normalization is used here: no replace, regexp_replace, translate or trim.
--
-- This script changes NO other object and NO data. It does not touch any
-- protected function body, signature, owner, security mode, search_path, table,
-- policy, constraint, index, RLS setting or ACL other than restating the
-- verifier's own reviewed grants.
--
-- Run ONCE, as one transaction, only after
-- 07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql returns
-- SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH.
-- ============================================================================

BEGIN;

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
