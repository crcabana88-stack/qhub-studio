-- ============================================================================
-- QHUB R15.3/R15.4 — 11 RESTORE REVIEWED BODIES + NORMALIZE THE TRIGGER ACL
-- Schema version: 2026-07-30.commercial-launch-r8 (UNCHANGED)
--
-- In ONE transaction this script:
--   1. requires the EXACT documented live starting state (bodies, attributes,
--      callable interface, owner/security, and both direct ACLs);
--   2. restores the two exact reviewed bodies;
--   3. normalizes ONLY public.qhub_row_immutable()'s ACL from the documented
--      five-row Supabase-default state to the reviewed owner-only contract;
--   4. re-asserts the complete final contract before COMMIT.
--
-- THE BODIES ARE VERBATIM. Everything from `AS $$` onward in each definition below is
-- a byte-for-byte extract of supabase/migrations/20260729_commercial_launch_foundation.sql
-- at the reviewed commit — copied, never retyped.
--
-- WHY THIS SCRIPT MAY CHANGE AN ACL AT ALL.
-- Every earlier round of this package refused to touch ACLs, and that rule still holds
-- for unknown drift. This one transition is different and is explicitly authorized:
-- the starting state is fully documented and reproduced (Supabase applies
-- ALTER DEFAULT PRIVILEGES granting EXECUTE on new functions to anon, authenticated
-- and service_role, so the trigger helper acquired five ACL rows the migration never
-- asked for), and the target is the reviewed least-privilege contract the migration now
-- states explicitly. GATE 1 refuses unless the live ACL is EXACTLY that documented
-- five-row set, so no unknown ACL drift can be silently normalized.
--
-- WHY REVOKING IS SAFE — verified, not assumed. PostgreSQL checks EXECUTE on a trigger
-- function at CREATE TRIGGER time, NOT at fire time. With EXECUTE revoked from PUBLIC,
-- anon, authenticated and service_role, the immutability triggers still fire: a
-- protected-field UPDATE is still rejected, the allowed ACTIVE->REVOKED transition
-- still succeeds, and direct invocation remains impossible for every role
-- ("trigger functions can only be called as triggers").
--
-- NOTHING ELSE CHANGES. No other function, table, policy, RLS setting, constraint,
-- index, trigger, configuration row or data. No overload, no DROP, no data mutation,
-- no destructive statement, and never any cluster role-membership change.
--
-- qhub_decide_review's ACL is restated verbatim from the migration and must already be
-- exactly the reviewed set both before and after.
--
-- Run ONCE, as one transaction, only after 10_PRE_RESTORE_LIVE_BODY_VERIFY.sql returns
-- SAFE_TO_RESTORE_REVIEWED_BODIES. A second run under the final reviewed state is a
-- no-op that still passes both gates.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- Never PowerShell 5.1 Get-Content without -Encoding UTF8 — that is the defect this
-- package repairs, and it would silently reintroduce it.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- GATE 1 — FAIL-CLOSED PRECONDITION (runs BEFORE any change).
-- Requires the exact documented live starting state, including the five-row
-- Supabase-default ACL on the trigger helper. Any other state raises and changes
-- nothing, leaving the drift intact as escalation evidence.
-- ---------------------------------------------------------------------------
DO $r15_4_pre$
DECLARE
  r     record;
  v_oid oid;
  v_own oid;
  p     record;
  v_acl_start boolean;
  v_acl_final boolean;
  v_is_start boolean;
  v_is_final boolean;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.qhub_decide_review(uuid,text,boolean,text,text,text)',
       'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
       'public.qhub_manual_review_requests', 'plpgsql', 'f', 'jsonb', TRUE,
       ARRAY['search_path=pg_catalog, public'], 6, ARRAY['p_request_id','p_actor','p_is_staff','p_decision','p_reason','p_policy_version'], '2950 25 16 25 25 25',
       '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf', '9bc91d1671c5f65241ea22538c00d703'),
      ('public.qhub_row_immutable()',
       '',
       'public.qhub_acknowledgments', 'plpgsql', 'f', 'trigger', FALSE,
       NULL::text[], 0, NULL::text[], '',
       '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f', '583882c1a9b203e278b27d1080065c9e')
    ) AS t(sig, args, owner_table, lang, kind, rettype, secdef, cfg, nargs, argnames, argtypes, lf, crlf, moji)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: % is missing or not at its exact reviewed signature', r.sig; END IF;
    IF (SELECT count(*) FROM pg_proc pp JOIN pg_namespace nn ON nn.oid = pp.pronamespace
         WHERE nn.nspname = 'public'
           AND pp.proname = split_part(split_part(r.sig, '(', 1), '.', 2)) <> 1 THEN
      RAISE EXCEPTION 'R15.3 PRE: % has an unexpected overload', r.sig; END IF;

    SELECT pp.*, l.lanname INTO p
      FROM pg_proc pp JOIN pg_language l ON l.oid = pp.prolang WHERE pp.oid = v_oid;
    SELECT c.relowner INTO v_own FROM pg_class c WHERE c.oid = to_regclass(r.owner_table);
    IF v_own IS NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: cannot resolve the contract owner from %', r.owner_table; END IF;

    IF pg_get_function_identity_arguments(v_oid) IS DISTINCT FROM r.args THEN
      RAISE EXCEPTION 'R15.3 PRE: % identity arguments drifted', r.sig; END IF;
    IF pg_get_function_arguments(v_oid) IS DISTINCT FROM r.args THEN
      RAISE EXCEPTION 'unexpected_function_default_argument_state: % full argument list drifted (live=%)', r.sig, pg_get_function_arguments(v_oid); END IF;
    IF p.pronargdefaults <> 0 OR p.proargdefaults IS NOT NULL THEN
      RAISE EXCEPTION 'unexpected_function_default_argument_state: % has % argument default(s). The reviewed contract has NONE.', r.sig, p.pronargdefaults; END IF;
    IF p.pronargs IS DISTINCT FROM r.nargs THEN
      RAISE EXCEPTION 'R15.3 PRE: % argument count drifted', r.sig; END IF;
    IF p.proargnames IS DISTINCT FROM r.argnames THEN
      RAISE EXCEPTION 'R15.3 PRE: % argument names drifted', r.sig; END IF;
    IF p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: % has non-IN argument modes', r.sig; END IF;
    IF p.proargtypes::text IS DISTINCT FROM r.argtypes THEN
      RAISE EXCEPTION 'R15.3 PRE: % argument types drifted', r.sig; END IF;
    IF p.proowner IS DISTINCT FROM v_own THEN
      RAISE EXCEPTION 'R15.3 PRE: % owner drifted', r.sig; END IF;
    IF p.prosecdef IS DISTINCT FROM r.secdef THEN
      RAISE EXCEPTION 'R15.3 PRE: % security mode drifted', r.sig; END IF;
    IF p.proconfig IS DISTINCT FROM r.cfg THEN
      RAISE EXCEPTION 'R15.3 PRE: % search_path drifted', r.sig; END IF;
    IF p.lanname IS DISTINCT FROM r.lang THEN
      RAISE EXCEPTION 'R15.3 PRE: % language drifted', r.sig; END IF;
    IF p.prokind IS DISTINCT FROM r.kind THEN
      RAISE EXCEPTION 'R15.3 PRE: % prokind drifted', r.sig; END IF;
    IF p.prorettype IS DISTINCT FROM r.rettype::regtype THEN
      RAISE EXCEPTION 'R15.3 PRE: % return type drifted', r.sig; END IF;
    IF p.provolatile <> 'v' OR p.proisstrict OR p.proparallel <> 'u' OR p.proleakproof
       OR p.proretset OR p.procost <> 100::real OR p.prorows <> 0::real
       OR p.provariadic <> 0::oid OR p.prosupport <> 0::oid
       OR p.protrftypes IS NOT NULL OR p.probin IS NOT NULL OR p.prosqlbody IS NOT NULL THEN
      RAISE EXCEPTION 'R15.3 PRE: % semantic attributes drifted (volatility/strict/parallel/leakproof/retset/cost/rows/variadic/support/transforms/probin/prosqlbody)', r.sig; END IF;


    IF r.sig = 'public.qhub_decide_review(uuid,text,boolean,text,text,text)' THEN
      v_acl_start := (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 2, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = p.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE));
      v_acl_final := (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 2, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = p.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE));
    ELSE
      v_acl_start := (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 5, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = 0 AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'anon' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'authenticated' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = 0 OR pg_get_userbyid(ae.grantee) = 'anon' OR pg_get_userbyid(ae.grantee) = 'authenticated' OR ae.grantee = p.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE));
      v_acl_final := (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 1, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = p.proowner)))), FALSE));
    END IF;

    v_is_start := (md5(p.prosrc) = r.moji)               AND v_acl_start;
    v_is_final := (md5(p.prosrc) IN (r.lf, r.crlf))      AND v_acl_final;

    IF NOT (v_is_start OR v_is_final) THEN
      -- Name the specific cause so the deterministic tokens stay meaningful.
      IF md5(p.prosrc) = r.moji OR md5(p.prosrc) IN (r.lf, r.crlf) THEN
        RAISE EXCEPTION 'unexpected_function_acl_state: % has a recognized body but its direct ACL does not match the ACL for that state (live acl=%). Authorized pairs are: known-mojibake body WITH the documented starting ACL, or a reviewed body WITH the reviewed target ACL. No change was made - STOP and escalate. This script never repairs unknown ACL drift.',
          r.sig, coalesce(p.proacl::text, '(NULL)');
      ELSE
        RAISE EXCEPTION 'unexpected_function_state: % carries an UNKNOWN body (md5=%) - neither the diagnosed mojibake nor a reviewed body. No change was made - STOP and escalate.',
          r.sig, md5(p.prosrc);
      END IF;
    END IF;
  END LOOP;
END;
$r15_4_pre$;

-- ---------------------------------------------------------------------------
-- VERBATIM REVIEWED BODY 1 of 2 — public.qhub_decide_review
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.qhub_decide_review(
  p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
) RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
CALLED ON NULL INPUT
PARALLEL UNSAFE
NOT LEAKPROOF
COST 100
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
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
-- VERBATIM REVIEWED BODY 2 of 2 — public.qhub_row_immutable
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.qhub_row_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
VOLATILE
CALLED ON NULL INPUT
PARALLEL UNSAFE
NOT LEAKPROOF
COST 100
AS $$
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
-- EXACT OWNER + ACL for qhub_decide_review (restated verbatim from the migration).
-- ---------------------------------------------------------------------------
DO $r15_4_owner$
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
$r15_4_owner$;

REVOKE ALL ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_decide_review(UUID, TEXT, BOOLEAN, TEXT, TEXT, TEXT) TO service_role;

-- ---------------------------------------------------------------------------
-- R15.4 — NORMALIZE THE TRIGGER HELPER ACL to the reviewed owner-only contract.
-- Identical statements to the ones the migration now contains, so a fresh install
-- and a live-patched database reach byte-identical ACL state. The owner GRANT is
-- derived from the catalog, never a hardcoded role name.
-- ---------------------------------------------------------------------------
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM anon;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM authenticated;
REVOKE ALL PRIVILEGES ON FUNCTION public.qhub_row_immutable() FROM service_role;

DO $r15_4_trigger_acl$
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
$r15_4_trigger_acl$;

-- ---------------------------------------------------------------------------
-- GATE 2 — FAIL-CLOSED CERTIFICATION BEFORE COMMIT.
-- Re-asserts the COMPLETE final contract: both reviewed bodies, every semantic and
-- callable attribute, owner/security/search_path, and BOTH final ACL sets — the
-- trigger helper now owner-only. Any mismatch raises and the ENTIRE transaction
-- rolls back: both bodies and the ACL revert together.
-- ---------------------------------------------------------------------------
DO $r15_4_post$
DECLARE
  r     record;
  v_oid oid;
  v_own oid;
  p     record;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.qhub_decide_review(uuid,text,boolean,text,text,text)',
       'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
       'public.qhub_manual_review_requests', 'plpgsql', 'f', 'jsonb', TRUE,
       ARRAY['search_path=pg_catalog, public'], 6, ARRAY['p_request_id','p_actor','p_is_staff','p_decision','p_reason','p_policy_version'], '2950 25 16 25 25 25',
       '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf', '9bc91d1671c5f65241ea22538c00d703'),
      ('public.qhub_row_immutable()',
       '',
       'public.qhub_acknowledgments', 'plpgsql', 'f', 'trigger', FALSE,
       NULL::text[], 0, NULL::text[], '',
       '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f', '583882c1a9b203e278b27d1080065c9e')
    ) AS t(sig, args, owner_table, lang, kind, rettype, secdef, cfg, nargs, argnames, argtypes, lf, crlf, moji)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'R15.3 POST: % is missing or not at its exact reviewed signature', r.sig; END IF;
    IF (SELECT count(*) FROM pg_proc pp JOIN pg_namespace nn ON nn.oid = pp.pronamespace
         WHERE nn.nspname = 'public'
           AND pp.proname = split_part(split_part(r.sig, '(', 1), '.', 2)) <> 1 THEN
      RAISE EXCEPTION 'R15.3 POST: % has an unexpected overload', r.sig; END IF;

    SELECT pp.*, l.lanname INTO p
      FROM pg_proc pp JOIN pg_language l ON l.oid = pp.prolang WHERE pp.oid = v_oid;
    SELECT c.relowner INTO v_own FROM pg_class c WHERE c.oid = to_regclass(r.owner_table);
    IF v_own IS NULL THEN
      RAISE EXCEPTION 'R15.3 POST: cannot resolve the contract owner from %', r.owner_table; END IF;

    IF pg_get_function_identity_arguments(v_oid) IS DISTINCT FROM r.args THEN
      RAISE EXCEPTION 'R15.3 POST: % identity arguments drifted', r.sig; END IF;
    IF pg_get_function_arguments(v_oid) IS DISTINCT FROM r.args THEN
      RAISE EXCEPTION 'unexpected_function_default_argument_state: % full argument list drifted (live=%)', r.sig, pg_get_function_arguments(v_oid); END IF;
    IF p.pronargdefaults <> 0 OR p.proargdefaults IS NOT NULL THEN
      RAISE EXCEPTION 'unexpected_function_default_argument_state: % has % argument default(s). The reviewed contract has NONE.', r.sig, p.pronargdefaults; END IF;
    IF p.pronargs IS DISTINCT FROM r.nargs THEN
      RAISE EXCEPTION 'R15.3 POST: % argument count drifted', r.sig; END IF;
    IF p.proargnames IS DISTINCT FROM r.argnames THEN
      RAISE EXCEPTION 'R15.3 POST: % argument names drifted', r.sig; END IF;
    IF p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL THEN
      RAISE EXCEPTION 'R15.3 POST: % has non-IN argument modes', r.sig; END IF;
    IF p.proargtypes::text IS DISTINCT FROM r.argtypes THEN
      RAISE EXCEPTION 'R15.3 POST: % argument types drifted', r.sig; END IF;
    IF p.proowner IS DISTINCT FROM v_own THEN
      RAISE EXCEPTION 'R15.3 POST: % owner drifted', r.sig; END IF;
    IF p.prosecdef IS DISTINCT FROM r.secdef THEN
      RAISE EXCEPTION 'R15.3 POST: % security mode drifted', r.sig; END IF;
    IF p.proconfig IS DISTINCT FROM r.cfg THEN
      RAISE EXCEPTION 'R15.3 POST: % search_path drifted', r.sig; END IF;
    IF p.lanname IS DISTINCT FROM r.lang THEN
      RAISE EXCEPTION 'R15.3 POST: % language drifted', r.sig; END IF;
    IF p.prokind IS DISTINCT FROM r.kind THEN
      RAISE EXCEPTION 'R15.3 POST: % prokind drifted', r.sig; END IF;
    IF p.prorettype IS DISTINCT FROM r.rettype::regtype THEN
      RAISE EXCEPTION 'R15.3 POST: % return type drifted', r.sig; END IF;
    IF p.provolatile <> 'v' OR p.proisstrict OR p.proparallel <> 'u' OR p.proleakproof
       OR p.proretset OR p.procost <> 100::real OR p.prorows <> 0::real
       OR p.provariadic <> 0::oid OR p.prosupport <> 0::oid
       OR p.protrftypes IS NOT NULL OR p.probin IS NOT NULL OR p.prosqlbody IS NOT NULL THEN
      RAISE EXCEPTION 'R15.3 POST: % semantic attributes drifted (volatility/strict/parallel/leakproof/retset/cost/rows/variadic/support/transforms/probin/prosqlbody)', r.sig; END IF;

    IF r.sig = 'public.qhub_decide_review(uuid,text,boolean,text,text,text)' THEN
      IF NOT (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 2, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = p.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE)) THEN
        RAISE EXCEPTION 'unexpected_function_acl_state: % direct ACL is not the exact reviewed set (live=%). Reviewed: qhub_decide_review: exactly 2 row(s) — owner, service_role (EXECUTE, granted by owner, not grantable).', r.sig, coalesce(p.proacl::text,'(NULL)'); END IF;
    ELSE
      IF NOT (coalesce((SELECT count(*) FROM aclexplode(p.proacl)) = 1, FALSE)
                 AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE ae.grantee = p.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable)), FALSE)
                 AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = p.proowner AND NOT ae.is_grantable AND (ae.grantee = p.proowner)))), FALSE)) THEN
        RAISE EXCEPTION 'unexpected_function_acl_state: % direct ACL is not the expected reviewed target set (live=%). Expected: qhub_row_immutable: exactly 1 row(s) — owner (EXECUTE, granted by owner, not grantable).', r.sig, coalesce(p.proacl::text,'(NULL)'); END IF;
    END IF;

    IF md5(p.prosrc) = r.moji THEN
      RAISE EXCEPTION 'R15.3 POST: % is STILL the mojibake body (md5=%). Transferred through a non-UTF-8 channel. Rolling back. Re-copy with: Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard', r.sig, md5(p.prosrc); END IF;
    IF md5(p.prosrc) NOT IN (r.lf, r.crlf) THEN
      RAISE EXCEPTION 'R15.3 POST: % does not match either reviewed digest (md5=%). Rolling back.', r.sig, md5(p.prosrc); END IF;
  END LOOP;
END;
$r15_4_post$;

COMMIT;
