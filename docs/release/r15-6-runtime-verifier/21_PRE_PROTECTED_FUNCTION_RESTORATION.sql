-- ============================================================================
-- QHUB R15.6 — 21 PRE PROTECTED FUNCTION RESTORATION (READ-ONLY)
--
-- Authorizes 11_RESTORE_REVIEWED_PROTECTED_BODIES.sql ONLY if the live database is
-- in the EXACT documented starting state: both protected functions carry their exact
-- reviewed identity, callable interface, semantic attributes and owner/security mode,
-- both bodies are byte-identical to the KNOWN live mojibake digest, and the direct
-- ACLs are exactly the documented live sets. Performs NO writes.
--
-- WHY THE TWO ACL EXPECTATIONS DIFFER (R15.4).
-- The reviewed migration states an explicit ACL for qhub_decide_review, so every
-- environment agrees: exactly the owner's own EXECUTE plus service_role's.
-- It did NOT state one for qhub_row_immutable, so the result was whatever the
-- platform's default privileges produced â€” and the two environments disagreed:
--   * plain PostgreSQL / PGlite -> proacl IS NULL
--   * Supabase (ALTER DEFAULT PRIVILEGES ... GRANT EXECUTE ON FUNCTIONS TO
--     anon, authenticated, service_role) -> five rows: PUBLIC, anon, authenticated,
--     the owner and service_role
-- Both were reproduced from this exact migration. R15.3C's precheck correctly STOPPED
-- on the live five-row set because the reviewed contract (derived under PGlite) said
-- proacl IS NULL. That was a contract defect, not tampering.
--
-- R15.4 fixes the contract at source: the migration now states the ACL explicitly, and
-- this file authorizes the DELIBERATE, DOCUMENTED transition
--     five-row Supabase-default ACL  ->  owner-only reviewed ACL
-- for qhub_row_immutable, while requiring qhub_decide_review's ACL to be exactly the
-- reviewed set already verified live.
--
-- This is the ONLY ACL transition the package authorizes. Any other difference â€”
-- a sixth row, a missing expected row, a grant option, a different grantor, a
-- different owner â€” is drift and STOPs. 11 never repairs unknown ACL drift.
--
-- Safety: identities resolve through to_regprocedure(), which returns NULL for a
-- missing function rather than raising 42883. Neither target function is invoked, so
-- running this file IN FULL is safe in any state.
--
-- QUERY 1 is per-function detail. QUERY 2 â€” the LAST statement â€” is the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- R15.6 authority gate: verifier, exact live report, owner references, and triggers.
DO $r15_6_pre_authority$
DECLARE
  v_verifier oid := to_regprocedure('public.qhub_verify_commercial_schema()');
  v_row oid := to_regprocedure('public.qhub_row_immutable()');
  v_report jsonb;
  v_expected_labels jsonb := jsonb_build_array(
    'decide_review_body_drift',
    'r7_ack_immutable_body_drift',
    'row_immutable_body_digest',
    'row_immutable_acl_cardinality',
    'row_immutable_acl_unexpected_grantee'
  );
  v_failed text[] := ARRAY[]::text[];
  t text;
BEGIN
  IF v_verifier IS NULL
     OR (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='qhub_verify_commercial_schema') <> 1 THEN
    v_failed := v_failed || 'verifier_identity';
  ELSIF NOT EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
     WHERE p.oid=v_verifier
       AND pg_get_function_identity_arguments(p.oid)=''
       AND p.prorettype='jsonb'::regtype AND NOT p.proretset AND p.prokind='f'
       AND p.pronargs=0 AND p.pronargdefaults=0 AND p.proargdefaults IS NULL
       AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
       AND p.proargtypes::text='' AND p.provariadic=0
       AND l.lanname='plpgsql' AND p.provolatile='s' AND NOT p.proisstrict
       AND p.proparallel='u' AND NOT p.proleakproof AND p.procost=100 AND p.prorows=0
       AND p.prosupport::oid=0 AND p.protrftypes IS NULL
       AND p.probin IS NULL AND p.prosqlbody IS NULL
       AND p.proowner=(SELECT c.relowner FROM pg_class c
                        WHERE c.oid=to_regclass('public.qhub_manual_review_requests'))
       AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']
       AND md5(p.prosrc) IN ('1c6f85b4cb410dc4ca307ed22ee1de47',
                             '42b43aaa01a770dc7d4a2a0d2f7f33b6')
  ) THEN
    v_failed := v_failed || 'verifier_metadata_or_body';
  ELSIF NOT EXISTS (
    SELECT 1 FROM pg_proc p WHERE p.oid=v_verifier
      AND (SELECT count(*) FROM aclexplode(p.proacl))=2
      AND EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                   WHERE ae.grantee=p.proowner AND ae.grantor=p.proowner
                     AND ae.privilege_type='EXECUTE' AND NOT ae.is_grantable)
      AND EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                   WHERE pg_get_userbyid(ae.grantee)='service_role'
                     AND ae.grantor=p.proowner AND ae.privilege_type='EXECUTE'
                     AND NOT ae.is_grantable)
      AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                       WHERE ae.is_grantable OR ae.grantor<>p.proowner
                          OR ae.privilege_type<>'EXECUTE'
                          OR (ae.grantee<>p.proowner AND pg_get_userbyid(ae.grantee)<>'service_role'))
      AND NOT EXISTS (SELECT 1 FROM pg_roles r
                       WHERE NOT r.rolsuper AND r.oid<>p.proowner
                         AND r.rolname<>'service_role'
                         AND has_function_privilege(r.oid,p.oid,'EXECUTE'))
  ) THEN
    v_failed := v_failed || 'verifier_acl';
  ELSE
    v_report := public.qhub_verify_commercial_schema();
    IF jsonb_typeof(v_report) IS DISTINCT FROM 'object'
       OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(v_report) k)
            IS DISTINCT FROM ARRAY['expected_version','failed','ready']::text[]
       OR v_report->>'expected_version'<>'2026-07-30.commercial-launch-r8'
       OR v_report->'ready'<>'false'::jsonb
       OR v_report->'failed' IS DISTINCT FROM v_expected_labels THEN
      v_failed := v_failed || 'verifier_exact_live_report';
    END IF;
  END IF;

  IF current_user<>'postgres' OR session_user<>'postgres' THEN
    v_failed := v_failed || 'execution_role';
  END IF;

  IF to_regclass('public.qhub_manual_review_requests') IS NULL
     OR to_regclass('public.qhub_acknowledgments') IS NULL
     OR to_regclass('public.qhub_usage_ledger') IS NULL
     OR to_regclass('public.qhub_entitlement_audit') IS NULL
     OR EXISTS (
       SELECT 1 FROM unnest(ARRAY[
         'public.qhub_manual_review_requests',
         'public.qhub_acknowledgments',
         'public.qhub_usage_ledger',
         'public.qhub_entitlement_audit'
       ]) x(name)
       WHERE (SELECT pg_get_userbyid(c.relowner) FROM pg_class c
               WHERE c.oid=to_regclass(x.name))<>'postgres'
     ) THEN
    v_failed := v_failed || 'owner_reference_objects';
  END IF;

  IF v_row IS NULL THEN
    v_failed := v_failed || 'row_immutable_identity';
  ELSE
    FOREACH t IN ARRAY ARRAY['qhub_acknowledgments','qhub_usage_ledger','qhub_entitlement_audit']
    LOOP
      IF (SELECT count(*) FROM pg_trigger tg
           WHERE tg.tgname='trg_'||t||'_immutable'
             AND tg.tgrelid=to_regclass('public.'||t)
             AND tg.tgfoid=v_row AND tg.tgtype=27
             AND tg.tgenabled='O' AND NOT tg.tgisinternal
             AND tg.tgconstraint=0)<>1 THEN
        v_failed := v_failed || ('trigger_contract:'||t);
      END IF;
    END LOOP;
    IF (SELECT count(*) FROM pg_trigger tg
         WHERE tg.tgfoid=v_row AND NOT tg.tgisinternal)<>3 THEN
      v_failed := v_failed || 'trigger_binding_cardinality';
    END IF;
  END IF;

  IF cardinality(v_failed)>0 THEN
    RAISE EXCEPTION 'R15_6_PROTECTED_FUNCTION_PRE_STOP:%', array_to_string(v_failed,',');
  END IF;
END;
$r15_6_pre_authority$;


-- ---------------------------------------------------------------------------
-- QUERY 1 â€” Per-function detail. Every flag below is an input to the verdict.
--
-- Expected direct ACL on the live database BEFORE restoration:
--   qhub_decide_review : exactly 2 rows â€” owner, service_role
--   qhub_row_immutable : exactly 5 rows â€” PUBLIC, anon, authenticated, owner,
--                        service_role   (the Supabase default state)
-- all EXECUTE, granted by the owner, none grantable.
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_lang, expect_kind, expect_rettype, expect_secdef, expect_config,
            expect_nargs, expect_argnames, expect_argtypes,
            lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     'plpgsql', 'f', 'jsonb', TRUE, ARRAY['search_path=pg_catalog, public'],
     6, ARRAY['p_request_id','p_actor','p_is_staff','p_decision','p_reason','p_policy_version'], '2950 25 16 25 25 25',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     'plpgsql', 'f', 'trigger', FALSE, NULL::text[],
     0, NULL::text[], '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f',
     '583882c1a9b203e278b27d1080065c9e')
),
resolved AS (
  SELECT k.*, to_regprocedure(k.signature) AS resolved_regproc,
         (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
           WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
    FROM target k
),
live AS (
  SELECT r.*, p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl,
         p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.proretset,
         p.procost, p.prorows, p.provariadic, p.prosupport, p.protrftypes,
         p.prokind, p.prorettype, p.pronargs, p.pronargdefaults, p.proargdefaults,
         p.proargnames, p.proargmodes, p.proallargtypes, p.proargtypes,
         p.probin, p.prosqlbody, l.lanname
    FROM resolved r
    LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
    LEFT JOIN pg_language l ON l.oid = p.prolang
),
evaluated AS (
  SELECT
    v.proname,
    (v.oid IS NOT NULL)                                                          AS function_present,
    (v.overload_count = 1)                                                       AS single_overload,
    coalesce(pg_get_function_identity_arguments(v.oid) = v.identity_arguments, FALSE) AS signature_ok,
    coalesce(pg_get_function_arguments(v.oid) = v.identity_arguments, FALSE)   AS full_arguments_ok,
    coalesce(v.pronargs = v.expect_nargs, FALSE)                              AS nargs_ok,
    coalesce(v.pronargdefaults = 0, FALSE)                                       AS no_arg_defaults,
    (v.oid IS NOT NULL AND v.proargdefaults IS NULL)                          AS no_default_expressions,
    coalesce(v.proargnames IS NOT DISTINCT FROM v.expect_argnames, FALSE)     AS argnames_ok,
    (v.oid IS NOT NULL AND v.proargmodes IS NULL)                             AS argmodes_plain_in,
    (v.oid IS NOT NULL AND v.proallargtypes IS NULL)                          AS no_out_or_table_args,
    coalesce(v.proargtypes::text = v.expect_argtypes, FALSE)                  AS argtypes_ok,
    coalesce(v.pronargdefaults = 0 AND v.provariadic = 0::oid, FALSE)         AS no_alternate_arity,
    coalesce(v.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(v.owner_table)), FALSE)
                                                                                    AS owner_ok,
    coalesce(v.prosecdef = v.expect_secdef, FALSE)                            AS security_ok,
    coalesce(v.proconfig IS NOT DISTINCT FROM v.expect_config, FALSE)         AS search_path_ok,
    coalesce(v.lanname = v.expect_lang, FALSE)                                AS language_ok,
    coalesce(v.prokind = v.expect_kind, FALSE)                                AS prokind_ok,
    coalesce(v.prorettype = v.expect_rettype::regtype, FALSE)                 AS rettype_ok,
    coalesce(v.provolatile = 'v', FALSE)                                         AS volatility_ok,
    coalesce(v.proisstrict = FALSE, FALSE)                                       AS strictness_ok,
    coalesce(v.proparallel = 'u', FALSE)                                         AS parallel_ok,
    coalesce(v.proleakproof = FALSE, FALSE)                                      AS leakproof_ok,
    coalesce(v.proretset = FALSE, FALSE)                                         AS retset_ok,
    coalesce(v.procost = 100::real, FALSE)                                       AS cost_ok,
    coalesce(v.prorows = 0::real, FALSE)                                         AS rows_ok,
    coalesce(v.provariadic = 0::oid, FALSE)                                      AS variadic_ok,
    coalesce(v.prosupport = 0::oid, FALSE)                                       AS no_support_function,
    (v.oid IS NOT NULL AND v.protrftypes IS NULL)                             AS no_transforms,
    (v.oid IS NOT NULL AND v.probin IS NULL)                                  AS no_c_binary_link,
    (v.oid IS NOT NULL AND v.prosqlbody IS NULL)                              AS no_sql_standard_body,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT count(*) FROM aclexplode(v.proacl)) = 2, FALSE)
           ELSE coalesce((SELECT count(*) FROM aclexplode(v.proacl)) = 5, FALSE) END                                                    AS acl_cardinality_exact,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
           ELSE coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = 0 AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'anon' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'authenticated' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE) END                                                 AS acl_expected_rows_present,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = v.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE)
           ELSE coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = 0 OR pg_get_userbyid(ae.grantee) = 'anon' OR pg_get_userbyid(ae.grantee) = 'authenticated' OR ae.grantee = v.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE) END                                                 AS acl_no_unexpected_entry,
    coalesce(md5(v.prosrc) = v.mojibake_digest, FALSE)                        AS is_known_mojibake,
    coalesce(md5(v.prosrc) IN (v.lf_digest, v.crlf_digest), FALSE)         AS already_reviewed
  FROM live v
),
scored AS (
  SELECT e.*, (function_present AND single_overload AND signature_ok AND full_arguments_ok
     AND nargs_ok AND no_arg_defaults AND no_default_expressions AND argnames_ok
     AND argmodes_plain_in AND no_out_or_table_args AND argtypes_ok AND no_alternate_arity
     AND owner_ok AND security_ok AND search_path_ok
     AND language_ok AND prokind_ok AND rettype_ok
     AND volatility_ok AND strictness_ok AND parallel_ok AND leakproof_ok
     AND retset_ok AND cost_ok AND rows_ok AND variadic_ok
     AND no_support_function AND no_transforms AND no_c_binary_link AND no_sql_standard_body
     AND acl_cardinality_exact AND acl_expected_rows_present AND acl_no_unexpected_entry) AS attributes_ok FROM evaluated e
)
SELECT
  proname,
  function_present, single_overload, signature_ok,
  full_arguments_ok, nargs_ok, no_arg_defaults, no_default_expressions,
  argnames_ok, argmodes_plain_in, no_out_or_table_args, argtypes_ok, no_alternate_arity,
  owner_ok, security_ok, search_path_ok,
  acl_cardinality_exact, acl_expected_rows_present, acl_no_unexpected_entry,
  language_ok, prokind_ok, rettype_ok,
  volatility_ok, strictness_ok, parallel_ok, leakproof_ok,
  retset_ok, cost_ok, rows_ok, variadic_ok, no_support_function, no_transforms,
  no_c_binary_link, no_sql_standard_body,
  attributes_ok, is_known_mojibake, already_reviewed,
  (attributes_ok AND is_known_mojibake AND NOT already_reviewed) AS restorable
FROM scored
ORDER BY proname;

-- ---------------------------------------------------------------------------
-- QUERY 2 â€” VERDICT. Act on this value alone.
--
--   SAFE_TO_RESTORE_REVIEWED_BODIES
--     both functions are in the exact documented live starting state, so the
--     deliberate body restoration + trigger-ACL normalization may proceed.
--
--   UNEXPECTED_LIVE_BODY_STOP
--     anything else. Distinct causes, kept separate in the runbook:
--       * already_reviewed_count > 0 â€” restoration already ran; go to 12.
--       * attributes_ok = false      â€” attribute, callable-interface or ACL drift
--                                      outside the documented transition.
--                                      STOP and ESCALATE. Do NOT run 11.
--       * a body that is not the known mojibake â€” unexplained drift. Escalate.
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_lang, expect_kind, expect_rettype, expect_secdef, expect_config,
            expect_nargs, expect_argnames, expect_argtypes,
            lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     'plpgsql', 'f', 'jsonb', TRUE, ARRAY['search_path=pg_catalog, public'],
     6, ARRAY['p_request_id','p_actor','p_is_staff','p_decision','p_reason','p_policy_version'], '2950 25 16 25 25 25',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     'plpgsql', 'f', 'trigger', FALSE, NULL::text[],
     0, NULL::text[], '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f',
     '583882c1a9b203e278b27d1080065c9e')
),
resolved AS (
  SELECT k.*, to_regprocedure(k.signature) AS resolved_regproc,
         (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
           WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
    FROM target k
),
live AS (
  SELECT r.*, p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl,
         p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.proretset,
         p.procost, p.prorows, p.provariadic, p.prosupport, p.protrftypes,
         p.prokind, p.prorettype, p.pronargs, p.pronargdefaults, p.proargdefaults,
         p.proargnames, p.proargmodes, p.proallargtypes, p.proargtypes,
         p.probin, p.prosqlbody, l.lanname
    FROM resolved r
    LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
    LEFT JOIN pg_language l ON l.oid = p.prolang
),
evaluated AS (
  SELECT
    v.proname,
    (v.oid IS NOT NULL)                                                          AS function_present,
    (v.overload_count = 1)                                                       AS single_overload,
    coalesce(pg_get_function_identity_arguments(v.oid) = v.identity_arguments, FALSE) AS signature_ok,
    coalesce(pg_get_function_arguments(v.oid) = v.identity_arguments, FALSE)   AS full_arguments_ok,
    coalesce(v.pronargs = v.expect_nargs, FALSE)                              AS nargs_ok,
    coalesce(v.pronargdefaults = 0, FALSE)                                       AS no_arg_defaults,
    (v.oid IS NOT NULL AND v.proargdefaults IS NULL)                          AS no_default_expressions,
    coalesce(v.proargnames IS NOT DISTINCT FROM v.expect_argnames, FALSE)     AS argnames_ok,
    (v.oid IS NOT NULL AND v.proargmodes IS NULL)                             AS argmodes_plain_in,
    (v.oid IS NOT NULL AND v.proallargtypes IS NULL)                          AS no_out_or_table_args,
    coalesce(v.proargtypes::text = v.expect_argtypes, FALSE)                  AS argtypes_ok,
    coalesce(v.pronargdefaults = 0 AND v.provariadic = 0::oid, FALSE)         AS no_alternate_arity,
    coalesce(v.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(v.owner_table)), FALSE)
                                                                                    AS owner_ok,
    coalesce(v.prosecdef = v.expect_secdef, FALSE)                            AS security_ok,
    coalesce(v.proconfig IS NOT DISTINCT FROM v.expect_config, FALSE)         AS search_path_ok,
    coalesce(v.lanname = v.expect_lang, FALSE)                                AS language_ok,
    coalesce(v.prokind = v.expect_kind, FALSE)                                AS prokind_ok,
    coalesce(v.prorettype = v.expect_rettype::regtype, FALSE)                 AS rettype_ok,
    coalesce(v.provolatile = 'v', FALSE)                                         AS volatility_ok,
    coalesce(v.proisstrict = FALSE, FALSE)                                       AS strictness_ok,
    coalesce(v.proparallel = 'u', FALSE)                                         AS parallel_ok,
    coalesce(v.proleakproof = FALSE, FALSE)                                      AS leakproof_ok,
    coalesce(v.proretset = FALSE, FALSE)                                         AS retset_ok,
    coalesce(v.procost = 100::real, FALSE)                                       AS cost_ok,
    coalesce(v.prorows = 0::real, FALSE)                                         AS rows_ok,
    coalesce(v.provariadic = 0::oid, FALSE)                                      AS variadic_ok,
    coalesce(v.prosupport = 0::oid, FALSE)                                       AS no_support_function,
    (v.oid IS NOT NULL AND v.protrftypes IS NULL)                             AS no_transforms,
    (v.oid IS NOT NULL AND v.probin IS NULL)                                  AS no_c_binary_link,
    (v.oid IS NOT NULL AND v.prosqlbody IS NULL)                              AS no_sql_standard_body,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT count(*) FROM aclexplode(v.proacl)) = 2, FALSE)
           ELSE coalesce((SELECT count(*) FROM aclexplode(v.proacl)) = 5, FALSE) END                                                    AS acl_cardinality_exact,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
           ELSE coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = 0 AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'anon' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'authenticated' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE) END                                                 AS acl_expected_rows_present,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = v.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE)
           ELSE coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = 0 OR pg_get_userbyid(ae.grantee) = 'anon' OR pg_get_userbyid(ae.grantee) = 'authenticated' OR ae.grantee = v.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE) END                                                 AS acl_no_unexpected_entry,
    coalesce(md5(v.prosrc) = v.mojibake_digest, FALSE)                        AS is_known_mojibake,
    coalesce(md5(v.prosrc) IN (v.lf_digest, v.crlf_digest), FALSE)         AS already_reviewed
  FROM live v
),
scored AS (
  SELECT e.*, (function_present AND single_overload AND signature_ok AND full_arguments_ok
     AND nargs_ok AND no_arg_defaults AND no_default_expressions AND argnames_ok
     AND argmodes_plain_in AND no_out_or_table_args AND argtypes_ok AND no_alternate_arity
     AND owner_ok AND security_ok AND search_path_ok
     AND language_ok AND prokind_ok AND rettype_ok
     AND volatility_ok AND strictness_ok AND parallel_ok AND leakproof_ok
     AND retset_ok AND cost_ok AND rows_ok AND variadic_ok
     AND no_support_function AND no_transforms AND no_c_binary_link AND no_sql_standard_body
     AND acl_cardinality_exact AND acl_expected_rows_present AND acl_no_unexpected_entry) AS attributes_ok FROM evaluated e
)
SELECT
  count(*)                                                                  AS functions_expected,
  count(*) FILTER (WHERE attributes_ok)                                     AS attributes_ok_count,
  count(*) FILTER (WHERE is_known_mojibake)                                 AS known_mojibake_count,
  count(*) FILTER (WHERE already_reviewed)                                  AS already_reviewed_count,
  count(*) FILTER (WHERE attributes_ok AND is_known_mojibake AND NOT already_reviewed)
                                                                            AS restorable_count,
  to_jsonb(coalesce(array_agg(proname ORDER BY proname) FILTER (
    WHERE NOT attributes_ok OR NOT is_known_mojibake OR already_reviewed
  ), ARRAY[]::text[])) AS failed_labels,
  CASE
    WHEN count(*) = 2
     AND count(*) FILTER (WHERE attributes_ok AND is_known_mojibake AND NOT already_reviewed) = 2
      THEN 'SAFE_TO_APPLY_PROTECTED_FUNCTION_RESTORATION'
    ELSE 'PROTECTED_FUNCTION_RESTORATION_STOP'
  END                                                                       AS verdict
FROM scored;

COMMIT;
