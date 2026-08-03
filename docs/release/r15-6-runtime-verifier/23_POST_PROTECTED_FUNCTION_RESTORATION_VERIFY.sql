-- ============================================================================
-- QHUB R15.6 — 23 POST PROTECTED FUNCTION RESTORATION VERIFY (READ-ONLY)
--
-- Run IN FULL immediately after 11_RESTORE_REVIEWED_PROTECTED_BODIES.sql.
-- Performs NO writes.
--
-- One transaction, one snapshot, one authoritative statement. Every displayed check
-- feeds final_status, so nothing shown can be silently excluded from the verdict.
--
-- FINAL REVIEWED CONTRACT:
--   qhub_decide_review : SECURITY DEFINER, search_path 'pg_catalog, public',
--                        ACL exactly 2 rows â€” owner + service_role EXECUTE
--   qhub_row_immutable : SECURITY INVOKER, no proconfig,
--                        ACL exactly 1 row â€” the OWNER's EXECUTE only.
--                        PUBLIC, anon, authenticated and service_role are all denied.
--                        service_role is deliberately NOT granted: trigger execution
--                        does not require it (PostgreSQL checks EXECUTE at
--                        CREATE TRIGGER time, not at fire time), which was verified
--                        before this contract was adopted.
--
-- Both are also required to have NO unexpected EFFECTIVE executor beyond the owner
-- and superusers â€” now applicable to the trigger helper too, because it is no longer
-- intentionally PUBLIC-executable.
--
-- The three immutability triggers must remain attached and enabled, bound to this
-- exact function, BEFORE UPDATE OR DELETE, FOR EACH ROW.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

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
checks AS (
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
           ELSE coalesce((SELECT count(*) FROM aclexplode(v.proacl)) = 1, FALSE) END                                                    AS acl_cardinality_exact,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
                AND coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE pg_get_userbyid(ae.grantee) = 'service_role' AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)
           ELSE coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE) END                                                 AS acl_expected_rows_present,
    CASE WHEN v.proname = 'qhub_decide_review'
           THEN coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = v.proowner OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE)
           ELSE coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                     WHERE NOT (ae.privilege_type = 'EXECUTE' AND ae.grantor = v.proowner AND NOT ae.is_grantable AND (ae.grantee = v.proowner)))), FALSE) END                                                 AS acl_no_unexpected_entry,
    coalesce(md5(v.prosrc) = v.mojibake_digest, FALSE)                        AS is_known_mojibake,
    coalesce(md5(v.prosrc) IN (v.lf_digest, v.crlf_digest), FALSE)         AS already_reviewed,
    coalesce(md5(v.prosrc) <> v.mojibake_digest, FALSE)                            AS mojibake_cleared,
    coalesce((SELECT NOT EXISTS (
       SELECT 1 FROM pg_roles r
        WHERE NOT r.rolsuper
          AND r.oid IS DISTINCT FROM v.proowner
          AND has_function_privilege(r.oid, v.oid, 'EXECUTE')
          AND NOT (v.proname = 'qhub_decide_review' AND r.rolname = 'service_role'))), FALSE)
                                                                                    AS effective_acl_ok,
    -- The immutability triggers must still be attached, enabled and bound to this
    -- exact function on all three append-only tables.
    CASE WHEN v.proname <> 'qhub_row_immutable' THEN TRUE
         ELSE coalesce((SELECT count(*) = 3 FROM pg_trigger tg
                 WHERE tg.tgfoid = v.oid AND NOT tg.tgisinternal
                   AND tg.tgenabled = 'O'
                   AND (tg.tgtype & 1) <> 0 AND (tg.tgtype & 2) <> 0
                   AND (tg.tgtype & 8) <> 0 AND (tg.tgtype & 16) <> 0
                   AND tg.tgrelid IN (to_regclass('public.qhub_acknowledgments'),
                                      to_regclass('public.qhub_usage_ledger'),
                                      to_regclass('public.qhub_entitlement_audit'))), FALSE) END
                                                                                    AS triggers_attached_enabled,
    v.prosrc, v.proacl, v.proowner, v.provolatile, v.proisstrict, v.proparallel,
    v.proleakproof, v.procost, v.prorows, v.lf_digest, v.crlf_digest
  FROM live v
),
verdict AS (
  SELECT c.*,
    (function_present AND single_overload AND signature_ok AND full_arguments_ok
         AND nargs_ok AND no_arg_defaults AND no_default_expressions AND argnames_ok
         AND argmodes_plain_in AND no_out_or_table_args AND argtypes_ok AND no_alternate_arity
         AND owner_ok AND security_ok AND search_path_ok
         AND language_ok AND prokind_ok AND rettype_ok
         AND volatility_ok AND strictness_ok AND parallel_ok AND leakproof_ok
         AND retset_ok AND cost_ok AND rows_ok AND variadic_ok
         AND no_support_function AND no_transforms AND no_c_binary_link AND no_sql_standard_body
         AND acl_cardinality_exact AND acl_expected_rows_present AND acl_no_unexpected_entry
         AND already_reviewed AND mojibake_cleared
         AND effective_acl_ok AND triggers_attached_enabled)                        AS function_ok
  FROM checks c
)
-- Column names deliberately mirror the reviewed R15.3A/B/C output contract so the
-- verdict row stays readable to anyone (or anything) that already reviewed it.
SELECT
  proname,
  function_present,
  single_overload      AS single_function_no_overload,
  signature_ok         AS signature_exact,
  full_arguments_ok    AS full_arguments_exact,
  nargs_ok             AS nargs_exact,
  no_arg_defaults, no_default_expressions,
  argnames_ok          AS argnames_exact,
  argmodes_plain_in, no_out_or_table_args,
  argtypes_ok          AS argtypes_exact,
  no_alternate_arity,
  owner_ok             AS owner_exact,
  security_ok          AS security_mode_exact,
  search_path_ok       AS search_path_exact,
  acl_cardinality_exact, acl_expected_rows_present, acl_no_unexpected_entry, effective_acl_ok,
  language_ok          AS language_exact,
  prokind_ok           AS prokind_exact,
  rettype_ok           AS rettype_exact,
  volatility_ok        AS volatility_exact,
  strictness_ok        AS strictness_exact,
  parallel_ok          AS parallel_safety_exact,
  leakproof_ok         AS leakproof_exact,
  retset_ok            AS retset_exact,
  cost_ok              AS cost_exact,
  rows_ok              AS rows_exact,
  variadic_ok          AS variadic_exact,
  no_support_function, no_transforms,
  no_c_binary_link, no_sql_standard_body,
  already_reviewed AS body_reviewed,
  mojibake_cleared,
  triggers_attached_enabled,
  md5(prosrc)                                        AS live_raw_md5_prosrc,
  (md5(prosrc) = lf_digest)                          AS restored_as_lf,
  (md5(prosrc) = crlf_digest)                        AS restored_as_crlf,
  coalesce(proacl::text, '(default)')                AS live_acl,
  function_ok,
  CASE
    WHEN bool_and(function_ok) OVER () AND count(*) OVER () = 2
      THEN 'R15_3_REVIEWED_BODIES_RESTORED'
    ELSE 'R15_3_BODY_RESTORE_NOT_READY'
  END                                                AS final_status
FROM verdict
ORDER BY proname;


-- Final R15.6 closure row. The verifier is invoked once and only after its own
-- complete authority contract is proven in this snapshot.
WITH verifier AS MATERIALIZED (
  SELECT p.*, l.lanname,
    (SELECT count(*) FROM pg_proc q JOIN pg_namespace n ON n.oid=q.pronamespace
      WHERE n.nspname='public' AND q.proname='qhub_verify_commercial_schema') AS name_count
  FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
  WHERE p.oid=to_regprocedure('public.qhub_verify_commercial_schema()')
),
verifier_authority AS MATERIALIZED (
  SELECT v.*,
    (
      v.name_count=1 AND pg_get_function_identity_arguments(v.oid)=''
      AND v.prorettype='jsonb'::regtype AND NOT v.proretset AND v.prokind='f'
      AND v.pronargs=0 AND v.pronargdefaults=0 AND v.proargdefaults IS NULL
      AND v.proargnames IS NULL AND v.proargmodes IS NULL AND v.proallargtypes IS NULL
      AND v.proargtypes::text='' AND v.provariadic=0
      AND v.lanname='plpgsql' AND v.provolatile='s' AND NOT v.proisstrict
      AND v.proparallel='u' AND NOT v.proleakproof AND v.procost=100 AND v.prorows=0
      AND v.prosupport::oid=0 AND v.protrftypes IS NULL
      AND v.probin IS NULL AND v.prosqlbody IS NULL
      AND v.proowner=(SELECT c.relowner FROM pg_class c
                       WHERE c.oid=to_regclass('public.qhub_manual_review_requests'))
      AND v.prosecdef AND v.proconfig=ARRAY['search_path=pg_catalog, public']
      AND md5(v.prosrc) IN ('1c6f85b4cb410dc4ca307ed22ee1de47',
                            '42b43aaa01a770dc7d4a2a0d2f7f33b6')
      AND (SELECT count(*) FROM aclexplode(v.proacl))=2
      AND EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                   WHERE ae.grantee=v.proowner AND ae.grantor=v.proowner
                     AND ae.privilege_type='EXECUTE' AND NOT ae.is_grantable)
      AND EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                   WHERE pg_get_userbyid(ae.grantee)='service_role'
                     AND ae.grantor=v.proowner AND ae.privilege_type='EXECUTE'
                     AND NOT ae.is_grantable)
      AND NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                       WHERE ae.is_grantable OR ae.grantor<>v.proowner
                          OR ae.privilege_type<>'EXECUTE'
                          OR (ae.grantee<>v.proowner AND pg_get_userbyid(ae.grantee)<>'service_role'))
      AND NOT EXISTS (SELECT 1 FROM pg_roles r
                       WHERE NOT r.rolsuper AND r.oid<>v.proowner
                         AND r.rolname<>'service_role'
                         AND has_function_privilege(r.oid,v.oid,'EXECUTE'))
    ) AS authority_ok
  FROM verifier v
),
product AS MATERIALIZED (
  SELECT va.authority_ok,
    CASE WHEN va.authority_ok THEN public.qhub_verify_commercial_schema() END AS report
  FROM verifier_authority va
),
function_facts AS MATERIALIZED (
  SELECT
    row_number() OVER (ORDER BY p.proname) AS ordinal,
    p.oid,
    n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' AS identity,
    pg_get_userbyid(p.proowner) AS owner,
    format_type(p.prorettype,NULL) AS return_type,
    l.lanname AS language,
    p.provolatile AS volatility,
    p.proisstrict AS strict,
    p.prosecdef AS security_definer,
    p.proleakproof AS leakproof,
    p.proparallel AS parallel_safety,
    p.proconfig AS configuration,
    md5(p.prosrc) AS body_digest,
    CASE WHEN p.proname='qhub_decide_review'
      THEN md5(p.prosrc) IN ('7e678f1e4bba0c540507cfe3743fbe54','dac8abcd56d7fc804baac660059c14bf')
      ELSE md5(p.prosrc) IN ('41ae59dde9a471b580d28e2cb45984f5','4936e3f58627dde5abc10d2b0ecf5b4f')
    END AS body_approved
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  JOIN pg_language l ON l.oid=p.prolang
  WHERE p.oid IN (
    to_regprocedure('public.qhub_decide_review(uuid,text,boolean,text,text,text)'),
    to_regprocedure('public.qhub_row_immutable()')
  )
),
acl_entries AS MATERIALIZED (
  SELECT p.proname,
    row_number() OVER (PARTITION BY p.proname ORDER BY ae.grantee,ae.grantor,ae.privilege_type,ae.is_grantable) AS ordinal,
    CASE WHEN ae.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(ae.grantee) END AS grantee,
    pg_get_userbyid(ae.grantor) AS grantor,
    ae.privilege_type AS privilege,
    ae.is_grantable AS grantable
  FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) ae
  WHERE p.oid IN (
    to_regprocedure('public.qhub_decide_review(uuid,text,boolean,text,text,text)'),
    to_regprocedure('public.qhub_row_immutable()')
  )
),
acl_contract AS MATERIALIZED (
  SELECT
    (SELECT count(*)=2 FROM acl_entries WHERE proname='qhub_decide_review')
    AND EXISTS (SELECT 1 FROM acl_entries WHERE proname='qhub_decide_review'
      AND grantee='postgres' AND grantor='postgres' AND privilege='EXECUTE' AND NOT grantable)
    AND EXISTS (SELECT 1 FROM acl_entries WHERE proname='qhub_decide_review'
      AND grantee='service_role' AND grantor='postgres' AND privilege='EXECUTE' AND NOT grantable)
    AND NOT EXISTS (SELECT 1 FROM acl_entries WHERE proname='qhub_decide_review'
      AND (grantee NOT IN ('postgres','service_role') OR grantor<>'postgres'
        OR privilege<>'EXECUTE' OR grantable)) AS decide_acl_exact,
    (SELECT count(*)=1 FROM acl_entries WHERE proname='qhub_row_immutable')
    AND EXISTS (SELECT 1 FROM acl_entries WHERE proname='qhub_row_immutable'
      AND grantee='postgres' AND grantor='postgres' AND privilege='EXECUTE' AND NOT grantable)
    AND NOT EXISTS (SELECT 1 FROM acl_entries WHERE proname='qhub_row_immutable'
      AND (grantee<>'postgres' OR grantor<>'postgres' OR privilege<>'EXECUTE' OR grantable))
      AS row_acl_exact
),
trigger_facts AS MATERIALIZED (
  SELECT
    t.name AS table_name,
    'trg_'||t.name||'_immutable' AS expected_trigger_name,
    tg.tgname AS actual_trigger_name,
    tg.tgtype,
    tg.tgenabled,
    tg.tgisinternal,
    tg.tgconstraint,
    tg.tgfoid,
    to_regprocedure('public.qhub_row_immutable()') AS expected_function_oid,
    (tg.tgname='trg_'||t.name||'_immutable'
      AND tg.tgrelid=to_regclass('public.'||t.name)
      AND tg.tgfoid=to_regprocedure('public.qhub_row_immutable()')
      AND tg.tgtype=27 AND tg.tgenabled='O'
      AND NOT tg.tgisinternal AND tg.tgconstraint=0) AS contract_match
  FROM unnest(ARRAY['qhub_acknowledgments','qhub_usage_ledger','qhub_entitlement_audit']) t(name)
  LEFT JOIN pg_trigger tg ON tg.tgname='trg_'||t.name||'_immutable'
    AND tg.tgrelid=to_regclass('public.'||t.name)
),
effective AS MATERIALIZED (
  SELECT jsonb_build_object(
    'qhub_decide_review',coalesce((SELECT jsonb_agg(r.rolname ORDER BY r.rolname)
      FROM pg_roles r
      WHERE NOT r.rolsuper AND r.rolname NOT IN ('postgres','service_role')
        AND has_function_privilege(r.oid,
          to_regprocedure('public.qhub_decide_review(uuid,text,boolean,text,text,text)'),'EXECUTE')),'[]'::jsonb),
    'qhub_row_immutable',coalesce((SELECT jsonb_agg(r.rolname ORDER BY r.rolname)
      FROM pg_roles r
      WHERE NOT r.rolsuper AND r.rolname<>'postgres'
        AND has_function_privilege(r.oid,to_regprocedure('public.qhub_row_immutable()'),'EXECUTE')),'[]'::jsonb)
  ) AS unexpected_effective_executors
),
evidence AS MATERIALIZED (
  SELECT
    coalesce((SELECT authority_ok FROM verifier_authority),FALSE) AS verifier_authority_ok,
    (SELECT report FROM product) AS report,
    (SELECT count(*)=2 AND bool_and(body_approved) FROM function_facts) AS bodies_approved,
    a.decide_acl_exact,
    a.row_acl_exact,
    (SELECT count(*)=3 AND bool_and(contract_match) FROM trigger_facts) AS triggers_exact,
    e.unexpected_effective_executors,
    (SELECT jsonb_agg(to_jsonb(ff) ORDER BY ff.ordinal) FROM function_facts ff) AS function_evidence,
    (SELECT jsonb_agg(to_jsonb(ae) ORDER BY ae.proname,ae.ordinal) FROM acl_entries ae) AS acl_evidence,
    (SELECT jsonb_agg(to_jsonb(tf) ORDER BY tf.table_name) FROM trigger_facts tf) AS trigger_evidence
  FROM acl_contract a CROSS JOIN effective e
)
SELECT
  verifier_authority_ok,
  report->'ready'='true'::jsonb AS product_ready,
  report->>'expected_version' AS product_version,
  report->'failed' AS failed_labels,
  function_evidence,
  acl_evidence,
  trigger_evidence,
  unexpected_effective_executors,
  bodies_approved,
  decide_acl_exact,
  row_acl_exact,
  triggers_exact,
  CASE
    WHEN verifier_authority_ok
     AND report IS NOT DISTINCT FROM jsonb_build_object(
       'ready',TRUE,
       'expected_version','2026-07-30.commercial-launch-r8',
       'failed','[]'::jsonb
     )
     AND bodies_approved AND decide_acl_exact AND row_acl_exact AND triggers_exact
     AND unexpected_effective_executors=jsonb_build_object(
       'qhub_decide_review','[]'::jsonb,'qhub_row_immutable','[]'::jsonb
     )
    THEN 'R15_6_PROTECTED_FUNCTION_RESTORATION_VERIFIED'
    ELSE 'R15_6_PROTECTED_FUNCTION_RESTORATION_STOP'
  END AS final_status
FROM evidence;

COMMIT;
