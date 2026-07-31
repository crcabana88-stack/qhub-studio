-- ============================================================================
-- QHUB R15.3 — 12 POST-RESTORE BODY + ATTRIBUTE VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Run this file IN FULL immediately after 11_RESTORE_REVIEWED_PROTECTED_BODIES.sql.
-- Performs NO writes.
--
-- One transaction, one snapshot, one authoritative statement: every catalog fact is
-- read under REPEATABLE READ + READ ONLY, and final_status is computed from the same
-- rows that display every check, so no displayed condition can be silently excluded
-- from the verdict.
--
-- Neither target function is invoked. Identities resolve through to_regprocedure(),
-- which yields NULL for a missing function instead of raising 42883, so this file is
-- safe to run in full in any state.
--
-- R15.3A — COMPLETE ATTRIBUTE CERTIFICATION. CREATE OR REPLACE FUNCTION resets every
-- omitted attribute clause to its default, so "the body is right" is NOT sufficient
-- evidence that the function is the reviewed function. This file therefore certifies
-- language, prokind, return type, volatility, strictness, parallel safety, leakproof,
-- set-returning flag, cost, rows estimate, variadic, support function and transforms
-- alongside identity, owner, security mode, search_path, ACL and the raw body digest.
-- A restored body with drifted strictness or parallel safety is NOT READY.
--
-- R15.3B — CALLABLE-INTERFACE CERTIFICATION. pg_get_function_identity_arguments()
-- EXCLUDES argument defaults, so a trailing `DEFAULT NULL` leaves both the identity
-- arguments and the raw prosrc digest completely unchanged while adding a NEW callable
-- arity. Independently verified against this package: with the reviewed body intact and
-- one default added, this file previously returned R15_3_REVIEWED_BODIES_RESTORED while
--     SELECT public.qhub_decide_review(uuid, text, boolean, text, text)
-- SUCCEEDED — a five-argument call into a SECURITY DEFINER decision RPC with
-- p_policy_version silently NULL. The verdict therefore now also requires
-- pg_get_function_arguments(), pronargs, pronargdefaults = 0, proargdefaults IS NULL,
-- proargnames, proargmodes, proallargtypes, proargtypes and provariadic to be exact.
--
-- THE TWO CONTRACTS DIFFER, AND THAT IS DELIBERATE:
--
--   public.qhub_decide_review(uuid,text,boolean,text,text,text)
--     SECURITY DEFINER, fixed search_path 'pg_catalog, public', owner = owner of
--     public.qhub_manual_review_requests, and an EXACT ACL: service_role holds
--     EXECUTE without grant option; PUBLIC / anon / authenticated denied; no
--     unexpected direct grantee; and no unexpected EFFECTIVE executor (role
--     membership included, superusers excepted as inherent platform admins).
--
--   public.qhub_row_immutable()
--     A trigger function. The reviewed migration deliberately grants it NOTHING, so
--     its proacl is NULL (PostgreSQL default: PUBLIC may EXECUTE). Requiring a
--     browser-denied ACL here would be a FALSE failure against the reviewed contract,
--     and R15.2C's own verifier does not pin it either. The exact reviewed state —
--     proacl IS NULL — is what is required, which still catches any grant or revoke
--     applied to it. It is SECURITY INVOKER with no proconfig, and calling it outside
--     a trigger raises.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

WITH target(signature, proname, identity_arguments, full_arguments, owner_table,
            expect_lang, expect_kind, expect_rettype, expect_secdef, expect_config,
            expect_volatile, expect_strict, expect_parallel, expect_leakproof,
            expect_retset, expect_cost, expect_rows, expect_variadic, expect_default_acl,
            expect_nargs, expect_argnames, expect_argtypes,
            lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     'plpgsql', 'f', 'jsonb', TRUE, ARRAY['search_path=pg_catalog, public'],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, FALSE,
     6, ARRAY['p_request_id','p_actor','p_is_staff','p_decision','p_reason','p_policy_version'], '2950 25 16 25 25 25',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     '',
     'public.qhub_acknowledgments',
     'plpgsql', 'f', 'trigger', FALSE, NULL::text[],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, TRUE,
     0, NULL::text[], '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f',
     '583882c1a9b203e278b27d1080065c9e')
),
obj AS (
  SELECT t.*, to_regprocedure(t.signature) AS regproc FROM target t
),
base AS (
  SELECT o.*, p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl,
         p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.proretset,
         p.procost, p.prorows, p.provariadic, p.prosupport, p.protrftypes,
         p.prokind, p.prorettype, p.pronargs, p.pronargdefaults, p.proargdefaults,
         p.proargnames, p.proargmodes, p.proallargtypes, p.proargtypes,
         p.probin, p.prosqlbody, l.lanname
    FROM obj o
    LEFT JOIN pg_proc p ON p.oid = o.regproc
    LEFT JOIN pg_language l ON l.oid = p.prolang
),
checks AS (
  SELECT
    b.*,
    -- IDENTITY
    (b.oid IS NOT NULL)                                                          AS function_present,
    coalesce(pg_get_function_identity_arguments(b.oid) = b.identity_arguments, FALSE)
                                                                                 AS signature_exact,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = b.proname) = 1)              AS single_function_no_overload,
    coalesce(b.lanname = b.expect_lang, FALSE)                                   AS language_exact,
    coalesce(b.prokind = b.expect_kind, FALSE)                                   AS prokind_exact,
    coalesce(b.prorettype = b.expect_rettype::regtype, FALSE)                    AS rettype_exact,
    -- CALLABLE INTERFACE (R15.3B) — identity arguments alone are NOT sufficient,
    -- because PostgreSQL excludes argument defaults from them.
    coalesce(pg_get_function_arguments(b.oid) = b.full_arguments, FALSE)         AS full_arguments_exact,
    coalesce(b.pronargs = b.expect_nargs, FALSE)                                 AS nargs_exact,
    coalesce(b.pronargdefaults = 0, FALSE)                                       AS no_arg_defaults,
    (b.oid IS NOT NULL AND b.proargdefaults IS NULL)                             AS no_default_expressions,
    coalesce(b.proargnames IS NOT DISTINCT FROM b.expect_argnames, FALSE)        AS argnames_exact,
    (b.oid IS NOT NULL AND b.proargmodes IS NULL)                                AS argmodes_plain_in,
    (b.oid IS NOT NULL AND b.proallargtypes IS NULL)                             AS no_out_or_table_args,
    coalesce(b.proargtypes::text = b.expect_argtypes, FALSE)                     AS argtypes_exact,
    -- With zero defaults and no VARIADIC, the ONLY callable arity is pronargs.
    coalesce(b.pronargdefaults = 0 AND b.provariadic = 0::oid, FALSE)            AS no_alternate_arity,
    -- AUTHORITY
    coalesce(b.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(b.owner_table)), FALSE)
                                                                                 AS owner_exact,
    coalesce(b.prosecdef = b.expect_secdef, FALSE)                               AS security_mode_exact,
    coalesce(b.proconfig IS NOT DISTINCT FROM b.expect_config, FALSE)            AS search_path_exact,
    -- SEMANTIC / EXECUTION ATTRIBUTES (R15.3A)
    coalesce(b.provolatile = b.expect_volatile, FALSE)                           AS volatility_exact,
    coalesce(b.proisstrict = b.expect_strict, FALSE)                             AS strictness_exact,
    coalesce(b.proparallel = b.expect_parallel, FALSE)                           AS parallel_safety_exact,
    coalesce(b.proleakproof = b.expect_leakproof, FALSE)                         AS leakproof_exact,
    coalesce(b.proretset = b.expect_retset, FALSE)                               AS retset_exact,
    coalesce(b.procost = b.expect_cost, FALSE)                                   AS cost_exact,
    coalesce(b.prorows = b.expect_rows, FALSE)                                   AS rows_exact,
    coalesce(b.provariadic = b.expect_variadic, FALSE)                           AS variadic_exact,
    coalesce(b.prosupport = 0::oid, FALSE)                                       AS no_support_function,
    (b.oid IS NOT NULL AND b.protrftypes IS NULL)                                AS no_transforms,
    -- BODY CARRIER: a plpgsql function stores its source in prosrc alone. probin is set
    -- only for C-language functions and prosqlbody only for SQL-standard BEGIN ATOMIC
    -- bodies; either being non-NULL means the body lives somewhere the digest cannot see.
    (b.oid IS NOT NULL AND b.probin IS NULL)                                     AS no_c_binary_link,
    (b.oid IS NOT NULL AND b.prosqlbody IS NULL)                                 AS no_sql_standard_body,
    -- BODY: raw digest, dual reviewed encodings, NO normalization
    coalesce(md5(b.prosrc) IN (b.lf_digest, b.crlf_digest), FALSE)               AS body_reviewed,
    coalesce(md5(b.prosrc) <> b.mojibake_digest, FALSE)                          AS mojibake_cleared,
    -- DIRECT ACL — R15.3C EXACT SET EQUALITY. Contracts differ per function (see header).
    CASE WHEN b.expect_default_acl THEN (b.oid IS NOT NULL AND b.proacl IS NULL)
         ELSE coalesce((SELECT count(*) FROM aclexplode(b.proacl)) = 2, FALSE) END AS acl_cardinality_exact,
    CASE WHEN b.expect_default_acl THEN (b.oid IS NOT NULL)
         ELSE coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
                         WHERE ae.grantee = b.proowner AND ae.privilege_type = 'EXECUTE'
                           AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE) END
                                                                                 AS acl_owner_entry_exact,
    CASE WHEN b.expect_default_acl THEN (b.oid IS NOT NULL)
         ELSE coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
                         WHERE pg_get_userbyid(ae.grantee) = 'service_role'
                           AND ae.privilege_type = 'EXECUTE'
                           AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE) END
                                                                                 AS acl_service_role_entry_exact,
    CASE WHEN b.expect_default_acl THEN (b.oid IS NOT NULL AND b.proacl IS NULL)
         ELSE coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
                         WHERE NOT (ae.privilege_type = 'EXECUTE'
                                    AND ae.grantor = b.proowner
                                    AND NOT ae.is_grantable
                                    AND (ae.grantee = b.proowner
                                         OR pg_get_userbyid(ae.grantee) = 'service_role')))), FALSE) END
                                                                                 AS acl_no_unexpected_entry,
    -- EFFECTIVE ACL — applicable ONLY where the reviewed contract restricts EXECUTE.
    -- qhub_row_immutable is intentionally PUBLIC-executable, so it is reported as
    -- not-applicable (TRUE) rather than failed.
    CASE WHEN b.expect_default_acl THEN TRUE
      ELSE coalesce((SELECT NOT EXISTS (
             SELECT 1 FROM pg_roles r
              WHERE NOT r.rolsuper
                AND r.oid IS DISTINCT FROM b.proowner
                AND r.rolname <> 'service_role'
                AND has_function_privilege(r.oid, b.oid, 'EXECUTE'))), FALSE)
    END                                                                          AS effective_acl_ok
  FROM base b
),
verdict AS (
  SELECT
    c.*,
    (c.function_present AND c.signature_exact AND c.single_function_no_overload
     AND c.language_exact AND c.prokind_exact AND c.rettype_exact
     AND c.full_arguments_exact AND c.nargs_exact AND c.no_arg_defaults
     AND c.no_default_expressions AND c.argnames_exact AND c.argmodes_plain_in
     AND c.no_out_or_table_args AND c.argtypes_exact AND c.no_alternate_arity
     AND c.owner_exact AND c.security_mode_exact AND c.search_path_exact
     AND c.volatility_exact AND c.strictness_exact AND c.parallel_safety_exact
     AND c.leakproof_exact AND c.retset_exact AND c.cost_exact AND c.rows_exact
     AND c.variadic_exact AND c.no_support_function AND c.no_transforms
     AND c.no_c_binary_link AND c.no_sql_standard_body
     AND c.body_reviewed AND c.mojibake_cleared
     AND c.acl_cardinality_exact AND c.acl_owner_entry_exact
     AND c.acl_service_role_entry_exact AND c.acl_no_unexpected_entry
     AND c.effective_acl_ok)                                                     AS function_ok
  FROM checks c
)
SELECT
  proname,
  -- identity
  function_present,
  signature_exact,
  single_function_no_overload,
  language_exact,
  prokind_exact,
  rettype_exact,
  -- callable interface (R15.3B)
  full_arguments_exact,
  nargs_exact,
  no_arg_defaults,
  no_default_expressions,
  argnames_exact,
  argmodes_plain_in,
  no_out_or_table_args,
  argtypes_exact,
  no_alternate_arity,
  -- authority
  owner_exact,
  security_mode_exact,
  search_path_exact,
  acl_cardinality_exact,
  acl_owner_entry_exact,
  acl_service_role_entry_exact,
  acl_no_unexpected_entry,
  effective_acl_ok,
  -- semantic / execution attributes
  volatility_exact,
  strictness_exact,
  parallel_safety_exact,
  leakproof_exact,
  retset_exact,
  cost_exact,
  rows_exact,
  variadic_exact,
  no_support_function,
  no_transforms,
  no_c_binary_link,
  no_sql_standard_body,
  -- body
  body_reviewed,
  mojibake_cleared,
  -- live values, for escalation evidence
  md5(prosrc)                                        AS live_raw_md5_prosrc,
  octet_length(prosrc)                               AS live_bytes,
  pg_get_function_arguments(oid)                     AS live_full_arguments,
  pronargdefaults                                    AS live_nargdefaults,
  (proargdefaults IS NOT NULL)                       AS live_has_default_expressions,
  (md5(prosrc) = lf_digest)                          AS restored_as_lf,
  (md5(prosrc) = crlf_digest)                        AS restored_as_crlf,
  provolatile                                        AS live_volatility,
  proisstrict                                        AS live_strict,
  proparallel                                        AS live_parallel,
  proleakproof                                       AS live_leakproof,
  procost                                            AS live_cost,
  prorows                                            AS live_rows,
  coalesce(proacl::text, '(default)')                AS live_acl,
  function_ok,
  CASE
    WHEN bool_and(function_ok) OVER () AND count(*) OVER () = 2
      THEN 'R15_3_REVIEWED_BODIES_RESTORED'
    ELSE 'R15_3_BODY_RESTORE_NOT_READY'
  END                                                AS final_status
FROM verdict
ORDER BY proname;

COMMIT;
