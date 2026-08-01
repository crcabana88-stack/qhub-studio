-- ============================================================================
-- QHUB R15.6 — 16 PRE-PATCH RUNTIME VERIFIER VERIFY (READ-ONLY)
--
-- Authorizes 17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql ONLY if the live
-- verifier is in a fully explained state:
--   * present at its exact zero-argument signature, no overload
--   * SECURITY DEFINER, exact fixed search_path, exact owner
--   * the EXACT normalized direct ACL set (R15.6): exactly TWO rows — the
--     owner's own EXECUTE and service_role's EXECUTE, both granted BY the owner,
--     neither grantable; PUBLIC/anon/authenticated/anything else denied. A
--     missing owner row was previously accepted (Codex-reproduced P1) — it is
--     not a benign state, it is evidence someone rewrote the verifier's ACL.
--   * exact semantic/callable attributes (R15.6): jsonb-returning zero-argument
--     plpgsql STABLE non-strict PARALLEL UNSAFE non-leakproof function, cost 100,
--     no defaults/variadic/transforms/support/probin/prosqlbody — shared by both
--     explained states, derived from the reviewed migration, never guessed
--   * no unexpected EFFECTIVE executor (role membership included; superusers
--     reported separately as inherent platform administrators)
--   * body digest is EITHER the documented live start
--     (a35d8320d4a9804725a95f76534fe5a2 — commit 644b5c6's verifier through
--     the 2026-07-30 CRLF+cp1252 mojibake channel, consistent with all body
--     forensics) OR already the reviewed final R15.6 body (idempotent re-run).
-- Performs NO writes and never invokes any user-defined function, so running this
-- file IN FULL is safe in any state and cannot raise 42883.
--
-- The start digest is DERIVED, not measured: the live verifier body was never
-- extracted directly. It is computed from the exact commit the live database was
-- applied from, through the exact channel proven by the R15.3 forensics. If the
-- live digest differs, this file STOPs — that is the correct outcome, not a
-- calibration problem: it means the live verifier is in a state nobody has
-- explained, and it must be escalated rather than patched over.
--
-- QUERY 1 is detail; QUERY 2 — the LAST statement — is the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- ---------------------------------------------------------------------------
-- QUERY 1 — verifier detail.
-- ---------------------------------------------------------------------------
WITH vobj AS (
  SELECT p.oid, p.proowner, p.proacl, p.prosrc, p.prosecdef, p.proconfig
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
)
SELECT
  ((SELECT count(*) FROM vobj) = 1)                                              AS verifier_present,
  coalesce((SELECT pg_get_function_identity_arguments(v.oid) = '' FROM vobj v), FALSE)
                                                                                 AS zero_argument_signature,
  ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
     WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                 AS single_function_no_overload,
  coalesce((SELECT v.prosecdef FROM vobj v), FALSE)                              AS security_definer,
  coalesce((SELECT v.proconfig = ARRAY['search_path=pg_catalog, public'] FROM vobj v), FALSE)
                                                                                 AS search_path_exact,
  (SELECT pg_get_userbyid(v.proowner) FROM vobj v)                               AS live_owner,
  coalesce((SELECT v.proowner = (SELECT c.relowner FROM pg_class c
             WHERE c.oid = to_regclass('public.qhub_manual_review_requests')) FROM vobj v), FALSE)
                                                                                 AS owner_exact,
  (SELECT md5(v.prosrc) FROM vobj v)                                             AS live_verifier_md5,
  coalesce((SELECT md5(v.prosrc) = 'a35d8320d4a9804725a95f76534fe5a2' FROM vobj v), FALSE)          AS is_documented_live_start,
  coalesce((SELECT md5(v.prosrc) IN ('1c6f85b4cb410dc4ca307ed22ee1de47', '42b43aaa01a770dc7d4a2a0d2f7f33b6') FROM vobj v), FALSE)
                                                                                 AS is_reviewed_r15_6_body,
  coalesce((SELECT position('2026-07-30.commercial-launch-r8' IN v.prosrc) > 0 FROM vobj v), FALSE)
                                                                                 AS version_string_present,
  coalesce((SELECT v.proacl::text FROM vobj v), '(NULL)')                        AS live_acl,
  (SELECT count(*) FROM vobj v, aclexplode(v.proacl))                            AS live_acl_cardinality,
  coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
             WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE'
               AND ae.grantor = v.proowner AND NOT ae.is_grantable) FROM vobj v), FALSE)
                                                                                 AS owner_execute_row_exact,
  coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
             WHERE ae.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'service_role')
               AND ae.privilege_type = 'EXECUTE'
               AND ae.grantor = v.proowner AND NOT ae.is_grantable) FROM vobj v), FALSE)
                                                                                 AS service_role_execute_row_exact
FROM (SELECT 1) one;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT. Act on this value alone.
--
--   SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH
--     the verifier is at its exact identity and authority, its body is a fully
--     explained state (documented live start, or already R15.6), and no
--     unapproved role holds effective EXECUTE on it.
--
--   UNEXPECTED_RUNTIME_VERIFIER_STOP
--     anything else. Capture QUERY 1 and escalate. If the body digest is the
--     unexplained value, do NOT patch over it.
-- ---------------------------------------------------------------------------
WITH vobj AS (
  SELECT p.oid, p.proowner, p.proacl, p.prosrc, p.prosecdef, p.proconfig
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
),
vident AS (
  SELECT
    ((SELECT count(*) FROM vobj) = 1)                                             AS verifier_present,
    coalesce((SELECT pg_get_function_identity_arguments(v.oid) = '' FROM vobj v), FALSE)
                                                                                  AS zero_arg,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                  AS single_fn,
    coalesce((SELECT v.prosecdef FROM vobj v), FALSE)                             AS secdef,
    coalesce((SELECT v.proconfig = ARRAY['search_path=pg_catalog, public'] FROM vobj v), FALSE)
                                                                                  AS spath,
    coalesce((SELECT v.proowner = (SELECT c.relowner FROM pg_class c
               WHERE c.oid = to_regclass('public.qhub_manual_review_requests')) FROM vobj v), FALSE)
                                                                                  AS owner_ok,
    coalesce((SELECT md5(v.prosrc) IN ('a35d8320d4a9804725a95f76534fe5a2', '1c6f85b4cb410dc4ca307ed22ee1de47', '42b43aaa01a770dc7d4a2a0d2f7f33b6') FROM vobj v), FALSE)
                                                                                  AS body_explained,
    -- R15.6: exact semantic/callable interface, shared by BOTH explained states.
    -- Values derived from the reviewed migration in a disposable database.
    coalesce((SELECT (p.prorettype = 'jsonb'::regtype AND NOT p.proretset AND p.prokind = 'f'
                  AND p.pronargs = 0 AND p.pronargdefaults = 0 AND p.proargdefaults IS NULL
                  AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
                  AND p.proargtypes::text = '' AND p.provariadic = 0
                  AND l.lanname = 'plpgsql'
                  AND p.provolatile = 's' AND NOT p.proisstrict AND p.proparallel = 'u'
                  AND NOT p.proleakproof AND p.procost = 100 AND p.prorows = 0
                  AND p.prosupport::oid = 0 AND coalesce(cardinality(p.protrftypes), 0) = 0
                  AND p.probin IS NULL AND p.prosqlbody IS NULL)
               FROM vobj v JOIN pg_proc p ON p.oid = v.oid
               JOIN pg_language l ON l.oid = p.prolang), FALSE)                   AS semantic_callable_exact
),
-- R15.6: the EXACT normalized direct-ACL set. Exactly two rows — the owner's own
-- EXECUTE and service_role's EXECUTE, both granted BY the owner, neither
-- grantable — and nothing else. Set-based on (grantee, privilege, grantor,
-- is_grantable): a missing owner row, a wrong grantor, a grant option on EITHER
-- row, or any third grantee all fail. The previous formulation accepted a
-- missing owner row (Codex-reproduced P1).
vdirect AS (
  SELECT
    coalesce((SELECT count(*) = 2 FROM vobj v, aclexplode(v.proacl)), FALSE)      AS acl_cardinality_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.grantee = v.proowner AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)    AS owner_execute_row_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'service_role')
                 AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = v.proowner AND NOT ae.is_grantable)), FALSE)    AS service_role_execute_row_exact,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.grantee <> v.proowner
                 AND ae.grantee <> (SELECT oid FROM pg_roles WHERE rolname = 'service_role'))), FALSE)
                                                                                  AS no_unexpected_grantee,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.is_grantable)), FALSE)                                    AS no_grant_option
),
veff AS (
  SELECT
    (count(*) > 0
     AND count(*) FILTER (WHERE f.hfp AND NOT f.approved) = 0)                    AS effective_acl_ok,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND NOT f.approved)
                                                                                  AS unexpected_effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND r.rolsuper)   AS superuser_executor_roles
  FROM pg_roles r
  CROSS JOIN vobj v
  CROSS JOIN LATERAL (
    SELECT
      has_function_privilege(r.oid, v.oid, 'EXECUTE')                             AS hfp,
      (r.rolsuper
       OR coalesce(r.oid = (SELECT c.relowner FROM pg_class c
                             WHERE c.oid = to_regclass('public.qhub_manual_review_requests')), FALSE)
       OR r.rolname = 'service_role')                                             AS approved
  ) f
)
SELECT
  vident.verifier_present, vident.zero_arg AS zero_argument_signature,
  vident.single_fn AS single_function_no_overload,
  vident.secdef AS security_definer, vident.spath AS search_path_exact,
  vident.owner_ok AS owner_exact, vident.body_explained,
  vident.semantic_callable_exact,
  vdirect.acl_cardinality_exact, vdirect.owner_execute_row_exact,
  vdirect.service_role_execute_row_exact, vdirect.no_unexpected_grantee,
  vdirect.no_grant_option,
  veff.effective_acl_ok, veff.unexpected_effective_executor_roles, veff.superuser_executor_roles,
  CASE
    WHEN vident.verifier_present AND vident.zero_arg AND vident.single_fn
     AND vident.secdef AND vident.spath AND vident.owner_ok AND vident.body_explained
     AND vident.semantic_callable_exact
     AND vdirect.acl_cardinality_exact AND vdirect.owner_execute_row_exact
     AND vdirect.service_role_execute_row_exact AND vdirect.no_unexpected_grantee
     AND vdirect.no_grant_option
     AND veff.effective_acl_ok
      THEN 'SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH'
    ELSE 'UNEXPECTED_RUNTIME_VERIFIER_STOP'
  END                                                                             AS verdict
FROM vident
CROSS JOIN vdirect
CROSS JOIN veff;

COMMIT;
