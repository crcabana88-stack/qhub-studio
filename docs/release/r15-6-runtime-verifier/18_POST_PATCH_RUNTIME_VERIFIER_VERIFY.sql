-- ============================================================================
-- QHUB R15.6 — 18 POST-PATCH RUNTIME VERIFIER VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Run this file IN FULL, as one unit, immediately after
-- 17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql. It performs NO writes.
--
-- Identical architecture to the Codex-approved R15.2C 09 (single snapshot, single
-- authoritative statement, guarded query_to_xml invocation, effective-executor
-- contract). The verifier's own approved body digests pin the R15.6 body, whose
-- row_immutable ACL, semantic/callable, body-digest and EXACT-tgtype trigger
-- checks are therefore part of what "body_approved" certifies. ready=true now
-- REQUIRES the R15.4 one-row trigger-helper ACL, the complete reviewed pg_proc
-- contract for the helper, and all three immutability triggers attached, enabled
-- and bound with tgtype EXACTLY 27 (an extra INSERT event is NOT READY), because
-- the R15.6 verifier fails otherwise.
--
-- R15.6 — this file additionally certifies the verifier's OWN complete final
-- authority: the exact TWO-row normalized direct ACL (the owner's own EXECUTE row
-- is MANDATORY — its absence was previously accepted, a Codex-reproduced P1 —
-- and both rows must be owner-granted and non-grantable, with no grant option
-- anywhere), plus the exact semantic/callable attribute contract. Every displayed
-- check feeds final_status.
--
-- R15.2B design — one transaction, one snapshot, one authoritative statement:
--
--   * REPEATABLE READ + READ ONLY, so every catalog fact and the verifier result
--     are read from the same snapshot. There is no inter-statement window in which
--     the verifier could drift after being authorized and before being invoked.
--
--   * The verifier is invoked ONLY when authority_ok is true. The invocation sits in
--     the ELSE-less branch of a CASE over a VOLATILE dynamic call, so an unreviewed
--     or unauthorized body is never executed. This is proven by a test that installs
--     a body raising SHOULD_NOT_EXECUTE_UNREVIEWED_VERIFIER and then breaks
--     authority: the statement still returns R15_6_VERIFIER_NOT_READY.
--
--   * The call is made through query_to_xml() with the function named inside a
--     string literal, so a MISSING function is not resolved at parse time and
--     cannot raise PostgreSQL 42883. A missing verifier simply fails authority and
--     returns R15_6_VERIFIER_NOT_READY.
--
--   * R15.2C — EFFECTIVE ACL. The same snapshot enumerates EVERY pg_roles role
--     and evaluates has_function_privilege(role_oid, verifier_oid, 'EXECUTE'),
--     which follows PostgreSQL's own privilege inheritance (direct grants,
--     PUBLIC, and nested role memberships alike). The only approved effective
--     executors are the exact contract owner, service_role, and superusers —
--     displayed separately as inherent platform administrators, because a
--     function ACL cannot meaningfully deny a superuser. Any other effective
--     executor fails effective_acl_ok, which is part of authority_ok, so the
--     verifier is NOT invoked and final_status is R15_6_VERIFIER_NOT_READY.
--
-- final_status is computed from the same row that displays every check, so no
-- displayed condition can be silently excluded from the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

WITH approved(lf_digest, crlf_digest, expected_search_path, expected_version) AS (
  VALUES (
    '1c6f85b4cb410dc4ca307ed22ee1de47',
    '42b43aaa01a770dc7d4a2a0d2f7f33b6',
    ARRAY['search_path=pg_catalog, public'],
    '2026-07-30.commercial-launch-r8'
  )
),
-- Resolve by exact signature; to_regprocedure() yields NULL when absent and never raises.
obj AS (
  SELECT p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
),
-- Exactly one anchor row, so a missing verifier still produces a verdict row.
base AS (
  SELECT a.*, o.oid, o.proowner, o.prosecdef, o.proconfig, o.prosrc, o.proacl
    FROM approved a
    LEFT JOIN obj o ON TRUE
),
-- R15.2C — EFFECTIVE ACL from the SAME snapshot: every role, evaluated with the
-- exact verifier OID through PostgreSQL's own privilege inheritance (nested
-- memberships included). Aggregation over zero rows (missing verifier) yields
-- count(*) = 0, so effective_acl_ok fails closed. coalesce(..., FALSE) on the
-- owner comparison keeps a missing contract table fail-closed too.
eff AS (
  SELECT
    (count(*) > 0
     AND count(*) FILTER (WHERE f.hfp AND NOT f.approved_role) = 0)                 AS effective_acl_ok,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp)                    AS effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND f.approved_role)
                                                                                    AS expected_effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND NOT f.approved_role)
                                                                                    AS unexpected_effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND r.rolsuper)     AS superuser_executor_roles
  FROM pg_roles r
  CROSS JOIN obj o
  CROSS JOIN LATERAL (
    SELECT
      has_function_privilege(r.oid, o.oid, 'EXECUTE')                               AS hfp,
      (r.rolsuper
       OR coalesce(r.oid = (SELECT c.relowner FROM pg_class c
                             WHERE c.oid = to_regclass('public.qhub_manual_review_requests')), FALSE)
       OR r.rolname = 'service_role')                                               AS approved_role
  ) f
),
checks AS (
  SELECT
    b.*,
    -- IDENTITY
    (b.oid IS NOT NULL)                                                          AS verifier_present,
    coalesce(pg_get_function_identity_arguments(b.oid) = '', FALSE)              AS zero_argument_signature,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                 AS single_function_no_overload,
    -- OWNER (the migration-created authority tables' owner is the reviewed contract)
    coalesce(b.proowner = (SELECT c.relowner FROM pg_class c
                            WHERE c.oid = to_regclass('public.qhub_manual_review_requests')), FALSE)
                                                                                 AS owner_exact,
    -- SECURITY MODE
    coalesce(b.prosecdef, FALSE)                                                 AS security_definer,
    -- FIXED SEARCH PATH (order-sensitive, single entry)
    coalesce(b.proconfig = b.expected_search_path, FALSE)                        AS search_path_exact,
    -- ACL, read directly from proacl so grant options are visible
    coalesce((SELECT count(*) = 1 FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'service_role'), FALSE)       AS service_role_execute,
    coalesce((SELECT bool_and(NOT ae.is_grantable) FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'service_role'), FALSE)       AS service_role_no_grant_option,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee = 0)), FALSE)  AS public_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'anon')), FALSE)              AS anon_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'authenticated')), FALSE)     AS authenticated_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND ae.grantee <> 0
                 AND ae.grantee <> b.proowner
                 AND pg_get_userbyid(ae.grantee) <> 'service_role')), FALSE)     AS no_unexpected_grantee,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.is_grantable
                 AND ae.grantee <> b.proowner)), FALSE)                          AS no_unexpected_grant_option,
    -- R15.6 — EXACT normalized direct-ACL set: exactly TWO rows, the owner's own
    -- EXECUTE and service_role's EXECUTE, both granted BY the owner, neither
    -- grantable. The owner row is MANDATORY (its absence was previously accepted
    -- — Codex-reproduced P1) and NO row may carry a grant option, the owner's
    -- included. Set-based on (grantee, privilege, grantor, is_grantable).
    coalesce((SELECT count(*) = 2 FROM aclexplode(b.proacl)), FALSE)             AS acl_cardinality_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.grantee = b.proowner AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE)   AS owner_execute_row_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'service_role')
                 AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE)   AS service_role_owner_granted,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.is_grantable)), FALSE)                                   AS no_grant_option,
    -- R15.6 — exact semantic/callable attributes of the verifier itself, derived
    -- from the reviewed migration in a disposable database, never guessed.
    coalesce((SELECT (p.prorettype = 'jsonb'::regtype AND NOT p.proretset AND p.prokind = 'f'
                  AND p.pronargs = 0 AND p.pronargdefaults = 0 AND p.proargdefaults IS NULL
                  AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
                  AND p.proargtypes::text = '' AND p.provariadic = 0
                  AND l.lanname = 'plpgsql'
                  AND p.provolatile = 's' AND NOT p.proisstrict AND p.proparallel = 'u'
                  AND NOT p.proleakproof AND p.procost = 100 AND p.prorows = 0
                  AND p.prosupport::oid = 0 AND coalesce(cardinality(p.protrftypes), 0) = 0
                  AND p.probin IS NULL AND p.prosqlbody IS NULL)
               FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
               WHERE p.oid = b.oid), FALSE)                                      AS semantic_callable_exact,
    -- BODY (raw, dual reviewed encodings, no normalization)
    coalesce(md5(b.prosrc) IN (b.lf_digest, b.crlf_digest), FALSE)               AS body_approved
  FROM base b
),
authority AS (
  SELECT
    c.*,
    e.effective_acl_ok,
    e.effective_executor_roles,
    e.expected_effective_executor_roles,
    e.unexpected_effective_executor_roles,
    e.superuser_executor_roles,
    (c.verifier_present AND c.zero_argument_signature AND c.single_function_no_overload
     AND c.owner_exact AND c.security_definer AND c.search_path_exact
     AND c.service_role_execute AND c.service_role_no_grant_option
     AND c.public_denied AND c.anon_denied AND c.authenticated_denied
     AND c.no_unexpected_grantee AND c.no_unexpected_grant_option
     AND c.acl_cardinality_exact AND c.owner_execute_row_exact
     AND c.service_role_owner_granted AND c.no_grant_option
     AND c.semantic_callable_exact
     AND c.body_approved
     AND e.effective_acl_ok)                                                     AS authority_ok
  FROM checks c
  CROSS JOIN eff e
),
-- The verifier runs ONLY when authority_ok. Naming it inside a string literal keeps a
-- missing function from being resolved at parse time (no 42883).
product AS (
  SELECT
    a.*,
    CASE WHEN a.authority_ok THEN
      (xpath('/row/c/text()',
             query_to_xml($q$SELECT (public.qhub_verify_commercial_schema() ->> 'ready') AS c$q$,
                          false, true, '')))[1]::text
    END AS product_ready,
    CASE WHEN a.authority_ok THEN
      (xpath('/row/c/text()',
             query_to_xml($q$SELECT (public.qhub_verify_commercial_schema() ->> 'expected_version') AS c$q$,
                          false, true, '')))[1]::text
    END AS product_version,
    CASE WHEN a.authority_ok THEN
      (xpath('/row/c/text()',
             query_to_xml($q$SELECT jsonb_array_length(public.qhub_verify_commercial_schema() -> 'failed')::text AS c$q$,
                          false, true, '')))[1]::text
    END AS product_failed_count
  FROM authority a
)
SELECT
  -- identity
  verifier_present,
  zero_argument_signature,
  single_function_no_overload,
  -- authority
  owner_exact,
  security_definer,
  search_path_exact,
  service_role_execute,
  service_role_no_grant_option,
  public_denied,
  anon_denied,
  authenticated_denied,
  no_unexpected_grantee,
  no_unexpected_grant_option,
  -- R15.6 exactness
  acl_cardinality_exact,
  owner_execute_row_exact,
  service_role_owner_granted,
  no_grant_option,
  semantic_callable_exact,
  body_approved,
  -- effective ACL (R15.2C) — inherited privilege, evaluated per role
  effective_acl_ok,
  effective_executor_roles,
  expected_effective_executor_roles,
  unexpected_effective_executor_roles,
  superuser_executor_roles,
  authority_ok,
  -- product verifier (NULL when authority_ok is false — it was never invoked)
  product_ready,
  product_version,
  product_failed_count,
  (product_ready = 'true')                       AS product_ready_true,
  (product_version = expected_version)           AS product_version_exact,
  (product_failed_count = '0')                   AS product_failed_empty,
  CASE
    WHEN authority_ok
     AND product_ready = 'true'
     AND product_version = expected_version
     AND product_failed_count = '0'
      THEN 'R15_6_VERIFIER_READY'
    ELSE 'R15_6_VERIFIER_NOT_READY'
  END                                            AS final_status
FROM product;

COMMIT;
