-- ============================================================================
-- QHUB R15.2 — 09 POST-PATCH VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Run this file IN FULL, as one unit, immediately after
-- 08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql. It performs NO writes.
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
--     authority: the statement still returns R15_2_VERIFIER_NOT_READY.
--
--   * The call is made through query_to_xml() with the function named inside a
--     string literal, so a MISSING function is not resolved at parse time and
--     cannot raise PostgreSQL 42883. A missing verifier simply fails authority and
--     returns R15_2_VERIFIER_NOT_READY.
--
-- final_status is computed from the same row that displays every check, so no
-- displayed condition can be silently excluded from the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

WITH approved(lf_digest, crlf_digest, expected_search_path, expected_version) AS (
  VALUES (
    '2f08add23a070ea67634bbbf6f6827cd',
    '269b40cc6859307019ca34ca84bab709',
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
    -- BODY (raw, dual reviewed encodings, no normalization)
    coalesce(md5(b.prosrc) IN (b.lf_digest, b.crlf_digest), FALSE)               AS body_approved
  FROM base b
),
authority AS (
  SELECT
    c.*,
    (c.verifier_present AND c.zero_argument_signature AND c.single_function_no_overload
     AND c.owner_exact AND c.security_definer AND c.search_path_exact
     AND c.service_role_execute AND c.service_role_no_grant_option
     AND c.public_denied AND c.anon_denied AND c.authenticated_denied
     AND c.no_unexpected_grantee AND c.no_unexpected_grant_option
     AND c.body_approved)                                                        AS authority_ok
  FROM checks c
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
  body_approved,
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
      THEN 'R15_2_VERIFIER_READY'
    ELSE 'R15_2_VERIFIER_NOT_READY'
  END                                            AS final_status
FROM product;

COMMIT;
