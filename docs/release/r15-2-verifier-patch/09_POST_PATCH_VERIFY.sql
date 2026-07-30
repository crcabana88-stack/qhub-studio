-- ============================================================================
-- QHUB R15.2 — 09 POST-PATCH VERIFY (READ-ONLY)
--
-- Run immediately after 08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql.
-- Performs NO writes.
--
-- R15_2_VERIFIER_READY requires ALL of the following, and every one of them is an
-- INPUT to the final verdict — nothing displayed here is merely informational:
--   verifier result : ready = true, expected_version exact, failed = []
--   identity        : exact signature public.qhub_verify_commercial_schema(),
--                     resolved OID, exactly one function of that name
--   owner           : same owner as the migration-created authority tables
--   security mode   : SECURITY DEFINER
--   search path     : proconfig exactly {search_path=pg_catalog, public}
--   ACL             : service_role holds EXECUTE; PUBLIC/anon/authenticated denied;
--                     no unexpected privileged grantee
--   body            : raw md5(prosrc) equals the approved LF or CRLF encoding of
--                     the corrected verifier body (no normalization)
--
-- ORDER OF OPERATIONS — READ THIS FIRST. Run the queries in order and stop at the
-- first one that reports R15_2_VERIFIER_NOT_READY; that value IS the final status.
--
--   QUERY 1  existence gate      pure catalog, cannot raise. A missing verifier is
--                                reported here, NOT as PostgreSQL 42883.
--   QUERY 2  authority gate      pure catalog, cannot raise. Owner, security mode,
--                                fixed search_path, ACL, body identity and overload.
--                                These are checked BEFORE the verifier is invoked
--                                because a drifted owner makes a SECURITY DEFINER
--                                function raise "permission denied" instead of
--                                returning — an error is not a verdict, so the
--                                catalog decides first.
--   QUERY 3  final status        invokes the verifier and re-applies every catalog
--                                check, so the verdict never depends on a condition
--                                it did not evaluate.
--
-- Do not run QUERY 3 unless QUERY 1 and QUERY 2 both passed.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- QUERY 1 — Existence gate (cannot throw; safe on a database with no verifier).
-- If verifier_present = false, the final status is the value in
-- status_if_absent and you must stop here.
-- ---------------------------------------------------------------------------
SELECT
  (to_regprocedure('public.qhub_verify_commercial_schema()') IS NOT NULL) AS verifier_present,
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'qhub_verify_commercial_schema') AS overload_count,
  CASE WHEN to_regprocedure('public.qhub_verify_commercial_schema()') IS NULL
       THEN 'R15_2_VERIFIER_NOT_READY'
       ELSE 'CONTINUE_TO_QUERY_2'
  END AS status_if_absent;

-- ---------------------------------------------------------------------------
-- QUERY 2 — CATALOG AUTHORITY GATE (pure catalog; cannot raise).
--
-- authority_status is a real verdict: if it reads R15_2_VERIFIER_NOT_READY, that
-- is the final status — STOP and do not run QUERY 3. Every column shown is an
-- input to authority_status, and all of them are re-applied in QUERY 3.
-- ---------------------------------------------------------------------------
WITH approved(lf_digest, crlf_digest, expected_search_path) AS (
  VALUES ('2f08add23a070ea67634bbbf6f6827cd',
          '269b40cc6859307019ca34ca84bab709',
          ARRAY['search_path=pg_catalog, public'])
)
SELECT
  p.oid::regprocedure                                   AS verifier_identity,
  pg_get_userbyid(p.proowner)                           AS owner,
  (p.proowner = (SELECT c.relowner FROM pg_class c
                  WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))) AS owner_matches_authority_tables,
  p.prosecdef                                           AS security_definer,
  p.proconfig                                           AS proconfig_search_path,
  (p.proconfig = a.expected_search_path)                AS search_path_exact,
  pg_get_function_identity_arguments(p.oid)             AS identity_arguments,
  (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
    WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') AS overload_count,
  md5(p.prosrc)                                         AS live_raw_md5_prosrc,
  a.lf_digest                                           AS approved_lf_digest,
  a.crlf_digest                                         AS approved_crlf_digest,
  (md5(p.prosrc) IN (a.lf_digest, a.crlf_digest))       AS body_approved,
  -- ACL, resolved by OID so a missing function can never raise 42883.
  has_function_privilege('service_role',  p.oid, 'EXECUTE') AS service_role_execute,
  has_function_privilege('anon',          p.oid, 'EXECUTE') AS anon_execute,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_execute,
  EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
           WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee = 0)           AS public_execute_in_acl,
  -- Any EXECUTE grantee other than the owner or service_role is unexpected.
  (SELECT coalesce(array_agg(DISTINCT pg_get_userbyid(ae.grantee)), ARRAY[]::name[])
     FROM aclexplode(p.proacl) ae
    WHERE ae.privilege_type = 'EXECUTE'
      AND ae.grantee <> 0
      AND ae.grantee <> p.proowner
      AND pg_get_userbyid(ae.grantee) <> 'service_role')                     AS unexpected_execute_grantees,
  -- The catalog verdict. Any false input above makes this NOT READY.
  CASE
    WHEN (p.proowner = (SELECT c.relowner FROM pg_class c
                         WHERE c.oid = to_regclass('public.qhub_manual_review_requests')))
     AND p.prosecdef
     AND p.proconfig = a.expected_search_path
     AND pg_get_function_identity_arguments(p.oid) = ''
     AND (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
           WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1
     AND md5(p.prosrc) IN (a.lf_digest, a.crlf_digest)
     AND has_function_privilege('service_role', p.oid, 'EXECUTE')
     AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
     AND NOT has_function_privilege('authenticated', p.oid, 'EXECUTE')
     AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                      WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee = 0)
     AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) ae
                      WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee <> 0
                        AND ae.grantee <> p.proowner
                        AND pg_get_userbyid(ae.grantee) <> 'service_role')
      THEN 'CATALOG_AUTHORITY_OK_CONTINUE_TO_QUERY_3'
    ELSE 'R15_2_VERIFIER_NOT_READY'
  END                                                                        AS authority_status
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN approved a
WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()');

-- ---------------------------------------------------------------------------
-- QUERY 3 — FINAL STATUS. Every check below is an input to final_status.
--   R15_2_VERIFIER_READY      -> mark migration 20260729 applied, then continue
--   R15_2_VERIFIER_NOT_READY  -> STOP; capture QUERY 1 and QUERY 2 and escalate
--
-- Do not run this if QUERY 1 reported verifier_present = false.
-- ---------------------------------------------------------------------------
WITH approved(lf_digest, crlf_digest, expected_search_path) AS (
  VALUES ('2f08add23a070ea67634bbbf6f6827cd',
          '269b40cc6859307019ca34ca84bab709',
          ARRAY['search_path=pg_catalog, public'])
),
ver AS (SELECT v FROM public.qhub_verify_commercial_schema() AS v),
obj AS (
  SELECT p.*
  FROM pg_proc p
  WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
),
checks AS (
  SELECT
    -- verifier result
    coalesce((SELECT (v ->> 'ready')::boolean FROM ver), FALSE)                        AS ready,
    coalesce((SELECT (v ->> 'expected_version') = '2026-07-30.commercial-launch-r8' FROM ver), FALSE)
                                                                                       AS version_exact,
    coalesce((SELECT jsonb_array_length(v -> 'failed') = 0 FROM ver), FALSE)           AS no_failed_checks,
    -- identity
    (SELECT count(*) = 1 FROM obj)                                                     AS verifier_present,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                       AS single_overload,
    coalesce((SELECT pg_get_function_identity_arguments(o.oid) = '' FROM obj o), FALSE) AS signature_exact,
    -- owner
    coalesce((SELECT o.proowner = (SELECT c.relowner FROM pg_class c
                WHERE c.oid = to_regclass('public.qhub_manual_review_requests')) FROM obj o), FALSE)
                                                                                       AS owner_exact,
    -- security mode
    coalesce((SELECT o.prosecdef FROM obj o), FALSE)                                   AS security_definer,
    -- fixed search_path (order-sensitive array equality)
    coalesce((SELECT o.proconfig = (SELECT expected_search_path FROM approved) FROM obj o), FALSE)
                                                                                       AS search_path_exact,
    -- ACL
    coalesce((SELECT has_function_privilege('service_role', o.oid, 'EXECUTE') FROM obj o), FALSE)
                                                                                       AS service_role_execute,
    coalesce((SELECT NOT has_function_privilege('anon', o.oid, 'EXECUTE') FROM obj o), FALSE)
                                                                                       AS anon_denied,
    coalesce((SELECT NOT has_function_privilege('authenticated', o.oid, 'EXECUTE') FROM obj o), FALSE)
                                                                                       AS authenticated_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(o.proacl) ae
                WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee = 0) FROM obj o), FALSE)
                                                                                       AS public_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(o.proacl) ae
                WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee <> 0
                  AND ae.grantee <> o.proowner
                  AND pg_get_userbyid(ae.grantee) <> 'service_role') FROM obj o), FALSE)
                                                                                       AS no_unexpected_grantee,
    -- body identity (raw, dual-encoding, no normalization)
    coalesce((SELECT md5(o.prosrc) IN ((SELECT lf_digest FROM approved), (SELECT crlf_digest FROM approved))
                FROM obj o), FALSE)                                                    AS body_approved
)
SELECT
  *,
  CASE WHEN ready AND version_exact AND no_failed_checks
            AND verifier_present AND single_overload AND signature_exact
            AND owner_exact AND security_definer AND search_path_exact
            AND service_role_execute AND anon_denied AND authenticated_denied
            AND public_denied AND no_unexpected_grantee
            AND body_approved
       THEN 'R15_2_VERIFIER_READY'
       ELSE 'R15_2_VERIFIER_NOT_READY'
  END AS final_status
FROM checks;
