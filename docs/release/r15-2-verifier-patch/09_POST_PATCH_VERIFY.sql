-- ============================================================================
-- QHUB R15.2 — 09 POST-PATCH VERIFY (READ-ONLY)
--
-- Run immediately after 08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql.
-- Performs NO writes. QUERY 3 returns the single final status.
--
-- Only on R15_2_VERIFIER_READY may migration 20260729 be marked applied, and only
-- then may the founder-access preview proceed.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- QUERY 1 — The verifier's verdict.
-- Expect: ready = true, expected_version = 2026-07-30.commercial-launch-r8,
--         failed_checks = [] (empty array).
-- ---------------------------------------------------------------------------
SELECT
  v ->> 'expected_version'          AS expected_version,
  (v ->> 'ready')::boolean          AS ready,
  v -> 'failed'                     AS failed_checks,
  jsonb_array_length(v -> 'failed') AS failed_count
FROM public.qhub_verify_commercial_schema() AS v;

-- ---------------------------------------------------------------------------
-- QUERY 2 — The verifier object's own identity is exact and unchanged, and it
-- still hashes RAW prosrc (no normalization was reintroduced).
-- ---------------------------------------------------------------------------
SELECT
  p.oid::regprocedure          AS verifier_identity,
  pg_get_userbyid(p.proowner)  AS owner,
  p.prosecdef                  AS security_definer,
  p.proconfig                  AS proconfig_search_path,
  (p.proowner = (SELECT relowner FROM pg_class
                 WHERE oid = 'public.qhub_manual_review_requests'::regclass)) AS owner_matches_authority_tables,
  has_function_privilege('service_role',  'public.qhub_verify_commercial_schema()', 'EXECUTE') AS service_role_execute,
  has_function_privilege('anon',          'public.qhub_verify_commercial_schema()', 'EXECUTE') AS anon_execute,
  has_function_privilege('authenticated', 'public.qhub_verify_commercial_schema()', 'EXECUTE') AS authenticated_execute,
  -- Raw-digest contract: five md5(p.prosrc) pins, and no normalization helper on prosrc.
  (length(p.prosrc) - length(replace(p.prosrc, 'md5(p.prosrc)', ''))) / length('md5(p.prosrc)') AS raw_pin_count,
  (position('replace(p.prosrc' in p.prosrc) = 0
   AND position('regexp_replace(p.prosrc' in p.prosrc) = 0
   AND position('translate(p.prosrc' in p.prosrc) = 0)                                          AS no_prosrc_normalization
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname = 'qhub_verify_commercial_schema';

-- ---------------------------------------------------------------------------
-- QUERY 3 — FINAL STATUS. Act only on this value.
--   R15_2_VERIFIER_READY      -> mark migration 20260729 applied, then continue
--   R15_2_VERIFIER_NOT_READY  -> STOP; capture QUERY 1 and QUERY 2 and escalate
-- ---------------------------------------------------------------------------
WITH v AS (SELECT v FROM public.qhub_verify_commercial_schema() AS v),
verifier AS (
  SELECT p.prosecdef, p.prosrc
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public' AND p.proname = 'qhub_verify_commercial_schema'
),
checks AS (
  SELECT
    (SELECT (v ->> 'ready')::boolean FROM v)                                       AS ready,
    (SELECT (v ->> 'expected_version') = '2026-07-30.commercial-launch-r8' FROM v) AS version_exact,
    (SELECT jsonb_array_length(v -> 'failed') = 0 FROM v)                          AS no_failed_checks,
    (SELECT prosecdef FROM verifier)                                               AS security_definer,
    has_function_privilege('service_role',  'public.qhub_verify_commercial_schema()', 'EXECUTE') AS service_execute,
    (NOT has_function_privilege('anon',          'public.qhub_verify_commercial_schema()', 'EXECUTE')
     AND NOT has_function_privilege('authenticated', 'public.qhub_verify_commercial_schema()', 'EXECUTE'))
                                                                                   AS browser_execute_denied,
    (SELECT (length(prosrc) - length(replace(prosrc, 'md5(p.prosrc)', ''))) / length('md5(p.prosrc)') = 5
       FROM verifier)                                                              AS five_raw_pins,
    (SELECT position('replace(p.prosrc' in prosrc) = 0
        AND position('regexp_replace(p.prosrc' in prosrc) = 0
        AND position('translate(p.prosrc' in prosrc) = 0 FROM verifier)            AS no_normalization
)
SELECT
  *,
  CASE WHEN ready AND version_exact AND no_failed_checks
            AND security_definer AND service_execute AND browser_execute_denied
            AND five_raw_pins AND no_normalization
       THEN 'R15_2_VERIFIER_READY'
       ELSE 'R15_2_VERIFIER_NOT_READY'
  END AS final_status
FROM checks;
