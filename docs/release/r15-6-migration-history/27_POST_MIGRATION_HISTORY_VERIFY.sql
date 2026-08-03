-- ============================================================================
-- QHUB R15.6 — 27 POST MIGRATION-HISTORY VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Run this file IN FULL, as one unit, immediately after
-- 26_MIGRATION_HISTORY_RECORD.sql (or directly after a PRE verdict of
-- ALREADY_RECORDED_EXACTLY). It performs NO writes.
--
-- Certifies, from ONE REPEATABLE READ snapshot with every displayed check
-- feeding the verdict:
--   * exactly ONE history row exists for version 20260729 and its name is
--     exactly commercial_launch_foundation (values derived from the committed
--     migration filename through the pinned CLI's own parse contract)
--   * no conflicting row: the name under no other version, no version newer
--     than 20260729, and the version-PK table shape still matches the pinned
--     CLI contract
--   * the commercial verifier still has its complete reviewed authority (18
--     contract: approved body digest, owner, SECURITY DEFINER, search_path,
--     exact two-row owner+service_role ACL, effective-executor contract) and,
--     invoked ONLY behind that authority through the guarded query_to_xml
--     pattern, still returns product_ready=true with the exact schema version
--     and zero failed labels — proving no application object or state the
--     verifier binds was changed by the history-only reconciliation.
--
--   MIGRATION_20260729_HISTORY_RECONCILED   every condition above holds
--   MIGRATION_HISTORY_NOT_RECONCILED        anything else — capture the full
--                                           row, STOP, and escalate. Do not
--                                           re-run 26.
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
obj AS (
  SELECT p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
),
base AS (
  SELECT a.*, o.oid, o.proowner, o.prosecdef, o.proconfig, o.prosrc, o.proacl
    FROM approved a
    LEFT JOIN obj o ON TRUE
),
eff AS (
  SELECT
    (count(*) > 0
     AND count(*) FILTER (WHERE f.hfp AND NOT f.approved_role) = 0)                 AS effective_acl_ok,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND NOT f.approved_role)
                                                                                    AS unexpected_effective_executor_roles
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
    (b.oid IS NOT NULL)                                                          AS verifier_present,
    coalesce(pg_get_function_identity_arguments(b.oid) = '', FALSE)              AS zero_argument_signature,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                 AS single_function_no_overload,
    coalesce(b.proowner = (SELECT c.relowner FROM pg_class c
                            WHERE c.oid = to_regclass('public.qhub_manual_review_requests')), FALSE)
                                                                                 AS owner_exact,
    coalesce(b.prosecdef, FALSE)                                                 AS security_definer,
    coalesce(b.proconfig = b.expected_search_path, FALSE)                        AS search_path_exact,
    coalesce((SELECT count(*) = 2 FROM aclexplode(b.proacl)), FALSE)             AS acl_cardinality_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.grantee = b.proowner AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE)   AS owner_execute_row_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'service_role')
                 AND ae.privilege_type = 'EXECUTE'
                 AND ae.grantor = b.proowner AND NOT ae.is_grantable)), FALSE)   AS service_role_owner_granted,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.grantee <> b.proowner
                 AND ae.grantee <> (SELECT oid FROM pg_roles WHERE rolname = 'service_role'))), FALSE)
                                                                                 AS no_unexpected_grantee,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(b.proacl) ae
               WHERE ae.is_grantable)), FALSE)                                   AS no_grant_option,
    coalesce(md5(b.prosrc) IN (b.lf_digest, b.crlf_digest), FALSE)               AS body_approved
  FROM base b
),
authority AS (
  SELECT
    c.*,
    e.effective_acl_ok,
    e.unexpected_effective_executor_roles,
    (c.verifier_present AND c.zero_argument_signature AND c.single_function_no_overload
     AND c.owner_exact AND c.security_definer AND c.search_path_exact
     AND c.acl_cardinality_exact AND c.owner_execute_row_exact
     AND c.service_role_owner_granted AND c.no_unexpected_grantee AND c.no_grant_option
     AND c.body_approved
     AND e.effective_acl_ok)                                                     AS authority_ok
  FROM checks c
  CROSS JOIN eff e
),
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
),
hist AS (
  SELECT to_regclass('supabase_migrations.schema_migrations') AS reloid
),
hist_shape AS (
  SELECT
    ((SELECT reloid FROM hist) IS NOT NULL)                                      AS table_present,
    coalesce((SELECT a.atttypid = 'text'::regtype AND a.attnotnull
                FROM pg_attribute a, hist h
               WHERE a.attrelid = h.reloid AND a.attname = 'version'
                 AND NOT a.attisdropped), FALSE)                                 AS version_column_exact,
    coalesce((SELECT a.atttypid = 'text'::regtype
                FROM pg_attribute a, hist h
               WHERE a.attrelid = h.reloid AND a.attname = 'name'
                 AND NOT a.attisdropped), FALSE)                                 AS name_column_exact,
    coalesce((SELECT (SELECT array_agg(att.attname::text ORDER BY k.ord)
                        FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute att
                          ON att.attrelid = c.conrelid AND att.attnum = k.attnum)
                     = ARRAY['version']
                FROM pg_constraint c, hist h
               WHERE c.conrelid = h.reloid AND c.contype = 'p'), FALSE)          AS version_primary_key
),
hist_rows AS (
  SELECT
    CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE version = '20260729'$q$, false, true, '')))[1]::text
    END AS target_rows,
    CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE version = '20260729' AND name = 'commercial_launch_foundation'$q$,
        false, true, '')))[1]::text
    END AS target_exact_rows,
    CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT coalesce(string_agg(version || '=' || coalesce(name, '(null)'), ' | ' ORDER BY version), '(absent)') AS c
             FROM supabase_migrations.schema_migrations WHERE version = '20260729'$q$,
        false, true, '')))[1]::text
    END AS target_row_detail,
    CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE name = 'commercial_launch_foundation' AND version <> '20260729'$q$,
        false, true, '')))[1]::text
    END AS name_conflict_rows,
    CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE version > '20260729'$q$, false, true, '')))[1]::text
    END AS newer_version_rows
)
SELECT
  p.verifier_present, p.zero_argument_signature, p.single_function_no_overload,
  p.owner_exact, p.security_definer, p.search_path_exact,
  p.acl_cardinality_exact, p.owner_execute_row_exact, p.service_role_owner_granted,
  p.no_unexpected_grantee, p.no_grant_option, p.body_approved,
  p.effective_acl_ok, p.unexpected_effective_executor_roles,
  p.authority_ok,
  p.product_ready, p.product_version, p.product_failed_count,
  (p.product_ready = 'true')                       AS product_ready_true,
  (p.product_version = p.expected_version)         AS product_version_exact,
  (p.product_failed_count = '0')                   AS product_failed_empty,
  s.table_present, s.version_column_exact, s.name_column_exact, s.version_primary_key,
  r.target_rows, r.target_exact_rows, r.target_row_detail,
  r.name_conflict_rows, r.newer_version_rows,
  CASE
    WHEN p.authority_ok
     AND p.product_ready = 'true'
     AND p.product_version = p.expected_version
     AND p.product_failed_count = '0'
     AND s.table_present AND s.version_column_exact AND s.name_column_exact
     AND s.version_primary_key
     AND r.target_rows = '1'
     AND r.target_exact_rows = '1'
     AND r.name_conflict_rows = '0'
     AND r.newer_version_rows = '0'
      THEN 'MIGRATION_20260729_HISTORY_RECONCILED'
    ELSE 'MIGRATION_HISTORY_NOT_RECONCILED'
  END                                              AS final_status
FROM product p
CROSS JOIN hist_shape s
CROSS JOIN hist_rows r;

COMMIT;
