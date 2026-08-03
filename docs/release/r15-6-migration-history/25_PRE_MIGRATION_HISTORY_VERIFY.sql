-- ============================================================================
-- QHUB R15.6 — 25 PRE MIGRATION-HISTORY VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Authorizes 26_MIGRATION_HISTORY_RECORD.sql ONLY if the live database is safe
-- for a HISTORY-ONLY reconciliation of migration version 20260729. Performs NO
-- writes. Every read of supabase_migrations.schema_migrations is guarded through
-- query_to_xml() with the table named inside a string literal, so a MISSING or
-- renamed history table produces a STOP verdict — never a SQL error.
--
-- THE EXPECTED HISTORY ENTRY IS DERIVED, NOT GUESSED. The pinned project CLI
-- (supabase@2.110.0, the binary cached by the runbook-mandated npx invocation)
-- embeds the authoritative contract, extracted verbatim offline:
--
--   filename parse   ^([0-9]+)_(.*)\.sql$
--   table DDL        CREATE SCHEMA IF NOT EXISTS supabase_migrations;
--                    CREATE TABLE IF NOT EXISTS supabase_migrations.schema_migrations
--                      (version text NOT NULL PRIMARY KEY);
--                    ALTER TABLE ... ADD COLUMN IF NOT EXISTS statements text[];
--                    ALTER TABLE ... ADD COLUMN IF NOT EXISTS name text;
--   read query       SELECT version, coalesce(name, '') as name, statements FROM ...
--
-- Applied to the committed migration supabase/migrations/
-- 20260729_commercial_launch_foundation.sql (SHA-256
-- 1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755):
--
--   version = '20260729'
--   name    = 'commercial_launch_foundation'
--
-- The verifier authority + product portion is the Codex-approved 18 architecture
-- unchanged (single snapshot, guarded invocation, effective-executor contract,
-- approved digests LF 1c6f85b4cb410dc4ca307ed22ee1de47 /
-- CRLF 42b43aaa01a770dc7d4a2a0d2f7f33b6). ready=true through THAT verifier is
-- what proves the 20260729 migration is already materially applied: the R15.6
-- verifier binds every governed table, policy, function body digest, ACL and
-- trigger of the migration, so a database that passes it and carries schema
-- version 2026-07-30.commercial-launch-r8 is running exactly this migration.
--
-- QUERY 1 is history detail; QUERY 2 — the LAST statement — is the verdict:
--
--   SAFE_TO_RECORD_MIGRATION_HISTORY   shape exact, no entry for 20260729, no
--                                      conflict, verifier READY -> run 26
--   ALREADY_RECORDED_EXACTLY           exactly one row (20260729,
--                                      commercial_launch_foundation), no
--                                      conflict, verifier READY -> skip 26, run
--                                      27 to certify
--   UNEXPECTED_MIGRATION_HISTORY_STOP  anything else. Capture both queries and
--                                      escalate. Do NOT run 26.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- ---------------------------------------------------------------------------
-- QUERY 1 — history detail. Every value tolerates a missing table.
-- ---------------------------------------------------------------------------
WITH hist AS (
  SELECT to_regclass('supabase_migrations.schema_migrations') AS reloid
)
SELECT
  ((SELECT reloid FROM hist) IS NOT NULL)                                        AS history_table_present,
  (SELECT n.nspname IS NOT NULL FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')
                                                                                 AS history_schema_present,
  (SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod)
                     || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END,
                     ', ' ORDER BY a.attnum)
     FROM pg_attribute a, hist h
    WHERE a.attrelid = h.reloid AND a.attnum > 0 AND NOT a.attisdropped)         AS history_columns,
  (SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c, hist h
    WHERE c.conrelid = h.reloid AND c.contype = 'p')                             AS history_primary_key,
  CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml(
      $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations$q$,
      false, true, '')))[1]::text
  END                                                                            AS history_total_rows,
  CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml(
      $q$SELECT coalesce(string_agg(version || '=' || coalesce(name, '(null)'), ' | ' ORDER BY version), '(empty)') AS c
           FROM supabase_migrations.schema_migrations$q$,
      false, true, '')))[1]::text
  END                                                                            AS history_all_rows,
  CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml(
      $q$SELECT coalesce(string_agg(
                  version || '=' || coalesce(name, '(null)')
                  || ' [statements: ' || coalesce(cardinality(statements)::text, 'null') || ']',
                  ' | ' ORDER BY version), '(absent)') AS c
           FROM supabase_migrations.schema_migrations WHERE version = '20260729'$q$,
      false, true, '')))[1]::text
  END                                                                            AS target_version_rows_detail,
  CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml(
      $q$SELECT coalesce(string_agg(version || '=' || coalesce(name, '(null)'), ' | ' ORDER BY version), '(none)') AS c
           FROM supabase_migrations.schema_migrations
          WHERE name = 'commercial_launch_foundation' AND version <> '20260729'$q$,
      false, true, '')))[1]::text
  END                                                                            AS name_under_other_version_rows,
  CASE WHEN (SELECT reloid FROM hist) IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml(
      $q$SELECT coalesce(string_agg(version || '=' || coalesce(name, '(null)'), ' | ' ORDER BY version), '(none)') AS c
           FROM supabase_migrations.schema_migrations WHERE version > '20260729'$q$,
      false, true, '')))[1]::text
  END                                                                            AS versions_newer_than_target,
  '20260729'                                                                     AS expected_version,
  'commercial_launch_foundation'                                                 AS expected_name
FROM (SELECT 1) one;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT. Act on this value alone. Single snapshot, single
-- authoritative statement; every displayed check feeds the verdict.
-- ---------------------------------------------------------------------------
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
    coalesce((SELECT a.atttypid = 'text[]'::regtype
                FROM pg_attribute a, hist h
               WHERE a.attrelid = h.reloid AND a.attname = 'statements'
                 AND NOT a.attisdropped), FALSE)                                 AS statements_column_exact,
    coalesce((SELECT (SELECT array_agg(att.attname::text ORDER BY k.ord)
                        FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute att
                          ON att.attrelid = c.conrelid AND att.attnum = k.attnum)
                     = ARRAY['version']
                FROM pg_constraint c, hist h
               WHERE c.conrelid = h.reloid AND c.contype = 'p'), FALSE)          AS version_primary_key,
    -- INSERT (version, name) must be satisfiable: every other live column is
    -- nullable or defaulted. An unexpected mandatory column is a STOP.
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM pg_attribute a, hist h
               WHERE a.attrelid = h.reloid AND a.attnum > 0 AND NOT a.attisdropped
                 AND a.attname <> 'version' AND a.attnotnull AND NOT a.atthasdef)), FALSE)
                                                                                 AS insert_compatible
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
  -- verifier authority (the 18 contract, every element feeding the verdict)
  p.verifier_present, p.zero_argument_signature, p.single_function_no_overload,
  p.owner_exact, p.security_definer, p.search_path_exact,
  p.acl_cardinality_exact, p.owner_execute_row_exact, p.service_role_owner_granted,
  p.no_unexpected_grantee, p.no_grant_option, p.body_approved,
  p.effective_acl_ok, p.unexpected_effective_executor_roles,
  p.authority_ok,
  -- product verifier (NULL when authority_ok is false — never invoked)
  p.product_ready, p.product_version, p.product_failed_count,
  -- history shape
  s.table_present, s.version_column_exact, s.name_column_exact,
  s.statements_column_exact, s.version_primary_key, s.insert_compatible,
  -- history rows
  r.target_rows, r.target_exact_rows, r.name_conflict_rows, r.newer_version_rows,
  CASE
    WHEN NOT (p.authority_ok
              AND p.product_ready = 'true'
              AND p.product_version = p.expected_version
              AND p.product_failed_count = '0')
      THEN 'UNEXPECTED_MIGRATION_HISTORY_STOP'
    WHEN NOT (s.table_present AND s.version_column_exact AND s.name_column_exact
              AND s.statements_column_exact AND s.version_primary_key
              AND s.insert_compatible)
      THEN 'UNEXPECTED_MIGRATION_HISTORY_STOP'
    WHEN r.name_conflict_rows <> '0' OR r.newer_version_rows <> '0'
      THEN 'UNEXPECTED_MIGRATION_HISTORY_STOP'
    WHEN r.target_rows = '0'
      THEN 'SAFE_TO_RECORD_MIGRATION_HISTORY'
    WHEN r.target_rows = '1' AND r.target_exact_rows = '1'
      THEN 'ALREADY_RECORDED_EXACTLY'
    ELSE 'UNEXPECTED_MIGRATION_HISTORY_STOP'
  END                                                                            AS verdict
FROM product p
CROSS JOIN hist_shape s
CROSS JOIN hist_rows r;

COMMIT;
