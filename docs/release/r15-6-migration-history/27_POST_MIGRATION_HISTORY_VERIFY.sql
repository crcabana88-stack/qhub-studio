-- ============================================================================
-- QHUB R15.6 — 27 POST MIGRATION-HISTORY VERIFY (READ-ONLY, SINGLE SNAPSHOT)
--
-- Run this file IN FULL, as one unit, in a FRESH SESSION, after a separately
-- authorized 26_MIGRATION_HISTORY_RECORD.sql run (or directly after a PRE
-- verdict of ALREADY_RECORDED_EXACTLY). It performs NO writes — REPEATABLE READ
-- + READ ONLY, no temporary or persistent object of any kind. This file — not
-- RECORD's audit display — is the final certification of durable state.
--
-- Certifies, from ONE snapshot, with every displayed check feeding the verdict
-- and all logic NULL-safe (success requires every condition affirmatively TRUE):
--
--   * exactly ONE history row exists for version 20260729, and its name AND
--     complete statements array are exact: name commercial_launch_foundation,
--     statements cardinality 89, total bytes 124,959, canonical digest
--     7b28ccf3ba7cae3e29c17bc5c3be60b6 — the array the pinned supabase@2.110.0
--     CLI (binary sha256 14814afa6fe59081eb9f24709fc077226bf89bc25cf77ee3
--     bcb19565f3ef8899) deterministically records for the committed migration
--     (sha256 1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755).
--     A missing, NULL, incomplete or different statements array is
--     NOT_RECONCILED.
--   * no conflicting row: the name under no other version, no malformed
--     (non-numeric) recorded version anywhere — checked BEFORE any ordered
--     comparison — and no version newer than 20260729
--   * the COMPLETE pinned CLI table contract still holds: ordinary permanent
--     non-partition table, exact owner, exact columns/positions/types/
--     nullability/defaults/identity/generated (statements and name nullable
--     exactly as the CLI defines), PK schema_migrations_pkey on (version) as
--     the only constraint, its index as the only index, no triggers, no rules,
--     no policies, RLS off, no inheritance
--   * the commercial verifier still holds its complete reviewed authority
--     (approved body digest, signature, jsonb/plpgsql/STABLE, SECURITY DEFINER,
--     owner, search_path, exact two-row owner+service_role ACL, effective-
--     executor contract) and — invoked ONLY behind that authority through the
--     guarded query_to_xml pattern — returns product_ready=true, the exact
--     schema version, and zero failed labels, proving no application object or
--     state the verifier binds was changed by the history-only reconciliation.
--
--   MIGRATION_20260729_HISTORY_RECONCILED   every condition above holds
--   MIGRATION_HISTORY_NOT_RECONCILED        anything else — capture the full
--                                           row, STOP, and escalate. Do not
--                                           re-run 26.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SET LOCAL search_path = pg_catalog;

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
    -- R15.6.2: proparallel and proisstrict pinned from the approved verifier
    -- artifact (STABLE, CALLED ON NULL INPUT, PARALLEL UNSAFE). NULL-safe.
    coalesce((SELECT (p.prorettype = 'jsonb'::regtype AND NOT p.proretset AND p.prokind = 'f'
                  AND l.lanname = 'plpgsql' AND p.provolatile = 's'
                  AND p.proparallel = 'u' AND NOT p.proisstrict)
               FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
              WHERE p.oid = b.oid), FALSE)                                       AS semantic_callable_exact,
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
     AND c.semantic_callable_exact
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
  SELECT t.reloid,
         coalesce((SELECT count(*) = 3 FROM pg_attribute a
                    WHERE a.attrelid = t.reloid AND NOT a.attisdropped
                      AND a.attname IN ('version', 'name', 'statements')), FALSE) AS cols_ok
    FROM (SELECT to_regclass('supabase_migrations.schema_migrations') AS reloid) t
),
hist_shape AS (
  SELECT
    ((SELECT reloid FROM hist) IS NOT NULL)                                      AS table_present,
    coalesce((SELECT c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relispartition
                FROM pg_class c, hist h WHERE c.oid = h.reloid), FALSE)          AS kind_ok,
    coalesce((SELECT c.relowner = (SELECT c2.relowner FROM pg_class c2
                 WHERE c2.oid = to_regclass('public.qhub_manual_review_requests'))
                FROM pg_class c, hist h WHERE c.oid = h.reloid), FALSE)          AS table_owner_ok,
    coalesce((SELECT NOT c.relrowsecurity AND NOT c.relforcerowsecurity
                FROM pg_class c, hist h WHERE c.oid = h.reloid), FALSE)          AS rls_off,
    coalesce((SELECT (SELECT string_agg(a.attname || ':' || a.attnum::text || ':'
                        || format_type(a.atttypid, a.atttypmod)
                        || ':' || a.attnotnull::text || ':' || a.atthasdef::text
                        || ':' || a.attidentity::text || ':' || a.attgenerated::text, '|' ORDER BY a.attnum)
                        FROM pg_attribute a
                       WHERE a.attrelid = h.reloid AND a.attnum > 0 AND NOT a.attisdropped)
                 = 'version:1:text:true:false::|statements:2:text[]:false:false::|name:3:text:false:false::'
                FROM hist h), FALSE)                                             AS columns_exact,
    coalesce((SELECT (SELECT string_agg(c.conname || ':' || c.contype::text, '|' ORDER BY c.conname)
                        FROM pg_constraint c WHERE c.conrelid = h.reloid)
                 = 'schema_migrations_pkey:p'
                FROM hist h), FALSE)                                             AS constraints_exact,
    coalesce((SELECT EXISTS (SELECT 1 FROM pg_constraint c
               WHERE c.conrelid = h.reloid AND c.contype = 'p'
                 AND (SELECT array_agg(att.attname::text ORDER BY k.ord)
                        FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute att
                          ON att.attrelid = c.conrelid AND att.attnum = k.attnum)
                     = ARRAY['version'])
                FROM hist h), FALSE)                                             AS pk_exact,
    coalesce((SELECT (SELECT string_agg(ic.relname || ':' || i.indisprimary::text, '|' ORDER BY ic.relname)
                        FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
                       WHERE i.indrelid = h.reloid)
                 = 'schema_migrations_pkey:true'
                FROM hist h), FALSE)                                             AS indexes_exact,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = h.reloid)
                FROM hist h), FALSE)                                             AS no_triggers,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM pg_rewrite w WHERE w.ev_class = h.reloid)
                FROM hist h), FALSE)                                             AS no_rules,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM pg_policy pol WHERE pol.polrelid = h.reloid)
                FROM hist h), FALSE)                                             AS no_policies,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM pg_inherits i
                WHERE i.inhrelid = h.reloid OR i.inhparent = h.reloid)
                FROM hist h), FALSE)                                             AS no_inheritance
),
-- R15.6.2 — the pinned privilege contract (see 25 for the derivation): schema
-- owner = table owner = contract owner, nspacl NULL, relacl NULL (zero explicit
-- entries), and no role other than superusers and the owner holding schema
-- USAGE/CREATE or any table privilege — evaluated per pg_roles role through the
-- inheritance-aware privilege functions, so membership-derived access is caught.
hist_priv AS (
  SELECT
    coalesce((SELECT n.nspowner = (SELECT c2.relowner FROM pg_class c2
                 WHERE c2.oid = to_regclass('public.qhub_manual_review_requests'))
                FROM pg_namespace n WHERE n.nspname = 'supabase_migrations'), FALSE)
                                                                                 AS schema_owner_ok,
    coalesce((SELECT n.nspacl IS NULL FROM pg_namespace n
               WHERE n.nspname = 'supabase_migrations'), FALSE)                  AS schema_acl_empty,
    coalesce((SELECT c.relacl IS NULL FROM pg_class c, hist h
               WHERE c.oid = h.reloid), FALSE)                                   AS table_acl_empty,
    -- Browser/application roles established by authoritative evidence (anon,
    -- authenticated, service_role) must EXIST and must hold NO schema or table
    -- privilege, directly or through any role membership (the privilege
    -- functions are inheritance-aware, so access inherited from a capability
    -- role such as pg_read_all_data is caught here too).
    coalesce(((SELECT count(*) FROM pg_roles r
                WHERE r.rolname IN ('anon', 'authenticated', 'service_role')) = 3), FALSE)
                                                                                 AS browser_roles_present,
    coalesce((SELECT h.reloid IS NOT NULL AND ns.oid IS NOT NULL
                 AND NOT EXISTS (
                   SELECT 1 FROM pg_roles r
                    WHERE r.rolname IN ('anon', 'authenticated', 'service_role')
                      AND (has_schema_privilege(r.oid, ns.oid, 'USAGE, CREATE')
                           OR has_table_privilege(r.oid, h.reloid,
                                'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')))
                FROM hist h
                LEFT JOIN LATERAL (SELECT n.oid FROM pg_namespace n
                                    WHERE n.nspname = 'supabase_migrations') ns ON TRUE), FALSE)
                                                                                 AS no_browser_role_privilege,
    -- INFORMATIONAL ONLY (deliberately non-gating, and named accordingly): the
    -- complete inventory of non-superuser, non-owner roles holding any effective
    -- schema/table access. On a healthy deployment this contains at most
    -- PostgreSQL's predefined pg_* capability bundles (e.g. pg_read_all_data),
    -- which hold read/write on EVERY table by design and whose live membership
    -- inventory cannot be pinned offline; gating them would make the healthy
    -- state unsatisfiable. Direct grants to ANY role are gated by the
    -- cardinality-zero nspacl/relacl checks above, and browser/app roles are
    -- gated inheritance-aware — this column exists so the human reviewer sees
    -- the full picture at PRE time.
    (SELECT array_agg(r.rolname ORDER BY r.rolname)
       FROM pg_roles r, hist h,
            LATERAL (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'supabase_migrations') ns
      WHERE h.reloid IS NOT NULL AND NOT r.rolsuper
        AND r.oid IS DISTINCT FROM (SELECT c2.relowner FROM pg_class c2
              WHERE c2.oid = to_regclass('public.qhub_manual_review_requests'))
        AND (has_schema_privilege(r.oid, ns.oid, 'USAGE, CREATE')
             OR has_table_privilege(r.oid, h.reloid,
                  'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')))
                                                                                 AS roles_with_access_informational
),
hist_rows AS (
  SELECT
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE (version ~ '^[0-9]+$') IS DISTINCT FROM TRUE$q$, false, true, '')))[1]::text
    END AS malformed_rows,
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE version ~ '^[0-9]+$' AND version::numeric > 20260729$q$, false, true, '')))[1]::text
    END AS newer_version_rows,
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE name = 'commercial_launch_foundation' AND version <> '20260729'$q$,
        false, true, '')))[1]::text
    END AS name_conflict_rows,
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations
            WHERE version = '20260729'$q$, false, true, '')))[1]::text
    END AS target_rows,
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT count(*)::text AS c FROM supabase_migrations.schema_migrations m
            WHERE m.version = '20260729'
              AND m.name = 'commercial_launch_foundation'
              AND m.statements IS NOT NULL
              AND cardinality(m.statements) = 89
              AND (SELECT sum(octet_length(s)) FROM unnest(m.statements) t(s)) = 124959
              AND (SELECT md5(string_agg(octet_length(s)::text || ':' || s, '' ORDER BY ord))
                     FROM unnest(m.statements) WITH ORDINALITY t(s, ord))
                  = '7b28ccf3ba7cae3e29c17bc5c3be60b6'$q$,
        false, true, '')))[1]::text
    END AS target_exact_rows,
    CASE WHEN (SELECT h.reloid IS NOT NULL AND h.cols_ok FROM hist h) THEN
      (xpath('/row/c/text()', query_to_xml(
        $q$SELECT coalesce(string_agg(
                  version || '=' || coalesce(name, '(null)')
                  || ' [stmts: ' || coalesce(cardinality(statements)::text, 'null')
                  || ' digest: ' || coalesce((SELECT md5(string_agg(octet_length(s)::text || ':' || s, '' ORDER BY ord))
                                               FROM unnest(statements) WITH ORDINALITY t(s, ord)), 'null') || ']',
                  ' | ' ORDER BY version), '(absent)') AS c
             FROM supabase_migrations.schema_migrations WHERE version = '20260729'$q$,
        false, true, '')))[1]::text
    END AS target_row_detail
)
SELECT
  p.verifier_present, p.zero_argument_signature, p.single_function_no_overload,
  p.semantic_callable_exact,
  p.owner_exact, p.security_definer, p.search_path_exact,
  p.acl_cardinality_exact, p.owner_execute_row_exact, p.service_role_owner_granted,
  p.no_unexpected_grantee, p.no_grant_option, p.body_approved,
  p.effective_acl_ok, p.unexpected_effective_executor_roles,
  p.authority_ok,
  p.product_ready, p.product_version, p.product_failed_count,
  (p.product_ready IS NOT DISTINCT FROM 'true')                    AS product_ready_true,
  (p.product_version IS NOT DISTINCT FROM p.expected_version)      AS product_version_exact,
  (p.product_failed_count IS NOT DISTINCT FROM '0')                AS product_failed_empty,
  s.table_present, s.kind_ok, s.table_owner_ok, s.rls_off,
  s.columns_exact, s.constraints_exact, s.pk_exact, s.indexes_exact,
  s.no_triggers, s.no_rules, s.no_policies, s.no_inheritance,
  v.schema_owner_ok, v.schema_acl_empty, v.table_acl_empty,
  v.browser_roles_present, v.no_browser_role_privilege, v.roles_with_access_informational,
  r.malformed_rows, r.newer_version_rows, r.name_conflict_rows,
  r.target_rows, r.target_exact_rows, r.target_row_detail,
  CASE
    WHEN coalesce(p.authority_ok, FALSE)
     AND p.product_ready IS NOT DISTINCT FROM 'true'
     AND p.product_version IS NOT DISTINCT FROM p.expected_version
     AND p.product_failed_count IS NOT DISTINCT FROM '0'
     AND coalesce(s.table_present, FALSE) AND coalesce(s.kind_ok, FALSE)
     AND coalesce(s.table_owner_ok, FALSE) AND coalesce(s.rls_off, FALSE)
     AND coalesce(s.columns_exact, FALSE) AND coalesce(s.constraints_exact, FALSE)
     AND coalesce(s.pk_exact, FALSE) AND coalesce(s.indexes_exact, FALSE)
     AND coalesce(s.no_triggers, FALSE) AND coalesce(s.no_rules, FALSE)
     AND coalesce(s.no_policies, FALSE) AND coalesce(s.no_inheritance, FALSE)
     AND coalesce(v.schema_owner_ok, FALSE) AND coalesce(v.schema_acl_empty, FALSE)
     AND coalesce(v.table_acl_empty, FALSE)
     AND coalesce(v.browser_roles_present, FALSE)
     AND coalesce(v.no_browser_role_privilege, FALSE)
     AND r.malformed_rows IS NOT DISTINCT FROM '0'
     AND r.newer_version_rows IS NOT DISTINCT FROM '0'
     AND r.name_conflict_rows IS NOT DISTINCT FROM '0'
     AND r.target_rows IS NOT DISTINCT FROM '1'
     AND r.target_exact_rows IS NOT DISTINCT FROM '1'
      THEN 'MIGRATION_20260729_HISTORY_RECONCILED'
    ELSE 'MIGRATION_HISTORY_NOT_RECONCILED'
  END                                                              AS final_status
FROM product p
CROSS JOIN hist_shape s
CROSS JOIN hist_priv v
CROSS JOIN hist_rows r;

COMMIT;
