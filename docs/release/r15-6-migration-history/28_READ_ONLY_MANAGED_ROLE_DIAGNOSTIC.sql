-- ============================================================================
-- QHUB R15.6.4 — 28 READ-ONLY MANAGED-ROLE ACCESS DIAGNOSTIC
--
-- EVIDENCE ONLY. This file authorizes NOTHING. It declares no role trusted, it
-- does not relax any gate, and it must never be treated as permission to run
-- 26_MIGRATION_HISTORY_RECORD.sql. RECORD and POST remain unauthorized.
--
-- WHY THIS EXISTS. The authorized live run of PRE 25 returned
-- UNEXPECTED_MIGRATION_HISTORY_STOP with exactly one failing condition:
--   no_unauthorized_access_path = false
--   unauthorized_access_paths   = {cli_login_postgres, supabase_etl_admin,
--                                  supabase_read_only_user}
-- Every other check passed (verifier authority + product READY, exact table
-- contract, empty nspacl/relacl, anon/authenticated/service_role clean, no
-- conflicting/malformed/newer rows, target absent). The three names look
-- platform-managed, but a name is not a capability: this diagnostic collects
-- the exact catalog evidence a human reviewer needs to decide whether each path
-- is genuinely benign managed infrastructure or a real exposure.
--
-- SCOPE AND SAFETY.
--   * One explicit transaction: REPEATABLE READ + READ ONLY. No mutating SQL of
--     any kind — no INSERT/UPDATE/DELETE/TRUNCATE/CREATE/ALTER/DROP/GRANT/
--     REVOKE/LOCK, no temporary objects, no dynamic SQL, no function calls
--     other than PostgreSQL's own catalog/privilege inspection functions.
--   * Reads ONLY: pg_roles, pg_auth_members, pg_namespace, pg_class,
--     pg_default_acl (scoped), and the privilege functions. It never reads
--     application tables, user records, secrets, tokens, customer data, or any
--     schema other than supabase_migrations (plus the pinned owner lookup in
--     public.qhub_manual_review_requests, from pg_class metadata only — no row
--     is read from that table).
--   * nspacl / relacl are reported for exactly the two protected objects.
--   * Candidates are DISCOVERED from the catalog, never from a name list. The
--     three observed names are not special-cased anywhere in this file.
--
-- CANDIDATE DEFINITION (identical to the PRE 25 / RECORD 26 / POST 27 gate):
--   any role that is NOT a superuser, NOT the pinned owner, and is either
--   rolcanlogin OR one of anon / authenticated / service_role.
--
-- ACCESS DEFINITION: a candidate reaches the protected objects if ANY role it
-- can assume — itself, or any role reachable by transitive membership
-- REGARDLESS OF INHERIT (pg_has_role(..., 'MEMBER')) — holds schema
-- USAGE/CREATE or table SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/
-- TRIGGER. Membership closure is used because a NOINHERIT login reports FALSE
-- from has_table_privilege yet can still SET ROLE (verified on PostgreSQL 16).
--
-- OUTPUT: four result sets, deterministic and ordered.
--   QUERY 1 — protected-object identity: owners, nspacl, relacl, RLS.
--   QUERY 2 — candidate inventory with role attributes and headline access.
--   QUERY 3 — per-candidate, per-privilege route attribution (direct vs
--             inherited vs SET-ROLE-only) — the core evidence table.
--   QUERY 4 — membership edges and predefined-capability-role reachability.
-- Run the file IN FULL; read all four. Capture every row verbatim.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SET LOCAL search_path = pg_catalog;

-- ---------------------------------------------------------------------------
-- QUERY 1 — the protected objects themselves: exact owners, explicit ACLs,
-- RLS state, and the pinned contract owner the gate compares against.
-- ---------------------------------------------------------------------------
SELECT
  'supabase_migrations'                                                          AS schema_name,
  (SELECT pg_get_userbyid(n.nspowner) FROM pg_namespace n
    WHERE n.nspname = 'supabase_migrations')                                     AS schema_owner,
  (SELECT coalesce(n.nspacl::text, '(NULL - no explicit entries)') FROM pg_namespace n
    WHERE n.nspname = 'supabase_migrations')                                     AS schema_nspacl,
  (SELECT pg_get_userbyid(c.relowner) FROM pg_class c
    WHERE c.oid = to_regclass('supabase_migrations.schema_migrations'))          AS table_owner,
  (SELECT coalesce(c.relacl::text, '(NULL - no explicit entries)') FROM pg_class c
    WHERE c.oid = to_regclass('supabase_migrations.schema_migrations'))          AS table_relacl,
  (SELECT c.relrowsecurity::text || '/' || c.relforcerowsecurity::text FROM pg_class c
    WHERE c.oid = to_regclass('supabase_migrations.schema_migrations'))          AS table_rls_enabled_forced,
  (SELECT pg_get_userbyid(c.relowner) FROM pg_class c
    WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))             AS pinned_contract_owner,
  (SELECT count(*) FROM pg_default_acl d
    JOIN pg_namespace n ON n.oid = d.defaclnamespace
   WHERE n.nspname = 'supabase_migrations')                                      AS default_acl_entries_for_schema,
  (SELECT count(*) FROM pg_roles r WHERE r.rolsuper)                             AS superuser_count,
  (SELECT count(*) FROM pg_roles)                                                AS total_role_count;

-- ---------------------------------------------------------------------------
-- QUERY 2 — candidate inventory. Every non-superuser, non-owner role that can
-- log in, plus anon/authenticated/service_role. Role attributes are reported in
-- full so a reviewer can judge what each identity is actually capable of.
-- reaches_protected_objects is the same predicate the PRE/RECORD/POST gate uses.
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT
    (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')   AS nsp_oid,
    to_regclass('supabase_migrations.schema_migrations')                         AS rel_oid,
    (SELECT c.relowner FROM pg_class c
      WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))           AS owner_oid
),
cand AS (
  SELECT r.oid, r.rolname, r.rolsuper, r.rolcanlogin, r.rolinherit, r.rolcreaterole,
         r.rolcreatedb, r.rolreplication, r.rolbypassrls, r.rolconnlimit, r.rolvaliduntil
    FROM pg_roles r, ids i
   WHERE NOT r.rolsuper
     AND r.oid IS DISTINCT FROM i.owner_oid
     AND (r.rolcanlogin OR r.rolname IN ('anon', 'authenticated', 'service_role'))
)
SELECT
  c.rolname                                                                      AS candidate_role,
  c.rolcanlogin                                                                  AS can_login,
  c.rolsuper                                                                     AS is_superuser,
  c.rolinherit                                                                   AS inherits,
  c.rolcreaterole                                                                AS createrole,
  c.rolcreatedb                                                                  AS createdb,
  c.rolreplication                                                               AS replication,
  c.rolbypassrls                                                                 AS bypassrls,
  c.rolconnlimit                                                                 AS conn_limit,
  (c.rolvaliduntil IS NOT NULL)                                                  AS has_valid_until,
  (c.rolname IN ('anon', 'authenticated', 'service_role'))                       AS is_required_platform_role,
  -- The gate predicate, reproduced verbatim for this candidate.
  EXISTS (
    SELECT 1 FROM pg_roles a, ids i
     WHERE (a.oid = c.oid OR pg_has_role(c.oid, a.oid, 'MEMBER'))
       AND (has_schema_privilege(a.oid, i.nsp_oid, 'USAGE, CREATE')
            OR has_table_privilege(a.oid, i.rel_oid,
                 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'))
  )                                                                              AS reaches_protected_objects,
  -- Can this candidate become the pinned owner, or any superuser?
  EXISTS (SELECT 1 FROM ids i WHERE pg_has_role(c.oid, i.owner_oid, 'MEMBER'))   AS can_assume_pinned_owner,
  EXISTS (SELECT 1 FROM pg_roles s
           WHERE s.rolsuper AND pg_has_role(c.oid, s.oid, 'MEMBER'))             AS can_assume_a_superuser,
  -- Predefined capability roles reachable by this candidate (empty = none).
  (SELECT coalesce(array_agg(p.rolname ORDER BY p.rolname), '{}'::name[])
     FROM pg_roles p
    WHERE p.rolname LIKE 'pg\_%' AND p.oid <> c.oid
      AND pg_has_role(c.oid, p.oid, 'MEMBER'))                                   AS predefined_roles_reachable,
  -- Every non-self role this candidate can assume (the full closure).
  (SELECT coalesce(array_agg(a.rolname ORDER BY a.rolname), '{}'::name[])
     FROM pg_roles a
    WHERE a.oid <> c.oid AND pg_has_role(c.oid, a.oid, 'MEMBER'))                AS all_assumable_roles
FROM cand c
ORDER BY reaches_protected_objects DESC, c.rolname;

-- ---------------------------------------------------------------------------
-- QUERY 3 — THE CORE EVIDENCE TABLE. One row per (candidate, privilege), only
-- where the candidate actually reaches the privilege. Each row attributes the
-- route:
--   direct_or_inherited  = has_*_privilege(candidate, ...) — what the candidate
--                          holds without switching roles (direct grant, PUBLIC,
--                          ownership, or INHERIT-ed membership)
--   set_role_only        = NOT direct_or_inherited, but some assumable role has
--                          it — reachable exclusively via SET ROLE (the
--                          NOINHERIT case)
--   via_explicit_acl     = an explicit ACL entry names the candidate or a role
--                          it can assume
--   via_public_grant     = the privilege is granted to PUBLIC
--   via_predefined_role  = granted through a pg_* capability role
--   granting_roles       = exactly which assumable roles supply the privilege
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT
    (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')   AS nsp_oid,
    to_regclass('supabase_migrations.schema_migrations')                         AS rel_oid,
    (SELECT c.relowner FROM pg_class c
      WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))           AS owner_oid
),
cand AS (
  SELECT r.oid, r.rolname
    FROM pg_roles r, ids i
   WHERE NOT r.rolsuper
     AND r.oid IS DISTINCT FROM i.owner_oid
     AND (r.rolcanlogin OR r.rolname IN ('anon', 'authenticated', 'service_role'))
),
privs(object_kind, priv) AS (
  VALUES ('schema', 'USAGE'), ('schema', 'CREATE'),
         ('table', 'SELECT'), ('table', 'INSERT'), ('table', 'UPDATE'),
         ('table', 'DELETE'), ('table', 'TRUNCATE'), ('table', 'REFERENCES'),
         ('table', 'TRIGGER')
),
-- Every (candidate, assumable role) pair, including the candidate itself.
reach AS (
  SELECT c.oid AS cand_oid, c.rolname AS cand_name, a.oid AS via_oid, a.rolname AS via_name
    FROM cand c
    JOIN pg_roles a ON (a.oid = c.oid OR pg_has_role(c.oid, a.oid, 'MEMBER'))
),
hits AS (
  SELECT
    r.cand_oid, r.cand_name, p.object_kind, p.priv, r.via_oid, r.via_name,
    (r.via_oid = r.cand_oid)                                                     AS is_self
  FROM reach r
  CROSS JOIN privs p
  CROSS JOIN ids i
  WHERE CASE p.object_kind
          WHEN 'schema' THEN has_schema_privilege(r.via_oid, i.nsp_oid, p.priv)
          ELSE has_table_privilege(r.via_oid, i.rel_oid, p.priv)
        END
)
SELECT
  h.cand_name                                                                    AS candidate_role,
  h.object_kind,
  h.priv                                                                         AS privilege,
  bool_or(h.is_self)                                                             AS direct_or_inherited,
  NOT bool_or(h.is_self)                                                         AS set_role_only,
  bool_or(h.via_name LIKE 'pg\_%' AND NOT h.is_self)                             AS via_predefined_role,
  bool_or(h.via_oid = (SELECT owner_oid FROM ids) AND NOT h.is_self)             AS via_owner_role,
  -- Explicit ACL attribution, evaluated against the object's own acl array.
  bool_or(
    CASE h.object_kind
      WHEN 'schema' THEN EXISTS (
        SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) ae
         WHERE n.nspname = 'supabase_migrations'
           AND ae.grantee = h.via_oid AND ae.privilege_type = h.priv)
      ELSE EXISTS (
        SELECT 1 FROM pg_class c, aclexplode(c.relacl) ae
         WHERE c.oid = (SELECT rel_oid FROM ids)
           AND ae.grantee = h.via_oid AND ae.privilege_type = h.priv)
    END)                                                                         AS via_explicit_acl,
  bool_or(
    CASE h.object_kind
      WHEN 'schema' THEN EXISTS (
        SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) ae
         WHERE n.nspname = 'supabase_migrations'
           AND ae.grantee = 0 AND ae.privilege_type = h.priv)
      ELSE EXISTS (
        SELECT 1 FROM pg_class c, aclexplode(c.relacl) ae
         WHERE c.oid = (SELECT rel_oid FROM ids)
           AND ae.grantee = 0 AND ae.privilege_type = h.priv)
    END)                                                                         AS via_public_grant,
  array_agg(h.via_name ORDER BY h.via_name)                                      AS granting_roles
FROM hits h
GROUP BY h.cand_name, h.object_kind, h.priv
ORDER BY h.cand_name,
         CASE h.object_kind WHEN 'schema' THEN 0 ELSE 1 END,
         CASE h.priv WHEN 'USAGE' THEN 0 WHEN 'CREATE' THEN 1 WHEN 'SELECT' THEN 2
                     WHEN 'INSERT' THEN 3 WHEN 'UPDATE' THEN 4 WHEN 'DELETE' THEN 5
                     WHEN 'TRUNCATE' THEN 6 WHEN 'REFERENCES' THEN 7 ELSE 8 END;

-- ---------------------------------------------------------------------------
-- QUERY 4 — membership edges for every candidate: the direct GRANT ... TO
-- edges (with admin option and inheritance semantics) plus whether the edge is
-- usable without SET ROLE. This is the raw graph behind QUERY 2/3, so a
-- reviewer can trace each path by hand.
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT (SELECT c.relowner FROM pg_class c
           WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))      AS owner_oid
),
cand AS (
  SELECT r.oid, r.rolname, r.rolinherit
    FROM pg_roles r, ids i
   WHERE NOT r.rolsuper
     AND r.oid IS DISTINCT FROM i.owner_oid
     AND (r.rolcanlogin OR r.rolname IN ('anon', 'authenticated', 'service_role'))
)
SELECT
  c.rolname                                                                      AS candidate_role,
  c.rolinherit                                                                   AS candidate_inherits,
  g.rolname                                                                      AS granted_role,
  m.admin_option                                                                 AS with_admin_option,
  pg_get_userbyid(m.grantor)                                                     AS membership_grantor,
  (g.rolname LIKE 'pg\_%')                                                       AS granted_role_is_predefined,
  g.rolcanlogin                                                                  AS granted_role_can_login,
  g.rolsuper                                                                     AS granted_role_is_superuser,
  -- Whether privileges of the granted role apply without an explicit SET ROLE.
  (c.rolinherit AND pg_has_role(c.oid, g.oid, 'USAGE'))                          AS usable_without_set_role,
  pg_has_role(c.oid, g.oid, 'MEMBER')                                            AS assumable_via_set_role
FROM cand c
JOIN pg_auth_members m ON m.member = c.oid
JOIN pg_roles g ON g.oid = m.roleid
ORDER BY c.rolname, g.rolname;

COMMIT;
