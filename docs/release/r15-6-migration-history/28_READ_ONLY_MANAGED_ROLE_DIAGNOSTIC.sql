-- ============================================================================
-- QHUB R15.6.4 — READ-ONLY MANAGED-ROLE ACCESS DIAGNOSTIC (corrected)
--
-- EVIDENCE ONLY. This file authorizes NOTHING. It declares no role safe, it
-- relaxes no gate, and it must never be read as permission to run
-- 26_MIGRATION_HISTORY_RECORD.sql. PRE 25, RECORD 26, POST 27 and this file all
-- remain unauthorized for further live execution.
--
-- WHY THIS EXISTS. The authorized live run of PRE 25 returned
-- UNEXPECTED_MIGRATION_HISTORY_STOP with exactly one failing condition:
--   no_unauthorized_access_path = false
--   unauthorized_access_paths   = {cli_login_postgres, supabase_etl_admin,
--                                  supabase_read_only_user}
-- Every other check passed. The three names look platform-managed, but a name
-- is not a capability: this file collects the exact catalog evidence a human
-- reviewer needs to decide whether each path is benign managed infrastructure
-- or a real exposure.
--
-- ---------------------------------------------------------------------------
-- CORRECTION (independent review): MEMBER != USAGE != SET.
--
-- The first revision used pg_has_role(candidate, role, 'MEMBER') as proof that
-- a candidate could inherit privileges or execute SET ROLE. In PostgreSQL 16
-- these are three distinct facts, verified here against a live PostgreSQL 16
-- and against actual SET ROLE attempts:
--
--   membership (GRANT r TO c WITH ...)  MEMBER  USAGE  SET   priv?  SET ROLE?
--   INHERIT FALSE, SET FALSE              t       f      f     no     DENIED
--   INHERIT FALSE, SET TRUE               t       f      t     no     OK
--   INHERIT TRUE,  SET FALSE              t       t      f     yes    DENIED
--   INHERIT TRUE,  SET TRUE               t       t      t     yes    OK
--   ADMIN TRUE, INHERIT/SET FALSE         t       f      f     no     DENIED
--
-- So MEMBER alone is an INACTIVE membership: it confers no privilege and no
-- SET ROLE authority. ADMIN OPTION confers neither either — it only permits
-- re-granting the membership. This file therefore reports, separately:
--   * membership existence            — pg_has_role(..., 'MEMBER')
--   * privileges usable WITHOUT SET ROLE — has_*_privilege(candidate, ...),
--     which follows PostgreSQL's own inheritance (the USAGE property)
--   * roles actually settable         — pg_has_role(..., 'SET')
-- The word "assumable" is used ONLY for roles the candidate may actually SET
-- ROLE to. Inactive memberships remain visible as membership evidence and are
-- labelled as conferring no access.
--
-- NOTE ON THE GATE. PRE 25 / RECORD 26 / POST 27 use the MEMBER closure. Under
-- these semantics that predicate is CONSERVATIVE — it can flag an inactive
-- membership that confers nothing, so it may over-block, never under-block. It
-- is therefore still fail-closed and is deliberately left unchanged here; this
-- diagnostic supplies the precise picture a reviewer needs to interpret it.
-- ---------------------------------------------------------------------------
--
-- SCOPE AND SAFETY.
--   * One explicit transaction: REPEATABLE READ + READ ONLY.
--   * No DDL, no DML, no dynamic SQL, no DO block, no EXECUTE, no user-defined
--     function call, no temporary object — only catalog reads and PostgreSQL's
--     own privilege-inspection functions.
--   * Reads pg_roles, pg_auth_members, pg_namespace, pg_class, pg_default_acl
--     and the privilege functions. It reads NO application rows, NO
--     migration-history rows, no secrets, credentials, tokens, password hashes
--     or customer data, and no schema other than supabase_migrations (the
--     pinned-owner lookup reads pg_class metadata for a public table, never a
--     row from it).
--   * Candidates are DISCOVERED from the catalog. The three observed live names
--     appear nowhere in the executable SQL.
--
-- CANDIDATE DEFINITION (same population the gate considers): any role that is
-- NOT a superuser, NOT the pinned owner, and is either rolcanlogin or one of
-- anon / authenticated / service_role.
--
-- OUTPUT: five deterministic, ordered result sets.
--   QUERY 1 — protected-object identity.
--   QUERY 2 — candidate inventory: attributes, validity, and the three
--             separated reachability facts.
--   QUERY 3 — per-privilege route evidence (usable-without-SET-ROLE vs
--             reachable-only-via-SET-ROLE vs inactive membership).
--   QUERY 4 — membership PATHS: every direct and transitive route with per-edge
--             admin/inherit/set options, depth, deterministic path identity,
--             and whether that specific path permits inheritance / SET ROLE.
--   QUERY 5 — structured ACL evidence for the protected schema and table.
-- Run the file IN FULL and read all five. Capture every row verbatim.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SET LOCAL search_path = pg_catalog;

-- ---------------------------------------------------------------------------
-- QUERY 1 — the protected objects: exact owners, explicit ACLs, RLS state, and
-- the pinned contract owner the gate compares against.
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
  (SELECT count(*) FROM pg_roles)                                                AS total_role_count,
  current_setting('server_version')                                              AS server_version;

-- ---------------------------------------------------------------------------
-- QUERY 2 — candidate inventory.
--
-- Reachability is reported as THREE separate facts, never conflated:
--   privileges_usable_without_set_role — has_*_privilege(candidate, ...) is
--       true: the candidate holds the privilege directly, through PUBLIC,
--       through ownership, or through an INHERIT-enabled membership chain.
--   privileges_via_set_role_only       — the candidate holds nothing itself,
--       but MAY SET ROLE (pg_has_role ... 'SET') to a role that does.
--   inactive_memberships_with_access   — memberships that EXIST (MEMBER) to
--       roles that hold access, but confer neither inheritance nor SET ROLE.
--       Evidence only: these are NOT access.
-- reaches_protected_objects is true only for the first two.
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
),
-- Does this role hold ANY relevant privilege on the protected objects?
holds AS (
  SELECT r.oid, r.rolname,
         (has_schema_privilege(r.oid, i.nsp_oid, 'USAGE, CREATE')
          OR has_table_privilege(r.oid, i.rel_oid,
               'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')) AS has_any
    FROM pg_roles r, ids i
)
SELECT
  c.rolname                                                                      AS candidate_role,
  c.rolcanlogin                                                                  AS can_login,
  c.rolsuper                                                                     AS is_superuser,
  c.rolinherit                                                                   AS role_default_inherit,
  c.rolcreaterole                                                                AS createrole,
  c.rolcreatedb                                                                  AS createdb,
  c.rolreplication                                                               AS replication,
  c.rolbypassrls                                                                 AS bypassrls,
  c.rolconnlimit                                                                 AS conn_limit,
  -- ROLE VALIDITY (exact, not a boolean reduction). No password material.
  coalesce(c.rolvaliduntil::text, '(null)')                                      AS rolvaliduntil,
  (c.rolvaliduntil IS NULL)                                                      AS never_expires,
  (c.rolvaliduntil IS NULL OR c.rolvaliduntil > now())                           AS currently_valid,
  (c.rolvaliduntil IS NOT NULL AND c.rolvaliduntil <= now())                     AS expired,
  (c.rolname IN ('anon', 'authenticated', 'service_role'))                       AS is_required_platform_role,
  -- THE THREE SEPARATED FACTS
  (SELECT h.has_any FROM holds h WHERE h.oid = c.oid)                            AS privileges_usable_without_set_role,
  EXISTS (SELECT 1 FROM holds h
           WHERE h.oid <> c.oid AND h.has_any AND pg_has_role(c.oid, h.oid, 'SET'))
                                                                                 AS privileges_via_set_role,
  ((SELECT h.has_any FROM holds h WHERE h.oid = c.oid)
   OR EXISTS (SELECT 1 FROM holds h
               WHERE h.oid <> c.oid AND h.has_any AND pg_has_role(c.oid, h.oid, 'SET')))
                                                                                 AS reaches_protected_objects,
  -- Inactive memberships: MEMBER holds, but neither USAGE nor SET — no access.
  (SELECT coalesce(array_agg(h.rolname ORDER BY h.rolname), '{}'::name[])
     FROM holds h
    WHERE h.oid <> c.oid AND h.has_any
      AND pg_has_role(c.oid, h.oid, 'MEMBER')
      AND NOT pg_has_role(c.oid, h.oid, 'USAGE')
      AND NOT pg_has_role(c.oid, h.oid, 'SET'))                                  AS inactive_memberships_with_access,
  -- Owner / superuser: SET authority and inheritance reported separately.
  EXISTS (SELECT 1 FROM ids i WHERE pg_has_role(c.oid, i.owner_oid, 'SET'))      AS can_set_role_to_pinned_owner,
  EXISTS (SELECT 1 FROM ids i WHERE pg_has_role(c.oid, i.owner_oid, 'USAGE'))    AS inherits_from_pinned_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE pg_has_role(c.oid, i.owner_oid, 'MEMBER')
             AND NOT pg_has_role(c.oid, i.owner_oid, 'USAGE')
             AND NOT pg_has_role(c.oid, i.owner_oid, 'SET'))                     AS inactive_membership_of_pinned_owner,
  EXISTS (SELECT 1 FROM pg_roles s WHERE s.rolsuper AND pg_has_role(c.oid, s.oid, 'SET'))
                                                                                 AS can_set_role_to_a_superuser,
  EXISTS (SELECT 1 FROM pg_roles s WHERE s.rolsuper AND pg_has_role(c.oid, s.oid, 'USAGE'))
                                                                                 AS inherits_from_a_superuser,
  -- Role sets, split by what the membership actually permits.
  (SELECT coalesce(array_agg(r.rolname ORDER BY r.rolname), '{}'::name[])
     FROM pg_roles r WHERE r.oid <> c.oid AND pg_has_role(c.oid, r.oid, 'USAGE'))
                                                                                 AS roles_inherited_from,
  (SELECT coalesce(array_agg(r.rolname ORDER BY r.rolname), '{}'::name[])
     FROM pg_roles r WHERE r.oid <> c.oid AND pg_has_role(c.oid, r.oid, 'SET'))
                                                                                 AS roles_settable_via_set_role,
  (SELECT coalesce(array_agg(r.rolname ORDER BY r.rolname), '{}'::name[])
     FROM pg_roles r
    WHERE r.oid <> c.oid AND pg_has_role(c.oid, r.oid, 'MEMBER')
      AND NOT pg_has_role(c.oid, r.oid, 'USAGE')
      AND NOT pg_has_role(c.oid, r.oid, 'SET'))                                  AS roles_inactive_membership_only,
  -- Predefined capability roles, split the same way.
  (SELECT coalesce(array_agg(p.rolname ORDER BY p.rolname), '{}'::name[])
     FROM pg_roles p
    WHERE p.rolname LIKE 'pg\_%' AND p.oid <> c.oid AND pg_has_role(c.oid, p.oid, 'USAGE'))
                                                                                 AS predefined_roles_inherited,
  (SELECT coalesce(array_agg(p.rolname ORDER BY p.rolname), '{}'::name[])
     FROM pg_roles p
    WHERE p.rolname LIKE 'pg\_%' AND p.oid <> c.oid AND pg_has_role(c.oid, p.oid, 'SET'))
                                                                                 AS predefined_roles_settable,
  (SELECT coalesce(array_agg(p.rolname ORDER BY p.rolname), '{}'::name[])
     FROM pg_roles p
    WHERE p.rolname LIKE 'pg\_%' AND p.oid <> c.oid AND pg_has_role(c.oid, p.oid, 'MEMBER')
      AND NOT pg_has_role(c.oid, p.oid, 'USAGE') AND NOT pg_has_role(c.oid, p.oid, 'SET'))
                                                                                 AS predefined_roles_inactive_membership
FROM cand c
ORDER BY reaches_protected_objects DESC, c.rolname;

-- ---------------------------------------------------------------------------
-- QUERY 3 — per-privilege route evidence. One row per (candidate, object,
-- privilege) that the candidate can actually reach by SOME route, plus rows
-- where only an inactive membership exists (reported with both reach flags
-- false, so a reviewer sees the membership without it counting as access).
--
--   usable_without_set_role — has_*_privilege(candidate, ...) is true
--   reachable_via_set_role  — some SET-settable role holds the privilege
--   inheriting_roles        — roles supplying it WITHOUT SET ROLE (incl. self)
--   settable_roles          — roles supplying it only AFTER SET ROLE
--   inactive_membership_roles — roles that hold it but whose membership grants
--                               neither inheritance nor SET ROLE (NOT access)
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
privs(object_kind, priv, ord) AS (
  VALUES ('schema', 'USAGE', 0), ('schema', 'CREATE', 1),
         ('table', 'SELECT', 2), ('table', 'INSERT', 3), ('table', 'UPDATE', 4),
         ('table', 'DELETE', 5), ('table', 'TRUNCATE', 6), ('table', 'REFERENCES', 7),
         ('table', 'TRIGGER', 8)
),
-- Which roles hold each privilege, evaluated per role by PostgreSQL itself.
holder AS (
  SELECT r.oid, r.rolname, p.object_kind, p.priv, p.ord
    FROM pg_roles r
    CROSS JOIN privs p
    CROSS JOIN ids i
   WHERE CASE p.object_kind
           WHEN 'schema' THEN has_schema_privilege(r.oid, i.nsp_oid, p.priv)
           ELSE has_table_privilege(r.oid, i.rel_oid, p.priv)
         END
),
-- Classify every (candidate, privilege, holder) relationship.
routed AS (
  SELECT
    c.oid AS cand_oid, c.rolname AS cand_name, h.object_kind, h.priv, h.ord,
    h.oid AS holder_oid, h.rolname AS holder_name,
    (h.oid = c.oid)                                                              AS is_self,
    (h.oid <> c.oid AND pg_has_role(c.oid, h.oid, 'USAGE'))                      AS inherited,
    (h.oid <> c.oid AND pg_has_role(c.oid, h.oid, 'SET'))                        AS settable,
    (h.oid <> c.oid AND pg_has_role(c.oid, h.oid, 'MEMBER')
       AND NOT pg_has_role(c.oid, h.oid, 'USAGE')
       AND NOT pg_has_role(c.oid, h.oid, 'SET'))                                 AS inactive_member
  FROM cand c
  JOIN holder h ON TRUE
)
SELECT
  r.cand_name                                                                    AS candidate_role,
  r.object_kind,
  r.priv                                                                         AS privilege,
  bool_or(r.is_self OR r.inherited)                                              AS usable_without_set_role,
  bool_or(r.settable)                                                            AS reachable_via_set_role,
  bool_or(r.inactive_member)                                                     AS inactive_membership_only,
  bool_or(r.is_self)                                                             AS held_directly_or_inherited_by_self,
  (SELECT coalesce(array_agg(x.holder_name ORDER BY x.holder_name), '{}'::name[])
     FROM routed x
    WHERE x.cand_oid = r.cand_oid AND x.object_kind = r.object_kind AND x.priv = r.priv
      AND (x.is_self OR x.inherited))                                            AS inheriting_roles,
  (SELECT coalesce(array_agg(x.holder_name ORDER BY x.holder_name), '{}'::name[])
     FROM routed x
    WHERE x.cand_oid = r.cand_oid AND x.object_kind = r.object_kind AND x.priv = r.priv
      AND x.settable)                                                            AS settable_roles,
  (SELECT coalesce(array_agg(x.holder_name ORDER BY x.holder_name), '{}'::name[])
     FROM routed x
    WHERE x.cand_oid = r.cand_oid AND x.object_kind = r.object_kind AND x.priv = r.priv
      AND x.inactive_member)                                                     AS inactive_membership_roles,
  bool_or((r.is_self OR r.inherited) AND r.holder_name LIKE 'pg\_%')             AS via_predefined_role_inherited,
  bool_or(r.settable AND r.holder_name LIKE 'pg\_%')                             AS via_predefined_role_settable,
  bool_or((r.is_self OR r.inherited) AND r.holder_oid = (SELECT owner_oid FROM ids)
          AND NOT r.is_self)                                                     AS via_owner_role_inherited,
  bool_or(r.settable AND r.holder_oid = (SELECT owner_oid FROM ids))             AS via_owner_role_settable,
  -- Explicit ACL / PUBLIC attribution against the object's own acl array.
  bool_or(
    CASE r.object_kind
      WHEN 'schema' THEN EXISTS (
        SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) ae
         WHERE n.nspname = 'supabase_migrations'
           AND ae.grantee = r.holder_oid AND ae.privilege_type = r.priv)
      ELSE EXISTS (
        SELECT 1 FROM pg_class c2, aclexplode(c2.relacl) ae
         WHERE c2.oid = (SELECT rel_oid FROM ids)
           AND ae.grantee = r.holder_oid AND ae.privilege_type = r.priv)
    END)                                                                         AS via_explicit_acl,
  bool_or(
    CASE r.object_kind
      WHEN 'schema' THEN EXISTS (
        SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) ae
         WHERE n.nspname = 'supabase_migrations'
           AND ae.grantee = 0 AND ae.privilege_type = r.priv)
      ELSE EXISTS (
        SELECT 1 FROM pg_class c2, aclexplode(c2.relacl) ae
         WHERE c2.oid = (SELECT rel_oid FROM ids)
           AND ae.grantee = 0 AND ae.privilege_type = r.priv)
    END)                                                                         AS via_public_grant
FROM routed r
WHERE r.is_self OR r.inherited OR r.settable OR r.inactive_member
GROUP BY r.cand_oid, r.cand_name, r.object_kind, r.priv, r.ord
ORDER BY r.cand_name, r.ord;

-- ---------------------------------------------------------------------------
-- QUERY 4 — membership PATHS. Every direct and transitive route from a
-- candidate to a granted role, with each edge's options and the path-level
-- consequences. Conflicting paths are NOT collapsed: each path is its own row,
-- so a candidate reachable by both an inheriting and a non-inheriting path
-- shows both. Cycles are prevented by excluding any role already on the path;
-- depth is capped at 16.
--
--   path_permits_inheritance — every edge on THIS path has inherit_option
--   path_permits_set_role    — every edge on THIS path has set_option
--   admin_option is reported but is NOT evidence of either.
-- The authoritative per-role answers remain the pg_has_role columns, shown
-- alongside so path evidence can be cross-checked against PostgreSQL itself.
-- ---------------------------------------------------------------------------
WITH RECURSIVE ids AS (
  SELECT (SELECT c.relowner FROM pg_class c
           WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))      AS owner_oid
),
cand AS (
  SELECT r.oid, r.rolname
    FROM pg_roles r, ids i
   WHERE NOT r.rolsuper
     AND r.oid IS DISTINCT FROM i.owner_oid
     AND (r.rolcanlogin OR r.rolname IN ('anon', 'authenticated', 'service_role'))
),
paths AS (
  SELECT
    c.oid                                        AS cand_oid,
    c.rolname                                    AS cand_name,
    m.member                                     AS member_oid,
    m.roleid                                     AS granted_oid,
    1                                            AS depth,
    ARRAY[c.oid, m.roleid]                       AS path_oids,
    c.rolname::text || ' -> ' || (SELECT r2.rolname FROM pg_roles r2 WHERE r2.oid = m.roleid)::text
                                                 AS path_text,
    m.admin_option, m.inherit_option, m.set_option, m.grantor,
    m.inherit_option                             AS path_permits_inheritance,
    m.set_option                                 AS path_permits_set_role
  FROM cand c
  JOIN pg_auth_members m ON m.member = c.oid
  UNION ALL
  SELECT
    p.cand_oid, p.cand_name, m.member, m.roleid,
    p.depth + 1,
    p.path_oids || m.roleid,
    p.path_text || ' -> ' || (SELECT r2.rolname FROM pg_roles r2 WHERE r2.oid = m.roleid)::text,
    m.admin_option, m.inherit_option, m.set_option, m.grantor,
    (p.path_permits_inheritance AND m.inherit_option),
    (p.path_permits_set_role AND m.set_option)
  FROM paths p
  JOIN pg_auth_members m ON m.member = p.granted_oid
  WHERE NOT (m.roleid = ANY (p.path_oids))
    AND p.depth < 16
)
SELECT
  p.cand_name                                                                    AS candidate_role,
  p.depth                                                                        AS path_depth,
  p.path_text                                                                    AS path,
  (SELECT r.rolname FROM pg_roles r WHERE r.oid = p.member_oid)                  AS edge_member_role,
  (SELECT r.rolname FROM pg_roles r WHERE r.oid = p.granted_oid)                 AS edge_granted_role,
  pg_get_userbyid(p.grantor)                                                     AS edge_grantor,
  p.admin_option                                                                 AS edge_admin_option,
  p.inherit_option                                                               AS edge_inherit_option,
  p.set_option                                                                   AS edge_set_option,
  p.path_permits_inheritance,
  p.path_permits_set_role,
  (SELECT r.rolname FROM pg_roles r WHERE r.oid = p.granted_oid) LIKE 'pg\_%'    AS granted_role_is_predefined,
  (SELECT r.rolcanlogin FROM pg_roles r WHERE r.oid = p.granted_oid)             AS granted_role_can_login,
  (SELECT r.rolsuper FROM pg_roles r WHERE r.oid = p.granted_oid)                AS granted_role_is_superuser,
  (p.granted_oid = (SELECT owner_oid FROM ids))                                  AS granted_role_is_pinned_owner,
  -- Authoritative cross-check for the END role of this path.
  pg_has_role(p.cand_oid, p.granted_oid, 'MEMBER')                               AS authoritative_member,
  pg_has_role(p.cand_oid, p.granted_oid, 'USAGE')                                AS authoritative_usage,
  pg_has_role(p.cand_oid, p.granted_oid, 'SET')                                  AS authoritative_set,
  p.path_oids::text                                                              AS path_identity
FROM paths p
ORDER BY p.cand_name, p.depth, p.path_text;

-- ---------------------------------------------------------------------------
-- QUERY 5 — structured ACL evidence for the protected schema and table. One
-- row per explicit ACL entry, with grantee/grantor identity, privilege,
-- grantability and PUBLIC attribution. Empty output means both ACLs are NULL,
-- which is the pinned contract.
-- ---------------------------------------------------------------------------
SELECT
  'schema'                                                                       AS object_type,
  'supabase_migrations'                                                          AS object_identity,
  ae.grantee                                                                     AS grantee_oid,
  coalesce(pg_get_userbyid(ae.grantee), '(unknown)')                             AS grantee_name,
  (ae.grantee = 0)                                                               AS grantee_is_public,
  ae.grantor                                                                     AS grantor_oid,
  coalesce(pg_get_userbyid(ae.grantor), '(unknown)')                             AS grantor_name,
  ae.privilege_type,
  ae.is_grantable
FROM pg_namespace n, aclexplode(n.nspacl) ae
WHERE n.nspname = 'supabase_migrations'
UNION ALL
SELECT
  'table',
  'supabase_migrations.schema_migrations',
  ae.grantee,
  coalesce(pg_get_userbyid(ae.grantee), '(unknown)'),
  (ae.grantee = 0),
  ae.grantor,
  coalesce(pg_get_userbyid(ae.grantor), '(unknown)'),
  ae.privilege_type,
  ae.is_grantable
FROM pg_class c, aclexplode(c.relacl) ae
WHERE c.oid = to_regclass('supabase_migrations.schema_migrations')
ORDER BY 1, 4, 8;

COMMIT;
