-- ============================================================================
-- QHUB R15.6.5 — READ-ONLY MANAGED-ROLE ACCESS DIAGNOSTIC (second correction)
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
-- CORRECTION 1 (R15.6.4, retained): MEMBER != USAGE != SET.
--
-- PostgreSQL 16 records three independent facts per membership, verified here
-- against a live PostgreSQL 16 and against actual SET ROLE attempts:
--
--   membership (GRANT r TO c WITH ...)  MEMBER  USAGE  SET   priv?  SET ROLE?
--   INHERIT FALSE, SET FALSE              t       f      f     no     DENIED
--   INHERIT FALSE, SET TRUE               t       f      t     no     OK
--   INHERIT TRUE,  SET FALSE              t       t      f     yes    DENIED
--   INHERIT TRUE,  SET TRUE               t       t      t     yes    OK
--   ADMIN TRUE, INHERIT/SET FALSE         t       f      f     no     DENIED
--
-- MEMBER alone is an INACTIVE membership: it confers no privilege and no SET
-- ROLE authority. ADMIN OPTION confers neither either — it only permits
-- re-granting the membership. The word "settable" is used ONLY for roles the
-- candidate may actually SET ROLE to.
--
-- CORRECTION 2 (R15.6.5, this revision) — three defects found by the second
-- independent review:
--
--   (a) COMPLETE PATH ENUMERATION. The previous revision silently truncated
--       membership paths at depth 16. PostgreSQL accepts longer chains, and a
--       17-edge route with full USAGE and SET authority was proven to vanish
--       from the path output while Queries 2 and 3 still showed the privilege.
--       The fixed depth cutoff is REMOVED. Recursion now terminates only
--       through cycle prevention: a role already on the path is never
--       revisited, so every enumerated path is a simple path and the recursion
--       is finite — bounded by the (finite) number of roles in the cluster,
--       not by an arbitrary constant. PostgreSQL itself refuses circular role
--       grants, so the membership graph is acyclic and the no-repeat rule is a
--       belt-and-suspenders guarantee, not a semantic filter. Every finite,
--       cycle-free path relevant to a candidate is emitted; nothing is
--       truncated, and there is no truncation to warn about.
--
--   (b) REACHABILITY-GATED ATTRIBUTION. The previous revision could report
--       via_explicit_acl = true when the ACL belonged to a holder the
--       candidate could NOT reach (an inactive, MEMBER-only membership). An
--       explicit ACL is now attributed as an EFFECTIVE route only when the
--       holder is the candidate itself, reachable through USAGE, or reachable
--       through SET; an ACL behind an inactive membership is reported
--       separately as membership evidence, never as access. The same rule is
--       applied to owner-route and predefined-role attribution. PUBLIC
--       attribution is independent of role membership and stays independent.
--       Additionally, inactive_membership_only is now true ONLY when inactive
--       membership evidence exists AND no direct/self, USAGE, or SET route
--       exists for that candidate/privilege; when active and inactive routes
--       coexist, both kinds of evidence are reported side by side.
--
--   (c) ACTUAL OWNERS, NOT THE PINNED OWNER. Owner-route attribution now
--       compares holders against the ACTUAL owner of each protected object
--       (the schema's nspowner for schema privileges, the table's relowner for
--       table privileges). The pinned contract owner is reported separately,
--       with explicit conformity flags, so effective access remains visible
--       when the actual owners and the pinned owner differ.
--
-- ROLE VALIDITY. rolvaliduntil bounds PASSWORD AUTHENTICATION only. An expired
-- LOGIN role still holds every catalog-defined membership and object
-- privilege; expiry is NOT evidence that an access path is harmless, so no
-- reachability fact in this file depends on the validity columns. rolpassword
-- is never read.
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
--   QUERY 1 — protected-object identity, actual owners, pinned-owner
--             conformity.
--   QUERY 2 — candidate inventory: attributes, validity, and the three
--             separated reachability facts.
--   QUERY 3 — per-privilege route evidence with reachability-gated
--             attribution (explicit ACL, actual object owner, predefined
--             role, PUBLIC — each split by how the holder is reached).
--   QUERY 4 — membership PATHS: every direct and transitive route with
--             per-edge admin/inherit/set options, depth, deterministic path
--             identity, and whether that specific path permits inheritance /
--             SET ROLE. No depth cutoff.
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
-- QUERY 1 — the protected objects: exact ACTUAL owners, explicit ACLs, RLS
-- state, the pinned contract owner, and whether the actual owners conform to
-- it. Actual ownership and expected ownership are separate facts.
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
  (SELECT n.nspowner = (SELECT c.relowner FROM pg_class c
      WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))
     FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')                AS schema_owner_matches_pinned_contract_owner,
  (SELECT t.relowner = (SELECT c.relowner FROM pg_class c
      WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))
     FROM pg_class t
    WHERE t.oid = to_regclass('supabase_migrations.schema_migrations'))          AS table_owner_matches_pinned_contract_owner,
  (SELECT n.nspowner = (SELECT t.relowner FROM pg_class t
      WHERE t.oid = to_regclass('supabase_migrations.schema_migrations'))
     FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')                AS schema_owner_matches_table_owner,
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
--   privileges_via_set_role            — the candidate MAY SET ROLE
--       (pg_has_role ... 'SET') to a role that holds access.
--   inactive_memberships_with_access   — memberships that EXIST (MEMBER) to
--       roles that hold access, but confer neither inheritance nor SET ROLE.
--       Evidence only: these are NOT access.
-- reaches_protected_objects is true only for the first two.
--
-- Owner exposure is reported against the PINNED contract owner AND against the
-- ACTUAL schema and table owners, separately — they can differ, and effective
-- access must remain visible when they do.
--
-- ROLE VALIDITY columns describe password-authentication validity ONLY. An
-- expired role keeps all catalog authority; nothing here gates on validity.
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT
    (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')   AS nsp_oid,
    (SELECT n.nspowner FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')
                                                                                 AS schema_owner_oid,
    to_regclass('supabase_migrations.schema_migrations')                         AS rel_oid,
    (SELECT t.relowner FROM pg_class t
      WHERE t.oid = to_regclass('supabase_migrations.schema_migrations'))        AS table_owner_oid,
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
  -- ROLE VALIDITY (password authentication only — never a reachability input).
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
  -- PINNED contract owner: SET authority and inheritance reported separately.
  EXISTS (SELECT 1 FROM ids i WHERE pg_has_role(c.oid, i.owner_oid, 'SET'))      AS can_set_role_to_pinned_owner,
  EXISTS (SELECT 1 FROM ids i WHERE pg_has_role(c.oid, i.owner_oid, 'USAGE'))    AS inherits_from_pinned_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE pg_has_role(c.oid, i.owner_oid, 'MEMBER')
             AND NOT pg_has_role(c.oid, i.owner_oid, 'USAGE')
             AND NOT pg_has_role(c.oid, i.owner_oid, 'SET'))                     AS inactive_membership_of_pinned_owner,
  -- ACTUAL owners of the protected objects (may differ from the pinned owner).
  (c.oid = (SELECT i.schema_owner_oid FROM ids i))                               AS is_actual_schema_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE i.schema_owner_oid <> c.oid
             AND pg_has_role(c.oid, i.schema_owner_oid, 'SET'))                  AS can_set_role_to_schema_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE i.schema_owner_oid <> c.oid
             AND pg_has_role(c.oid, i.schema_owner_oid, 'USAGE'))                AS inherits_from_schema_owner,
  (c.oid = (SELECT i.table_owner_oid FROM ids i))                                AS is_actual_table_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE i.table_owner_oid <> c.oid
             AND pg_has_role(c.oid, i.table_owner_oid, 'SET'))                   AS can_set_role_to_table_owner,
  EXISTS (SELECT 1 FROM ids i
           WHERE i.table_owner_oid <> c.oid
             AND pg_has_role(c.oid, i.table_owner_oid, 'USAGE'))                 AS inherits_from_table_owner,
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
--   inactive_membership_evidence_present — some holder is reachable only as an
--       inactive membership (raw evidence, NOT access)
--   inactive_membership_only — inactive evidence exists AND no direct/self,
--       USAGE, or SET route exists. NEVER true when an active route coexists.
--
-- ATTRIBUTION IS REACHABILITY-GATED. Every attribution family is split by HOW
-- the supplying holder is reached: as the candidate itself / through USAGE
-- (no SET ROLE needed), through SET ROLE, or not at all (inactive membership —
-- evidence, never access):
--   explicit_acl_*      — the holder carries an explicit ACL entry for this
--                         exact privilege on this exact object
--   via_object_owner_*  — the holder IS the actual owner of THIS object
--                         (schema owner for schema rows, table owner for table
--                         rows; the pinned owner is a separate fact)
--   via_predefined_role_* — the holder is a pg_* predefined role
-- via_public_grant depends only on the object ACL, not on membership, and is
-- attributed independently.
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT
    (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')   AS nsp_oid,
    (SELECT n.nspowner FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')
                                                                                 AS schema_owner_oid,
    to_regclass('supabase_migrations.schema_migrations')                         AS rel_oid,
    (SELECT t.relowner FROM pg_class t
      WHERE t.oid = to_regclass('supabase_migrations.schema_migrations'))        AS table_owner_oid,
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
-- Explicit ACL entries on the protected objects, decomposed once.
aclmap AS (
  SELECT 'schema'::text AS object_kind, ae.grantee, ae.privilege_type
    FROM pg_namespace n, aclexplode(n.nspacl) ae
   WHERE n.nspname = 'supabase_migrations'
  UNION ALL
  SELECT 'table'::text, ae.grantee, ae.privilege_type
    FROM pg_class c, aclexplode(c.relacl) ae
   WHERE c.oid = to_regclass('supabase_migrations.schema_migrations')
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
       AND NOT pg_has_role(c.oid, h.oid, 'SET'))                                 AS inactive_member,
    (h.oid = CASE h.object_kind WHEN 'schema' THEN i.schema_owner_oid
                                ELSE i.table_owner_oid END)                      AS holder_is_object_owner,
    EXISTS (SELECT 1 FROM aclmap a
             WHERE a.object_kind = h.object_kind AND a.grantee = h.oid
               AND a.privilege_type = h.priv)                                    AS holder_has_explicit_acl
  FROM cand c
  JOIN holder h ON TRUE
  CROSS JOIN ids i
)
SELECT
  r.cand_name                                                                    AS candidate_role,
  r.object_kind,
  r.priv                                                                         AS privilege,
  bool_or(r.is_self OR r.inherited)                                              AS usable_without_set_role,
  bool_or(r.settable)                                                            AS reachable_via_set_role,
  bool_or(r.inactive_member)                                                     AS inactive_membership_evidence_present,
  (bool_or(r.inactive_member)
   AND NOT bool_or(r.is_self OR r.inherited)
   AND NOT bool_or(r.settable))                                                  AS inactive_membership_only,
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
  bool_or(r.inactive_member AND r.holder_name LIKE 'pg\_%')                      AS via_predefined_role_inactive_membership,
  -- ACTUAL owner of THIS object; the pinned owner is a separate, labelled fact.
  (SELECT CASE r.object_kind WHEN 'schema' THEN pg_get_userbyid(i.schema_owner_oid)
                             ELSE pg_get_userbyid(i.table_owner_oid) END
     FROM ids i)                                                                 AS object_owner_role,
  (SELECT CASE r.object_kind WHEN 'schema' THEN i.schema_owner_oid = i.owner_oid
                             ELSE i.table_owner_oid = i.owner_oid END
     FROM ids i)                                                                 AS object_owner_is_pinned_contract_owner,
  bool_or(r.holder_is_object_owner AND (r.is_self OR r.inherited))               AS via_object_owner_usable_without_set_role,
  bool_or(r.holder_is_object_owner AND r.settable)                               AS via_object_owner_reachable_via_set_role,
  bool_or(r.holder_is_object_owner AND r.inactive_member)                        AS via_object_owner_inactive_membership,
  bool_or(r.holder_has_explicit_acl AND (r.is_self OR r.inherited))              AS explicit_acl_usable_without_set_role,
  bool_or(r.holder_has_explicit_acl AND r.settable)                              AS explicit_acl_reachable_via_set_role,
  bool_or(r.holder_has_explicit_acl AND r.inactive_member)                       AS explicit_acl_inactive_membership_evidence,
  EXISTS (SELECT 1 FROM aclmap a
           WHERE a.object_kind = r.object_kind AND a.grantee = 0
             AND a.privilege_type = r.priv)                                      AS via_public_grant
FROM routed r
WHERE r.is_self OR r.inherited OR r.settable OR r.inactive_member
GROUP BY r.cand_oid, r.cand_name, r.object_kind, r.priv, r.ord
ORDER BY r.cand_name, r.ord;

-- ---------------------------------------------------------------------------
-- QUERY 4 — membership PATHS. Every direct and transitive route from a
-- candidate to a granted role, with each edge's options and the path-level
-- consequences. Conflicting paths are NOT collapsed: each path is its own row,
-- so a candidate reachable by both an inheriting and a non-inheriting path
-- shows both.
--
-- COMPLETENESS. There is NO depth cutoff. Recursion terminates only through
-- cycle prevention: a role already on the path is never revisited, so every
-- path is a simple path and the recursion is finite (bounded by the number of
-- roles, which is finite). PostgreSQL refuses circular role grants, so the
-- membership graph is acyclic and the no-repeat rule cannot exclude a real
-- route: a path revisiting a role would add no authority a shorter path does
-- not already carry. Every finite, cycle-free path is emitted.
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
ORDER BY p.cand_name, p.depth, p.path_text, p.path_oids::text,
         pg_get_userbyid(p.grantor), p.admin_option, p.inherit_option, p.set_option;

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
