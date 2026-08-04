-- ============================================================================
-- QHUB R15.6.6 — BOUNDED READ-ONLY MANAGED-ROLE ACCESS DIAGNOSTIC
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
--   (a) MEMBERSHIP EVIDENCE (superseded by CORRECTION 3 below — see it for the
--       current, bounded design). R15.6.4 truncated membership paths at depth
--       16, hiding a real 17-edge route; R15.6.5 removed the cutoff and
--       enumerated every simple path instead.
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
-- ---------------------------------------------------------------------------
-- CORRECTION 3 (R15.6.6, this revision) — EXHAUSTIVE SIMPLE-PATH ENUMERATION
-- IS OPERATIONALLY UNSAFE AND HAS BEEN WITHDRAWN.
--
-- R15.6.5 emitted one row per distinct simple membership path. That is
-- exponential in the shape of the role graph, not merely large. On a modest
-- disposable fixture of 33 roles and 116 membership edges (one login role
-- feeding eight fully connected layers of four roles), the number of simple
-- paths is exactly sum(4^k) for k = 1..8 = 87,380 — and that is with a maximum
-- depth of only 8. A live role graph of unknown shape could expand far
-- further. Running that against a production database would be irresponsible
-- regardless of how complete the answer is.
--
-- Completeness of *paths* and bounded resource use on an arbitrary graph
-- cannot both be guaranteed. This revision therefore withdraws the path
-- enumeration entirely and replaces it with a bounded evidence model. There is
-- NO recursion anywhere in this file, no path array, no path text, no depth
-- counter, no outer LIMIT, no truncation and no heuristic preflight.
--
-- WHY THE BOUNDED MODEL IS STILL COMPLETE EVIDENCE. What a reviewer must be
-- able to establish is not "by which of the many alternative routes could this
-- role arrive", but "what can this role actually do, and which grants produce
-- that". Those questions are answered exactly by the combination of:
--   * QUERY 4 — the COMPLETE direct-edge inventory: every row of
--     pg_auth_members exactly once, with grantor and all three options. Any
--     multi-step route is a composition of these edges, so no grant that could
--     contribute to any route is missing.
--   * QUERY 5 — AUTHORITATIVE reachability per (candidate, role) pair computed
--     by PostgreSQL itself: pg_has_role MEMBER / USAGE / SET. These already
--     account for every transitive route of any depth, without enumerating
--     them. If any route of any length confers inheritance, USAGE is true; if
--     any confers SET ROLE, SET is true.
--   * QUERY 3 — effective privilege checks (has_schema_privilege /
--     has_table_privilege) with reachability-gated attribution, plus direct/
--     self authority reported separately.
--   * QUERIES 1 and 6 — structured owner and ACL evidence.
-- An effective privilege can therefore never disappear because alternative
-- path rows were removed: no reachability or privilege fact in this file was
-- ever derived from the enumerated paths — they were illustrative detail.
--
-- WORST-CASE ROW BOUND (exact, polynomial; R = roles, C = candidates,
-- E = pg_auth_members rows, A = explicit ACL entries on the two objects):
--   QUERY 1: exactly 1
--   QUERY 2: exactly C
--   QUERY 3: at most 9 * C          (9 privileges)
--   QUERY 4: exactly E              (one row per membership edge)
--   QUERY 5: at most C * R
--   QUERY 6: exactly A
--   TOTAL:   1 + C + 9C + E + C*R + A  =  O(C*R + E + A)
-- For the 33-role / 116-edge fixture above this is a few hundred rows instead
-- of 87,380, and the bound holds for ANY graph shape because no result set
-- depends on the number of distinct routes.
--
-- A conservative transaction-local statement_timeout is set below as defense
-- in depth. It is NOT the protection — the query shapes are. Read the
-- COMPLETENESS CONTRACT below before relying on any output.
--
-- ---------------------------------------------------------------------------
-- COMPLETENESS CONTRACT — WHAT COUNTS AS A VALID RUN.
--
-- SET LOCAL statement_timeout = '120s' is TRANSACTION-LOCAL, and PostgreSQL
-- applies it SEPARATELY TO EACH SUBSEQUENT STATEMENT. The six-result-set
-- script is therefore NOT limited to 120 seconds in total: each query gets its
-- own 120-second allowance. A later query can time out after earlier result
-- sets have already been returned to the client, leaving earlier result tabs
-- visible in the SQL editor.
--
-- THOSE PARTIAL RESULTS ARE NOT A DIAGNOSTIC 28 EVIDENCE PACKAGE. Any of the
-- following invalidates the entire run: a statement timeout, any SQL error,
-- connection loss, cancellation, transaction abort, a missing result set, or
-- incomplete result transmission. After any such failure no partial output may
-- be used for authorization or for any conclusion about a role. A complete new
-- run of the exact reviewed artifact must succeed from the beginning, and only
-- then may its results be evaluated.
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
-- OUTPUT: six deterministic, ordered result sets.
--   QUERY 1 — protected-object identity, actual owners, pinned-owner
--             conformity.
--   QUERY 2 — candidate inventory: attributes, validity, and the three
--             separated reachability facts.
--   QUERY 3 — per-privilege route evidence with reachability-gated
--             attribution (explicit ACL, actual object owner, predefined
--             role, PUBLIC — each split by how the holder is reached).
--   QUERY 4 — membership EDGE INVENTORY: every direct pg_auth_members edge
--             exactly once, with grantor and all three options. Not paths.
--   QUERY 5 — authoritative ROLE REACHABILITY per (candidate, role):
--             pg_has_role MEMBER / USAGE / SET, which already account for
--             every transitive route without enumerating any.
--   QUERY 6 — structured ACL evidence for the protected schema and table.
-- Run the file IN FULL and read all six. Capture every row verbatim.
--
-- NOTE ON NAMING: no result set or column in this file claims to contain
-- complete paths, all routes, or equivalent. QUERY 4 is an EDGE inventory and
-- QUERY 5 is a REACHABILITY summary. Neither asserts by which route authority
-- arrives, only which grants exist and what PostgreSQL says the candidate can
-- actually do.
--
-- ORDERING AUDIT (every result set is a TOTAL order over its own rows):
--   QUERY 1  single row — nothing to order.
--   QUERY 2  (reaches_protected_objects DESC, rolname). One row per candidate
--            role; rolname is UNIQUE in pg_authid, so it alone breaks all ties.
--   QUERY 3  (candidate_role, ord). Grouped by (cand_oid, object_kind, priv,
--            ord); ord is a 1:1 label for the nine (object_kind, privilege)
--            pairs, so (role, ord) is unique per group.
--   QUERY 4  (member name, granted name, grantor, member, roleid). The last
--            three are exactly pg_auth_members' unique key (roleid, member,
--            grantor), so the order is total by construction.
--   QUERY 5  (candidate_role, related_role). One row per pair of unique names.
--   QUERY 6  see the proof of totality above QUERY 6 — corrected in R15.6.7,
--            it was the one result set with a real tie.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SET LOCAL search_path = pg_catalog;
-- Defense in depth only. Every result set below is bounded by construction;
-- this exists so an unforeseen catalog pathology cannot pin a live server.
SET LOCAL statement_timeout = '120s';

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
-- QUERY 4 — MEMBERSHIP EDGE INVENTORY. Every direct pg_auth_members edge in
-- the cluster, exactly once. This is a flat catalog read: no recursion, no
-- path array, no depth, no traversal of any kind.
--
-- ROW BOUND: exactly one row per pg_auth_members row (E). It cannot grow with
-- the number of alternative routes because it never considers routes.
--
-- WHY THIS IS SUFFICIENT. Every multi-step route, of any depth, is a
-- composition of these edges. Publishing all of them means no grant that could
-- participate in any route is missing, while the AUTHORITATIVE answer to "does
-- some route actually confer inheritance / SET ROLE" is given per (candidate,
-- role) by QUERY 5 without enumerating the routes themselves.
--
--   edge_admin_option   — permits re-granting the membership. NOT authority.
--   edge_inherit_option — this edge would carry inherited privileges.
--   edge_set_option     — this edge would permit SET ROLE.
-- An edge's options describe THAT GRANT only. Whether the candidate ends up
-- with the authority depends on the whole graph, which is why the per-edge
-- options are never combined here into a reachability claim.
-- ---------------------------------------------------------------------------
WITH ids AS (
  SELECT
    (SELECT n.nspowner FROM pg_namespace n WHERE n.nspname = 'supabase_migrations')
                                                                                 AS schema_owner_oid,
    (SELECT t.relowner FROM pg_class t
      WHERE t.oid = to_regclass('supabase_migrations.schema_migrations'))        AS table_owner_oid,
    (SELECT c.relowner FROM pg_class c
      WHERE c.oid = to_regclass('public.qhub_manual_review_requests'))           AS owner_oid
)
SELECT
  m.member                                                                       AS edge_member_oid,
  mr.rolname                                                                     AS edge_member_role,
  m.roleid                                                                       AS edge_granted_oid,
  gr.rolname                                                                     AS edge_granted_role,
  m.grantor                                                                      AS edge_grantor_oid,
  gt.rolname                                                                     AS edge_grantor,
  m.admin_option                                                                 AS edge_admin_option,
  m.inherit_option                                                               AS edge_inherit_option,
  m.set_option                                                                   AS edge_set_option,
  -- Context flags so a reviewer can locate the interesting edges directly.
  (NOT mr.rolsuper
   AND mr.oid IS DISTINCT FROM i.owner_oid
   AND (mr.rolcanlogin OR mr.rolname IN ('anon', 'authenticated', 'service_role')))
                                                                                 AS member_is_candidate,
  mr.rolcanlogin                                                                 AS member_can_login,
  gr.rolname LIKE 'pg\_%'                                                        AS granted_role_is_predefined,
  gr.rolcanlogin                                                                 AS granted_role_can_login,
  gr.rolsuper                                                                    AS granted_role_is_superuser,
  (m.roleid = i.owner_oid)                                                       AS granted_role_is_pinned_owner,
  (m.roleid = i.schema_owner_oid)                                                AS granted_role_is_schema_owner,
  (m.roleid = i.table_owner_oid)                                                 AS granted_role_is_table_owner
FROM pg_auth_members m
JOIN pg_roles mr ON mr.oid = m.member
JOIN pg_roles gr ON gr.oid = m.roleid
LEFT JOIN pg_roles gt ON gt.oid = m.grantor
CROSS JOIN ids i
ORDER BY mr.rolname, gr.rolname, m.grantor, m.member, m.roleid;

-- ---------------------------------------------------------------------------
-- QUERY 5 — ROLE REACHABILITY (authoritative, computed by PostgreSQL).
--
-- One row per (candidate, related role) pair. `related` means PostgreSQL
-- reports a membership relationship, or the role is one of the identities the
-- gate cares about (pinned contract owner, actual schema owner, actual table
-- owner, any superuser) so that a NEGATIVE answer is visible too.
--
-- ROW BOUND: at most C * R. No route enumeration, so graph density cannot
-- change the row count — only the number of roles can.
--
-- pg_has_role already accounts for EVERY transitive route of any depth:
--   membership_exists                     — pg_has_role(..., 'MEMBER')
--   privileges_inherited_without_set_role — pg_has_role(..., 'USAGE')
--   set_role_permitted                    — pg_has_role(..., 'SET')
-- If ANY route of ANY length confers inheritance, USAGE is true; if any
-- confers SET ROLE, SET is true. An inactive membership (MEMBER without either)
-- is therefore exactly a relationship that no route activates.
--
-- direct_edge_count / distinct_edge_option_shapes report how many DIRECT
-- grants exist between the pair, so a candidate holding two conflicting direct
-- grants to one role stays visible without enumerating alternatives.
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
)
SELECT
  c.rolname                                                                      AS candidate_role,
  r.rolname                                                                      AS related_role,
  pg_has_role(c.oid, r.oid, 'MEMBER')                                            AS membership_exists,
  pg_has_role(c.oid, r.oid, 'USAGE')                                             AS privileges_inherited_without_set_role,
  pg_has_role(c.oid, r.oid, 'SET')                                               AS set_role_permitted,
  (pg_has_role(c.oid, r.oid, 'MEMBER')
   AND NOT pg_has_role(c.oid, r.oid, 'USAGE')
   AND NOT pg_has_role(c.oid, r.oid, 'SET'))                                     AS inactive_membership_only,
  (SELECT count(*) FROM pg_auth_members m
    WHERE m.member = c.oid AND m.roleid = r.oid)                                 AS direct_edge_count,
  (SELECT count(DISTINCT (m.admin_option, m.inherit_option, m.set_option))
     FROM pg_auth_members m
    WHERE m.member = c.oid AND m.roleid = r.oid)                                 AS distinct_direct_edge_option_shapes,
  r.rolname LIKE 'pg\_%'                                                         AS related_role_is_predefined,
  r.rolcanlogin                                                                  AS related_role_can_login,
  r.rolsuper                                                                     AS related_role_is_superuser,
  (r.oid = i.owner_oid)                                                          AS related_role_is_pinned_owner,
  (r.oid = i.schema_owner_oid)                                                   AS related_role_is_schema_owner,
  (r.oid = i.table_owner_oid)                                                    AS related_role_is_table_owner,
  (has_schema_privilege(r.oid, i.nsp_oid, 'USAGE, CREATE')
   OR has_table_privilege(r.oid, i.rel_oid,
        'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'))        AS related_role_holds_protected_privilege
FROM cand c
CROSS JOIN pg_roles r
CROSS JOIN ids i
WHERE r.oid <> c.oid
  AND (pg_has_role(c.oid, r.oid, 'MEMBER')
       OR r.rolsuper
       OR r.oid IN (i.owner_oid, i.schema_owner_oid, i.table_owner_oid))
ORDER BY c.rolname, r.rolname;

-- ---------------------------------------------------------------------------
-- QUERY 6 — structured ACL evidence for the protected schema and table. One
-- row per explicit ACL entry, with grantee/grantor identity, privilege,
-- grantability and PUBLIC attribution. Empty output means both ACLs are NULL,
-- which is the pinned contract.
--
-- ORDERING (corrected). The previous ordering was (object_type, grantee_name,
-- privilege_type), which left a genuine tie: the SAME grantee can hold the SAME
-- privilege on the SAME object from TWO DIFFERENT grantors, and PostgreSQL 16
-- emits both as separate aclexplode rows. Two semantically distinct rows could
-- therefore appear in an unspecified relative order.
--
-- The ordering is now total over stable catalog identities, with OIDs — not
-- display names — as the decisive tie-breakers:
--   object_type, object_oid, object_schema, object_identity,
--   grantee_oid, privilege_type, grantor_oid, is_grantable
-- Names are emitted for readability but never decide an ordering.
--
-- PROOF OF TOTALITY. A PostgreSQL ACL is an aclitem[] in which each entry is
-- keyed by (grantee, grantor): re-granting the same privilege from the same
-- grantor updates the existing entry rather than appending one, and raising a
-- privilege to WITH GRANT OPTION flips that entry's goption bit rather than
-- adding a row. aclexplode emits one row per privilege bit of each entry, so
-- (object, grantee, grantor, privilege_type) is UNIQUE — verified on
-- PostgreSQL 16, including the two-distinct-grantor case, the re-grant case
-- and the mixed-grant-option case. Ordering by all four components is
-- therefore a total order over semantically distinct rows, and is_grantable
-- (functionally determined by that key) is appended for completeness. No
-- ordinality discriminator is required.
-- ---------------------------------------------------------------------------
SELECT
  'schema'                                                                       AS object_type,
  (SELECT n2.oid FROM pg_namespace n2 WHERE n2.nspname = 'supabase_migrations')   AS object_oid,
  'supabase_migrations'                                                          AS object_schema,
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
  to_regclass('supabase_migrations.schema_migrations')::oid,
  'supabase_migrations',
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
ORDER BY 1, 2, 3, 4, 5, 10, 8, 11;

COMMIT;
