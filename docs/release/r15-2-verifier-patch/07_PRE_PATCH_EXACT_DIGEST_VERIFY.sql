-- ============================================================================
-- QHUB R15.2 — 07 PRE-PATCH EXACT DIGEST VERIFY (READ-ONLY)
--
-- Authorizes the R15.2 verifier patch ONLY if:
--   * all five protected functions are bound to their exact reviewed identity AND
--     their raw body is byte-identical to one of the two reviewed encodings; AND
--   * the verifier exists at its exact zero-argument signature with no overload; AND
--   * the verifier's DIRECT ACL is exact (service_role EXECUTE without grant
--     option; PUBLIC/anon/authenticated denied; no unexpected direct grantee or
--     grant option); AND
--   * (R15.2C) NO unexpected role holds EFFECTIVE EXECUTE on the verifier.
-- Performs NO writes.
--
-- R15.2C — EFFECTIVE-PRIVILEGE CONTRACT. A role can hold EXECUTE through role
-- membership (GRANT service_role TO some_role) without ever appearing in the
-- function's direct ACL. Every role in pg_roles is therefore evaluated with
-- has_function_privilege(role_oid, verifier_oid, 'EXECUTE'), which follows
-- PostgreSQL's own privilege inheritance (nested memberships included). The only
-- approved effective executors are:
--   * the exact contract owner (the owner of public.qhub_manual_review_requests),
--   * service_role,
--   * superuser roles — displayed separately as inherent platform administrators,
--     because superusers bypass ordinary object privilege checks and cannot be
--     meaningfully denied by a function ACL.
-- No role is approved for being non-login, system-looking, name-prefixed,
-- BYPASSRLS, or absent from proacl. Any other effective executor is a STOP.
--
-- Safety: signatures are resolved with to_regprocedure(), which returns NULL for a
-- missing function instead of raising 42883. There is no text::regprocedure cast,
-- so a missing or renamed function fails closed rather than erroring. Privilege
-- evaluation uses only OID-based catalog functions (has_function_privilege with a
-- resolved OID, pg_has_role with role OIDs) — no user-defined function is ever
-- invoked, so running this file in full is safe in any state and cannot raise
-- PostgreSQL 42883.
--
-- QUERY 3 (line-ending counts) and QUERY 4 (per-role membership diagnostics) are
-- NON-AUTHORIZING diagnostics only. QUERY 2 — the LAST statement — is the sole
-- authority; act on its verdict alone.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- ---------------------------------------------------------------------------
-- QUERY 1 — Per-function exact identity and raw digest.
--
-- Expected on the current live database (applied through the CRLF channel):
--   resolved_oid          not null
--   signature_matches     true
--   overload_count        1
--   matches_lf            false
--   matches_crlf          true
--   authorized            true
--
-- An LF-applied database shows matches_lf = true instead. Any row with
-- authorized = false is unreviewed drift.
-- ---------------------------------------------------------------------------
WITH protected(signature, proname, identity_arguments, lf_digest, crlf_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf'),
    ('public.qhub_create_review_request(text,uuid,text,text,text)', 'qhub_create_review_request',
     'p_org_id text, p_project_id uuid, p_requester text, p_reason text, p_idempotency_key text',
     '6b46c3d75636fd0c8b628b34a86f4084', '349b59554232ab7f3b9e4aa3a8cc2331'),
    ('public.qhub_record_acknowledgment(text,uuid,text,text)', 'qhub_record_acknowledgment',
     'p_org_id text, p_project_id uuid, p_user_id text, p_action text',
     'b6035e9a35f5ecc49369b68000c7b2a6', '09e053d93afb7aca96064b758d76213a'),
    ('public.qhub_canon_cells(text[])', 'qhub_canon_cells',
     'p_cells text[]',
     '6151a5d4794e56fbc26fc891f8fefdb4', '2d569f42d1e95f2ffd38dc82e14d727c'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f')
),
resolved AS (
  SELECT
    k.*,
    to_regprocedure(k.signature) AS resolved_regproc,
    (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
      WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
  FROM protected k
)
SELECT
  r.signature                                                        AS expected_signature,
  r.resolved_regproc::text                                           AS resolved_signature,
  (r.resolved_regproc IS NOT NULL)                                   AS function_present,
  p.oid                                                              AS resolved_oid,
  pg_get_function_identity_arguments(p.oid)                          AS live_identity_arguments,
  r.identity_arguments                                               AS expected_identity_arguments,
  coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE) AS signature_matches,
  r.overload_count,
  md5(p.prosrc)                                                      AS live_raw_md5_prosrc,
  r.lf_digest                                                        AS approved_lf_digest,
  r.crlf_digest                                                      AS approved_crlf_digest,
  coalesce(md5(p.prosrc) = r.lf_digest, FALSE)                       AS matches_lf,
  coalesce(md5(p.prosrc) = r.crlf_digest, FALSE)                     AS matches_crlf,
  -- The per-function authorization: exact identity AND exact raw body, together.
  (r.resolved_regproc IS NOT NULL
   AND r.overload_count = 1
   AND coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE)
   AND coalesce(md5(p.prosrc) IN (r.lf_digest, r.crlf_digest), FALSE))  AS authorized
FROM resolved r
LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
ORDER BY r.proname;

-- ---------------------------------------------------------------------------
-- QUERY 3 — NON-AUTHORIZING DIAGNOSTICS ONLY.
-- Informational line-ending counts. These MUST NOT be used to authorize the
-- patch; QUERY 2 is the sole authority.
-- ---------------------------------------------------------------------------
SELECT
  p.proname,
  octet_length(p.prosrc)                                       AS prosrc_octet_length,
  (length(p.prosrc) - length(replace(p.prosrc, chr(13), '')))  AS cr_count,
  (length(p.prosrc) - length(replace(p.prosrc, chr(10), '')))  AS lf_count
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname IN ('qhub_decide_review','qhub_create_review_request',
                    'qhub_record_acknowledgment','qhub_canon_cells','qhub_row_immutable')
ORDER BY p.proname;

-- ---------------------------------------------------------------------------
-- QUERY 4 — NON-AUTHORIZING DIAGNOSTICS ONLY (R15.2C).
-- Per-role privilege picture for the verifier: direct ACL entry, effective
-- EXECUTE, and service_role membership (direct, recursive, and the membership
-- path that explains WHY a role is effective). This identifies the role graph
-- behind any unexpected effective executor. It MUST NOT be used to authorize:
-- authorization is the effective-privilege contract in QUERY 2, never role names.
-- ---------------------------------------------------------------------------
WITH RECURSIVE sr AS (
  SELECT oid FROM pg_roles WHERE rolname = 'service_role'
),
member_paths(member_oid, path) AS (
  SELECT am.member, 'service_role <- ' || pg_get_userbyid(am.member)
    FROM pg_auth_members am JOIN sr ON sr.oid = am.roleid
  UNION ALL
  SELECT am.member, mp.path || ' <- ' || pg_get_userbyid(am.member)
    FROM pg_auth_members am JOIN member_paths mp ON mp.member_oid = am.roleid
),
vobj AS (
  SELECT p.oid, p.proowner, p.proacl
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
)
SELECT
  r.rolname,
  r.oid                                                                  AS role_oid,
  r.rolcanlogin,
  r.rolinherit,
  r.rolsuper,
  (SELECT string_agg(ae.privilege_type
                     || CASE WHEN ae.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END, ', ')
     FROM vobj v, aclexplode(v.proacl) ae
    WHERE ae.grantee = r.oid)                                            AS direct_function_acl,
  coalesce((SELECT has_function_privilege(r.oid, v.oid, 'EXECUTE') FROM vobj v), FALSE)
                                                                         AS effective_execute,
  EXISTS (SELECT 1 FROM pg_auth_members am JOIN sr ON sr.oid = am.roleid
           WHERE am.member = r.oid)                                      AS direct_member_of_service_role,
  EXISTS (SELECT 1 FROM member_paths mp WHERE mp.member_oid = r.oid)     AS member_of_service_role_recursive,
  (SELECT min(mp.path) FROM member_paths mp WHERE mp.member_oid = r.oid) AS membership_path
FROM pg_roles r
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT. Act on this value alone.
--
--   SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH
--     all five protected functions carry their exact reviewed identity and a
--     reviewed raw body; the verifier exists at its exact zero-argument
--     signature with no overload; its direct ACL is exact; and no unexpected
--     role holds effective EXECUTE on it (directly, through PUBLIC, or through
--     any chain of role memberships).
--
--   UNEXPECTED_FUNCTION_BODY_STOP
--     any protected function missing, renamed, wrong argument list, overloaded,
--     or carrying an unapproved raw body — or the verifier missing, overloaded,
--     wrong-signature, carrying a non-exact direct ACL, or executable by an
--     unapproved role. STOP. Do NOT apply the patch. Escalate with QUERY 1 and
--     QUERY 4. If the cause is a role membership, note that neither this
--     package nor the operator may revoke cluster role memberships without a
--     separately reviewed plan.
-- ---------------------------------------------------------------------------
WITH protected(signature, proname, identity_arguments, lf_digest, crlf_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf'),
    ('public.qhub_create_review_request(text,uuid,text,text,text)', 'qhub_create_review_request',
     'p_org_id text, p_project_id uuid, p_requester text, p_reason text, p_idempotency_key text',
     '6b46c3d75636fd0c8b628b34a86f4084', '349b59554232ab7f3b9e4aa3a8cc2331'),
    ('public.qhub_record_acknowledgment(text,uuid,text,text)', 'qhub_record_acknowledgment',
     'p_org_id text, p_project_id uuid, p_user_id text, p_action text',
     'b6035e9a35f5ecc49369b68000c7b2a6', '09e053d93afb7aca96064b758d76213a'),
    ('public.qhub_canon_cells(text[])', 'qhub_canon_cells',
     'p_cells text[]',
     '6151a5d4794e56fbc26fc891f8fefdb4', '2d569f42d1e95f2ffd38dc82e14d727c'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f')
),
resolved AS (
  SELECT
    k.*,
    to_regprocedure(k.signature) AS resolved_regproc,
    (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
      WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
  FROM protected k
),
evaluated AS (
  SELECT
    r.proname,
    (r.resolved_regproc IS NOT NULL)                                                   AS present,
    (r.overload_count = 1)                                                             AS single_overload,
    coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE)  AS signature_ok,
    coalesce(md5(p.prosrc) IN (r.lf_digest, r.crlf_digest), FALSE)                     AS digest_ok
  FROM resolved r
  LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
),
five AS (
  SELECT
    count(*)                                                                          AS functions_expected,
    count(*) FILTER (WHERE present)                                                   AS present_count,
    count(*) FILTER (WHERE single_overload)                                           AS single_overload_count,
    count(*) FILTER (WHERE signature_ok)                                              AS signature_ok_count,
    count(*) FILTER (WHERE digest_ok)                                                 AS digest_ok_count,
    count(*) FILTER (WHERE present AND single_overload AND signature_ok AND digest_ok) AS authorized_count
  FROM evaluated
),
-- The verifier, resolved by exact signature. to_regprocedure() yields NULL when
-- absent and never raises.
vobj AS (
  SELECT p.oid, p.proowner, p.proacl
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('public.qhub_verify_commercial_schema()')
),
vident AS (
  SELECT
    ((SELECT count(*) FROM vobj) = 1)                                                 AS verifier_present,
    coalesce((SELECT pg_get_function_identity_arguments(v.oid) = '' FROM vobj v), FALSE)
                                                                                      AS verifier_zero_argument_signature,
    ((SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
       WHERE n2.nspname = 'public' AND p2.proname = 'qhub_verify_commercial_schema') = 1)
                                                                                      AS verifier_single_function
),
-- DIRECT ACL, read from proacl so grant options are visible.
vdirect AS (
  SELECT
    coalesce((SELECT count(*) = 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'service_role'), FALSE)            AS service_role_execute,
    coalesce((SELECT bool_and(NOT ae.is_grantable) FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'service_role'), FALSE)            AS service_role_no_grant_option,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE' AND ae.grantee = 0)), FALSE)       AS public_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'anon')), FALSE)                   AS anon_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND pg_get_userbyid(ae.grantee) = 'authenticated')), FALSE)          AS authenticated_denied,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.privilege_type = 'EXECUTE'
                 AND ae.grantee <> 0
                 AND ae.grantee <> v.proowner
                 AND pg_get_userbyid(ae.grantee) <> 'service_role')), FALSE)          AS no_unexpected_direct_grantee,
    coalesce((SELECT NOT EXISTS (SELECT 1 FROM vobj v, aclexplode(v.proacl) ae
               WHERE ae.is_grantable
                 AND ae.grantee <> v.proowner)), FALSE)                               AS no_unexpected_direct_grant_option
),
-- EFFECTIVE ACL (R15.2C): every pg_roles role, evaluated with the exact verifier
-- OID through PostgreSQL's own privilege inheritance. Approved: the exact
-- contract owner, service_role, and superusers (inherent platform
-- administrators). coalesce(..., FALSE) on the owner comparison keeps a missing
-- contract table fail-closed (nobody is approved as owner).
veff AS (
  SELECT
    (count(*) > 0
     AND count(*) FILTER (WHERE f.hfp AND NOT f.approved) = 0)                        AS effective_acl_ok,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp)                      AS effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND f.approved)       AS expected_effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND NOT f.approved)   AS unexpected_effective_executor_roles,
    array_agg(r.rolname ORDER BY r.rolname) FILTER (WHERE f.hfp AND r.rolsuper)       AS superuser_executor_roles
  FROM pg_roles r
  CROSS JOIN vobj v
  CROSS JOIN LATERAL (
    SELECT
      has_function_privilege(r.oid, v.oid, 'EXECUTE')                                 AS hfp,
      (r.rolsuper
       OR coalesce(r.oid = (SELECT c.relowner FROM pg_class c
                             WHERE c.oid = to_regclass('public.qhub_manual_review_requests')), FALSE)
       OR r.rolname = 'service_role')                                                 AS approved
  ) f
)
SELECT
  five.functions_expected,
  five.present_count,
  five.single_overload_count,
  five.signature_ok_count,
  five.digest_ok_count,
  five.authorized_count,
  vident.verifier_present,
  vident.verifier_zero_argument_signature,
  vident.verifier_single_function,
  (vident.verifier_present AND vident.verifier_zero_argument_signature
   AND vident.verifier_single_function)                                               AS verifier_identity_ok,
  vdirect.service_role_execute,
  vdirect.service_role_no_grant_option,
  vdirect.public_denied,
  vdirect.anon_denied,
  vdirect.authenticated_denied,
  vdirect.no_unexpected_direct_grantee,
  vdirect.no_unexpected_direct_grant_option,
  (vdirect.service_role_execute AND vdirect.service_role_no_grant_option
   AND vdirect.public_denied AND vdirect.anon_denied AND vdirect.authenticated_denied
   AND vdirect.no_unexpected_direct_grantee
   AND vdirect.no_unexpected_direct_grant_option)                                     AS direct_acl_ok,
  veff.effective_acl_ok,
  veff.effective_executor_roles,
  veff.expected_effective_executor_roles,
  veff.unexpected_effective_executor_roles,
  veff.superuser_executor_roles,
  CASE
    WHEN five.functions_expected = 5
     AND five.authorized_count = 5
     AND vident.verifier_present
     AND vident.verifier_zero_argument_signature
     AND vident.verifier_single_function
     AND vdirect.service_role_execute
     AND vdirect.service_role_no_grant_option
     AND vdirect.public_denied
     AND vdirect.anon_denied
     AND vdirect.authenticated_denied
     AND vdirect.no_unexpected_direct_grantee
     AND vdirect.no_unexpected_direct_grant_option
     AND veff.effective_acl_ok
      THEN 'SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH'
    ELSE 'UNEXPECTED_FUNCTION_BODY_STOP'
  END                                                                                 AS verdict
FROM five
CROSS JOIN vident
CROSS JOIN vdirect
CROSS JOIN veff;

COMMIT;

-- ---------------------------------------------------------------------------
-- R15.2B — the previous optional "current verifier output" query was REMOVED.
-- It invoked public.qhub_verify_commercial_schema() unconditionally, so running
-- this file in full against a database whose verifier is missing raised
-- PostgreSQL 42883 *after* the STOP verdict had already been produced. This file
-- touches pg_catalog only: it is safe to paste and run in full, in any state,
-- and it never invokes a user-defined function. The verifier's own output is
-- reported by 09_POST_PATCH_VERIFY.sql, which gates the call on catalog
-- authority (identity, owner, security, search_path, direct ACL, AND the
-- R15.2C effective-executor contract).
-- ---------------------------------------------------------------------------
