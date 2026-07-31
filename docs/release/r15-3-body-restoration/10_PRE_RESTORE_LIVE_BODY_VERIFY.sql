-- ============================================================================
-- QHUB R15.3 — 10 PRE-RESTORE LIVE BODY + ATTRIBUTE VERIFY (READ-ONLY)
--
-- Authorizes 11_RESTORE_REVIEWED_PROTECTED_BODIES.sql ONLY if BOTH protected
-- functions carry their exact reviewed identity, their exact reviewed SEMANTIC
-- ATTRIBUTE CONTRACT, their exact reviewed authority (owner / security mode /
-- search_path / ACL), AND a raw body byte-identical to the KNOWN mojibake digest
-- that is not already a reviewed body. Performs NO writes.
--
-- WHY THIS EXISTS. The 2026-07-30 manual apply moved the migration through a
-- Windows PowerShell clipboard command that read the BOM-less UTF-8 file WITHOUT
-- -Encoding UTF8. PowerShell 5.1 Get-Content then decodes as the system ANSI code
-- page (Windows-1252) and re-encodes mangled:
--     §  ->  Â§        —  ->  â€"        →  ->  â†'
-- Both affected functions carry non-ASCII ONLY inside comments, so the executable
-- text is byte-identical while the raw digest is not. Restoring the reviewed bytes
-- is the fix; the reviewed migration is correct and is NOT changed.
--
-- R15.3A — WHY THE ATTRIBUTE CONTRACT IS PART OF AUTHORIZATION.
-- CREATE OR REPLACE FUNCTION does NOT preserve omitted attribute clauses: it RESETS
-- volatility, strictness, parallel safety, leakproof and cost to their defaults
-- (independently verified: IMMUTABLE/STRICT/PARALLEL SAFE/COST 42 became
-- VOLATILE/CALLED ON NULL INPUT/PARALLEL UNSAFE/COST 100). Before R15.3A this file
-- did not bind those attributes, so a live function altered to STRICT PARALLEL SAFE
-- still returned SAFE, the restoration silently normalised it, and the postcheck
-- reported RESTORED — erasing the evidence that someone had altered a
-- SECURITY DEFINER decision function. This file now binds every pg_proc attribute
-- that can change execution, planner or authority behaviour, so such a database
-- STOPS here and is escalated rather than silently repaired.
--
-- AUTHORIZATION IS BY EXACT RAW DIGEST AND EXACT CATALOG VALUES ONLY. No
-- replace/regexp_replace/translate/trim participates in any verdict — accepting a
-- "normalized" match is exactly the withdrawn-R15.1 mistake.
--
-- Safety: identities resolve through to_regprocedure(), which returns NULL for a
-- missing function rather than raising 42883. There is no text::regprocedure cast
-- and neither target function is ever invoked, so running this file IN FULL is safe
-- in any state and cannot raise a permission error.
--
-- QUERY 1 is per-function detail. QUERY 2 — the LAST statement — is the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- ---------------------------------------------------------------------------
-- The complete reviewed contract for both targets, derived from the reviewed
-- migration against a disposable database — never guessed.
--
--   qhub_decide_review : plpgsql, prokind 'f', RETURNS jsonb, SECURITY DEFINER,
--                        search_path {pg_catalog, public}, VOLATILE,
--                        CALLED ON NULL INPUT, PARALLEL UNSAFE, NOT LEAKPROOF,
--                        not set-returning, cost 100, rows 0, no variadic,
--                        no support function, no transforms,
--                        ACL: owner + service_role EXECUTE (no grant option)
--   qhub_row_immutable : plpgsql, prokind 'f', RETURNS trigger, SECURITY INVOKER,
--                        no proconfig, VOLATILE, CALLED ON NULL INPUT,
--                        PARALLEL UNSAFE, NOT LEAKPROOF, not set-returning,
--                        cost 100, rows 0, no variadic, no support function,
--                        no transforms, ACL: NULL (the migration grants nothing)
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_lang, expect_kind, expect_rettype, expect_secdef, expect_config,
            expect_volatile, expect_strict, expect_parallel, expect_leakproof,
            expect_retset, expect_cost, expect_rows, expect_variadic, expect_default_acl,
            lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     'plpgsql', 'f', 'jsonb', TRUE, ARRAY['search_path=pg_catalog, public'],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, FALSE,
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     'plpgsql', 'f', 'trigger', FALSE, NULL::text[],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, TRUE,
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f',
     '583882c1a9b203e278b27d1080065c9e')
),
resolved AS (
  SELECT
    k.*,
    to_regprocedure(k.signature) AS resolved_regproc,
    (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
      WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
  FROM target k
),
live AS (
  SELECT r.*, p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl,
         p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.proretset,
         p.procost, p.prorows, p.provariadic, p.prosupport, p.protrftypes,
         p.prokind, p.prorettype, l.lanname
    FROM resolved r
    LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
    LEFT JOIN pg_language l ON l.oid = p.prolang
),
evaluated AS (
  SELECT
    v.*,
    (v.oid IS NOT NULL)                                                             AS function_present,
    (v.overload_count = 1)                                                          AS single_overload,
    coalesce(pg_get_function_identity_arguments(v.oid) = v.identity_arguments, FALSE) AS signature_ok,
    -- AUTHORITY
    coalesce(v.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(v.owner_table)), FALSE)
                                                                                    AS owner_ok,
    coalesce(v.prosecdef = v.expect_secdef, FALSE)                                  AS security_ok,
    coalesce(v.proconfig IS NOT DISTINCT FROM v.expect_config, FALSE)                AS search_path_ok,
    -- IDENTITY / TYPE
    coalesce(v.lanname = v.expect_lang, FALSE)                                       AS language_ok,
    coalesce(v.prokind = v.expect_kind, FALSE)                                       AS prokind_ok,
    coalesce(v.prorettype = v.expect_rettype::regtype, FALSE)                        AS rettype_ok,
    -- SEMANTIC / EXECUTION ATTRIBUTES (R15.3A)
    coalesce(v.provolatile = v.expect_volatile, FALSE)                               AS volatility_ok,
    coalesce(v.proisstrict = v.expect_strict, FALSE)                                 AS strictness_ok,
    coalesce(v.proparallel = v.expect_parallel, FALSE)                               AS parallel_ok,
    coalesce(v.proleakproof = v.expect_leakproof, FALSE)                             AS leakproof_ok,
    coalesce(v.proretset = v.expect_retset, FALSE)                                   AS retset_ok,
    coalesce(v.procost = v.expect_cost, FALSE)                                       AS cost_ok,
    coalesce(v.prorows = v.expect_rows, FALSE)                                       AS rows_ok,
    coalesce(v.provariadic = v.expect_variadic, FALSE)                               AS variadic_ok,
    coalesce(v.prosupport = 0::oid, FALSE)                                           AS no_support_function,
    (v.oid IS NOT NULL AND v.protrftypes IS NULL)                                    AS no_transforms,
    -- DIRECT ACL — the two contracts differ by design (see the runbook).
    CASE WHEN v.expect_default_acl
      THEN (v.oid IS NOT NULL AND v.proacl IS NULL)
      ELSE coalesce((SELECT count(*) = 1 FROM aclexplode(v.proacl) ae
                      WHERE ae.privilege_type = 'EXECUTE'
                        AND pg_get_userbyid(ae.grantee) = 'service_role'
                        AND NOT ae.is_grantable), FALSE)
           AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                      WHERE ae.privilege_type = 'EXECUTE'
                        AND (ae.grantee = 0
                             OR pg_get_userbyid(ae.grantee) IN ('anon','authenticated')
                             OR (ae.grantee <> v.proowner
                                 AND pg_get_userbyid(ae.grantee) <> 'service_role')))), FALSE)
           AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                      WHERE ae.is_grantable AND ae.grantee <> v.proowner)), FALSE)
    END                                                                              AS acl_ok,
    -- BODY
    coalesce(md5(v.prosrc) = v.mojibake_digest, FALSE)                               AS is_known_mojibake,
    coalesce(md5(v.prosrc) IN (v.lf_digest, v.crlf_digest), FALSE)                    AS already_reviewed
  FROM live v
),
scored AS (
  SELECT
    e.*,
    (e.function_present AND e.single_overload AND e.signature_ok
     AND e.owner_ok AND e.security_ok AND e.search_path_ok
     AND e.language_ok AND e.prokind_ok AND e.rettype_ok
     AND e.volatility_ok AND e.strictness_ok AND e.parallel_ok AND e.leakproof_ok
     AND e.retset_ok AND e.cost_ok AND e.rows_ok AND e.variadic_ok
     AND e.no_support_function AND e.no_transforms
     AND e.acl_ok)                                                                   AS attributes_ok
  FROM evaluated e
)
-- ---------------------------------------------------------------------------
-- QUERY 1 — Per-function detail. Every column below is an input to the verdict.
-- ---------------------------------------------------------------------------
SELECT
  proname,
  function_present, single_overload, signature_ok,
  owner_ok, security_ok, search_path_ok, acl_ok,
  language_ok, prokind_ok, rettype_ok,
  volatility_ok, strictness_ok, parallel_ok, leakproof_ok,
  retset_ok, cost_ok, rows_ok, variadic_ok, no_support_function, no_transforms,
  attributes_ok,
  is_known_mojibake, already_reviewed,
  (attributes_ok AND is_known_mojibake AND NOT already_reviewed)  AS restorable,
  -- live values, for escalation evidence
  lanname             AS live_language,
  prokind             AS live_prokind,
  prorettype::regtype AS live_rettype,
  provolatile         AS live_volatility,
  proisstrict         AS live_strict,
  proparallel         AS live_parallel,
  proleakproof        AS live_leakproof,
  proretset           AS live_retset,
  procost             AS live_cost,
  prorows             AS live_rows,
  pg_get_userbyid(proowner)          AS live_owner,
  proconfig::text                    AS live_search_path,
  coalesce(proacl::text, '(default)') AS live_acl,
  md5(prosrc)                        AS live_raw_md5_prosrc,
  octet_length(prosrc)               AS live_bytes
FROM scored
ORDER BY proname;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT. Act on this value alone.
--
--   SAFE_TO_RESTORE_REVIEWED_BODIES
--     both functions carry the exact reviewed identity, semantic attribute
--     contract and authority, and both bodies are the KNOWN mojibake and neither
--     reviewed digest. Only the comment bytes need repair.
--
--   UNEXPECTED_LIVE_BODY_STOP
--     anything else. Three distinct causes, which the runbook keeps separate:
--       * already_reviewed_count > 0 — restoration already ran; go to 12.
--       * attributes_ok = false      — an attribute/authority drift. STOP and
--                                      ESCALATE. Do NOT run 11: it would reset the
--                                      drifted attribute and destroy the evidence.
--       * a third unknown body       — unexplained drift. STOP and escalate.
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_lang, expect_kind, expect_rettype, expect_secdef, expect_config,
            expect_volatile, expect_strict, expect_parallel, expect_leakproof,
            expect_retset, expect_cost, expect_rows, expect_variadic, expect_default_acl,
            lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     'plpgsql', 'f', 'jsonb', TRUE, ARRAY['search_path=pg_catalog, public'],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, FALSE,
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     'plpgsql', 'f', 'trigger', FALSE, NULL::text[],
     'v', FALSE, 'u', FALSE,
     FALSE, 100::real, 0::real, 0::oid, TRUE,
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f',
     '583882c1a9b203e278b27d1080065c9e')
),
resolved AS (
  SELECT
    k.*,
    to_regprocedure(k.signature) AS resolved_regproc,
    (SELECT count(*) FROM pg_proc p2 JOIN pg_namespace n2 ON n2.oid = p2.pronamespace
      WHERE n2.nspname = 'public' AND p2.proname = k.proname) AS overload_count
  FROM target k
),
live AS (
  SELECT r.*, p.oid, p.proowner, p.prosecdef, p.proconfig, p.prosrc, p.proacl,
         p.provolatile, p.proisstrict, p.proparallel, p.proleakproof, p.proretset,
         p.procost, p.prorows, p.provariadic, p.prosupport, p.protrftypes,
         p.prokind, p.prorettype, l.lanname
    FROM resolved r
    LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
    LEFT JOIN pg_language l ON l.oid = p.prolang
),
evaluated AS (
  SELECT
    v.proname,
    (v.oid IS NOT NULL
     AND v.overload_count = 1
     AND coalesce(pg_get_function_identity_arguments(v.oid) = v.identity_arguments, FALSE)
     AND coalesce(v.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(v.owner_table)), FALSE)
     AND coalesce(v.prosecdef = v.expect_secdef, FALSE)
     AND coalesce(v.proconfig IS NOT DISTINCT FROM v.expect_config, FALSE)
     AND coalesce(v.lanname = v.expect_lang, FALSE)
     AND coalesce(v.prokind = v.expect_kind, FALSE)
     AND coalesce(v.prorettype = v.expect_rettype::regtype, FALSE)
     AND coalesce(v.provolatile = v.expect_volatile, FALSE)
     AND coalesce(v.proisstrict = v.expect_strict, FALSE)
     AND coalesce(v.proparallel = v.expect_parallel, FALSE)
     AND coalesce(v.proleakproof = v.expect_leakproof, FALSE)
     AND coalesce(v.proretset = v.expect_retset, FALSE)
     AND coalesce(v.procost = v.expect_cost, FALSE)
     AND coalesce(v.prorows = v.expect_rows, FALSE)
     AND coalesce(v.provariadic = v.expect_variadic, FALSE)
     AND coalesce(v.prosupport = 0::oid, FALSE)
     AND (v.oid IS NOT NULL AND v.protrftypes IS NULL)
     AND CASE WHEN v.expect_default_acl
           THEN (v.oid IS NOT NULL AND v.proacl IS NULL)
           ELSE coalesce((SELECT count(*) = 1 FROM aclexplode(v.proacl) ae
                           WHERE ae.privilege_type = 'EXECUTE'
                             AND pg_get_userbyid(ae.grantee) = 'service_role'
                             AND NOT ae.is_grantable), FALSE)
                AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                           WHERE ae.privilege_type = 'EXECUTE'
                             AND (ae.grantee = 0
                                  OR pg_get_userbyid(ae.grantee) IN ('anon','authenticated')
                                  OR (ae.grantee <> v.proowner
                                      AND pg_get_userbyid(ae.grantee) <> 'service_role')))), FALSE)
                AND coalesce((SELECT NOT EXISTS (SELECT 1 FROM aclexplode(v.proacl) ae
                           WHERE ae.is_grantable AND ae.grantee <> v.proowner)), FALSE)
         END)                                                                        AS attributes_ok,
    coalesce(md5(v.prosrc) = v.mojibake_digest, FALSE)                               AS is_known_mojibake,
    coalesce(md5(v.prosrc) IN (v.lf_digest, v.crlf_digest), FALSE)                    AS already_reviewed
  FROM live v
)
SELECT
  count(*)                                                                      AS functions_expected,
  count(*) FILTER (WHERE attributes_ok)                                         AS attributes_ok_count,
  count(*) FILTER (WHERE is_known_mojibake)                                     AS known_mojibake_count,
  count(*) FILTER (WHERE already_reviewed)                                      AS already_reviewed_count,
  count(*) FILTER (WHERE attributes_ok AND is_known_mojibake AND NOT already_reviewed)
                                                                                AS restorable_count,
  CASE
    WHEN count(*) = 2
     AND count(*) FILTER (WHERE attributes_ok AND is_known_mojibake AND NOT already_reviewed) = 2
      THEN 'SAFE_TO_RESTORE_REVIEWED_BODIES'
    ELSE 'UNEXPECTED_LIVE_BODY_STOP'
  END                                                                           AS verdict
FROM evaluated;

COMMIT;
