-- ============================================================================
-- QHUB R15.3 — 10 PRE-RESTORE LIVE BODY VERIFY (READ-ONLY)
--
-- Authorizes 11_RESTORE_REVIEWED_PROTECTED_BODIES.sql ONLY if the two protected
-- functions are bound to their exact reviewed identity AND their raw body is
-- byte-identical to the KNOWN mojibake digest produced by the 2026-07-30 legacy
-- transfer — and is NOT already a reviewed body. Performs NO writes.
--
-- WHY THIS EXISTS. The 2026-07-30 manual apply moved the migration through a
-- Windows PowerShell clipboard command that read the BOM-less UTF-8 file WITHOUT
-- -Encoding UTF8. PowerShell 5.1 Get-Content then decodes as the system ANSI code
-- page (Windows-1252), so every UTF-8 sequence was re-encoded mangled:
--     §  ->  Â§        —  ->  â€"        →  ->  â†'
-- Exactly two protected functions contain non-ASCII characters, and both carry
-- them ONLY inside comments, so the executable text is byte-identical while the
-- raw digest is not. That is why R15.2C's 07 correctly returned
-- UNEXPECTED_FUNCTION_BODY_STOP. Restoring the reviewed bytes is the fix; the
-- reviewed migration is correct and is NOT changed.
--
-- AUTHORIZATION IS BY EXACT RAW DIGEST ONLY. No replace/regexp_replace/translate/
-- trim, no normalization of any kind, participates in the verdict. Accepting a
-- "normalized" match is exactly the withdrawn-R15.1 mistake.
--
-- Safety: identities resolve through to_regprocedure(), which returns NULL for a
-- missing function rather than raising 42883. There is no text::regprocedure cast
-- and no user-defined function is ever invoked, so running this file IN FULL is
-- safe in any state.
--
-- QUERY 1 is per-function detail. QUERY 2 — the LAST statement — is the verdict.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

-- ---------------------------------------------------------------------------
-- QUERY 1 — Per-function exact identity, attributes and raw digest.
--
-- Expected on the live database BEFORE restoration:
--   function_present            true
--   overload_count              1
--   signature_matches           true
--   owner_exact                 true
--   security_mode_exact         true
--   search_path_exact           true
--   matches_known_mojibake      true
--   matches_reviewed_lf         false
--   matches_reviewed_crlf       false
--   restorable                  true
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_secdef, expect_config, lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     TRUE, ARRAY['search_path=pg_catalog, public'],
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     FALSE, NULL::text[],
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
)
SELECT
  r.signature                                                                   AS expected_signature,
  (r.resolved_regproc IS NOT NULL)                                              AS function_present,
  p.oid                                                                         AS resolved_oid,
  r.overload_count,
  coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE) AS signature_matches,
  pg_get_userbyid(p.proowner)                                                   AS live_owner,
  coalesce(p.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(r.owner_table)), FALSE)
                                                                                AS owner_exact,
  p.prosecdef                                                                   AS live_security_definer,
  coalesce(p.prosecdef = r.expect_secdef, FALSE)                                AS security_mode_exact,
  p.proconfig::text                                                             AS live_search_path,
  coalesce(p.proconfig IS NOT DISTINCT FROM r.expect_config, FALSE)             AS search_path_exact,
  p.provolatile                                                                 AS live_volatility,
  coalesce(p.proacl::text, '(default)')                                         AS live_acl,
  md5(p.prosrc)                                                                 AS live_raw_md5_prosrc,
  octet_length(p.prosrc)                                                        AS live_bytes,
  coalesce(md5(p.prosrc) = r.mojibake_digest, FALSE)                            AS matches_known_mojibake,
  coalesce(md5(p.prosrc) = r.lf_digest, FALSE)                                  AS matches_reviewed_lf,
  coalesce(md5(p.prosrc) = r.crlf_digest, FALSE)                                AS matches_reviewed_crlf,
  -- Restorable: exact identity, exact attributes, and the body is the KNOWN
  -- mojibake (so we know precisely what we are replacing and why).
  (r.resolved_regproc IS NOT NULL
   AND r.overload_count = 1
   AND coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE)
   AND coalesce(p.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(r.owner_table)), FALSE)
   AND coalesce(p.prosecdef = r.expect_secdef, FALSE)
   AND coalesce(p.proconfig IS NOT DISTINCT FROM r.expect_config, FALSE)
   AND coalesce(md5(p.prosrc) = r.mojibake_digest, FALSE)
   AND NOT coalesce(md5(p.prosrc) IN (r.lf_digest, r.crlf_digest), FALSE))      AS restorable
FROM resolved r
LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
ORDER BY r.proname;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT. Act on this value alone.
--
--   SAFE_TO_RESTORE_REVIEWED_BODIES
--     both functions exist at their exact reviewed signature with no overload,
--     exact owner / security mode / search_path, and both bodies are byte-identical
--     to the KNOWN mojibake digest and to neither reviewed digest.
--
--   UNEXPECTED_LIVE_BODY_STOP
--     anything else — including the case where a body is ALREADY reviewed (the
--     restoration has run: go straight to 12), and the case where a body is some
--     THIRD unknown value (unexplained drift: STOP and escalate, do not restore).
--     Capture QUERY 1 and escalate.
-- ---------------------------------------------------------------------------
WITH target(signature, proname, identity_arguments, owner_table,
            expect_secdef, expect_config, lf_digest, crlf_digest, mojibake_digest) AS (
  VALUES
    ('public.qhub_decide_review(uuid,text,boolean,text,text,text)', 'qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     'public.qhub_manual_review_requests',
     TRUE, ARRAY['search_path=pg_catalog, public'],
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf',
     '9bc91d1671c5f65241ea22538c00d703'),
    ('public.qhub_row_immutable()', 'qhub_row_immutable',
     '',
     'public.qhub_acknowledgments',
     FALSE, NULL::text[],
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
evaluated AS (
  SELECT
    r.proname,
    (r.resolved_regproc IS NOT NULL)                                                  AS present,
    (r.overload_count = 1)                                                            AS single_overload,
    coalesce(pg_get_function_identity_arguments(p.oid) = r.identity_arguments, FALSE) AS signature_ok,
    coalesce(p.proowner = (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(r.owner_table)), FALSE)
                                                                                      AS owner_ok,
    coalesce(p.prosecdef = r.expect_secdef, FALSE)                                    AS security_ok,
    coalesce(p.proconfig IS NOT DISTINCT FROM r.expect_config, FALSE)                 AS search_path_ok,
    coalesce(md5(p.prosrc) = r.mojibake_digest, FALSE)                                AS is_known_mojibake,
    coalesce(md5(p.prosrc) IN (r.lf_digest, r.crlf_digest), FALSE)                    AS already_reviewed
  FROM resolved r
  LEFT JOIN pg_proc p ON p.oid = r.resolved_regproc
)
SELECT
  count(*)                                                                       AS functions_expected,
  count(*) FILTER (WHERE present)                                                AS present_count,
  count(*) FILTER (WHERE single_overload)                                        AS single_overload_count,
  count(*) FILTER (WHERE signature_ok)                                           AS signature_ok_count,
  count(*) FILTER (WHERE owner_ok)                                               AS owner_ok_count,
  count(*) FILTER (WHERE security_ok)                                            AS security_ok_count,
  count(*) FILTER (WHERE search_path_ok)                                         AS search_path_ok_count,
  count(*) FILTER (WHERE is_known_mojibake)                                      AS known_mojibake_count,
  count(*) FILTER (WHERE already_reviewed)                                       AS already_reviewed_count,
  count(*) FILTER (WHERE present AND single_overload AND signature_ok AND owner_ok
                     AND security_ok AND search_path_ok
                     AND is_known_mojibake AND NOT already_reviewed)             AS restorable_count,
  CASE
    WHEN count(*) = 2
     AND count(*) FILTER (WHERE present AND single_overload AND signature_ok AND owner_ok
                            AND security_ok AND search_path_ok
                            AND is_known_mojibake AND NOT already_reviewed) = 2
      THEN 'SAFE_TO_RESTORE_REVIEWED_BODIES'
    ELSE 'UNEXPECTED_LIVE_BODY_STOP'
  END                                                                            AS verdict
FROM evaluated;

COMMIT;
