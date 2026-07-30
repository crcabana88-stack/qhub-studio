-- ============================================================================
-- QHUB R15.2 — 07 PRE-PATCH EXACT DIGEST VERIFY (READ-ONLY)
--
-- Authorizes the R15.2 verifier patch ONLY if all five protected functions are
-- bound to their exact reviewed identity AND their raw body is byte-identical to
-- one of the two reviewed encodings. Performs NO writes.
--
-- The authorization verdict (QUERY 2) requires, per protected function:
--   * exact schema + name + argument signature, resolved to a real OID
--   * exactly one function of that name (no unexpected overload)
--   * raw md5(prosrc) equal to the approved LF or CRLF digest
-- and NO normalization is applied anywhere in the decision.
--
-- Safety: signatures are resolved with to_regprocedure(), which returns NULL for a
-- missing function instead of raising 42883. There is no text::regprocedure cast,
-- so a missing or renamed function fails closed rather than erroring.
--
-- QUERY 3 (line-ending counts) is NON-AUTHORIZING diagnostics only.
--
-- R15.2B: this file reads pg_catalog ONLY. It never invokes a function, so running
-- it in full is safe in any state — including one where a protected function or the
-- verifier is missing — and it cannot raise PostgreSQL 42883.
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

-- QUERY 2 — VERDICT. Act on this value alone.
--
--   SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH
--     all five functions exist at their exact reviewed signature, have no
--     unexpected overload, and their raw bodies are byte-identical to a reviewed
--     encoding.
--
--   UNEXPECTED_FUNCTION_BODY_STOP
--     any function missing, renamed, wrong argument list, overloaded, or carrying
--     an unapproved raw body. STOP. Do NOT apply the patch. Escalate with QUERY 1.
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
)
SELECT
  count(*)                                                                          AS functions_expected,
  count(*) FILTER (WHERE present)                                                   AS present_count,
  count(*) FILTER (WHERE single_overload)                                           AS single_overload_count,
  count(*) FILTER (WHERE signature_ok)                                              AS signature_ok_count,
  count(*) FILTER (WHERE digest_ok)                                                 AS digest_ok_count,
  count(*) FILTER (WHERE present AND single_overload AND signature_ok AND digest_ok) AS authorized_count,
  CASE
    WHEN count(*) = 5
     AND count(*) FILTER (WHERE present AND single_overload AND signature_ok AND digest_ok) = 5
      THEN 'SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH'
    ELSE 'UNEXPECTED_FUNCTION_BODY_STOP'
  END                                                                               AS verdict
FROM evaluated;

COMMIT;

-- ---------------------------------------------------------------------------
-- R15.2B — the previous optional "current verifier output" query was REMOVED.
-- It invoked public.qhub_verify_commercial_schema() unconditionally, so running
-- this file in full against a database whose verifier is missing raised
-- PostgreSQL 42883 *after* the STOP verdict had already been produced. This file
-- now touches pg_catalog only: it is safe to paste and run in full, in any state,
-- and it never invokes a function. The verifier's own output is reported by
-- 09_POST_PATCH_VERIFY.sql, which gates the call on catalog authority.
-- ---------------------------------------------------------------------------
