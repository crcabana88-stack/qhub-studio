-- ============================================================================
-- QHUB R15.2 — 07 PRE-PATCH EXACT DIGEST VERIFY (READ-ONLY)
--
-- Confirms, before the dual-digest patch is applied, that each of the five live
-- protected function bodies is byte-for-byte one of the two separately reviewed
-- encodings of that reviewed body (LF or CRLF). Performs NO writes.
--
-- The authorization decision uses the RAW md5(prosrc) ONLY. No normalization is
-- applied anywhere in this script. QUERY 3 is supplementary diagnostics that must
-- NOT be used to authorize the patch.
--
-- QUERY 2 returns the verdict. Apply the patch ONLY on
-- SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- QUERY 1 — Per-function raw digest against the two approved encodings.
--
-- Expected on the current live database (applied through the CRLF channel):
--   matches_lf   = false
--   matches_crlf = true
--   matches_exactly_one_approved = true
--
-- An LF-applied database would show matches_lf = true instead. Any row where
-- matches_exactly_one_approved is false is unreviewed drift.
-- ---------------------------------------------------------------------------
WITH approved(proname, identity_arguments, lf_digest, crlf_digest) AS (
  VALUES
    ('qhub_decide_review',
     'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text',
     '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf'),
    ('qhub_create_review_request',
     'p_org_id text, p_project_id uuid, p_requester text, p_reason text, p_idempotency_key text',
     '6b46c3d75636fd0c8b628b34a86f4084', '349b59554232ab7f3b9e4aa3a8cc2331'),
    ('qhub_record_acknowledgment',
     'p_org_id text, p_project_id uuid, p_user_id text, p_action text',
     'b6035e9a35f5ecc49369b68000c7b2a6', '09e053d93afb7aca96064b758d76213a'),
    ('qhub_canon_cells',
     'p_cells text[]',
     '6151a5d4794e56fbc26fc891f8fefdb4', '2d569f42d1e95f2ffd38dc82e14d727c'),
    ('qhub_row_immutable',
     '',
     '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f')
)
SELECT
  a.proname,
  p.oid::regprocedure                                   AS live_signature,
  pg_get_function_identity_arguments(p.oid)             AS live_identity_arguments,
  a.identity_arguments                                  AS expected_identity_arguments,
  (pg_get_function_identity_arguments(p.oid) = a.identity_arguments) AS signature_matches,
  md5(p.prosrc)                                         AS live_raw_md5_prosrc,
  a.lf_digest                                           AS approved_lf_digest,
  a.crlf_digest                                         AS approved_crlf_digest,
  (md5(p.prosrc) = a.lf_digest)                         AS matches_lf,
  (md5(p.prosrc) = a.crlf_digest)                       AS matches_crlf,
  (md5(p.prosrc) IN (a.lf_digest, a.crlf_digest))       AS matches_exactly_one_approved
FROM approved a
JOIN pg_proc p      ON p.proname = a.proname
JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public'
ORDER BY a.proname;

-- ---------------------------------------------------------------------------
-- QUERY 2 — VERDICT (raw digests only). Act on this value alone.
--
--   SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH
--     all five live bodies are byte-identical to a reviewed encoding.
--
--   UNEXPECTED_FUNCTION_BODY_STOP
--     at least one body is neither the reviewed LF nor the reviewed CRLF
--     encoding. STOP. Do NOT apply the patch. Escalate with QUERY 1 output.
-- ---------------------------------------------------------------------------
WITH approved(proname, lf_digest, crlf_digest) AS (
  VALUES
    ('qhub_decide_review',         '7e678f1e4bba0c540507cfe3743fbe54', 'dac8abcd56d7fc804baac660059c14bf'),
    ('qhub_create_review_request', '6b46c3d75636fd0c8b628b34a86f4084', '349b59554232ab7f3b9e4aa3a8cc2331'),
    ('qhub_record_acknowledgment', 'b6035e9a35f5ecc49369b68000c7b2a6', '09e053d93afb7aca96064b758d76213a'),
    ('qhub_canon_cells',           '6151a5d4794e56fbc26fc891f8fefdb4', '2d569f42d1e95f2ffd38dc82e14d727c'),
    ('qhub_row_immutable',         '41ae59dde9a471b580d28e2cb45984f5', '4936e3f58627dde5abc10d2b0ecf5b4f')
)
SELECT
  count(*)                                                                       AS functions_found,
  count(*) FILTER (WHERE md5(p.prosrc) = a.lf_digest)                            AS matching_lf,
  count(*) FILTER (WHERE md5(p.prosrc) = a.crlf_digest)                          AS matching_crlf,
  count(*) FILTER (WHERE md5(p.prosrc) IN (a.lf_digest, a.crlf_digest))          AS matching_approved,
  CASE
    WHEN count(*) = 5
     AND count(*) FILTER (WHERE md5(p.prosrc) IN (a.lf_digest, a.crlf_digest)) = 5
      THEN 'SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH'
    ELSE 'UNEXPECTED_FUNCTION_BODY_STOP'
  END                                                                            AS verdict
FROM approved a
JOIN pg_proc p      ON p.proname = a.proname
JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public';

-- ---------------------------------------------------------------------------
-- QUERY 3 — SUPPLEMENTARY DIAGNOSTICS ONLY. Informational line-ending counts.
-- These values MUST NOT be used to authorize the patch; QUERY 2 is authoritative.
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
-- QUERY 4 — Current verifier output (evidence record).
-- ---------------------------------------------------------------------------
SELECT
  v ->> 'expected_version' AS expected_version,
  (v ->> 'ready')::boolean AS ready,
  v -> 'failed'            AS failed_checks
FROM public.qhub_verify_commercial_schema() AS v;
