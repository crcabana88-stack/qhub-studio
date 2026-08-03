-- ============================================================================
-- QHUB R15.6 — 19 READ-ONLY PRODUCT FAILURE DIAGNOSTIC
--
-- Purpose: expose the exact ordered failure labels already returned by the
-- committed public.qhub_verify_commercial_schema() report. This file diagnoses
-- no individual label and performs no repair.
--
-- The verifier is invoked once, inside a MATERIALIZED CTE, only after its exact
-- zero-argument jsonb-returning identity is confirmed and no overload exists.
-- The report must have exactly these fields and types:
--   expected_version : string
--   ready            : boolean
--   failed           : array of bounded canonical label strings
-- Readiness must agree with whether the failed array is empty.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

WITH verifier_catalog AS MATERIALIZED (
  SELECT
    to_regprocedure('public.qhub_verify_commercial_schema()') AS verifier_oid,
    (SELECT count(*)
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname = 'qhub_verify_commercial_schema') AS verifier_name_count
),
call_gate AS MATERIALIZED (
  SELECT
    vc.verifier_oid,
    (
      vc.verifier_oid IS NOT NULL
      AND vc.verifier_name_count = 1
      AND coalesce((
        SELECT pg_get_function_identity_arguments(p.oid) = ''
           AND p.pronargs = 0
           AND p.prorettype = 'jsonb'::regtype
           AND NOT p.proretset
           AND p.prokind = 'f'
          FROM pg_proc p
         WHERE p.oid = vc.verifier_oid
      ), FALSE)
    ) AS catalog_ok
  FROM verifier_catalog vc
),
invocation AS MATERIALIZED (
  SELECT
    g.catalog_ok,
    CASE WHEN g.catalog_ok
      THEN public.qhub_verify_commercial_schema()
      ELSE NULL::jsonb
    END AS report
  FROM call_gate g
),
shape_base AS MATERIALIZED (
  SELECT
    i.*,
    (
      i.catalog_ok
      AND jsonb_typeof(i.report) = 'object'
      AND coalesce((
        SELECT array_agg(k ORDER BY k)
          FROM jsonb_object_keys(
            CASE WHEN jsonb_typeof(i.report) = 'object' THEN i.report ELSE '{}'::jsonb END
          ) AS keys(k)
      ), ARRAY[]::text[]) = ARRAY['expected_version', 'failed', 'ready']::text[]
      AND jsonb_typeof(i.report -> 'expected_version') = 'string'
      AND length(i.report ->> 'expected_version') BETWEEN 1 AND 128
      AND jsonb_typeof(i.report -> 'ready') = 'boolean'
      AND jsonb_typeof(i.report -> 'failed') = 'array'
    ) AS base_shape_ok
  FROM invocation i
),
validated AS MATERIALIZED (
  SELECT
    s.*,
    (
      s.base_shape_ok
      AND NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(s.report -> 'failed') = 'array'
              THEN s.report -> 'failed'
              ELSE '[]'::jsonb
            END
          ) AS item(value)
         WHERE jsonb_typeof(item.value) <> 'string'
            OR length(item.value #>> '{}') NOT BETWEEN 1 AND 255
            OR (item.value #>> '{}') !~ '^[a-z0-9][a-z0-9_:.-]*$'
      )
      AND (s.report -> 'ready' = to_jsonb(jsonb_array_length(s.report -> 'failed') = 0))
    ) AS report_valid
  FROM shape_base s
),
evidence AS MATERIALIZED (
  SELECT
    v.catalog_ok,
    v.report,
    v.report_valid,
    coalesce(
      jsonb_agg(
        jsonb_build_object('ordinal', labels.ordinality, 'label', labels.label)
        ORDER BY labels.ordinality
      ) FILTER (WHERE labels.label IS NOT NULL),
      '[]'::jsonb
    ) AS ordered_label_evidence
  FROM validated v
  LEFT JOIN LATERAL jsonb_array_elements_text(
    CASE WHEN v.report_valid THEN v.report -> 'failed' ELSE '[]'::jsonb END
  ) WITH ORDINALITY AS labels(label, ordinality) ON TRUE
  GROUP BY v.catalog_ok, v.report, v.report_valid
)
SELECT
  CASE
    WHEN NOT catalog_ok THEN 'VERIFIER_CONTRACT_INVALID'
    WHEN NOT report_valid THEN 'VERIFIER_REPORT_INVALID'
    ELSE 'R15_6_PRODUCT_REPORT_VALID'
  END AS diagnostic_status,
  CASE WHEN report_valid THEN report -> 'ready' = 'true'::jsonb ELSE FALSE END AS product_ready,
  CASE WHEN report_valid THEN report ->> 'expected_version' END AS product_version,
  CASE WHEN report_valid THEN report -> 'failed' END AS failed_labels,
  CASE WHEN report_valid THEN jsonb_array_length(report -> 'failed') END AS failed_label_count,
  CASE WHEN report_valid THEN ordered_label_evidence END AS failed_labels_evidence
FROM evidence;

COMMIT;
