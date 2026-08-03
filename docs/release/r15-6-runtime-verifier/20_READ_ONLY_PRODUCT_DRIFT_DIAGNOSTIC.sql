-- ============================================================================
-- QHUB R15.6 - 20 READ-ONLY PRODUCT DRIFT DIAGNOSTIC
--
-- Purpose: explain only the five failure labels captured by Diagnostic 19.
-- The commercial verifier is invoked exactly once. Target evidence is withheld
-- unless the verifier contract, report shape, version, ordered labels, and both
-- implicated function identities are exact.
--
-- This diagnostic never returns complete function bodies and never invokes the
-- two implicated functions. It returns bounded pg_catalog metadata, raw-prosrc
-- MD5 digests, and direct ACL entries only.
-- ============================================================================

BEGIN;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;

WITH constants AS MATERIALIZED (
  SELECT
    '2026-07-30.commercial-launch-r8'::text AS expected_version,
    jsonb_build_array(
      'decide_review_body_drift',
      'r7_ack_immutable_body_drift',
      'row_immutable_body_digest',
      'row_immutable_acl_cardinality',
      'row_immutable_acl_unexpected_grantee'
    ) AS expected_labels,
    ARRAY['7e678f1e4bba0c540507cfe3743fbe54',
          'dac8abcd56d7fc804baac660059c14bf']::text[] AS decide_body_digests,
    ARRAY['41ae59dde9a471b580d28e2cb45984f5',
          '4936e3f58627dde5abc10d2b0ecf5b4f']::text[] AS row_immutable_body_digests
),
verifier_catalog AS MATERIALIZED (
  SELECT
    to_regprocedure('public.qhub_verify_commercial_schema()') AS verifier_oid,
    (SELECT count(*)
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname = 'qhub_verify_commercial_schema') AS verifier_name_count
),
verifier_contract AS MATERIALIZED (
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
    ) AS contract_ok
  FROM verifier_catalog vc
),
verifier_invocation AS MATERIALIZED (
  SELECT
    vc.contract_ok,
    CASE WHEN vc.contract_ok
      THEN public.qhub_verify_commercial_schema()
      ELSE NULL::jsonb
    END AS report
  FROM verifier_contract vc
),
report_validation AS MATERIALIZED (
  SELECT
    vi.contract_ok,
    vi.report,
    (
      vi.contract_ok
      AND jsonb_typeof(vi.report) = 'object'
      AND coalesce((
        SELECT array_agg(k ORDER BY k)
          FROM jsonb_object_keys(
            CASE WHEN jsonb_typeof(vi.report) = 'object' THEN vi.report ELSE '{}'::jsonb END
          ) AS keys(k)
      ), ARRAY[]::text[]) = ARRAY['expected_version', 'failed', 'ready']::text[]
      AND jsonb_typeof(vi.report -> 'expected_version') = 'string'
      AND length(vi.report ->> 'expected_version') BETWEEN 1 AND 128
      AND jsonb_typeof(vi.report -> 'ready') = 'boolean'
      AND jsonb_typeof(vi.report -> 'failed') = 'array'
      AND NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(vi.report -> 'failed') = 'array'
              THEN vi.report -> 'failed'
              ELSE '[]'::jsonb
            END
          ) AS item(value)
         WHERE jsonb_typeof(item.value) <> 'string'
            OR length(item.value #>> '{}') NOT BETWEEN 1 AND 255
            OR (item.value #>> '{}') !~ '^[a-z0-9][a-z0-9_:.-]*$'
      )
      AND vi.report -> 'ready' = to_jsonb(
        jsonb_array_length(
          CASE WHEN jsonb_typeof(vi.report -> 'failed') = 'array'
            THEN vi.report -> 'failed'
            ELSE '[]'::jsonb
          END
        ) = 0
      )
    ) AS report_shape_ok
  FROM verifier_invocation vi
),
report_gate AS MATERIALIZED (
  SELECT
    rv.contract_ok,
    rv.report,
    rv.report_shape_ok,
    (
      rv.report_shape_ok
      AND rv.report ->> 'expected_version' = c.expected_version
      AND rv.report -> 'ready' = 'false'::jsonb
      AND rv.report -> 'failed' = c.expected_labels
    ) AS report_gate_ok
  FROM report_validation rv
  CROSS JOIN constants c
),
target_catalog AS MATERIALIZED (
  SELECT
    rg.contract_ok,
    rg.report,
    rg.report_shape_ok,
    rg.report_gate_ok,
    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE rg.report_gate_ok AND n.nspname = 'public' AND p.proname = 'qhub_decide_review') AS decide_name_count,
    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE rg.report_gate_ok AND n.nspname = 'public' AND p.proname = 'qhub_decide_review'
        AND pg_get_function_identity_arguments(p.oid) =
          'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text')
      AS decide_signature_count,
    CASE WHEN rg.report_gate_ok
      THEN to_regprocedure('public.qhub_decide_review(uuid,text,boolean,text,text,text)')
    END AS decide_oid,
    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE rg.report_gate_ok AND n.nspname = 'public' AND p.proname = 'qhub_row_immutable') AS row_name_count,
    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE rg.report_gate_ok AND n.nspname = 'public' AND p.proname = 'qhub_row_immutable'
        AND pg_get_function_identity_arguments(p.oid) = '') AS row_signature_count,
    CASE WHEN rg.report_gate_ok
      THEN to_regprocedure('public.qhub_row_immutable()')
    END AS row_oid,
    CASE WHEN rg.report_gate_ok THEN to_regclass('public.qhub_manual_review_requests') END AS review_table_oid,
    CASE WHEN rg.report_gate_ok THEN to_regclass('public.qhub_acknowledgments') END AS acknowledgment_table_oid
  FROM report_gate rg
),
target_gate AS MATERIALIZED (
  SELECT
    tc.*,
    CASE
      WHEN NOT tc.report_gate_ok THEN 'WITHHELD_BY_REPORT_GATE'
      WHEN tc.decide_name_count = 0 OR tc.row_name_count = 0 THEN 'IMPLICATED_OBJECT_MISSING'
      WHEN tc.decide_name_count <> 1 OR tc.row_name_count <> 1 THEN 'IMPLICATED_OBJECT_OVERLOADED'
      WHEN tc.decide_signature_count <> 1 OR tc.row_signature_count <> 1
        OR tc.decide_oid IS NULL OR tc.row_oid IS NULL THEN 'IMPLICATED_OBJECT_IDENTITY_MISMATCH'
      WHEN tc.review_table_oid IS NULL OR tc.acknowledgment_table_oid IS NULL
        THEN 'AUTHORITATIVE_OWNER_REFERENCE_MISSING'
      ELSE 'EXACT_TARGETS_IDENTIFIED'
    END AS target_catalog_status,
    (
      tc.report_gate_ok
      AND tc.decide_name_count = 1 AND tc.decide_signature_count = 1 AND tc.decide_oid IS NOT NULL
      AND tc.row_name_count = 1 AND tc.row_signature_count = 1 AND tc.row_oid IS NOT NULL
      AND tc.review_table_oid IS NOT NULL AND tc.acknowledgment_table_oid IS NOT NULL
    ) AS targets_exact
  FROM target_catalog tc
),
expected_functions AS MATERIALIZED (
  SELECT
    1 AS object_order,
    'qhub_decide_review'::text AS object_key,
    'public.qhub_decide_review(p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text)'::text AS expected_identity,
    'p_request_id uuid, p_actor text, p_is_staff boolean, p_decision text, p_reason text, p_policy_version text'::text AS expected_identity_arguments,
    tg.decide_oid AS function_oid,
    (SELECT c.relowner FROM pg_class c WHERE c.oid = tg.review_table_oid) AS expected_owner_oid,
    'jsonb'::text AS expected_return_type,
    'plpgsql'::text AS expected_language,
    'v'::char AS expected_volatility,
    FALSE AS expected_strict,
    TRUE AS expected_security_definer,
    FALSE AS expected_leakproof,
    'u'::char AS expected_parallel_safety,
    ARRAY['search_path=pg_catalog, public']::text[] AS expected_configuration,
    100::real AS expected_cost,
    0::real AS expected_rows,
    c.decide_body_digests AS expected_body_digests
  FROM target_gate tg
  CROSS JOIN constants c
  WHERE tg.targets_exact
  UNION ALL
  SELECT
    2,
    'qhub_row_immutable',
    'public.qhub_row_immutable()',
    '',
    tg.row_oid,
    (SELECT c.relowner FROM pg_class c WHERE c.oid = tg.acknowledgment_table_oid),
    'trigger',
    'plpgsql',
    'v'::char,
    FALSE,
    FALSE,
    FALSE,
    'u'::char,
    NULL::text[],
    100::real,
    0::real,
    c.row_immutable_body_digests
  FROM target_gate tg
  CROSS JOIN constants c
  WHERE tg.targets_exact
),
function_facts AS MATERIALIZED (
  SELECT
    ef.*,
    p.oid,
    n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS actual_identity,
    pg_get_function_identity_arguments(p.oid) AS actual_identity_arguments,
    pg_get_userbyid(p.proowner) AS actual_owner,
    pg_get_userbyid(ef.expected_owner_oid) AS expected_owner,
    format_type(p.prorettype, NULL) AS actual_return_type,
    l.lanname AS actual_language,
    p.provolatile AS actual_volatility,
    p.proisstrict AS actual_strict,
    p.prosecdef AS actual_security_definer,
    p.proleakproof AS actual_leakproof,
    p.proparallel AS actual_parallel_safety,
    p.proconfig AS actual_configuration,
    p.procost AS actual_cost,
    p.prorows AS actual_rows,
    p.proretset AS actual_returns_set,
    p.prokind AS actual_prokind,
    p.pronargdefaults AS actual_default_argument_count,
    p.provariadic AS actual_variadic_type_oid,
    md5(p.prosrc) AS actual_body_digest,
    md5(p.prosrc) = ANY(ef.expected_body_digests) AS body_digest_match,
    (
      pg_get_function_identity_arguments(p.oid) = ef.expected_identity_arguments
      AND format_type(p.prorettype, NULL) = ef.expected_return_type
      AND l.lanname = ef.expected_language
      AND p.proowner = ef.expected_owner_oid
      AND p.provolatile = ef.expected_volatility
      AND p.proisstrict = ef.expected_strict
      AND p.prosecdef = ef.expected_security_definer
      AND p.proleakproof = ef.expected_leakproof
      AND p.proparallel = ef.expected_parallel_safety
      AND p.proconfig IS NOT DISTINCT FROM ef.expected_configuration
      AND p.procost = ef.expected_cost
      AND p.prorows = ef.expected_rows
      AND NOT p.proretset
      AND p.prokind = 'f'
      AND p.pronargdefaults = 0
      AND p.provariadic = 0
    ) AS metadata_match
  FROM expected_functions ef
  JOIN pg_proc p ON p.oid = ef.function_oid
  JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_language l ON l.oid = p.prolang
),
acl_facts AS MATERIALIZED (
  SELECT
    ae.grantee,
    CASE WHEN ae.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(ae.grantee) END AS grantee_name,
    ae.grantor,
    pg_get_userbyid(ae.grantor) AS grantor_name,
    ae.privilege_type,
    ae.is_grantable,
    p.proowner,
    ae.grantee <> p.proowner AS unexpected_grantee
  FROM target_gate tg
  JOIN pg_proc p ON p.oid = tg.row_oid AND tg.targets_exact
  CROSS JOIN LATERAL aclexplode(p.proacl) ae
),
acl_summary AS MATERIALIZED (
  SELECT
    count(*)::integer AS direct_acl_cardinality,
    count(*) FILTER (
      WHERE grantee = proowner AND grantor = proowner
        AND privilege_type = 'EXECUTE' AND NOT is_grantable
    )::integer AS exact_owner_entry_count,
    count(*) FILTER (WHERE unexpected_grantee)::integer AS unexpected_grantee_count,
    count(*) FILTER (WHERE is_grantable)::integer AS grant_option_count
  FROM acl_facts
),
function_check_summary AS MATERIALIZED (
  SELECT
    count(*)::integer AS function_count,
    bool_and(metadata_match) AS all_metadata_match,
    max(body_digest_match::integer) FILTER (WHERE object_key = 'qhub_decide_review') = 1
      AS decide_body_match,
    max(body_digest_match::integer) FILTER (WHERE object_key = 'qhub_row_immutable') = 1
      AS row_body_match
  FROM function_facts
),
label_conditions AS MATERIALIZED (
  SELECT * FROM (
    SELECT 1 AS label_order, 'decide_review_body_drift'::text AS label,
      'public.qhub_decide_review(uuid,text,boolean,text,text,text)'::text AS implicated_object,
      'raw_md5_prosrc_not_in_expected_digest_set'::text AS verifier_condition,
      NOT coalesce(fcs.decide_body_match, FALSE) AS condition_failed
    FROM function_check_summary fcs
    UNION ALL
    SELECT 2, 'r7_ack_immutable_body_drift', 'public.qhub_row_immutable()',
      'raw_md5_prosrc_not_in_expected_digest_set', NOT coalesce(fcs.row_body_match, FALSE)
    FROM function_check_summary fcs
    UNION ALL
    SELECT 3, 'row_immutable_body_digest', 'public.qhub_row_immutable()',
      'raw_md5_prosrc_not_in_expected_digest_set', NOT coalesce(fcs.row_body_match, FALSE)
    FROM function_check_summary fcs
    UNION ALL
    SELECT 4, 'row_immutable_acl_cardinality', 'public.qhub_row_immutable()',
      'direct_acl_cardinality_is_distinct_from_1', a.direct_acl_cardinality IS DISTINCT FROM 1
    FROM acl_summary a
    UNION ALL
    SELECT 5, 'row_immutable_acl_unexpected_grantee', 'public.qhub_row_immutable()',
      'direct_acl_contains_grantee_other_than_function_owner', a.unexpected_grantee_count > 0
    FROM acl_summary a
  ) mapped
),
evidence_readiness AS MATERIALIZED (
  SELECT
    tg.*,
    fcs.function_count,
    fcs.all_metadata_match,
    (
      tg.targets_exact
      AND fcs.function_count = 2
      AND (SELECT count(*) FROM label_conditions) = 5
      AND coalesce((SELECT bool_and(condition_failed) FROM label_conditions), FALSE)
    ) AS evidence_ready
  FROM target_gate tg
  CROSS JOIN function_check_summary fcs
),
structured_evidence AS MATERIALIZED (
  SELECT
    er.*,
    (SELECT jsonb_agg(jsonb_build_object(
        'object_order', ff.object_order,
        'object_key', ff.object_key,
        'expected', jsonb_build_object(
          'identity', ff.expected_identity,
          'owner', ff.expected_owner,
          'return_type', ff.expected_return_type,
          'language', ff.expected_language,
          'volatility', ff.expected_volatility,
          'null_input_behavior', CASE WHEN ff.expected_strict THEN 'STRICT' ELSE 'CALLED_ON_NULL_INPUT' END,
          'security_mode', CASE WHEN ff.expected_security_definer THEN 'SECURITY_DEFINER' ELSE 'SECURITY_INVOKER' END,
          'leakproof', ff.expected_leakproof,
          'parallel_safety', ff.expected_parallel_safety,
          'configuration', to_jsonb(ff.expected_configuration),
          'cost', ff.expected_cost,
          'rows', ff.expected_rows,
          'body_digest_method', 'raw_md5_pg_proc_prosrc_no_normalization',
          'accepted_body_digests', to_jsonb(ff.expected_body_digests)
        ),
        'actual', jsonb_build_object(
          'oid', ff.oid,
          'identity', ff.actual_identity,
          'identity_arguments', ff.actual_identity_arguments,
          'owner', ff.actual_owner,
          'return_type', ff.actual_return_type,
          'language', ff.actual_language,
          'volatility', ff.actual_volatility,
          'null_input_behavior', CASE WHEN ff.actual_strict THEN 'STRICT' ELSE 'CALLED_ON_NULL_INPUT' END,
          'security_mode', CASE WHEN ff.actual_security_definer THEN 'SECURITY_DEFINER' ELSE 'SECURITY_INVOKER' END,
          'leakproof', ff.actual_leakproof,
          'parallel_safety', ff.actual_parallel_safety,
          'configuration', to_jsonb(ff.actual_configuration),
          'cost', ff.actual_cost,
          'rows', ff.actual_rows,
          'returns_set', ff.actual_returns_set,
          'prokind', ff.actual_prokind,
          'default_argument_count', ff.actual_default_argument_count,
          'variadic_type_oid', ff.actual_variadic_type_oid,
          'body_digest', ff.actual_body_digest
        ),
        'metadata_match', ff.metadata_match,
        'body_digest_match', ff.body_digest_match,
        'drift_classification', CASE
          WHEN ff.metadata_match AND ff.body_digest_match THEN 'MATCH'
          WHEN ff.metadata_match THEN 'BODY_DRIFT'
          WHEN ff.body_digest_match THEN 'METADATA_DRIFT'
          ELSE 'METADATA_AND_BODY_DRIFT'
        END
      ) ORDER BY ff.object_order) FROM function_facts ff) AS function_evidence,
    (SELECT jsonb_agg(jsonb_build_object(
        'ordinal', row_number,
        'grantee_oid', grantee,
        'grantee', grantee_name,
        'grantor_oid', grantor,
        'grantor', grantor_name,
        'privilege', privilege_type,
        'grantable', is_grantable,
        'unexpected_grantee', unexpected_grantee
      ) ORDER BY row_number)
      FROM (
        SELECT af.*, row_number() OVER (
          ORDER BY af.grantee, af.grantor, af.privilege_type, af.is_grantable
        ) AS row_number
        FROM acl_facts af
      ) ordered_acl) AS direct_acl_entries,
    (SELECT coalesce(jsonb_agg(jsonb_build_object(
        'grantee_oid', af.grantee,
        'grantee', af.grantee_name,
        'grantor_oid', af.grantor,
        'grantor', af.grantor_name,
        'privilege', af.privilege_type,
        'grantable', af.is_grantable
      ) ORDER BY af.grantee, af.grantor, af.privilege_type, af.is_grantable), '[]'::jsonb)
      FROM acl_facts af WHERE af.unexpected_grantee) AS unexpected_grantee_evidence,
    (SELECT jsonb_agg(jsonb_build_object(
        'label_order', lc.label_order,
        'label', lc.label,
        'implicated_object', lc.implicated_object,
        'verifier_condition', lc.verifier_condition,
        'condition_failed', lc.condition_failed
      ) ORDER BY lc.label_order) FROM label_conditions lc) AS label_condition_evidence
  FROM evidence_readiness er
)
SELECT
  CASE
    WHEN NOT contract_ok THEN 'VERIFIER_CONTRACT_INVALID'
    WHEN NOT report_shape_ok THEN 'VERIFIER_REPORT_INVALID'
    WHEN NOT report_gate_ok THEN 'VERSION_OR_ORDERED_LABEL_GATE_FAILED'
    WHEN target_catalog_status <> 'EXACT_TARGETS_IDENTIFIED' THEN target_catalog_status
    WHEN NOT evidence_ready THEN 'TARGETED_EVIDENCE_INCOMPLETE'
    ELSE 'R15_6_TARGETED_DRIFT_EVIDENCE_READY'
  END AS diagnostic_status,
  CASE WHEN report_shape_ok THEN report -> 'ready' = 'true'::jsonb ELSE FALSE END AS product_ready,
  CASE WHEN report_shape_ok THEN report ->> 'expected_version' END AS product_version,
  CASE WHEN report_shape_ok THEN report -> 'failed' END AS failed_labels,
  CASE WHEN report_shape_ok THEN jsonb_array_length(report -> 'failed') END AS failed_label_count,
  target_catalog_status,
  CASE WHEN evidence_ready THEN function_evidence END AS function_evidence,
  CASE WHEN evidence_ready THEN jsonb_build_object(
    'expected_cardinality', 1,
    'expected_grantee', 'FUNCTION_OWNER',
    'expected_grantor', 'FUNCTION_OWNER',
    'expected_privilege', 'EXECUTE',
    'expected_grantable', FALSE,
    'actual_cardinality', a.direct_acl_cardinality,
    'exact_owner_entry_count', a.exact_owner_entry_count,
    'unexpected_grantee_count', a.unexpected_grantee_count,
    'grant_option_count', a.grant_option_count,
    'contract_match', a.direct_acl_cardinality = 1
      AND a.exact_owner_entry_count = 1
      AND a.unexpected_grantee_count = 0
      AND a.grant_option_count = 0
  ) END AS row_immutable_acl_summary,
  CASE WHEN evidence_ready THEN coalesce(direct_acl_entries, '[]'::jsonb) END AS row_immutable_direct_acl,
  CASE WHEN evidence_ready THEN unexpected_grantee_evidence END AS unexpected_grantee_evidence,
  CASE WHEN evidence_ready THEN label_condition_evidence END AS label_condition_evidence,
  CASE WHEN evidence_ready THEN jsonb_build_array(
    'decide_review_body', 'row_immutable_body', 'row_immutable_direct_acl'
  ) END AS implicated_discrepancy_classes
FROM structured_evidence
CROSS JOIN acl_summary a;

COMMIT;
