-- QHUB Gate 04 — authorized synthetic approval cleanup, schema assurance,
-- and atomic enforcement transitions
-- Migration: 20260726_gate04_schema_assurance_approval_cleanup
--
-- Additive and idempotent. This migration:
--   1. makes Gate 04 ownership/state invariants explicit,
--   2. adds service-role-only atomic claim/approval functions,
--   3. makes direct client access explicitly restrictive, and
--   4. exposes a service-role-only, metadata-only readiness result.
--
-- It does not return customer data, credentials, SQL definitions, or RLS
-- predicates. It does not grant table or function access to browser roles.

BEGIN;

-- The two rows below were explicitly authorized for deletion after independent
-- provenance review. They were inserted by the temporary staging live-test
-- driver with created_by='seed', then deliberately reassigned to
-- other-org-live through the service-role client. The driver did not emit an
-- ATTESTATION_SIGNED event. DynamoDB/S3 remain external, immutable systems and
-- are not mutated by this transaction.
DO $$
BEGIN
  IF to_regclass('public.qhub_applications') IS NULL
     OR to_regclass('public.qhub_enforcement_plans') IS NULL
     OR to_regclass('public.qhub_control_evaluations') IS NULL
     OR to_regclass('public.qhub_control_approvals') IS NULL THEN
    RAISE EXCEPTION 'Gate 04 cleanup aborted: required base table is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'qhub_applications'
      AND column_name = 'org_id'
  ) OR NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'qhub_applications'
      AND column_name = 'qhub_app_id'
      AND data_type = 'uuid'
  ) THEN
    RAISE EXCEPTION 'Gate 04 cleanup aborted: application ownership columns are missing or mismatched';
  END IF;
END
$$;

CREATE TEMP TABLE gate04_authorized_approval_cleanup (
  approval_id UUID PRIMARY KEY,
  qhub_app_id UUID NOT NULL,
  action_digest TEXT NOT NULL,
  expected_created_at TIMESTAMPTZ NOT NULL
)
ON COMMIT DROP;

INSERT INTO pg_temp.gate04_authorized_approval_cleanup (
  approval_id,
  qhub_app_id,
  action_digest,
  expected_created_at
)
VALUES
  (
    '623f674d-c58f-47fc-a385-faa4f758ae69'::uuid,
    'f3bf3be0-0e93-44e3-af1c-1f10713fc010'::uuid,
    '80c1b7f56904408656feded9fc824b7e3baf2a82ec3c01ae05b0782ad70bd612',
    '2026-07-26T13:18:18.150937+00:00'::timestamptz
  ),
  (
    '89b48d61-c70e-44bc-9fe2-cfe0189cf73a'::uuid,
    'd2838101-84d0-4d9f-b2ce-bb4997541ba6'::uuid,
    '5339153e6c4876e5deb62a1670a7185ad50f24d25a109825fd0233c4ea949a52',
    '2026-07-26T14:30:47.711317+00:00'::timestamptz
  );

DO $$
DECLARE
  present_count INTEGER;
  orphan_count INTEGER;
  deleted_count INTEGER;
  dependency RECORD;
  dependent_reference_exists BOOLEAN;
BEGIN
  SELECT count(*)
    INTO present_count
  FROM public.qhub_control_approvals approval
  JOIN pg_temp.gate04_authorized_approval_cleanup authorized
    ON authorized.approval_id = approval.approval_id;

  SELECT count(*)
    INTO orphan_count
  FROM public.qhub_control_approvals approval
  LEFT JOIN public.qhub_applications app
    ON app.org_id = approval.org_id
   AND app.qhub_app_id = approval.qhub_app_id
  WHERE app.qhub_app_id IS NULL;

  -- First execution must see both authorized rows and exactly two approval
  -- ownership orphans. A successful rerun must see neither.
  IF present_count NOT IN (0, 2) THEN
    RAISE EXCEPTION
      'Gate 04 cleanup aborted: expected zero or two authorized rows, found %',
      present_count;
  END IF;

  IF (present_count = 2 AND orphan_count <> 2)
     OR (present_count = 0 AND orphan_count <> 0) THEN
    RAISE EXCEPTION
      'Gate 04 cleanup aborted: approval orphan count % does not match idempotent state %',
      orphan_count, present_count;
  END IF;

  IF present_count = 2 THEN
    -- Exact identity, provenance, approval state, expiry, and immutable scope.
    IF EXISTS (
      SELECT 1
      FROM pg_temp.gate04_authorized_approval_cleanup authorized
      LEFT JOIN public.qhub_control_approvals approval
        ON approval.approval_id = authorized.approval_id
      WHERE approval.approval_id IS NULL
         OR approval.org_id <> 'other-org-live'
         OR approval.qhub_app_id <> authorized.qhub_app_id
         OR approval.action_digest <> authorized.action_digest
         OR approval.attestation_type <> 'OWNER_ATTESTATION'
         OR approval.status <> 'GRANTED'
         OR approval.created_by <> 'seed'
         OR approval.single_use IS DISTINCT FROM TRUE
         OR approval.consumed_by_evaluation IS NOT NULL
         OR approval.consumed_at IS NOT NULL
         OR approval.expires_at >= clock_timestamp()
         OR approval.created_at IS DISTINCT FROM authorized.expected_created_at
    ) THEN
      RAISE EXCEPTION 'Gate 04 cleanup aborted: authorized approval identity, provenance, or state differs';
    END IF;

    -- Each app has one legitimate client-smoke owner and no other-org-live
    -- ownership row. This rejects fabricated or ambiguous application parents.
    IF EXISTS (
      SELECT 1
      FROM pg_temp.gate04_authorized_approval_cleanup authorized
      WHERE (
        SELECT count(*)
        FROM public.qhub_applications app
        WHERE app.org_id = 'client-smoke'
          AND app.qhub_app_id = authorized.qhub_app_id
      ) <> 1
      OR EXISTS (
        SELECT 1
        FROM public.qhub_applications app
        WHERE app.org_id = 'other-org-live'
          AND app.qhub_app_id = authorized.qhub_app_id
      )
    ) THEN
      RAISE EXCEPTION 'Gate 04 cleanup aborted: application ownership is not exclusively client-smoke';
    END IF;

    -- No ALLOW claim or committed action for the same app/digest may have
    -- occurred at or after either synthetic approval was created. Combined
    -- with the unconsumed assertions above, this proves neither row authorized
    -- or preceded a successful protected action.
    IF EXISTS (
      SELECT 1
      FROM public.qhub_control_approvals approval
      JOIN pg_temp.gate04_authorized_approval_cleanup authorized
        ON authorized.approval_id = approval.approval_id
      JOIN public.qhub_control_evaluations evaluation
        ON evaluation.qhub_app_id = approval.qhub_app_id
       AND evaluation.action_digest = approval.action_digest
      WHERE (
        evaluation.claimed = TRUE
        OR evaluation.action_event_state = 'COMMITTED'
      )
        AND (
          evaluation.created_at >= approval.created_at
          OR evaluation.claimed_at >= approval.created_at
        )
    ) THEN
      RAISE EXCEPTION 'Gate 04 cleanup aborted: authorized approval may precede a successful action';
    END IF;

    -- Inspect declared foreign-key dependencies on approval_id.
    FOR dependency IN
      SELECT
        child_ns.nspname AS schema_name,
        child.relname AS table_name,
        child_col.attname AS column_name
      FROM pg_constraint fk
      JOIN pg_class child ON child.oid = fk.conrelid
      JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
      JOIN LATERAL unnest(fk.confkey) WITH ORDINALITY referenced(attnum, ord)
        ON TRUE
      JOIN LATERAL unnest(fk.conkey) WITH ORDINALITY dependent(attnum, ord)
        ON dependent.ord = referenced.ord
      JOIN pg_attribute parent_col
        ON parent_col.attrelid = fk.confrelid
       AND parent_col.attnum = referenced.attnum
      JOIN pg_attribute child_col
        ON child_col.attrelid = fk.conrelid
       AND child_col.attnum = dependent.attnum
      WHERE fk.contype = 'f'
        AND fk.confrelid = 'public.qhub_control_approvals'::regclass
        AND parent_col.attname = 'approval_id'
    LOOP
      EXECUTE format(
        'SELECT EXISTS (
           SELECT 1
           FROM %I.%I child
           JOIN pg_temp.gate04_authorized_approval_cleanup authorized
             ON child.%I = authorized.approval_id
         )',
        dependency.schema_name,
        dependency.table_name,
        dependency.column_name
      ) INTO dependent_reference_exists;

      IF dependent_reference_exists THEN
        RAISE EXCEPTION
          'Gate 04 cleanup aborted: approval is referenced by %.%.%',
          dependency.schema_name, dependency.table_name, dependency.column_name;
      END IF;
    END LOOP;

    -- Also search every other public UUID/text/JSON column for either exact
    -- approval identifier. This catches undeclared approval references and
    -- database-resident approval evidence without returning any row contents.
    FOR dependency IN
      SELECT table_schema AS schema_name, table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND NOT (
          table_name = 'qhub_control_approvals'
          AND column_name = 'approval_id'
        )
        AND data_type IN (
          'uuid',
          'text',
          'character varying',
          'json',
          'jsonb',
          'ARRAY'
        )
    LOOP
      EXECUTE format(
        'SELECT EXISTS (
           SELECT 1
           FROM %I.%I child
           CROSS JOIN pg_temp.gate04_authorized_approval_cleanup authorized
           WHERE position(authorized.approval_id::text in child.%I::text) > 0
         )',
        dependency.schema_name,
        dependency.table_name,
        dependency.column_name
      ) INTO dependent_reference_exists;

      IF dependent_reference_exists THEN
        RAISE EXCEPTION
          'Gate 04 cleanup aborted: approval identifier appears in %.%.%',
          dependency.schema_name, dependency.table_name, dependency.column_name;
      END IF;
    END LOOP;

    DELETE FROM public.qhub_control_approvals approval
    USING pg_temp.gate04_authorized_approval_cleanup authorized
    WHERE approval.approval_id = authorized.approval_id;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    IF deleted_count <> 2 THEN
      RAISE EXCEPTION
        'Gate 04 cleanup aborted: expected to delete exactly two rows, deleted %',
        deleted_count;
    END IF;
  END IF;

  SELECT count(*)
    INTO orphan_count
  FROM public.qhub_control_approvals approval
  LEFT JOIN public.qhub_applications app
    ON app.org_id = approval.org_id
   AND app.qhub_app_id = approval.qhub_app_id
  WHERE app.qhub_app_id IS NULL;

  IF orphan_count <> 0 THEN
    RAISE EXCEPTION
      'Gate 04 cleanup aborted: % approval tenant/app orphans remain',
      orphan_count;
  END IF;
END
$$;

-- Repair only the exact malformed identity condition produced by the Gate 04
-- insert bug. The embedded ID is part of the already-hashed deterministic plan
-- body; evaluation and immutable evidence identity are not changed.
CREATE TEMP TABLE gate04_plan_identity_repair
ON COMMIT DROP
AS
SELECT
  ep.enforcement_plan_id AS old_id,
  (ep.plan->>'enforcement_plan_id')::uuid AS intended_id,
  ep.org_id,
  ep.qhub_app_id,
  ep.policy_profile_id,
  ep.policy_profile_version,
  ep.policy_profile_hash,
  ep.enforcement_plan_version,
  ep.enforcement_plan_hash,
  ep.compiler_version,
  ep.policy_catalog_version
FROM public.qhub_enforcement_plans ep
WHERE NULLIF(ep.plan->>'enforcement_plan_id', '') IS NOT NULL
  AND ep.enforcement_plan_id::text <> ep.plan->>'enforcement_plan_id'
  AND EXISTS (
    SELECT 1
    FROM public.qhub_control_evaluations ce
    WHERE ce.enforcement_plan_id = (ep.plan->>'enforcement_plan_id')::uuid
  );

DO $$
DECLARE
  orphan_count BIGINT;
  mapped_orphan_count BIGINT;
  dependency RECORD;
  old_id_referenced BOOLEAN;
BEGIN
  SELECT count(*) INTO orphan_count
  FROM public.qhub_control_evaluations ce
  LEFT JOIN public.qhub_enforcement_plans ep
    ON ep.enforcement_plan_id = ce.enforcement_plan_id
  WHERE ce.enforcement_plan_id IS NOT NULL
    AND ep.enforcement_plan_id IS NULL;

  SELECT count(*) INTO mapped_orphan_count
  FROM public.qhub_control_evaluations ce
  LEFT JOIN public.qhub_enforcement_plans target
    ON target.enforcement_plan_id = ce.enforcement_plan_id
  JOIN pg_temp.gate04_plan_identity_repair repair
    ON repair.intended_id = ce.enforcement_plan_id
  WHERE ce.enforcement_plan_id IS NOT NULL
    AND target.enforcement_plan_id IS NULL;

  IF orphan_count <> mapped_orphan_count THEN
    RAISE EXCEPTION
      'Gate 04 repair aborted: % orphan evaluations but only % exactly reconstructable',
      orphan_count, mapped_orphan_count;
  END IF;

  -- Every old and intended identity must be unique and one-to-one.
  IF EXISTS (
    SELECT old_id FROM pg_temp.gate04_plan_identity_repair
    GROUP BY old_id HAVING count(*) <> 1
  ) OR EXISTS (
    SELECT intended_id FROM pg_temp.gate04_plan_identity_repair
    GROUP BY intended_id HAVING count(*) <> 1
  ) THEN
    RAISE EXCEPTION 'Gate 04 repair aborted: plan identity mapping is not one-to-one';
  END IF;

  -- Every orphan evaluation must have exactly one candidate row.
  IF EXISTS (
    SELECT ce.evaluation_id
    FROM public.qhub_control_evaluations ce
    LEFT JOIN public.qhub_enforcement_plans target
      ON target.enforcement_plan_id = ce.enforcement_plan_id
    LEFT JOIN pg_temp.gate04_plan_identity_repair repair
      ON repair.intended_id = ce.enforcement_plan_id
    WHERE ce.enforcement_plan_id IS NOT NULL
      AND target.enforcement_plan_id IS NULL
    GROUP BY ce.evaluation_id
    HAVING count(repair.old_id) <> 1
  ) THEN
    RAISE EXCEPTION 'Gate 04 repair aborted: orphan does not have exactly one candidate plan';
  END IF;

  -- A pre-existing intended ID is always a collision. Do not silently accept it,
  -- even if an evaluation therefore no longer appears orphaned.
  IF EXISTS (
    SELECT 1
    FROM pg_temp.gate04_plan_identity_repair repair
    JOIN public.qhub_enforcement_plans target
      ON target.enforcement_plan_id = repair.intended_id
    WHERE target.enforcement_plan_id <> repair.old_id
  ) THEN
    RAISE EXCEPTION 'Gate 04 repair aborted: intended enforcement plan id already exists';
  END IF;

  -- Verify every evaluation-to-candidate binding and every canonical plan-body
  -- field that participates in provenance.
  IF EXISTS (
    SELECT 1
    FROM pg_temp.gate04_plan_identity_repair repair
    JOIN public.qhub_enforcement_plans ep
      ON ep.enforcement_plan_id = repair.old_id
    JOIN public.qhub_control_evaluations ce
      ON ce.enforcement_plan_id = repair.intended_id
    WHERE ce.org_id <> repair.org_id
       OR ce.qhub_app_id <> repair.qhub_app_id
       OR ce.policy_profile_id IS DISTINCT FROM repair.policy_profile_id
       OR ce.policy_profile_version IS DISTINCT FROM repair.policy_profile_version
       OR ce.policy_profile_hash <> repair.policy_profile_hash
       OR ce.enforcement_plan_version IS DISTINCT FROM repair.enforcement_plan_version
       OR ce.enforcement_plan_hash <> repair.enforcement_plan_hash
       OR ep.plan->>'enforcement_plan_id' <> repair.intended_id::text
       OR ep.plan->>'qhub_app_id' <> repair.qhub_app_id::text
       OR NULLIF(ep.plan->>'policy_profile_id', '')::uuid
            IS DISTINCT FROM repair.policy_profile_id
       OR NULLIF(ep.plan->>'policy_profile_version', '')::integer
            IS DISTINCT FROM repair.policy_profile_version
       OR ep.plan->>'policy_profile_hash' <> repair.policy_profile_hash
       OR NULLIF(ep.plan->>'enforcement_plan_version', '')::integer
            IS DISTINCT FROM repair.enforcement_plan_version
       OR ep.plan->>'enforcement_plan_hash' <> repair.enforcement_plan_hash
       OR ep.plan->>'compiler_version' <> repair.compiler_version
       OR ep.plan->>'policy_catalog_version' <> repair.policy_catalog_version
  ) THEN
    RAISE EXCEPTION 'Gate 04 repair aborted: tenant, app, policy, hash, version, or compiler binding mismatch';
  END IF;

  -- Each candidate must actually be authoritative for at least one orphan.
  IF EXISTS (
    SELECT 1
    FROM pg_temp.gate04_plan_identity_repair repair
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.qhub_control_evaluations ce
      LEFT JOIN public.qhub_enforcement_plans target
        ON target.enforcement_plan_id = ce.enforcement_plan_id
      WHERE ce.enforcement_plan_id = repair.intended_id
        AND target.enforcement_plan_id IS NULL
    )
  ) THEN
    RAISE EXCEPTION 'Gate 04 repair aborted: candidate plan is not tied to an orphan evaluation';
  END IF;

  -- Inspect every FK dependency discovered through pg_catalog, including
  -- composite foreign keys and dependent columns with different names.
  FOR dependency IN
    SELECT
      child_ns.nspname AS schema_name,
      child.relname AS table_name,
      child_col.attname AS column_name
    FROM pg_constraint fk
    JOIN pg_class child ON child.oid = fk.conrelid
    JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
    JOIN LATERAL unnest(fk.confkey) WITH ORDINALITY referenced(attnum, ord)
      ON TRUE
    JOIN LATERAL unnest(fk.conkey) WITH ORDINALITY dependent(attnum, ord)
      ON dependent.ord = referenced.ord
    JOIN pg_attribute parent_col
      ON parent_col.attrelid = fk.confrelid
     AND parent_col.attnum = referenced.attnum
    JOIN pg_attribute child_col
      ON child_col.attrelid = fk.conrelid
     AND child_col.attnum = dependent.attnum
    WHERE fk.contype = 'f'
      AND fk.confrelid = 'public.qhub_enforcement_plans'::regclass
      AND parent_col.attname = 'enforcement_plan_id'
  LOOP
    EXECUTE format(
      'SELECT EXISTS (
         SELECT 1 FROM %I.%I child
         JOIN pg_temp.gate04_plan_identity_repair repair
           ON child.%I = repair.old_id
       )',
      dependency.schema_name,
      dependency.table_name,
      dependency.column_name
    ) INTO old_id_referenced;

    IF old_id_referenced THEN
      RAISE EXCEPTION
        'Gate 04 repair aborted: old plan id is referenced by %.%.%',
        dependency.schema_name, dependency.table_name, dependency.column_name;
    END IF;
  END LOOP;

  -- Also inspect every UUID enforcement_plan_id column, including tables that
  -- have not yet declared a foreign key.
  FOR dependency IN
    SELECT table_schema AS schema_name, table_name, column_name
    FROM information_schema.columns
    WHERE column_name = 'enforcement_plan_id'
      AND data_type = 'uuid'
      AND NOT (
        table_schema = 'public'
        AND table_name = 'qhub_enforcement_plans'
      )
  LOOP
    EXECUTE format(
      'SELECT EXISTS (
         SELECT 1 FROM %I.%I child
         JOIN pg_temp.gate04_plan_identity_repair repair
           ON child.%I = repair.old_id
       )',
      dependency.schema_name,
      dependency.table_name,
      dependency.column_name
    ) INTO old_id_referenced;

    IF old_id_referenced THEN
      RAISE EXCEPTION
        'Gate 04 repair aborted: old plan id is referenced by %.%.%',
        dependency.schema_name, dependency.table_name, dependency.column_name;
    END IF;
  END LOOP;
END
$$;

UPDATE public.qhub_enforcement_plans ep
SET enforcement_plan_id = (ep.plan->>'enforcement_plan_id')::uuid
FROM pg_temp.gate04_plan_identity_repair repair
WHERE ep.enforcement_plan_id = repair.old_id
  AND (ep.plan->>'enforcement_plan_id')::uuid = repair.intended_id;

-- Complete referential-integrity preflight for every foreign key installed by
-- this migration. Do not discover bad historical data one constraint at a time.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.qhub_enforcement_plans child
    LEFT JOIN public.qhub_applications parent
      ON parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: enforcement plan app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_enforcement_plans child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id
     AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: enforcement plan tenant/app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_applications parent
      ON parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id
     AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation tenant/app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_control_evaluations parent
      ON parent.evaluation_id = child.parent_evaluation_id
    WHERE child.parent_evaluation_id IS NOT NULL
      AND parent.evaluation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation parent orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_control_evaluations parent
      ON parent.org_id = child.org_id
     AND parent.evaluation_id = child.parent_evaluation_id
    WHERE child.parent_evaluation_id IS NOT NULL
      AND parent.evaluation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation tenant/parent orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_enforcement_plans parent
      ON parent.enforcement_plan_id = child.enforcement_plan_id
    WHERE child.enforcement_plan_id IS NOT NULL
      AND parent.enforcement_plan_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation plan orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_evaluations child
    LEFT JOIN public.qhub_enforcement_plans parent
      ON parent.org_id = child.org_id
     AND parent.qhub_app_id = child.qhub_app_id
     AND parent.enforcement_plan_id = child.enforcement_plan_id
    WHERE child.enforcement_plan_id IS NOT NULL
      AND parent.enforcement_plan_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: evaluation tenant/plan orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_approvals child
    LEFT JOIN public.qhub_applications parent
      ON parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: approval app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_approvals child
    LEFT JOIN public.qhub_applications parent
      ON parent.org_id = child.org_id
     AND parent.qhub_app_id = child.qhub_app_id
    WHERE parent.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: approval tenant/app orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_approvals child
    LEFT JOIN public.qhub_control_evaluations parent
      ON parent.evaluation_id = child.consumed_by_evaluation
    WHERE child.consumed_by_evaluation IS NOT NULL
      AND parent.evaluation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: approval consumption orphan';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.qhub_control_approvals child
    LEFT JOIN public.qhub_control_evaluations parent
      ON parent.org_id = child.org_id
     AND parent.evaluation_id = child.consumed_by_evaluation
    WHERE child.consumed_by_evaluation IS NOT NULL
      AND parent.evaluation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 preflight aborted: approval tenant/consumption orphan';
  END IF;
END
$$;

-- ─── Ownership and state integrity ────────────────────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ep_qhub_app') THEN
    ALTER TABLE public.qhub_enforcement_plans
      ADD CONSTRAINT fk_ep_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_qhub_app') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_parent_evaluation') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_parent_evaluation
      FOREIGN KEY (parent_evaluation_id) REFERENCES public.qhub_control_evaluations(evaluation_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_enforcement_plan') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_enforcement_plan
      FOREIGN KEY (enforcement_plan_id) REFERENCES public.qhub_enforcement_plans(enforcement_plan_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ca_qhub_app') THEN
    ALTER TABLE public.qhub_control_approvals
      ADD CONSTRAINT fk_ca_qhub_app
      FOREIGN KEY (qhub_app_id) REFERENCES public.qhub_applications(qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ca_consumed_evaluation') THEN
    ALTER TABLE public.qhub_control_approvals
      ADD CONSTRAINT fk_ca_consumed_evaluation
      FOREIGN KEY (consumed_by_evaluation) REFERENCES public.qhub_control_evaluations(evaluation_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_ce_claim_consistency') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT ck_ce_claim_consistency CHECK (
        (claimed = FALSE AND claimed_at IS NULL)
        OR
        (claimed = TRUE AND claimed_at IS NOT NULL AND decision = 'ALLOW')
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_ca_consumption_consistency') THEN
    ALTER TABLE public.qhub_control_approvals
      ADD CONSTRAINT ck_ca_consumption_consistency CHECK (
        (status = 'CONSUMED' AND consumed_at IS NOT NULL AND consumed_by_evaluation IS NOT NULL)
        OR
        (status <> 'CONSUMED' AND consumed_at IS NULL AND consumed_by_evaluation IS NULL)
      );
  END IF;
END
$$;

ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT ck_ce_claim_consistency;
ALTER TABLE public.qhub_control_approvals
  VALIDATE CONSTRAINT ck_ca_consumption_consistency;

-- Tenant/app-scoped access paths used by every service-role query.
CREATE INDEX IF NOT EXISTS idx_ep_org_app_status
  ON public.qhub_enforcement_plans (org_id, qhub_app_id, status);

CREATE INDEX IF NOT EXISTS idx_ce_org_app_eval
  ON public.qhub_control_evaluations (org_id, qhub_app_id, evaluation_id);

CREATE INDEX IF NOT EXISTS idx_ce_org_action_request
  ON public.qhub_control_evaluations (org_id, action_request_id);

CREATE INDEX IF NOT EXISTS idx_ca_org_app_digest_status
  ON public.qhub_control_approvals (org_id, qhub_app_id, action_digest, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_qhub_apps_org_app
  ON public.qhub_applications (org_id, qhub_app_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ep_org_app_plan
  ON public.qhub_enforcement_plans (org_id, qhub_app_id, enforcement_plan_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ce_org_evaluation
  ON public.qhub_control_evaluations (org_id, evaluation_id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ep_tenant_app') THEN
    ALTER TABLE public.qhub_enforcement_plans
      ADD CONSTRAINT fk_ep_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_tenant_app') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_tenant_parent') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_tenant_parent
      FOREIGN KEY (org_id, parent_evaluation_id)
      REFERENCES public.qhub_control_evaluations(org_id, evaluation_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ce_tenant_plan') THEN
    ALTER TABLE public.qhub_control_evaluations
      ADD CONSTRAINT fk_ce_tenant_plan
      FOREIGN KEY (org_id, qhub_app_id, enforcement_plan_id)
      REFERENCES public.qhub_enforcement_plans(org_id, qhub_app_id, enforcement_plan_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ca_tenant_app') THEN
    ALTER TABLE public.qhub_control_approvals
      ADD CONSTRAINT fk_ca_tenant_app
      FOREIGN KEY (org_id, qhub_app_id)
      REFERENCES public.qhub_applications(org_id, qhub_app_id)
      NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ca_tenant_consumption') THEN
    ALTER TABLE public.qhub_control_approvals
      ADD CONSTRAINT fk_ca_tenant_consumption
      FOREIGN KEY (org_id, consumed_by_evaluation)
      REFERENCES public.qhub_control_evaluations(org_id, evaluation_id)
      NOT VALID;
  END IF;
END
$$;

-- Every staged foreign key must be fully validated before later schema objects
-- are installed or the transaction can commit.
ALTER TABLE public.qhub_enforcement_plans
  VALIDATE CONSTRAINT fk_ep_qhub_app;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_qhub_app;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_parent_evaluation;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_enforcement_plan;
ALTER TABLE public.qhub_control_approvals
  VALIDATE CONSTRAINT fk_ca_qhub_app;
ALTER TABLE public.qhub_control_approvals
  VALIDATE CONSTRAINT fk_ca_consumed_evaluation;
ALTER TABLE public.qhub_enforcement_plans
  VALIDATE CONSTRAINT fk_ep_tenant_app;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_tenant_app;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_tenant_parent;
ALTER TABLE public.qhub_control_evaluations
  VALIDATE CONSTRAINT fk_ce_tenant_plan;
ALTER TABLE public.qhub_control_approvals
  VALIDATE CONSTRAINT fk_ca_tenant_app;
ALTER TABLE public.qhub_control_approvals
  VALIDATE CONSTRAINT fk_ca_tenant_consumption;

-- ─── Explicit service-only RLS posture ───────────────────────────────────────
ALTER TABLE public.qhub_enforcement_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_control_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qhub_control_approvals ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_enforcement_plans'::regclass
      AND polname = 'qhub_enforcement_plans_service_only'
  ) THEN
    CREATE POLICY qhub_enforcement_plans_service_only
      ON public.qhub_enforcement_plans
      AS RESTRICTIVE
      FOR ALL
      TO anon, authenticated
      USING (FALSE)
      WITH CHECK (FALSE);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_control_evaluations'::regclass
      AND polname = 'qhub_control_evaluations_service_only'
  ) THEN
    CREATE POLICY qhub_control_evaluations_service_only
      ON public.qhub_control_evaluations
      AS RESTRICTIVE
      FOR ALL
      TO anon, authenticated
      USING (FALSE)
      WITH CHECK (FALSE);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_control_approvals'::regclass
      AND polname = 'qhub_control_approvals_service_only'
  ) THEN
    CREATE POLICY qhub_control_approvals_service_only
      ON public.qhub_control_approvals
      AS RESTRICTIVE
      FOR ALL
      TO anon, authenticated
      USING (FALSE)
      WITH CHECK (FALSE);
  END IF;
END
$$;

REVOKE ALL ON TABLE public.qhub_enforcement_plans FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_control_evaluations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.qhub_control_approvals FROM PUBLIC, anon, authenticated;

GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_enforcement_plans TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_control_evaluations TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_control_approvals TO service_role;

-- ─── Atomic service-role transitions ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_claim_control_evaluation(
  p_evaluation_id UUID,
  p_org_id TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  changed_rows INTEGER;
BEGIN
  UPDATE public.qhub_control_evaluations
     SET claimed = TRUE,
         claimed_at = clock_timestamp(),
         action_event_state = 'PENDING'
   WHERE evaluation_id = p_evaluation_id
     AND org_id = p_org_id
     AND decision = 'ALLOW'
     AND claimed = FALSE;

  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  RETURN changed_rows = 1;
END
$$;

CREATE OR REPLACE FUNCTION public.qhub_consume_control_approvals(
  p_qhub_app_id UUID,
  p_org_id TEXT,
  p_action_digest TEXT,
  p_evaluation_id UUID
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  changed_rows INTEGER;
BEGIN
  UPDATE public.qhub_control_approvals
     SET status = 'CONSUMED',
         consumed_at = clock_timestamp(),
         consumed_by_evaluation = p_evaluation_id
   WHERE qhub_app_id = p_qhub_app_id
     AND org_id = p_org_id
     AND action_digest = p_action_digest
     AND single_use = TRUE
     AND status = 'GRANTED'
     AND expires_at > clock_timestamp();

  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  RETURN changed_rows;
END
$$;

REVOKE ALL ON FUNCTION public.qhub_claim_control_evaluation(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qhub_claim_control_evaluation(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.qhub_claim_control_evaluation(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_claim_control_evaluation(UUID, TEXT) TO service_role;

REVOKE ALL ON FUNCTION public.qhub_consume_control_approvals(UUID, TEXT, TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qhub_consume_control_approvals(UUID, TEXT, TEXT, UUID) FROM anon;
REVOKE ALL ON FUNCTION public.qhub_consume_control_approvals(UUID, TEXT, TEXT, UUID) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_consume_control_approvals(UUID, TEXT, TEXT, UUID) TO service_role;

-- ─── Metadata-only Gate 04 verifier ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_verify_governance_schema()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
WITH index_shape AS (
  SELECT
    i.indexrelid,
    i.indrelid,
    i.indisunique,
    pg_get_expr(i.indpred, i.indrelid) AS predicate,
    ARRAY(
      SELECT a.attname
      FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
      WHERE k.attnum > 0
      ORDER BY k.ord
    ) AS columns
  FROM pg_index i
),
checks(identifier, category, ready, reason_code) AS (
  VALUES
    ('table.enforcement_plans', 'TABLE',
      to_regclass('public.qhub_enforcement_plans') IS NOT NULL, 'TABLE_MISSING'),
    ('table.control_evaluations', 'TABLE',
      to_regclass('public.qhub_control_evaluations') IS NOT NULL, 'TABLE_MISSING'),
    ('table.control_approvals', 'TABLE',
      to_regclass('public.qhub_control_approvals') IS NOT NULL, 'TABLE_MISSING'),

    ('column.plan_hash', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_enforcement_plans'
        AND column_name = 'enforcement_plan_hash' AND is_nullable = 'NO'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.evaluation_claim', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_evaluations'
        AND column_name = 'claimed' AND data_type = 'boolean' AND is_nullable = 'NO'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.evaluation_action_request', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_evaluations'
        AND column_name = 'action_request_id' AND data_type = 'uuid' AND is_nullable = 'NO'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.evaluation_idempotency', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_evaluations'
        AND column_name = 'idempotency_key'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.approval_binding', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_approvals'
        AND column_name = 'scoped_enforcement_plan_hash' AND is_nullable = 'NO'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.approval_consumption', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_approvals'
        AND column_name = 'consumed_by_evaluation'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.kill_switch', 'COLUMN', EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_applications'
        AND column_name = 'kill_switch_active' AND data_type = 'boolean' AND is_nullable = 'NO'
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.enforcement_plan_contract', 'COLUMN', (
      SELECT count(*) = 17
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_enforcement_plans'
        AND column_name = ANY(ARRAY[
          'enforcement_plan_id','org_id','qhub_app_id','enforcement_plan_version',
          'classification_version','policy_profile_id','policy_profile_version',
          'policy_profile_hash','policy_catalog_version','risk_tier',
          'enforcement_plan_hash','plan','status','compiler_version','generated_at',
          'generated_by','created_at'
        ])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.control_evaluation_contract', 'COLUMN', (
      SELECT count(*) = 28
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_evaluations'
        AND column_name = ANY(ARRAY[
          'evaluation_id','action_request_id','parent_evaluation_id','org_id',
          'qhub_app_id','action_type','action_digest','environment','decision',
          'reason_codes','policy_profile_id','policy_profile_version',
          'policy_profile_hash','enforcement_plan_id','enforcement_plan_version',
          'enforcement_plan_hash','control_results','control_results_hash',
          'required_attestations','evaluator_version','enforcement_mode',
          'idempotency_key','claimed','claimed_at','action_event_state',
          'evaluated_at','created_by','created_at'
        ])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.control_approval_contract', 'COLUMN', (
      SELECT count(*) = 16
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_control_approvals'
        AND column_name = ANY(ARRAY[
          'approval_id','org_id','qhub_app_id','attestation_type','action_digest',
          'scoped_policy_profile_hash','scoped_enforcement_plan_hash','approver_id',
          'approver_role','single_use','status','expires_at',
          'consumed_by_evaluation','created_by','created_at','consumed_at'
        ])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.kill_switch_contract', 'COLUMN', (
      SELECT count(*) = 4
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'qhub_applications'
        AND column_name = ANY(ARRAY[
          'kill_switch_active','kill_switch_reason','kill_switch_set_by','kill_switch_set_at'
        ])
    ), 'COLUMN_MISSING_OR_MISMATCH'),

    ('constraint.evaluation_pk', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conrelid = 'public.qhub_control_evaluations'::regclass
        AND c.contype = 'p'
        AND ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n,o)
                  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.o)
            = ARRAY['evaluation_id']::name[]
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.plan_pk', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conrelid = 'public.qhub_enforcement_plans'::regclass
        AND c.contype = 'p'
        AND ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n,o)
                  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.o)
            = ARRAY['enforcement_plan_id']::name[]
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.approval_pk', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conrelid = 'public.qhub_control_approvals'::regclass
        AND c.contype = 'p'
        AND ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n,o)
                  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.o)
            = ARRAY['approval_id']::name[]
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.action_request_unique', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conrelid = 'public.qhub_control_evaluations'::regclass
        AND c.contype = 'u'
        AND ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n,o)
                  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.o)
            = ARRAY['action_request_id']::name[]
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.valid_decision', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'public.qhub_control_evaluations'::regclass
        AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%ALLOW%'
        AND pg_get_constraintdef(oid) LIKE '%DENY%'
        AND pg_get_constraintdef(oid) LIKE '%REQUIRE_APPROVAL%'
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.valid_plan_status', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'public.qhub_enforcement_plans'::regclass
        AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%ACTIVE%'
        AND pg_get_constraintdef(oid) LIKE '%SUPERSEDED%'
        AND pg_get_constraintdef(oid) LIKE '%SUSPENDED%'
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.approval_binding_unique', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conrelid = 'public.qhub_control_approvals'::regclass
        AND c.contype = 'u'
        AND ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n,o)
                  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.o)
            = ARRAY['qhub_app_id','action_digest','attestation_type','approver_id']::name[]
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.claim_consistency', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'public.qhub_control_evaluations'::regclass
        AND conname = 'ck_ce_claim_consistency' AND contype = 'c'
        AND convalidated
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.approval_consumption', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'public.qhub_control_approvals'::regclass
        AND conname = 'ck_ca_consumption_consistency' AND contype = 'c'
        AND convalidated
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.base_foreign_keys', 'CONSTRAINT', (
      SELECT count(*) = 6 FROM pg_constraint
      WHERE contype = 'f'
        AND convalidated
        AND conname IN (
          'fk_ep_qhub_app',
          'fk_ce_qhub_app',
          'fk_ce_parent_evaluation',
          'fk_ce_enforcement_plan',
          'fk_ca_qhub_app',
          'fk_ca_consumed_evaluation'
        )
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.app_ownership', 'CONSTRAINT', (
      SELECT count(*) = 3 FROM pg_constraint
      WHERE contype = 'f'
        AND convalidated
        AND conname IN ('fk_ep_tenant_app', 'fk_ce_tenant_app', 'fk_ca_tenant_app')
        AND pg_get_constraintdef(oid) LIKE '%FOREIGN KEY (org_id, qhub_app_id)%'
        AND pg_get_constraintdef(oid) LIKE '%qhub_applications(org_id, qhub_app_id)%'
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),
    ('constraint.tenant_references', 'CONSTRAINT', (
      SELECT count(*) = 3 FROM pg_constraint
      WHERE contype = 'f'
        AND convalidated
        AND conname IN ('fk_ce_tenant_parent', 'fk_ce_tenant_plan', 'fk_ca_tenant_consumption')
        AND pg_get_constraintdef(oid) LIKE '%FOREIGN KEY (org_id,%'
    ), 'CONSTRAINT_MISSING_OR_MISMATCH'),

    ('index.active_plan_unique', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_enforcement_plans'::regclass
        AND indisunique
        AND columns = ARRAY['qhub_app_id']::name[]
        AND regexp_replace(coalesce(predicate,''), '\s+', ' ', 'g') = '(status = ''ACTIVE''::text)'
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.evaluation_idempotency', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_control_evaluations'::regclass
        AND indisunique
        AND columns = ARRAY['org_id','qhub_app_id','idempotency_key']::name[]
        AND regexp_replace(coalesce(predicate,''), '\s+', ' ', 'g') = '(idempotency_key IS NOT NULL)'
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.evaluation_tenant_lookup', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_control_evaluations'::regclass
        AND columns = ARRAY['org_id','qhub_app_id','evaluation_id']::name[]
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.evaluation_digest_lookup', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_control_evaluations'::regclass
        AND columns = ARRAY['action_digest']::name[]
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.plan_tenant_lookup', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_enforcement_plans'::regclass
        AND columns = ARRAY['org_id','qhub_app_id','status']::name[]
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.approval_lookup', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_control_approvals'::regclass
        AND columns = ARRAY['org_id','qhub_app_id','action_digest','status']::name[]
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.kill_switch_lookup', 'INDEX', EXISTS (
      SELECT 1 FROM index_shape
      WHERE indrelid = 'public.qhub_applications'::regclass
        AND indisunique
        AND columns = ARRAY['org_id','qhub_app_id']::name[]
    ), 'INDEX_MISSING_OR_MISMATCH'),

    ('rls.enforcement_plans', 'RLS_ENABLED', EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid = 'public.qhub_enforcement_plans'::regclass AND relrowsecurity
    ), 'RLS_DISABLED'),
    ('rls.control_evaluations', 'RLS_ENABLED', EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid = 'public.qhub_control_evaluations'::regclass AND relrowsecurity
    ), 'RLS_DISABLED'),
    ('rls.control_approvals', 'RLS_ENABLED', EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid = 'public.qhub_control_approvals'::regclass AND relrowsecurity
    ), 'RLS_DISABLED'),
    ('rls.applications', 'RLS_ENABLED', EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid = 'public.qhub_applications'::regclass AND relrowsecurity
    ), 'RLS_DISABLED'),
    ('policy.enforcement_plans_service_only', 'RLS_POLICY', EXISTS (
      SELECT 1 FROM pg_policy
      WHERE polrelid = 'public.qhub_enforcement_plans'::regclass
        AND polname = 'qhub_enforcement_plans_service_only' AND NOT polpermissive
        AND pg_get_expr(polqual, polrelid) = 'false'
        AND pg_get_expr(polwithcheck, polrelid) = 'false'
    ), 'RLS_POLICY_MISSING_OR_MISMATCH'),
    ('policy.control_evaluations_service_only', 'RLS_POLICY', EXISTS (
      SELECT 1 FROM pg_policy
      WHERE polrelid = 'public.qhub_control_evaluations'::regclass
        AND polname = 'qhub_control_evaluations_service_only' AND NOT polpermissive
        AND pg_get_expr(polqual, polrelid) = 'false'
        AND pg_get_expr(polwithcheck, polrelid) = 'false'
    ), 'RLS_POLICY_MISSING_OR_MISMATCH'),
    ('policy.control_approvals_service_only', 'RLS_POLICY', EXISTS (
      SELECT 1 FROM pg_policy
      WHERE polrelid = 'public.qhub_control_approvals'::regclass
        AND polname = 'qhub_control_approvals_service_only' AND NOT polpermissive
        AND pg_get_expr(polqual, polrelid) = 'false'
        AND pg_get_expr(polwithcheck, polrelid) = 'false'
    ), 'RLS_POLICY_MISSING_OR_MISMATCH'),
    ('policy.app_tenant_isolation', 'RLS_POLICY', EXISTS (
      SELECT 1 FROM pg_policy
      WHERE polrelid = 'public.qhub_applications'::regclass
        AND polname = 'qhub_applications_tenant_isolation'
    ), 'RLS_POLICY_MISSING_OR_MISMATCH'),
    ('policy.no_broad_client_access', 'RLS_POLICY', NOT EXISTS (
      SELECT 1
      FROM pg_policy p
      WHERE p.polrelid IN (
        'public.qhub_enforcement_plans'::regclass,
        'public.qhub_control_evaluations'::regclass,
        'public.qhub_control_approvals'::regclass
        )
        AND p.polpermissive
        AND (
          0::oid = ANY(p.polroles)
          OR EXISTS (
            SELECT 1 FROM pg_roles r
            WHERE r.oid = ANY(p.polroles)
              AND r.rolname IN ('anon', 'authenticated')
          )
        )
    ), 'RLS_POLICY_BROAD_CLIENT_ACCESS'),
    ('policy.no_direct_client_table_privileges', 'RLS_POLICY',
      NOT (
        has_table_privilege('anon', 'public.qhub_enforcement_plans', 'SELECT')
        OR has_table_privilege('anon', 'public.qhub_enforcement_plans', 'INSERT')
        OR has_table_privilege('anon', 'public.qhub_enforcement_plans', 'UPDATE')
        OR has_table_privilege('anon', 'public.qhub_enforcement_plans', 'DELETE')
        OR has_table_privilege('authenticated', 'public.qhub_enforcement_plans', 'SELECT')
        OR has_table_privilege('authenticated', 'public.qhub_enforcement_plans', 'INSERT')
        OR has_table_privilege('authenticated', 'public.qhub_enforcement_plans', 'UPDATE')
        OR has_table_privilege('authenticated', 'public.qhub_enforcement_plans', 'DELETE')
        OR has_table_privilege('anon', 'public.qhub_control_evaluations', 'SELECT')
        OR has_table_privilege('anon', 'public.qhub_control_evaluations', 'INSERT')
        OR has_table_privilege('anon', 'public.qhub_control_evaluations', 'UPDATE')
        OR has_table_privilege('anon', 'public.qhub_control_evaluations', 'DELETE')
        OR has_table_privilege('authenticated', 'public.qhub_control_evaluations', 'SELECT')
        OR has_table_privilege('authenticated', 'public.qhub_control_evaluations', 'INSERT')
        OR has_table_privilege('authenticated', 'public.qhub_control_evaluations', 'UPDATE')
        OR has_table_privilege('authenticated', 'public.qhub_control_evaluations', 'DELETE')
        OR has_table_privilege('anon', 'public.qhub_control_approvals', 'SELECT')
        OR has_table_privilege('anon', 'public.qhub_control_approvals', 'INSERT')
        OR has_table_privilege('anon', 'public.qhub_control_approvals', 'UPDATE')
        OR has_table_privilege('anon', 'public.qhub_control_approvals', 'DELETE')
        OR has_table_privilege('authenticated', 'public.qhub_control_approvals', 'SELECT')
        OR has_table_privilege('authenticated', 'public.qhub_control_approvals', 'INSERT')
        OR has_table_privilege('authenticated', 'public.qhub_control_approvals', 'UPDATE')
        OR has_table_privilege('authenticated', 'public.qhub_control_approvals', 'DELETE')
      )
      AND has_table_privilege('service_role', 'public.qhub_enforcement_plans', 'SELECT')
      AND has_table_privilege('service_role', 'public.qhub_enforcement_plans', 'INSERT')
      AND has_table_privilege('service_role', 'public.qhub_enforcement_plans', 'UPDATE')
      AND has_table_privilege('service_role', 'public.qhub_control_evaluations', 'SELECT')
      AND has_table_privilege('service_role', 'public.qhub_control_evaluations', 'INSERT')
      AND has_table_privilege('service_role', 'public.qhub_control_evaluations', 'UPDATE')
      AND has_table_privilege('service_role', 'public.qhub_control_approvals', 'SELECT')
      AND has_table_privilege('service_role', 'public.qhub_control_approvals', 'INSERT')
      AND has_table_privilege('service_role', 'public.qhub_control_approvals', 'UPDATE'),
      'RLS_POLICY_BROAD_CLIENT_ACCESS'),

    ('function.atomic_claim', 'FUNCTION',
      to_regprocedure('public.qhub_claim_control_evaluation(uuid,text)') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc
           WHERE oid = 'public.qhub_claim_control_evaluation(uuid,text)'::regprocedure)
      AND (SELECT proconfig @> ARRAY['search_path=pg_catalog, public']
           FROM pg_proc WHERE oid = 'public.qhub_claim_control_evaluation(uuid,text)'::regprocedure)
      AND NOT has_function_privilege('anon',
        'public.qhub_claim_control_evaluation(uuid,text)', 'EXECUTE')
      AND NOT has_function_privilege('authenticated',
        'public.qhub_claim_control_evaluation(uuid,text)', 'EXECUTE')
      AND has_function_privilege('service_role',
        'public.qhub_claim_control_evaluation(uuid,text)', 'EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED'),
    ('function.atomic_approval_consumption', 'FUNCTION',
      to_regprocedure('public.qhub_consume_control_approvals(uuid,text,text,uuid)') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc
           WHERE oid = 'public.qhub_consume_control_approvals(uuid,text,text,uuid)'::regprocedure)
      AND (SELECT proconfig @> ARRAY['search_path=pg_catalog, public']
           FROM pg_proc WHERE oid = 'public.qhub_consume_control_approvals(uuid,text,text,uuid)'::regprocedure)
      AND NOT has_function_privilege('anon',
        'public.qhub_consume_control_approvals(uuid,text,text,uuid)', 'EXECUTE')
      AND NOT has_function_privilege('authenticated',
        'public.qhub_consume_control_approvals(uuid,text,text,uuid)', 'EXECUTE')
      AND has_function_privilege('service_role',
        'public.qhub_consume_control_approvals(uuid,text,text,uuid)', 'EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED'),
    ('function.metadata_verifier', 'FUNCTION',
      to_regprocedure('public.qhub_verify_governance_schema()') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc
           WHERE oid = 'public.qhub_verify_governance_schema()'::regprocedure)
      AND (SELECT provolatile = 's' FROM pg_proc
           WHERE oid = 'public.qhub_verify_governance_schema()'::regprocedure)
      AND NOT has_function_privilege('anon',
        'public.qhub_verify_governance_schema()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated',
        'public.qhub_verify_governance_schema()', 'EXECUTE')
      AND has_function_privilege('service_role',
        'public.qhub_verify_governance_schema()', 'EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED')
),
normalized AS (
  SELECT
    identifier,
    category,
    ready,
    CASE WHEN ready THEN 'OK' ELSE reason_code END AS reason_code
  FROM checks
)
SELECT jsonb_build_object(
  'expected_version', '2026-07-26.gate04',
  'ready', bool_and(ready),
  'checks', jsonb_agg(
    jsonb_build_object(
      'identifier', identifier,
      'category', category,
      'ready', ready,
      'reason_code', reason_code
    )
    ORDER BY category, identifier
  )
)
FROM normalized
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_governance_schema() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qhub_verify_governance_schema() FROM anon;
REVOKE ALL ON FUNCTION public.qhub_verify_governance_schema() FROM authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_governance_schema() TO service_role;

COMMENT ON FUNCTION public.qhub_verify_governance_schema() IS
  'Gate 04 service-role-only metadata verifier. Returns compact readiness checks without SQL definitions, policy expressions, credentials, or customer data.';

DO $$
DECLARE
  readiness JSONB;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.qhub_control_evaluations ce
    LEFT JOIN public.qhub_enforcement_plans ep
      ON ep.enforcement_plan_id = ce.enforcement_plan_id
    WHERE ce.enforcement_plan_id IS NOT NULL
      AND ep.enforcement_plan_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 schema assurance aborted: orphan enforcement plan reference remains';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.qhub_control_approvals approval
    LEFT JOIN public.qhub_applications app
      ON app.org_id = approval.org_id
     AND app.qhub_app_id = approval.qhub_app_id
    WHERE app.qhub_app_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Gate 04 schema assurance aborted: orphan approval tenant/app reference remains';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname IN (
      'fk_ep_qhub_app',
      'fk_ce_qhub_app',
      'fk_ce_parent_evaluation',
      'fk_ce_enforcement_plan',
      'fk_ca_qhub_app',
      'fk_ca_consumed_evaluation',
      'fk_ep_tenant_app',
      'fk_ce_tenant_app',
      'fk_ce_tenant_parent',
      'fk_ce_tenant_plan',
      'fk_ca_tenant_app',
      'fk_ca_tenant_consumption',
      'ck_ce_claim_consistency',
      'ck_ca_consumption_consistency'
    )
      AND NOT convalidated
  ) THEN
    RAISE EXCEPTION 'Gate 04 schema assurance aborted: required constraint remains unvalidated';
  END IF;

  SELECT public.qhub_verify_governance_schema()
    INTO readiness;

  IF readiness->>'expected_version' <> '2026-07-26.gate04'
     OR COALESCE((readiness->>'ready')::boolean, FALSE) IS NOT TRUE THEN
    RAISE EXCEPTION 'Gate 04 schema assurance aborted: metadata self-verification is not ready';
  END IF;
END
$$;

COMMIT;
