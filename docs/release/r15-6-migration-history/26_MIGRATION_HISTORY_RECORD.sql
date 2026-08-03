-- ============================================================================
-- QHUB R15.6 — 26 MIGRATION-HISTORY RECORD (ONE TRANSACTION — PREPARED, NOT YET
-- AUTHORIZED FOR EXECUTION)
--
-- Records EXACTLY ONE migration-history row and changes NOTHING else:
--
--   INSERT INTO supabase_migrations.schema_migrations (version, name)
--   VALUES ('20260729', 'commercial_launch_foundation');
--
-- Both values are DERIVED, not guessed: the pinned project CLI (supabase@2.110.0)
-- parses migration filenames with ^([0-9]+)_(.*)\.sql$ and records
-- (version, name, statements) into supabase_migrations.schema_migrations —
-- contract extracted verbatim offline from the installed CLI binary. Applied to
-- the committed file supabase/migrations/20260729_commercial_launch_foundation.sql
-- (SHA-256 1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755)
-- that yields version '20260729' and name 'commercial_launch_foundation'.
--
-- WHY SQL AND NOT `supabase migration repair --status applied 20260729`:
-- the installed CLI's repair path was extracted verbatim and performs
--   INSERT ... ON CONFLICT (version) DO UPDATE
--     SET name = EXCLUDED.name, statements = EXCLUDED.statements
-- i.e. it SILENTLY OVERWRITES a conflicting row, cannot refuse ambiguous history
-- state, and cannot gate on the commercial verifier being READY. This artifact
-- implements the identical single-row outcome with every refusal the CLI lacks.
--
-- `statements` is deliberately left NULL. The CLI-parsed statement split is not
-- derivable offline with byte certainty, so it is not fabricated; the column is
-- nullable in the CLI's own DDL, the CLI's version-comparison paths
-- (migration list / db push) key on `version` alone, and its read query
-- tolerates NULL (`coalesce(name, '')`, statements unprojected in comparisons).
--
-- FAIL-CLOSED GATES (each raises a deterministic exception BEFORE the insert;
-- any exception rolls back the entire transaction; nothing is normalized):
--   unexpected_runtime_verifier_state      verifier missing or body not an
--                                          approved digest
--   unexpected_runtime_verifier_authority  verifier not SECURITY DEFINER, wrong
--                                          search_path, or wrong owner
--   migration_history_product_not_ready    verifier != ready/version/failed=[]
--   unexpected_migration_history_shape     supabase_migrations.schema_migrations
--                                          missing, or columns/PK differ from the
--                                          CLI contract, or an unexpected
--                                          mandatory column exists
--   migration_history_conflict             20260729 recorded under another name,
--                                          the name recorded under another
--                                          version, partial/legacy row, or any
--                                          version newer than 20260729
--
-- IDEMPOTENT: if exactly one row (20260729, commercial_launch_foundation)
-- already exists, no insert happens and the result reports
-- ALREADY_RECORDED_EXACTLY. A second run after success is a clean no-op.
--
-- MUTATION INVENTORY (complete): at most ONE row inserted into
-- supabase_migrations.schema_migrations, plus one session-temporary audit row in
-- pg_temp (dropped automatically at session end). No schema, function, trigger,
-- ACL, policy, role, application-table, founder, entitlement, billing or Stripe
-- change of any kind. The commercial migration is NOT re-executed.
--
-- Run ONCE, in full, only after 25_PRE_MIGRATION_HISTORY_VERIFY.sql returned
-- SAFE_TO_RECORD_MIGRATION_HISTORY (or ALREADY_RECORDED_EXACTLY, where running
-- this file is a permitted no-op). The FINAL SELECT is the audit record —
-- capture it.
--
-- TRANSFER SAFELY OR NOT AT ALL:
--   Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
-- ============================================================================

CREATE TEMP TABLE IF NOT EXISTS r15_6_history_audit (
  at            timestamptz NOT NULL DEFAULT now(),
  action        text        NOT NULL,
  detail        text        NOT NULL
);

BEGIN;

DO $r15_6_record$
DECLARE
  v_oid oid;
  v_md5 text;
  v_owner_oid oid;
  v_reloid oid;
  v_json jsonb;
  v_target int;
  v_exact int;
  v_name_conflict int;
  v_newer int;
  v_detail text;
BEGIN
  -- GATE 1 — verifier body must be an approved reviewed encoding.
  v_oid := to_regprocedure('public.qhub_verify_commercial_schema()');
  IF v_oid IS NULL THEN
    RAISE EXCEPTION 'unexpected_runtime_verifier_state: public.qhub_verify_commercial_schema() is missing. No change was made - STOP and escalate.';
  END IF;

  SELECT md5(p.prosrc) INTO v_md5 FROM pg_proc p WHERE p.oid = v_oid;
  IF v_md5 NOT IN ('1c6f85b4cb410dc4ca307ed22ee1de47',   -- reviewed R15.6 body, LF
                   '42b43aaa01a770dc7d4a2a0d2f7f33b6') THEN -- reviewed R15.6 body, CRLF
    RAISE EXCEPTION 'unexpected_runtime_verifier_state: live verifier body (md5=%) is not a reviewed encoding. No change was made - STOP and escalate.', v_md5;
  END IF;

  -- GATE 2 — verifier authority.
  SELECT c.relowner INTO v_owner_oid FROM pg_class c
   WHERE c.oid = to_regclass('public.qhub_manual_review_requests');
  IF v_owner_oid IS NULL THEN
    RAISE EXCEPTION 'unexpected_runtime_verifier_authority: cannot resolve the contract owner from public.qhub_manual_review_requests. No change was made.';
  END IF;

  PERFORM 1 FROM pg_proc p
   WHERE p.oid = v_oid AND p.prosecdef
     AND p.proconfig = ARRAY['search_path=pg_catalog, public']
     AND p.proowner = v_owner_oid;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unexpected_runtime_verifier_authority: the live verifier is not SECURITY DEFINER with the exact search_path and owner. No change was made - STOP and escalate.';
  END IF;

  -- GATE 3 — the PRODUCT must verify READY on this exact snapshot. The digest
  -- and authority gates above have already proven this is the reviewed verifier,
  -- so invoking it here executes only reviewed code.
  EXECUTE 'SELECT public.qhub_verify_commercial_schema()' INTO v_json;
  IF NOT (v_json ->> 'ready' = 'true'
          AND v_json ->> 'expected_version' = '2026-07-30.commercial-launch-r8'
          AND jsonb_array_length(v_json -> 'failed') = 0) THEN
    RAISE EXCEPTION 'migration_history_product_not_ready: verifier returned % - the database is not in the verified state; history must not be recorded. No change was made.', v_json::text;
  END IF;

  -- GATE 4 — the history table must match the pinned CLI contract exactly.
  v_reloid := to_regclass('supabase_migrations.schema_migrations');
  IF v_reloid IS NULL THEN
    RAISE EXCEPTION 'unexpected_migration_history_shape: supabase_migrations.schema_migrations does not exist. This package does not create it - STOP and escalate.';
  END IF;

  SELECT string_agg(fail, ', ') INTO v_detail FROM (
    SELECT 'version column not text NOT NULL' AS fail
      WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = v_reloid AND a.attname = 'version'
                AND NOT a.attisdropped AND a.atttypid = 'text'::regtype AND a.attnotnull)
    UNION ALL
    SELECT 'name column not text'
      WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = v_reloid AND a.attname = 'name'
                AND NOT a.attisdropped AND a.atttypid = 'text'::regtype)
    UNION ALL
    SELECT 'statements column not text[]'
      WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = v_reloid AND a.attname = 'statements'
                AND NOT a.attisdropped AND a.atttypid = 'text[]'::regtype)
    UNION ALL
    SELECT 'primary key is not exactly (version)'
      WHERE NOT EXISTS (SELECT 1 FROM pg_constraint c
              WHERE c.conrelid = v_reloid AND c.contype = 'p'
                AND (SELECT array_agg(att.attname::text ORDER BY k.ord)
                       FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
                       JOIN pg_attribute att
                         ON att.attrelid = c.conrelid AND att.attnum = k.attnum)
                    = ARRAY['version'])
    UNION ALL
    SELECT 'unexpected mandatory column ' || a.attname
      FROM pg_attribute a
     WHERE a.attrelid = v_reloid AND a.attnum > 0 AND NOT a.attisdropped
       AND a.attname <> 'version' AND a.attnotnull AND NOT a.atthasdef
  ) s;
  IF v_detail IS NOT NULL THEN
    RAISE EXCEPTION 'unexpected_migration_history_shape: % - the live history table does not match the pinned CLI contract. No change was made - STOP and escalate.', v_detail;
  END IF;

  -- GATE 5 — conflict refusal. Any ambiguous state is a human decision, never a
  -- repair. (The CLI upsert would silently overwrite these; this artifact never
  -- does.)
  SELECT count(*) INTO v_target FROM supabase_migrations.schema_migrations
   WHERE version = '20260729';
  SELECT count(*) INTO v_exact FROM supabase_migrations.schema_migrations
   WHERE version = '20260729' AND name = 'commercial_launch_foundation';
  SELECT count(*) INTO v_name_conflict FROM supabase_migrations.schema_migrations
   WHERE name = 'commercial_launch_foundation' AND version <> '20260729';
  SELECT count(*) INTO v_newer FROM supabase_migrations.schema_migrations
   WHERE version > '20260729';

  IF v_name_conflict <> 0 THEN
    RAISE EXCEPTION 'migration_history_conflict: name commercial_launch_foundation is recorded under % other version(s). No change was made - STOP and escalate.', v_name_conflict;
  END IF;
  IF v_newer <> 0 THEN
    RAISE EXCEPTION 'migration_history_conflict: % history row(s) carry a version newer than 20260729, which no committed migration explains. No change was made - STOP and escalate.', v_newer;
  END IF;
  IF v_target <> 0 AND v_exact <> v_target THEN
    RAISE EXCEPTION 'migration_history_conflict: version 20260729 is recorded with an unexpected or missing name (partial/legacy row). This artifact never overwrites - STOP and escalate.';
  END IF;

  -- RECORD (or clean idempotent no-op).
  IF v_target = 0 THEN
    INSERT INTO supabase_migrations.schema_migrations (version, name)
    VALUES ('20260729', 'commercial_launch_foundation');

    INSERT INTO r15_6_history_audit (action, detail)
    VALUES ('RECORDED_NOW',
            'inserted (20260729, commercial_launch_foundation); statements intentionally NULL');
  ELSE
    INSERT INTO r15_6_history_audit (action, detail)
    VALUES ('ALREADY_RECORDED_EXACTLY',
            'exactly one row (20260729, commercial_launch_foundation) already present; no insert performed');
  END IF;
END;
$r15_6_record$;

COMMIT;

-- ---------------------------------------------------------------------------
-- AUDIT RECORD — the exact mutation result plus the committed history row.
-- Capture this output verbatim in the execution log.
-- ---------------------------------------------------------------------------
SELECT
  a.at                                                                 AS executed_at,
  a.action,
  a.detail,
  m.version                                                            AS history_version,
  m.name                                                               AS history_name,
  coalesce(cardinality(m.statements)::text, 'null')                    AS history_statements_cardinality,
  (SELECT count(*) FROM supabase_migrations.schema_migrations
    WHERE version = '20260729')                                        AS rows_for_version,
  (SELECT count(*) FROM supabase_migrations.schema_migrations)         AS total_history_rows
FROM r15_6_history_audit a
CROSS JOIN supabase_migrations.schema_migrations m
WHERE m.version = '20260729'
ORDER BY a.at DESC
LIMIT 1;
