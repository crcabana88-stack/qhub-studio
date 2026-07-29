-- QHUB Agent Framework — AGENT RUN-STEP RESULT CONTINUITY (authoritative, additive)
-- supabase/migrations/20260728_agent_run_step_result_continuity.sql
--
-- Server-owned, DATABASE-ENFORCED terminalization + result-continuity contract for
-- governed run steps, hardened through independent (Codex) review — R3.
--
-- Authorization is PRIVILEGE-BASED, not flag-based: service_role (and PUBLIC/anon/
-- authenticated) hold NO direct INSERT/UPDATE/DELETE on qhub_agent_run_steps or the
-- receipt-binding table — only SELECT. Rows are written EXCLUSIVELY through SECURITY
-- DEFINER RPCs owned by the migration owner: qhub_create_agent_run_step_pending
-- (nonterminal, DB-contiguous), qhub_bind_governed_action_receipt (authoritative
-- receipt binding), and qhub_finalize_agent_run_step (terminal). No caller-settable
-- GUC is trusted. Defensive triggers independently enforce every row invariant and
-- immutability, and recompute result_hash from authoritative records.
--
-- R3 receipt authority: a terminal EXECUTED/SIMULATED step requires an immutable row
-- in qhub_governed_action_receipt_bindings proving the receipt + durable ledger
-- evidence commitment bind to the EXACT run/agent/version/release/evaluation/action-
-- digest/policy/plan. The binding RPC derives all ownership from authoritative rows
-- (never caller assertions) and requires COMMITTED Gate 04 evidence. The finalizer
-- sources the canonical receipt_id from the binding row, not caller text.
--
-- The pending RPC computes the contiguous next step_index (MAX+1) under the run lock,
-- validates evaluation ownership + REQUIRE_APPROVAL, never overwrites, and is
-- exact-idempotent. Run + version identity bound into the hash is immutable.
--
-- The verifier (2026-07-29.agent-result-continuity-r3) is a SUPERSET of the Agent
-- Foundation contract (run-idempotency index, column/constraint/index contracts) plus
-- R2 + R3 checks: exact function owner, search_path, security mode, body digest, index
-- definitions, and restrictive policy expressions — every drift fails READY.
--
-- Idempotent + NON-destructive: no DROP/TRUNCATE/DELETE, no destructive type change,
-- no fabricated backfill, no browser-role broadening, no forgeable GUC. Every function
-- is catalog-guarded (created only when absent; aborts on drift) so a second run makes
-- ZERO catalog changes (stable function/trigger/table OID + xmin). Run ONCE in the
-- Supabase SQL editor (project jsjsanmaahvmynblmzkq).

BEGIN;

-- ─── 0. Required parents ─────────────────────────────────────────────────────
DO $$
BEGIN
  IF to_regclass('public.qhub_agent_runs') IS NULL
     OR to_regclass('public.qhub_agent_run_steps') IS NULL
     OR to_regclass('public.qhub_agent_versions') IS NULL
     OR to_regclass('public.qhub_agents') IS NULL
     OR to_regclass('public.qhub_control_evaluations') IS NULL
     OR to_regclass('public.qhub_enforcement_plans') IS NULL
     OR to_regclass('public.qhub_release_candidates') IS NULL THEN
    RAISE EXCEPTION 'Result-continuity aborted: a required Agent Framework / Gate 03-05 parent table is missing';
  END IF;
END
$$;

-- ─── 1. Additive continuity columns (nullable; legacy rows keep NULLs) ────────
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS result_hash                TEXT;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS safe_result                JSONB;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS previous_step_hash         TEXT;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS finalized_at               TIMESTAMPTZ;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS result_hash_schema_version TEXT;

-- ─── 1b. EVIDENCE-AUTHORITY TRUST BOUNDARY (R4) ──────────────────────────────
-- The general QHub runtime (service_role) may request Gate 04 authorization and
-- orchestrate runs, but CANNOT manufacture durable evidence, mark evidence
-- COMMITTED, create receipt bindings, or finalize EXECUTED/SIMULATED without an
-- authority-created binding. A distinct, NOLOGIN, ungranted role
-- `qhub_evidence_writer` is the SOLE role permitted to execute the atomic evidence
-- commitment RPCs. Only the separate Trust Spine / evidence-writer service is
-- provisioned that credential in production (a later human checkpoint) — the
-- general runtime process must never possess it. Privileged helper functions live
-- in the private `qhub_private` schema (no Data API exposure, search_path never
-- includes public), and public-schema CREATE is revoked from every client role so
-- no privileged search_path can be shadowed.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qhub_evidence_writer') THEN
    CREATE ROLE qhub_evidence_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'qhub_private') THEN
    CREATE SCHEMA qhub_private;
  END IF;
  -- Public CREATE lockdown (idempotent-guarded).
  IF has_schema_privilege('service_role', 'public', 'CREATE')
     OR has_schema_privilege('anon', 'public', 'CREATE')
     OR has_schema_privilege('authenticated', 'public', 'CREATE') THEN
    REVOKE CREATE ON SCHEMA public FROM PUBLIC, anon, authenticated, service_role;
  END IF;
  -- qhub_private is owner-only (public wrappers run as owner; no client USAGE).
  IF has_schema_privilege('service_role', 'qhub_private', 'USAGE')
     OR has_schema_privilege('anon', 'qhub_private', 'USAGE')
     OR has_schema_privilege('authenticated', 'qhub_private', 'USAGE') THEN
    REVOKE ALL ON SCHEMA qhub_private FROM PUBLIC, anon, authenticated, service_role;
  END IF;
END
$$;

-- ─── 2. Canonical-encoding primitives (private; browser+service_role denied) ──
-- cell(v) = '<utf8-byte-length>:<v>;'  |  '-1:;' for NULL. Byte-identical to the
-- TypeScript `cell` in app/lib/qhub/agent/runtime/safe-result.ts.
DO $mig$
DECLARE b text := $body$
  SELECT CASE WHEN v IS NULL THEN '-1:;' ELSE octet_length(v)::text || ':' || v || ';' END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_hash_cell(text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_hash_cell(v TEXT) RETURNS TEXT
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_hash_cell(text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_hash_cell drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $mig$
DECLARE b text := $body$
  SELECT qhub_private.qhub_agent_hash_cell(CASE WHEN v IS NULL THEN NULL ELSE v::text END)
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_hash_intcell(int)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_hash_intcell(v INT) RETURNS TEXT
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_hash_intcell(int)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_hash_intcell drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 3. Canonical SAFE RESULT serialization + strict ENUM validation ──────────
-- Mirrors app/lib/qhub/agent/runtime/safe-result.ts exactly (Option 1, enum-only).
DO $mig$
DECLARE b text := $body$
DECLARE
  meta JSONB := sr -> 'safe_metadata';
  keys TEXT[] := ARRAY['duration_ms','outcome','record_count','result_kind','status_code','truncated'];
  k    TEXT;
  out  TEXT := 'V' || qhub_private.qhub_agent_hash_cell('agent-safe-result-1.0.0')
               || qhub_private.qhub_agent_hash_cell(sr ->> 'execution_status');
  tv   TEXT;
BEGIN
  FOREACH k IN ARRAY keys LOOP
    IF meta IS NULL OR NOT (meta ? k) THEN
      tv := 'absent';
    ELSIF jsonb_typeof(meta -> k) = 'null' THEN
      tv := 'null';
    ELSIF jsonb_typeof(meta -> k) = 'boolean' THEN
      tv := 'b:' || (meta ->> k);
    ELSIF jsonb_typeof(meta -> k) = 'number' THEN
      tv := 'n:' || (meta ->> k);
    ELSE
      tv := 's:' || (meta ->> k);
    END IF;
    out := out || qhub_private.qhub_agent_hash_cell(tv);
  END LOOP;
  RETURN out;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_canonical_safe_result(jsonb)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_canonical_safe_result(sr JSONB) RETURNS TEXT
      LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_canonical_safe_result(jsonb)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_canonical_safe_result drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $mig$
DECLARE b text := $body$
DECLARE
  exec_status TEXT[] := ARRAY['SUCCEEDED','FAILED','SIMULATED_SUCCESS','SIMULATED','EXECUTED','ALLOWED','DENIED','COMPLETED','UNKNOWN'];
  outcomes    TEXT[] := ARRAY['OK','ERROR','DISCREPANCY','NO_DISCREPANCY','PARTIAL','SKIPPED'];
  kinds       TEXT[] := ARRAY['SUMMARY','RECEIPT','SIMULATION','ANALYSIS','PROPOSAL'];
  meta_keys   TEXT[] := ARRAY['duration_ms','outcome','record_count','result_kind','status_code','truncated'];
  es          JSONB;
  meta        JSONB;
  k           TEXT;
  vt          TEXT;
  num         NUMERIC;
BEGIN
  IF sr IS NULL OR jsonb_typeof(sr) <> 'object' THEN RETURN FALSE; END IF;

  IF EXISTS (SELECT 1 FROM jsonb_object_keys(sr) t(key) WHERE t.key NOT IN ('execution_status','safe_metadata')) THEN
    RETURN FALSE;
  END IF;

  es := sr -> 'execution_status';
  IF es IS NOT NULL AND jsonb_typeof(es) <> 'null' THEN
    IF jsonb_typeof(es) <> 'string' OR NOT ((sr ->> 'execution_status') = ANY(exec_status)) THEN
      RETURN FALSE;
    END IF;
  END IF;

  IF sr ? 'safe_metadata' THEN
    meta := sr -> 'safe_metadata';
    IF jsonb_typeof(meta) <> 'object' THEN RETURN FALSE; END IF;

    FOR k IN SELECT jsonb_object_keys(meta) LOOP
      IF NOT (k = ANY(meta_keys)) THEN RETURN FALSE; END IF;
      vt := jsonb_typeof(meta -> k);
      IF vt = 'null' THEN
        CONTINUE;
      ELSIF k = 'outcome' THEN
        IF vt <> 'string' OR NOT ((meta ->> k) = ANY(outcomes)) THEN RETURN FALSE; END IF;
      ELSIF k = 'result_kind' THEN
        IF vt <> 'string' OR NOT ((meta ->> k) = ANY(kinds)) THEN RETURN FALSE; END IF;
      ELSIF k = 'truncated' THEN
        IF vt <> 'boolean' THEN RETURN FALSE; END IF;
      ELSIF k IN ('record_count','duration_ms','status_code') THEN
        IF vt <> 'number' THEN RETURN FALSE; END IF;
        num := (meta ->> k)::numeric;
        IF num <> trunc(num) OR num < 0 THEN RETURN FALSE; END IF;
        IF k = 'record_count' AND num > 1000000000 THEN RETURN FALSE; END IF;
        IF k = 'duration_ms'  AND num > 1000000000000 THEN RETURN FALSE; END IF;
        IF k = 'status_code'  AND num > 599 THEN RETURN FALSE; END IF;
      ELSE
        RETURN FALSE;
      END IF;
    END LOOP;
  END IF;

  IF octet_length(qhub_private.qhub_agent_canonical_safe_result(sr)) > 1024 THEN RETURN FALSE; END IF;
  RETURN TRUE;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_safe_result_valid(jsonb)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_safe_result_valid(sr JSONB) RETURNS BOOLEAN
      LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_safe_result_valid(jsonb)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_safe_result_valid drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 4. Canonical STEP RESULT HASH (pure; mirrors step-result-hash.ts) ────────
DO $mig$
DECLARE b text := $body$
  SELECT encode(sha256(convert_to(
    qhub_private.qhub_agent_hash_cell('agent-step-result-1.0.0')
    || qhub_private.qhub_agent_hash_cell(p_org_id)
    || qhub_private.qhub_agent_hash_cell(p_qhub_app_id)
    || qhub_private.qhub_agent_hash_cell(p_agent_id)
    || qhub_private.qhub_agent_hash_cell(p_agent_version_id)
    || qhub_private.qhub_agent_hash_cell(p_release_candidate_id)
    || qhub_private.qhub_agent_hash_cell(p_release_candidate_hash)
    || qhub_private.qhub_agent_hash_cell(p_manifest_hash)
    || qhub_private.qhub_agent_hash_cell(p_run_id)
    || qhub_private.qhub_agent_hash_cell(p_runtime_provider_id)
    || qhub_private.qhub_agent_hash_cell(p_runtime_provider_version)
    || qhub_private.qhub_agent_hash_intcell(p_step_index)
    || qhub_private.qhub_agent_hash_cell(p_step_kind)
    || qhub_private.qhub_agent_hash_cell(p_action_type)
    || qhub_private.qhub_agent_hash_cell(p_input_hash)
    || qhub_private.qhub_agent_hash_cell(p_decision)
    || qhub_private.qhub_agent_hash_cell(p_evaluation_id)
    || qhub_private.qhub_agent_hash_cell(p_action_request_id)
    || qhub_private.qhub_agent_hash_cell(p_action_digest)
    || qhub_private.qhub_agent_hash_cell(p_policy_profile_id)
    || qhub_private.qhub_agent_hash_intcell(p_policy_profile_version)
    || qhub_private.qhub_agent_hash_cell(p_policy_profile_hash)
    || qhub_private.qhub_agent_hash_cell(p_enforcement_plan_id)
    || qhub_private.qhub_agent_hash_intcell(p_enforcement_plan_version)
    || qhub_private.qhub_agent_hash_cell(p_enforcement_plan_hash)
    || qhub_private.qhub_agent_hash_cell(p_receipt_id)
    || qhub_private.qhub_agent_hash_cell(CASE WHEN p_safe_result IS NULL THEN NULL
                                        ELSE qhub_private.qhub_agent_canonical_safe_result(p_safe_result) END)
    || qhub_private.qhub_agent_hash_cell(p_previous_step_hash)
  , 'UTF8')), 'hex')
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_step_result_hash(
      p_org_id TEXT, p_qhub_app_id TEXT, p_agent_id TEXT, p_agent_version_id TEXT, p_release_candidate_id TEXT,
      p_release_candidate_hash TEXT, p_manifest_hash TEXT, p_run_id TEXT, p_runtime_provider_id TEXT,
      p_runtime_provider_version TEXT, p_step_index INT, p_step_kind TEXT, p_action_type TEXT, p_input_hash TEXT,
      p_decision TEXT, p_evaluation_id TEXT, p_action_request_id TEXT, p_action_digest TEXT, p_policy_profile_id TEXT,
      p_policy_profile_version INT, p_policy_profile_hash TEXT, p_enforcement_plan_id TEXT, p_enforcement_plan_version INT,
      p_enforcement_plan_hash TEXT, p_receipt_id TEXT, p_safe_result JSONB, p_previous_step_hash TEXT)
      RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_step_result_hash drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 5. Authoritative result-hash computation from DB records ─────────────────
-- SECURITY DEFINER (reads authoritative rows); browser-denied; called by the
-- finalizer and the guard trigger only.
DO $mig$
DECLARE b text := $body$
DECLARE
  r RECORD;
  v_manifest_hash TEXT;
  e_action_request_id UUID; e_action_digest TEXT; e_policy_profile_id UUID; e_policy_profile_version INT;
  e_policy_profile_hash TEXT; e_enforcement_plan_id UUID; e_enforcement_plan_version INT; e_enforcement_plan_hash TEXT;
BEGIN
  SELECT org_id, qhub_app_id, agent_id, agent_version_id, release_candidate_id,
         release_candidate_hash, runtime_provider, runtime_provider_version
    INTO r FROM public.qhub_agent_runs WHERE run_id = p_run_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: run % not found', p_run_id; END IF;

  SELECT manifest_hash INTO v_manifest_hash FROM public.qhub_agent_versions WHERE agent_version_id = r.agent_version_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: version % not found', r.agent_version_id; END IF;

  IF p_evaluation_id IS NOT NULL THEN
    SELECT action_request_id, action_digest, policy_profile_id, policy_profile_version,
           policy_profile_hash, enforcement_plan_id, enforcement_plan_version, enforcement_plan_hash
      INTO e_action_request_id, e_action_digest, e_policy_profile_id, e_policy_profile_version,
           e_policy_profile_hash, e_enforcement_plan_id, e_enforcement_plan_version, e_enforcement_plan_hash
      FROM public.qhub_control_evaluations WHERE evaluation_id = p_evaluation_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: evaluation % not found', p_evaluation_id; END IF;
  END IF;

  RETURN qhub_private.qhub_agent_step_result_hash(
    r.org_id, r.qhub_app_id::text, r.agent_id::text, r.agent_version_id::text,
    r.release_candidate_id::text, r.release_candidate_hash, v_manifest_hash,
    p_run_id::text, r.runtime_provider, r.runtime_provider_version,
    p_step_index, p_step_kind, p_action_type, p_input_hash, p_decision, p_evaluation_id::text,
    e_action_request_id::text, e_action_digest, e_policy_profile_id::text, e_policy_profile_version,
    e_policy_profile_hash, e_enforcement_plan_id::text, e_enforcement_plan_version, e_enforcement_plan_hash,
    p_receipt_id, p_safe_result, p_previous_step_hash);
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_compute_agent_step_result_hash(
      p_run_id UUID, p_step_index INT, p_safe_result JSONB, p_previous_step_hash TEXT, p_decision TEXT,
      p_input_hash TEXT, p_step_kind TEXT, p_action_type TEXT, p_evaluation_id UUID, p_receipt_id TEXT)
      RETURNS TEXT LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_compute_agent_step_result_hash drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 6. Defensive + immutability guard trigger (NO GUC) ──────────────────────
-- Enforces row invariants for EVERY write. Legitimacy is guaranteed by PRIVILEGE
-- (only the owner-privileged RPCs can write) — this trigger trusts no path flag.
DO $mig$
DECLARE b text := $body$
DECLARE
  prior_hash TEXT;
  recomputed TEXT;
  run_org    TEXT;
  run_app    UUID;
  eval_org   TEXT;
  eval_app   UUID;
BEGIN
  -- (A) Immutability: a finalized row's protected fields may never change.
  IF TG_OP = 'UPDATE' AND OLD.result_hash IS NOT NULL THEN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.step_index IS DISTINCT FROM OLD.step_index
       OR NEW.step_kind IS DISTINCT FROM OLD.step_kind
       OR NEW.action_type IS DISTINCT FROM OLD.action_type
       OR NEW.input_hash IS DISTINCT FROM OLD.input_hash
       OR NEW.decision IS DISTINCT FROM OLD.decision
       OR NEW.evaluation_id IS DISTINCT FROM OLD.evaluation_id
       OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id
       OR NEW.reason_codes IS DISTINCT FROM OLD.reason_codes
       OR NEW.summary IS DISTINCT FROM OLD.summary
       OR NEW.safe_result IS DISTINCT FROM OLD.safe_result
       OR NEW.result_hash IS DISTINCT FROM OLD.result_hash
       OR NEW.previous_step_hash IS DISTINCT FROM OLD.previous_step_hash
       OR NEW.result_hash_schema_version IS DISTINCT FROM OLD.result_hash_schema_version
       OR NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
       OR NEW.org_id IS DISTINCT FROM OLD.org_id THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized step is immutable (run=%, step_index=%)', OLD.run_id, OLD.step_index;
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.result_hash IS NOT NULL THEN
    -- (B) Finalized row: full continuity required (malformed terminal rows impossible).
    IF NEW.decision NOT IN ('ALLOW','DENY','SIMULATED','EXECUTED') THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: a finalized row requires a terminal decision (got %)', NEW.decision;
    END IF;
    IF NEW.finalized_at IS NULL OR NEW.result_hash_schema_version IS DISTINCT FROM 'agent-step-result-1.0.0' THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized row requires finalized_at + result_hash_schema_version';
    END IF;
    IF NEW.safe_result IS NULL OR NOT qhub_private.qhub_agent_safe_result_valid(NEW.safe_result) THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized row requires a valid strict safe_result';
    END IF;
    IF NEW.decision IN ('EXECUTED','SIMULATED') AND NEW.receipt_id IS NULL THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: decision % requires a receipt_id', NEW.decision;
    END IF;
    IF NEW.decision = 'DENY' AND NEW.receipt_id IS NOT NULL THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: DENY step must not carry a receipt_id';
    END IF;

    IF NEW.evaluation_id IS NOT NULL THEN
      SELECT org_id, qhub_app_id INTO run_org, run_app FROM public.qhub_agent_runs WHERE run_id = NEW.run_id;
      SELECT org_id, qhub_app_id INTO eval_org, eval_app FROM public.qhub_control_evaluations WHERE evaluation_id = NEW.evaluation_id;
      IF eval_org IS NULL OR eval_org IS DISTINCT FROM run_org OR eval_app IS DISTINCT FROM run_app THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: evaluation % does not belong to this run''s tenant/app', NEW.evaluation_id;
      END IF;
    END IF;

    IF NEW.step_index = 0 THEN
      IF NEW.previous_step_hash IS NOT NULL THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: step 0 must have NULL previous_step_hash';
      END IF;
    ELSE
      SELECT result_hash INTO prior_hash FROM public.qhub_agent_run_steps
       WHERE run_id = NEW.run_id AND step_index = NEW.step_index - 1;
      IF prior_hash IS NULL THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: previous step %/% is missing or not finalized', NEW.run_id, NEW.step_index - 1;
      END IF;
      IF NEW.previous_step_hash IS DISTINCT FROM prior_hash THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: previous_step_hash does not match the prior finalized step';
      END IF;
    END IF;

    recomputed := qhub_private.qhub_compute_agent_step_result_hash(
      NEW.run_id, NEW.step_index, NEW.safe_result, NEW.previous_step_hash, NEW.decision,
      NEW.input_hash, NEW.step_kind, NEW.action_type, NEW.evaluation_id, NEW.receipt_id);
    IF NEW.result_hash IS DISTINCT FROM recomputed THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: result_hash is not the authoritative canonical hash';
    END IF;

    RETURN NEW;
  END IF;

  -- (C) Nonterminal row: MUST be a REQUIRE_APPROVAL pause with no continuity.
  IF NEW.decision IS DISTINCT FROM 'REQUIRE_APPROVAL' THEN
    RAISE EXCEPTION 'qhub_agent_run_steps: a non-finalized row must be REQUIRE_APPROVAL (got %) — terminal rows require finalization', NEW.decision;
  END IF;
  IF NEW.previous_step_hash IS NOT NULL OR NEW.safe_result IS NOT NULL
     OR NEW.finalized_at IS NOT NULL OR NEW.result_hash_schema_version IS NOT NULL THEN
    RAISE EXCEPTION 'qhub_agent_run_steps: continuity fields require finalization';
  END IF;

  RETURN NEW;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_run_step_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_run_step_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_run_step_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_run_step_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
                 AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_run_step_guard BEFORE INSERT OR UPDATE ON public.qhub_agent_run_steps
      FOR EACH ROW EXECUTE FUNCTION qhub_private.qhub_agent_run_step_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
                 AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal
                 AND tgtype = 23 AND tgenabled = 'O'
                 AND tgfoid = 'qhub_private.qhub_agent_run_step_guard()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_agent_run_step_guard exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- ─── 7. Run identity immutability (hash-bound fields frozen from creation) ────
-- Boundary: the run-identity fields bound into the step-result hash are immutable
-- on EVERY update (i.e. from run creation onward). The runtime only ever updates
-- state/counters/pointers, never these.
DO $mig$
DECLARE b text := $body$
BEGIN
  IF NEW.org_id IS DISTINCT FROM OLD.org_id
     OR NEW.qhub_app_id IS DISTINCT FROM OLD.qhub_app_id
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
     OR NEW.agent_version_id IS DISTINCT FROM OLD.agent_version_id
     OR NEW.release_candidate_id IS DISTINCT FROM OLD.release_candidate_id
     OR NEW.release_candidate_hash IS DISTINCT FROM OLD.release_candidate_hash
     OR NEW.runtime_provider IS DISTINCT FROM OLD.runtime_provider
     OR NEW.runtime_provider_version IS DISTINCT FROM OLD.runtime_provider_version
     OR NEW.policy_profile_hash IS DISTINCT FROM OLD.policy_profile_hash
     OR NEW.enforcement_plan_hash IS DISTINCT FROM OLD.enforcement_plan_hash
     OR NEW.primary_model IS DISTINCT FROM OLD.primary_model
     OR NEW.input_hash IS DISTINCT FROM OLD.input_hash
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.run_hash IS DISTINCT FROM OLD.run_hash THEN
    RAISE EXCEPTION 'qhub_agent_runs: hash-bound run identity is immutable (run=%)', OLD.run_id;
  END IF;
  RETURN NEW;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_run_identity_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_run_identity_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_run_identity_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_run_identity_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
                 AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_run_identity_guard BEFORE UPDATE ON public.qhub_agent_runs
      FOR EACH ROW EXECUTE FUNCTION qhub_private.qhub_agent_run_identity_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
                 AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'qhub_private.qhub_agent_run_identity_guard()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_agent_run_identity_guard exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- Version manifest_hash immutability (the one hash-bound field sourced from the version).
DO $mig$
DECLARE b text := $body$
BEGIN
  IF NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash THEN
    RAISE EXCEPTION 'qhub_agent_versions: manifest_hash is immutable (version=%)', OLD.agent_version_id;
  END IF;
  RETURN NEW;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_agent_version_manifest_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_agent_version_manifest_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_agent_version_manifest_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_version_manifest_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
                 AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_version_manifest_guard BEFORE UPDATE ON public.qhub_agent_versions
      FOR EACH ROW EXECUTE FUNCTION qhub_private.qhub_agent_version_manifest_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
                 AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'qhub_private.qhub_agent_version_manifest_guard()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_agent_version_manifest_guard exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- ─── 7.5 Authoritative receipt-binding table (additive, immutable) ───────────
-- Relationally proves a Gate 04 receipt exists and binds it to the EXACT run /
-- agent / version / release / evaluation / action-digest / policy / plan, together
-- with the durable ledger evidence commitment (event id + hash). Terminal
-- finalization requires a matching binding for EXECUTED/SIMULATED — an arbitrary
-- receipt_id is no longer sufficient. Rows are written ONLY by the binding RPC.
CREATE TABLE IF NOT EXISTS public.qhub_governed_action_receipt_bindings (
  binding_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  receipt_id               TEXT NOT NULL,
  receipt_type             TEXT NOT NULL,
  receipt_schema_version   TEXT NOT NULL,
  receipt_hash             TEXT NOT NULL,
  org_id                   TEXT NOT NULL,
  qhub_app_id              UUID NOT NULL,
  run_id                   UUID NOT NULL,
  agent_id                 UUID NOT NULL,
  agent_version_id         UUID NOT NULL,
  release_candidate_id     UUID,
  evaluation_id            UUID NOT NULL,
  action_request_id        UUID NOT NULL,
  action_digest            TEXT NOT NULL,
  action_type              TEXT NOT NULL,
  decision                 TEXT NOT NULL,
  policy_profile_id        UUID,
  policy_profile_version   INT,
  policy_profile_hash      TEXT NOT NULL,
  enforcement_plan_id      UUID,
  enforcement_plan_version INT,
  enforcement_plan_hash    TEXT NOT NULL,
  evidence_chain_id        TEXT,
  evidence_event_id        TEXT NOT NULL,
  evidence_event_hash      TEXT NOT NULL,
  evidence_seq             BIGINT,
  committed_at             TIMESTAMPTZ NOT NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_binding_receipt ON public.qhub_governed_action_receipt_bindings (receipt_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_binding_eval   ON public.qhub_governed_action_receipt_bindings (evaluation_id);
CREATE INDEX        IF NOT EXISTS idx_receipt_binding_run    ON public.qhub_governed_action_receipt_bindings (run_id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rb_tenant_run') THEN
    ALTER TABLE public.qhub_governed_action_receipt_bindings ADD CONSTRAINT fk_rb_tenant_run
      FOREIGN KEY (org_id, run_id) REFERENCES public.qhub_agent_runs(org_id, run_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_rb_evaluation') THEN
    ALTER TABLE public.qhub_governed_action_receipt_bindings ADD CONSTRAINT fk_rb_evaluation
      FOREIGN KEY (evaluation_id) REFERENCES public.qhub_control_evaluations(evaluation_id);
  END IF;
END $$;

-- Receipt bindings are fully immutable once written.
DO $mig$
DECLARE b text := $body$
BEGIN
  RAISE EXCEPTION 'qhub_governed_action_receipt_bindings: receipt bindings are immutable (binding_id=%)', OLD.binding_id;
  RETURN NULL;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_receipt_binding_immutable()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_receipt_binding_immutable() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_receipt_binding_immutable()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_receipt_binding_immutable drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_receipt_binding_immutable'
                 AND tgrelid='public.qhub_governed_action_receipt_bindings'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_receipt_binding_immutable BEFORE UPDATE ON public.qhub_governed_action_receipt_bindings
      FOR EACH ROW EXECUTE FUNCTION qhub_private.qhub_receipt_binding_immutable();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_receipt_binding_immutable'
                 AND tgrelid='public.qhub_governed_action_receipt_bindings'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'qhub_private.qhub_receipt_binding_immutable()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_receipt_binding_immutable exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- ─── 7.6 COMMITTED-state guard (only the authority owner may commit evidence) ─
-- General service_role has NO path to set action_event_state='COMMITTED'. Only the
-- owner context (the authority commit RPCs, which are SECURITY DEFINER owned by the
-- migration owner and executable ONLY by qhub_evidence_writer) may transition to
-- COMMITTED. Direct service_role updates are rejected.
DO $mig$
DECLARE b text := $body$
BEGIN
  IF NEW.action_event_state = 'COMMITTED' AND OLD.action_event_state IS DISTINCT FROM 'COMMITTED'
     AND current_user <> (SELECT rolname FROM pg_roles WHERE oid = (SELECT relowner FROM pg_class WHERE oid = 'public.qhub_control_evaluations'::regclass)) THEN
    RAISE EXCEPTION 'qhub_control_evaluations: action_event_state COMMITTED may only be set by the evidence authority';
  END IF;
  RETURN NEW;
END
$body$;
BEGIN
  IF to_regprocedure('qhub_private.qhub_evaluation_commit_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION qhub_private.qhub_evaluation_commit_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'qhub_private.qhub_evaluation_commit_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_evaluation_commit_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_evaluation_commit_guard'
                 AND tgrelid='public.qhub_control_evaluations'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_evaluation_commit_guard BEFORE UPDATE ON public.qhub_control_evaluations
      FOR EACH ROW EXECUTE FUNCTION qhub_private.qhub_evaluation_commit_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_evaluation_commit_guard'
                 AND tgrelid='public.qhub_control_evaluations'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'qhub_private.qhub_evaluation_commit_guard()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_evaluation_commit_guard exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- ─── 7.7 Evidence-authority atomic commit RPC (qhub_evidence_writer ONLY) ─────
-- The SOLE path that (1) marks the exact evaluation's evidence COMMITTED and (2)
-- inserts the immutable receipt binding — atomically, from the durable ledger
-- append result supplied by the separate Trust Spine. Ownership is DB-derived from
-- authoritative run + evaluation rows; only the receipt + evidence commitment come
-- from the caller. service_role and browser roles have NO EXECUTE.
DO $mig$
DECLARE b text := $body$
DECLARE
  run  RECORD;
  ev   RECORD;
  rel  RECORD;
  plan RECORD;
  bnd  RECORD;
BEGIN
  IF p_decision NOT IN ('SIMULATED','EXECUTED') THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: only executed/simulated actions commit a receipt (got %)', p_decision;
  END IF;
  IF p_receipt_id IS NULL OR btrim(p_receipt_id) = '' OR p_receipt_type IS NULL OR p_receipt_hash IS NULL OR btrim(p_receipt_hash) = ''
     OR p_evidence_event_id IS NULL OR btrim(p_evidence_event_id) = '' OR p_evidence_event_hash IS NULL OR btrim(p_evidence_event_hash) = ''
     OR p_committed_at IS NULL OR p_receipt_schema_version IS NULL OR btrim(p_receipt_schema_version) = '' THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: receipt + durable evidence commitment are required (strict formats)';
  END IF;
  IF p_receipt_type NOT IN ('SIMULATION','SANDBOX','PRODUCTION') THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: invalid receipt_type %', p_receipt_type;
  END IF;
  IF p_decision = 'SIMULATED' AND p_receipt_type NOT IN ('SIMULATION','SANDBOX') THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: SIMULATED requires a simulation/sandbox receipt';
  END IF;
  IF p_decision = 'EXECUTED' AND p_receipt_type NOT IN ('PRODUCTION','SANDBOX') THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: EXECUTED requires a production/sandbox receipt';
  END IF;

  SELECT * INTO run FROM public.qhub_agent_runs WHERE run_id = p_run_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_commit_governed_action_receipt: run % not found for org %', p_run_id, p_org_id; END IF;
  IF run.current_state NOT IN ('RUNNING','AWAITING_APPROVAL') THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: run % not in a bindable state (%)', p_run_id, run.current_state;
  END IF;

  SELECT org_id, qhub_app_id, action_type, decision, action_event_state, action_request_id, action_digest,
         policy_profile_id, policy_profile_version, policy_profile_hash,
         enforcement_plan_id, enforcement_plan_version, enforcement_plan_hash
    INTO ev FROM public.qhub_control_evaluations WHERE evaluation_id = p_evaluation_id FOR UPDATE;
  IF NOT FOUND OR ev.org_id IS DISTINCT FROM run.org_id OR ev.qhub_app_id IS DISTINCT FROM run.qhub_app_id THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: evaluation ownership mismatch';
  END IF;
  IF ev.decision <> 'ALLOW' THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: a receipt binding requires an ALLOW evaluation (got %)', ev.decision;
  END IF;
  IF p_action_request_id IS DISTINCT FROM ev.action_request_id OR p_action_digest IS DISTINCT FROM ev.action_digest THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: action_request_id/action_digest mismatch';
  END IF;
  IF p_action_type IS DISTINCT FROM ev.action_type THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: action_type mismatch';
  END IF;
  IF ev.policy_profile_hash IS DISTINCT FROM run.policy_profile_hash
     OR ev.enforcement_plan_hash IS DISTINCT FROM run.enforcement_plan_hash THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: policy/plan hash does not match the run';
  END IF;

  IF run.release_candidate_id IS NOT NULL THEN
    SELECT org_id, qhub_app_id, release_candidate_hash, status INTO rel
      FROM public.qhub_release_candidates WHERE release_candidate_id = run.release_candidate_id;
    IF NOT FOUND OR rel.org_id IS DISTINCT FROM run.org_id OR rel.qhub_app_id IS DISTINCT FROM run.qhub_app_id
       OR rel.release_candidate_hash IS DISTINCT FROM run.release_candidate_hash OR rel.status NOT IN ('APPROVED','DEPLOYED') THEN
      RAISE EXCEPTION 'qhub_commit_governed_action_receipt: release candidate invalid';
    END IF;
  END IF;
  IF ev.enforcement_plan_id IS NOT NULL THEN
    SELECT status, enforcement_plan_hash INTO plan FROM public.qhub_enforcement_plans WHERE enforcement_plan_id = ev.enforcement_plan_id;
    IF NOT FOUND OR plan.status <> 'ACTIVE' OR plan.enforcement_plan_hash IS DISTINCT FROM ev.enforcement_plan_hash THEN
      RAISE EXCEPTION 'qhub_commit_governed_action_receipt: enforcement plan invalid';
    END IF;
  END IF;

  -- Idempotency across EVERY material field.
  SELECT * INTO bnd FROM public.qhub_governed_action_receipt_bindings WHERE evaluation_id = p_evaluation_id;
  IF FOUND THEN
    IF bnd.receipt_schema_version = p_receipt_schema_version AND bnd.receipt_id = p_receipt_id
       AND bnd.receipt_type = p_receipt_type AND bnd.receipt_hash = p_receipt_hash
       AND bnd.evidence_chain_id IS NOT DISTINCT FROM p_evidence_chain_id AND bnd.evidence_seq IS NOT DISTINCT FROM p_evidence_seq
       AND bnd.evidence_event_id = p_evidence_event_id AND bnd.evidence_event_hash = p_evidence_event_hash
       AND bnd.committed_at = p_committed_at AND bnd.decision = 'ALLOW' AND bnd.run_id = run.run_id
       AND bnd.action_request_id = ev.action_request_id AND bnd.action_digest = ev.action_digest
       AND bnd.policy_profile_hash = ev.policy_profile_hash AND bnd.enforcement_plan_hash = ev.enforcement_plan_hash THEN
      RETURN jsonb_build_object('committed', true, 'idempotent', true, 'binding_id', bnd.binding_id, 'receipt_id', bnd.receipt_id);
    END IF;
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt: a materially different receipt is already committed to evaluation %', p_evaluation_id;
  END IF;

  -- (1) Authoritatively mark evidence COMMITTED (owner context passes the guard).
  UPDATE public.qhub_control_evaluations SET action_event_state = 'COMMITTED' WHERE evaluation_id = p_evaluation_id;

  -- (2) Insert the immutable binding.
  INSERT INTO public.qhub_governed_action_receipt_bindings (
    receipt_id, receipt_type, receipt_schema_version, receipt_hash, org_id, qhub_app_id, run_id, agent_id,
    agent_version_id, release_candidate_id, evaluation_id, action_request_id, action_digest, action_type, decision,
    policy_profile_id, policy_profile_version, policy_profile_hash, enforcement_plan_id, enforcement_plan_version,
    enforcement_plan_hash, evidence_chain_id, evidence_event_id, evidence_event_hash, evidence_seq, committed_at)
  VALUES (
    p_receipt_id, p_receipt_type, p_receipt_schema_version, p_receipt_hash,
    run.org_id, run.qhub_app_id, run.run_id, run.agent_id, run.agent_version_id, run.release_candidate_id,
    p_evaluation_id, ev.action_request_id, ev.action_digest, ev.action_type, ev.decision,
    ev.policy_profile_id, ev.policy_profile_version, ev.policy_profile_hash, ev.enforcement_plan_id,
    ev.enforcement_plan_version, ev.enforcement_plan_hash, p_evidence_chain_id, p_evidence_event_id,
    p_evidence_event_hash, p_evidence_seq, p_committed_at)
  RETURNING * INTO bnd;

  RETURN jsonb_build_object('committed', true, 'idempotent', false, 'binding_id', bnd.binding_id, 'receipt_id', bnd.receipt_id);
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_commit_governed_action_receipt(uuid,text,uuid,text,text,uuid,text,text,text,text,text,text,text,text,bigint,timestamptz)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_commit_governed_action_receipt(
      p_run_id UUID, p_org_id TEXT, p_evaluation_id UUID, p_decision TEXT, p_action_type TEXT, p_action_request_id UUID,
      p_action_digest TEXT, p_receipt_id TEXT, p_receipt_type TEXT, p_receipt_schema_version TEXT, p_receipt_hash TEXT,
      p_evidence_chain_id TEXT, p_evidence_event_id TEXT, p_evidence_event_hash TEXT, p_evidence_seq BIGINT, p_committed_at TIMESTAMPTZ)
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_commit_governed_action_receipt(uuid,text,uuid,text,text,uuid,text,text,text,text,text,text,text,text,bigint,timestamptz)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_commit_governed_action_receipt drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 7.8 General evidence-COMMIT RPC (qhub_evidence_writer ONLY) ──────────────
-- The authority path for the broader Gate 04 evidence-commit flow (non-agent
-- governed actions). Marks the exact evaluation's action_event_state COMMITTED
-- (owner context passes the guard). The general runtime (service_role) has no
-- EXECUTE and no direct COMMITTED path; it hands off to the evidence authority.
DO $mig$
DECLARE b text := $body$
DECLARE ev RECORD;
BEGIN
  SELECT org_id, action_event_state INTO ev FROM public.qhub_control_evaluations
   WHERE evaluation_id = p_evaluation_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'qhub_commit_evaluation_evidence: evaluation % not found for org %', p_evaluation_id, p_org_id;
  END IF;
  IF ev.action_event_state = 'COMMITTED' THEN
    RETURN jsonb_build_object('committed', true, 'idempotent', true, 'evaluation_id', p_evaluation_id);
  END IF;
  UPDATE public.qhub_control_evaluations SET action_event_state = 'COMMITTED' WHERE evaluation_id = p_evaluation_id;
  RETURN jsonb_build_object('committed', true, 'idempotent', false, 'evaluation_id', p_evaluation_id);
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_commit_evaluation_evidence(uuid,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_commit_evaluation_evidence(p_evaluation_id UUID, p_org_id TEXT)
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_commit_evaluation_evidence(uuid,text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_commit_evaluation_evidence drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 8. Nonterminal create-step RPC (service-role only; DB-contiguous) ────────
-- Validates evaluation ownership (org/app/run) + REQUIRE_APPROVAL decision, then
-- appends at the DB-computed contiguous next index (MAX(step_index)+1 under the run
-- lock) or requires the supplied index to equal it. Never overwrites; exact repeat
-- (same evaluation at the tail pending index) is idempotent.
DO $mig$
DECLARE b text := $body$
DECLARE
  run       RECORD;
  ev        RECORD;
  next_idx  INT;
  tail      RECORD;
BEGIN
  SELECT * INTO run FROM public.qhub_agent_runs WHERE run_id = p_run_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_create_agent_run_step_pending: run % not found for org %', p_run_id, p_org_id; END IF;
  IF run.current_state NOT IN ('RUNNING','AWAITING_APPROVAL') THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: run % not in a writable state (%)', p_run_id, run.current_state;
  END IF;

  IF p_evaluation_id IS NULL THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: a pending step requires an authoritative evaluation';
  END IF;
  SELECT org_id, qhub_app_id, decision INTO ev FROM public.qhub_control_evaluations WHERE evaluation_id = p_evaluation_id;
  IF NOT FOUND OR ev.org_id IS DISTINCT FROM run.org_id OR ev.qhub_app_id IS DISTINCT FROM run.qhub_app_id THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: evaluation ownership mismatch (cross-tenant/run/agent/version/release)';
  END IF;
  IF ev.decision <> 'REQUIRE_APPROVAL' THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: a pending step requires a REQUIRE_APPROVAL evaluation (got %)', ev.decision;
  END IF;

  -- Contiguity: DB-owned next index = MAX(step_index)+1 under the run lock.
  SELECT COALESCE(MAX(step_index) + 1, 0) INTO next_idx FROM public.qhub_agent_run_steps WHERE run_id = p_run_id;

  -- Exact idempotency: repeating the create for the current tail pending row (same
  -- evaluation) returns it unchanged; any other supplied index is rejected.
  IF p_step_index IS NOT NULL AND p_step_index = next_idx - 1 THEN
    SELECT step_index, decision, evaluation_id INTO tail FROM public.qhub_agent_run_steps
     WHERE run_id = p_run_id AND step_index = p_step_index FOR UPDATE;
    IF FOUND AND tail.decision = 'REQUIRE_APPROVAL' AND tail.evaluation_id = p_evaluation_id THEN
      RETURN jsonb_build_object('recorded', true, 'idempotent', true, 'run_id', p_run_id, 'step_index', p_step_index, 'decision', 'REQUIRE_APPROVAL');
    END IF;
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: step %/% already exists with a different evaluation/decision', p_run_id, p_step_index;
  END IF;

  IF p_step_index IS NOT NULL AND p_step_index <> next_idx THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: noncontiguous step_index % (expected %)', p_step_index, next_idx;
  END IF;

  INSERT INTO public.qhub_agent_run_steps
    (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, input_hash, summary)
  VALUES (p_run_id, p_org_id, next_idx, p_step_kind, p_action_type, p_evaluation_id, 'REQUIRE_APPROVAL',
          COALESCE(p_reason_codes,'{}'), p_input_hash, p_summary);

  RETURN jsonb_build_object('recorded', true, 'idempotent', false, 'run_id', p_run_id, 'step_index', next_idx, 'decision', 'REQUIRE_APPROVAL');
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_create_agent_run_step_pending(
      p_run_id UUID, p_org_id TEXT, p_step_index INT, p_step_kind TEXT, p_action_type TEXT, p_evaluation_id UUID,
      p_reason_codes TEXT[], p_input_hash TEXT, p_summary TEXT)
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 9. Atomic finalization RPC (service-role only; full authoritative validation) ─
DO $mig$
DECLARE b text := $body$
DECLARE
  run         RECORD;
  agent       RECORD;
  ver         RECORD;
  rel         RECORD;
  ev          RECORD;
  plan        RECORD;
  bnd         RECORD;
  v_receipt_id TEXT;
  step_exists BOOLEAN;
  step_hash   TEXT;
  prev_hash   TEXT;
  new_hash    TEXT;
BEGIN
  IF p_decision NOT IN ('ALLOW','DENY','SIMULATED','EXECUTED') THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: decision % is not terminal', p_decision;
  END IF;
  IF p_evaluation_id IS NULL THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: a terminal step requires an authoritative evaluation';
  END IF;
  IF NOT qhub_private.qhub_agent_safe_result_valid(p_safe_result) THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: safe_result failed strict validation';
  END IF;

  -- Run (locked).
  SELECT * INTO run FROM public.qhub_agent_runs WHERE run_id = p_run_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_finalize_agent_run_step: run % not found for org %', p_run_id, p_org_id; END IF;
  IF run.current_state NOT IN ('RUNNING','AWAITING_APPROVAL') THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: run % not in a finalizable state (%)', p_run_id, run.current_state;
  END IF;

  -- Agent + lifecycle.
  SELECT org_id, qhub_app_id, current_lifecycle_state INTO agent FROM public.qhub_agents WHERE agent_id = run.agent_id;
  IF NOT FOUND OR agent.org_id IS DISTINCT FROM run.org_id OR agent.qhub_app_id IS DISTINCT FROM run.qhub_app_id THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: agent ownership mismatch';
  END IF;
  IF agent.current_lifecycle_state NOT IN ('SIMULATION','SUPERVISED','ACTIVE') THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: agent lifecycle % is not runnable', agent.current_lifecycle_state;
  END IF;

  -- Version.
  SELECT org_id, qhub_app_id, agent_id INTO ver FROM public.qhub_agent_versions WHERE agent_version_id = run.agent_version_id;
  IF NOT FOUND OR ver.org_id IS DISTINCT FROM run.org_id OR ver.qhub_app_id IS DISTINCT FROM run.qhub_app_id
     OR ver.agent_id IS DISTINCT FROM run.agent_id THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: agent version ownership mismatch';
  END IF;

  -- Release candidate (when the run is release-bound).
  IF run.release_candidate_id IS NOT NULL THEN
    SELECT org_id, qhub_app_id, release_candidate_hash, status INTO rel
      FROM public.qhub_release_candidates WHERE release_candidate_id = run.release_candidate_id;
    IF NOT FOUND OR rel.org_id IS DISTINCT FROM run.org_id OR rel.qhub_app_id IS DISTINCT FROM run.qhub_app_id
       OR rel.release_candidate_hash IS DISTINCT FROM run.release_candidate_hash THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: release candidate mismatch';
    END IF;
    IF rel.status NOT IN ('APPROVED','DEPLOYED') THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: release candidate status % is not valid for execution', rel.status;
    END IF;
  END IF;

  -- Evaluation + decision/event/policy/plan relationships.
  SELECT org_id, qhub_app_id, action_type, decision, action_event_state, action_digest, action_request_id,
         policy_profile_hash, enforcement_plan_id, enforcement_plan_hash
    INTO ev FROM public.qhub_control_evaluations WHERE evaluation_id = p_evaluation_id;
  IF NOT FOUND OR ev.org_id IS DISTINCT FROM run.org_id OR ev.qhub_app_id IS DISTINCT FROM run.qhub_app_id THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: evaluation ownership mismatch';
  END IF;
  IF p_action_type IS NOT NULL AND ev.action_type IS DISTINCT FROM p_action_type THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: evaluation action_type mismatch';
  END IF;
  IF ev.policy_profile_hash IS DISTINCT FROM run.policy_profile_hash
     OR ev.enforcement_plan_hash IS DISTINCT FROM run.enforcement_plan_hash THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: evaluation policy/plan hash does not match the run';
  END IF;
  IF p_decision IN ('ALLOW','SIMULATED','EXECUTED') AND ev.decision <> 'ALLOW' THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: decision % requires an ALLOW evaluation (got %)', p_decision, ev.decision;
  END IF;
  IF p_decision = 'DENY' AND ev.decision <> 'DENY' THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: DENY step requires a DENY evaluation (got %)', ev.decision;
  END IF;

  -- Enforcement plan row (active) anchoring the policy hash.
  IF ev.enforcement_plan_id IS NOT NULL THEN
    SELECT org_id, qhub_app_id, enforcement_plan_hash, status, policy_profile_hash INTO plan
      FROM public.qhub_enforcement_plans WHERE enforcement_plan_id = ev.enforcement_plan_id;
    IF NOT FOUND OR plan.org_id IS DISTINCT FROM run.org_id OR plan.qhub_app_id IS DISTINCT FROM run.qhub_app_id
       OR plan.enforcement_plan_hash IS DISTINCT FROM ev.enforcement_plan_hash
       OR plan.policy_profile_hash IS DISTINCT FROM ev.policy_profile_hash THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: enforcement plan mismatch';
    END IF;
    IF plan.status <> 'ACTIVE' THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: enforcement plan status % is not ACTIVE', plan.status;
    END IF;
  END IF;

  -- Receipt authority: EXECUTED/SIMULATED require an authoritative receipt BINDING
  -- for the exact evaluation. The canonical receipt_id comes from the binding row,
  -- NOT from caller text. DENY carries no receipt.
  IF p_decision IN ('EXECUTED','SIMULATED') THEN
    SELECT receipt_id, receipt_type, run_id, org_id, qhub_app_id, agent_id, agent_version_id, evaluation_id,
           action_request_id, action_digest, decision INTO bnd
      FROM public.qhub_governed_action_receipt_bindings WHERE evaluation_id = p_evaluation_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: decision % requires an authoritative receipt binding', p_decision;
    END IF;
    IF bnd.run_id IS DISTINCT FROM run.run_id OR bnd.org_id IS DISTINCT FROM run.org_id
       OR bnd.qhub_app_id IS DISTINCT FROM run.qhub_app_id OR bnd.agent_id IS DISTINCT FROM run.agent_id
       OR bnd.agent_version_id IS DISTINCT FROM run.agent_version_id
       OR bnd.action_request_id IS DISTINCT FROM ev.action_request_id
       OR bnd.action_digest IS DISTINCT FROM ev.action_digest OR bnd.decision <> 'ALLOW' THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: receipt binding does not match this run/evaluation/action';
    END IF;
    IF p_receipt_id IS NOT NULL AND p_receipt_id IS DISTINCT FROM bnd.receipt_id THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: caller receipt_id does not match the authoritative binding';
    END IF;
    IF p_decision = 'SIMULATED' AND bnd.receipt_type NOT IN ('SIMULATION','SANDBOX') THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: SIMULATED requires a simulation/sandbox receipt (got %)', bnd.receipt_type;
    END IF;
    IF p_decision = 'EXECUTED' AND bnd.receipt_type NOT IN ('PRODUCTION','SANDBOX') THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: EXECUTED requires a production/sandbox receipt (got %)', bnd.receipt_type;
    END IF;
    v_receipt_id := bnd.receipt_id;
  ELSIF p_decision = 'DENY' THEN
    IF p_receipt_id IS NOT NULL THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: DENY step must not carry a receipt';
    END IF;
    v_receipt_id := NULL;
  ELSE
    v_receipt_id := NULL; -- ALLOW with no side effect carries no receipt
  END IF;

  -- Target step (may be a pre-recorded REQUIRE_APPROVAL row or absent).
  SELECT result_hash INTO step_hash FROM public.qhub_agent_run_steps
   WHERE run_id = p_run_id AND step_index = p_step_index FOR UPDATE;
  step_exists := FOUND;

  IF p_step_index = 0 THEN
    prev_hash := NULL;
  ELSE
    SELECT result_hash INTO prev_hash FROM public.qhub_agent_run_steps
     WHERE run_id = p_run_id AND step_index = p_step_index - 1;
    IF prev_hash IS NULL THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: previous step %/% is missing or not finalized', p_run_id, p_step_index - 1;
    END IF;
  END IF;

  new_hash := qhub_private.qhub_compute_agent_step_result_hash(
    p_run_id, p_step_index, p_safe_result, prev_hash, p_decision, p_input_hash, p_step_kind, p_action_type, p_evaluation_id, v_receipt_id);

  -- Idempotency: exact repeat = no-op; materially different repeat = rejected.
  IF step_exists AND step_hash IS NOT NULL THEN
    IF step_hash = new_hash THEN
      RETURN jsonb_build_object('finalized', true, 'idempotent', true, 'run_id', p_run_id, 'step_index', p_step_index,
        'result_hash', new_hash, 'previous_step_hash', prev_hash, 'result_hash_schema_version', 'agent-step-result-1.0.0');
    END IF;
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: step %/% already finalized with a different result', p_run_id, p_step_index;
  END IF;

  IF step_exists THEN
    UPDATE public.qhub_agent_run_steps
       SET step_kind = p_step_kind, action_type = p_action_type, evaluation_id = p_evaluation_id, decision = p_decision,
           reason_codes = COALESCE(p_reason_codes,'{}'), receipt_id = v_receipt_id, input_hash = p_input_hash,
           summary = p_summary, safe_result = p_safe_result, previous_step_hash = prev_hash, result_hash = new_hash,
           result_hash_schema_version = 'agent-step-result-1.0.0', finalized_at = NOW()
     WHERE run_id = p_run_id AND step_index = p_step_index;
  ELSE
    INSERT INTO public.qhub_agent_run_steps
      (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, receipt_id,
       input_hash, summary, safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
    VALUES (p_run_id, p_org_id, p_step_index, p_step_kind, p_action_type, p_evaluation_id, p_decision,
            COALESCE(p_reason_codes,'{}'), v_receipt_id, p_input_hash, p_summary, p_safe_result, prev_hash, new_hash,
            'agent-step-result-1.0.0', NOW());
  END IF;

  RETURN jsonb_build_object('finalized', true, 'idempotent', false, 'run_id', p_run_id, 'step_index', p_step_index,
    'result_hash', new_hash, 'previous_step_hash', prev_hash, 'result_hash_schema_version', 'agent-step-result-1.0.0');
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_finalize_agent_run_step(
      p_run_id UUID, p_org_id TEXT, p_step_index INT, p_step_kind TEXT, p_action_type TEXT, p_evaluation_id UUID,
      p_decision TEXT, p_reason_codes TEXT[], p_receipt_id TEXT, p_input_hash TEXT, p_summary TEXT, p_safe_result JSONB)
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 10. ACLs + table privileges (idempotent-guarded for a true no-op) ───────
-- Applied ONLY when the target state is not already in place, so a second run
-- performs ZERO catalog writes (stable pg_proc / pg_class xmin). The verifier
-- independently proves the final state.
DO $$
DECLARE
  hashsig      text := 'qhub_private.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)';
  finalsig     text := 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)';
  createsig    text := 'public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)';
  commitsig    text := 'public.qhub_commit_governed_action_receipt(uuid,text,uuid,text,text,uuid,text,text,text,text,text,text,text,text,bigint,timestamptz)';
BEGIN
  IF has_function_privilege('service_role', hashsig, 'EXECUTE')                 -- helper still exposed, OR
     OR NOT has_function_privilege('service_role', finalsig, 'EXECUTE')          -- finalize not yet granted, OR
     OR NOT has_function_privilege('service_role', createsig, 'EXECUTE')         -- create not yet granted, OR
     OR has_function_privilege('service_role', commitsig, 'EXECUTE')             -- authority RPC service_role-exposed, OR
     OR NOT has_function_privilege('qhub_evidence_writer', commitsig, 'EXECUTE') -- authority not yet granted, OR
     OR has_table_privilege('service_role','public.qhub_agent_run_steps','INSERT')  -- direct write present, OR
     OR has_table_privilege('service_role','public.qhub_governed_action_receipt_bindings','INSERT')  -- binding direct write, OR
     OR NOT has_table_privilege('service_role','public.qhub_agent_run_steps','SELECT') THEN  -- read missing
    -- Helpers: executable by NO client role (owner-only; called within DEFINER fns).
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_hash_cell(text) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_hash_intcell(int) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_canonical_safe_result(jsonb) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_safe_result_valid(jsonb) FROM PUBLIC, anon, authenticated, service_role;
    EXECUTE 'REVOKE ALL ON FUNCTION ' || hashsig || ' FROM PUBLIC, anon, authenticated, service_role';
    REVOKE ALL ON FUNCTION qhub_private.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_run_step_guard() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_run_identity_guard() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_agent_version_manifest_guard() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_receipt_binding_immutable() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION qhub_private.qhub_evaluation_commit_guard() FROM PUBLIC, anon, authenticated, service_role;

    -- General runtime write RPCs: executable ONLY by service_role.
    EXECUTE 'REVOKE ALL ON FUNCTION ' || createsig || ' FROM PUBLIC, anon, authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || createsig || ' TO service_role';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || finalsig || ' FROM PUBLIC, anon, authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || finalsig || ' TO service_role';

    -- Evidence-authority RPCs: executable ONLY by qhub_evidence_writer (NOT service_role).
    EXECUTE 'REVOKE ALL ON FUNCTION ' || commitsig || ' FROM PUBLIC, anon, authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || commitsig || ' TO qhub_evidence_writer';
    REVOKE ALL ON FUNCTION public.qhub_commit_evaluation_evidence(uuid,text) FROM PUBLIC, anon, authenticated, service_role;
    GRANT EXECUTE ON FUNCTION public.qhub_commit_evaluation_evidence(uuid,text) TO qhub_evidence_writer;

    -- Verifier: browser-denied, service-role-only (re-asserted after replace).
    REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM PUBLIC, anon, authenticated;
    GRANT EXECUTE ON FUNCTION public.qhub_verify_agent_schema() TO service_role;

    -- Steps + receipt-binding tables: NO direct write path — SELECT only for service_role.
    REVOKE ALL ON TABLE public.qhub_agent_run_steps FROM PUBLIC, anon, authenticated, service_role;
    GRANT SELECT ON TABLE public.qhub_agent_run_steps TO service_role;
    REVOKE ALL ON TABLE public.qhub_governed_action_receipt_bindings FROM PUBLIC, anon, authenticated, service_role;
    GRANT SELECT ON TABLE public.qhub_governed_action_receipt_bindings TO service_role;
  END IF;
END $$;

-- RLS posture (guarded so a rerun does not rewrite pg_class).
DO $$
BEGIN
  IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.qhub_agent_run_steps'::regclass) THEN
    ALTER TABLE public.qhub_agent_run_steps ENABLE ROW LEVEL SECURITY;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_agent_run_steps'::regclass
                 AND polname = 'qhub_agent_run_steps_service_only') THEN
    CREATE POLICY qhub_agent_run_steps_service_only ON public.qhub_agent_run_steps
      AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
  IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.qhub_governed_action_receipt_bindings'::regclass) THEN
    ALTER TABLE public.qhub_governed_action_receipt_bindings ENABLE ROW LEVEL SECURITY;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'public.qhub_governed_action_receipt_bindings'::regclass
                 AND polname = 'qhub_receipt_bindings_service_only') THEN
    CREATE POLICY qhub_receipt_bindings_service_only ON public.qhub_governed_action_receipt_bindings
      AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
END $$;

-- ─── 12. Indexes ─────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_run_steps_run_result
  ON public.qhub_agent_run_steps (run_id, result_hash) WHERE result_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_finalized
  ON public.qhub_agent_run_steps (run_id, step_index) WHERE result_hash IS NOT NULL;

-- ─── 13. Schema verifier — prove the full hardened contract ──────────────────
DO $mig$
DECLARE b text := $body$
WITH owner_oid AS (SELECT relowner AS oid FROM pg_class WHERE oid='public.qhub_agent_run_steps'::regclass),
agent_tables(name) AS (
  VALUES ('qhub_agents'), ('qhub_agent_versions'), ('qhub_agent_runs'), ('qhub_agent_run_steps')
),
fk_count AS (
  SELECT count(*) AS n FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
  WHERE c.contype='f' AND n.nspname='public'
    AND t.relname IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps') AND c.convalidated
),
hashsig AS (SELECT 'qhub_private.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)'::text s),
computesig AS (SELECT 'qhub_private.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)'::text s),
finalsig AS (SELECT 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)'::text s),
createsig AS (SELECT 'public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)'::text s),
commitsig AS (SELECT 'public.qhub_commit_governed_action_receipt(uuid,text,uuid,text,text,uuid,text,text,text,text,text,text,text,text,bigint,timestamptz)'::text s),
-- Pinned functions: exact owner + search_path + security mode + body digest.
pf(sig, secdef, digest) AS (VALUES
  ('qhub_private.qhub_agent_hash_cell(text)', false, '5592c0cbc562233aca23a2cc5f15c369'),
  ('qhub_private.qhub_agent_hash_intcell(int)', false, '0c999cfa0b51734383df116e80701988'),
  ('qhub_private.qhub_agent_canonical_safe_result(jsonb)', false, '97b9ba0f2aa60ed362cfd6b0c2746947'),
  ('qhub_private.qhub_agent_safe_result_valid(jsonb)', false, '8feeacdf7a531981d516fe7c67e23d9e'),
  ('qhub_private.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)', false, 'b3e2794206a93ac0ff9eccb81a93ca89'),
  ('qhub_private.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)', true, '407ef3fcef2ba9efe7753c7dfd75c759'),
  ('qhub_private.qhub_agent_run_step_guard()', true, '5cd1caf65571297737bdafc10bbf462d'),
  ('qhub_private.qhub_agent_run_identity_guard()', false, 'dd57c916293a5ef8ed73412f69b928c6'),
  ('qhub_private.qhub_agent_version_manifest_guard()', false, '2d51507ec314288172479f594e2ac269'),
  ('qhub_private.qhub_receipt_binding_immutable()', false, 'fcd03e86bf0fd73a88a686d6bb028e96'),
  ('qhub_private.qhub_evaluation_commit_guard()', false, 'cf3b574d7f2ef5cfaa55859dddba2c48'),
  ('public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)', true, 'fdb3b9458915dbae80ae154bdb265741'),
  ('public.qhub_commit_governed_action_receipt(uuid,text,uuid,text,text,uuid,text,text,text,text,text,text,text,text,bigint,timestamptz)', true, 'a57615b32e7b62be85c40c903a04c0a7'),
  ('public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)', true, '08f9f87bee2e0a0922c9202ffd250d3d')
),
pfmeta AS (
  SELECT pf.sig, pf.secdef AS want_secdef, pf.digest AS want_digest,
    p.oid IS NOT NULL AS present, p.proowner AS proowner, p.prosecdef AS secdef, p.proconfig AS cfg,
    CASE WHEN p.oid IS NULL THEN NULL ELSE md5(p.prosrc) END AS digest
  FROM pf LEFT JOIN pg_proc p ON p.oid = to_regprocedure(pf.sig)
),
-- Pinned indexes: exact table + columns + predicate + uniqueness via indexdef.
pidx(name, def) AS (VALUES
  ('idx_agent_versions_hash', 'CREATE UNIQUE INDEX idx_agent_versions_hash ON public.qhub_agent_versions USING btree (agent_id, manifest_hash)'),
  ('idx_agent_runs_idem', 'CREATE UNIQUE INDEX idx_agent_runs_idem ON public.qhub_agent_runs USING btree (agent_version_id, idempotency_key)'),
  ('idx_agent_run_steps_run_index', 'CREATE UNIQUE INDEX idx_agent_run_steps_run_index ON public.qhub_agent_run_steps USING btree (run_id, step_index)'),
  ('idx_agent_run_steps_run_result', 'CREATE UNIQUE INDEX idx_agent_run_steps_run_result ON public.qhub_agent_run_steps USING btree (run_id, result_hash) WHERE (result_hash IS NOT NULL)'),
  ('idx_receipt_binding_receipt', 'CREATE UNIQUE INDEX idx_receipt_binding_receipt ON public.qhub_governed_action_receipt_bindings USING btree (receipt_id)'),
  ('idx_receipt_binding_eval', 'CREATE UNIQUE INDEX idx_receipt_binding_eval ON public.qhub_governed_action_receipt_bindings USING btree (evaluation_id)')
),
pidxmeta AS (
  SELECT pidx.name, pidx.def AS want_def, pg_get_indexdef(c.oid) AS def
  FROM pidx LEFT JOIN pg_class c ON c.relname = pidx.name AND c.relkind='i'
),
-- Pinned RESTRICTIVE policies: exact table/roles/qual/withcheck, no permissive broadening.
ptab(name) AS (VALUES ('qhub_agents'),('qhub_agent_versions'),('qhub_agent_runs'),('qhub_agent_run_steps'),('qhub_governed_action_receipt_bindings')),
checks(identifier, category, ready, reason_code) AS (
  VALUES
    -- ── Agent Foundation tables (preserved) ──
    ('table.qhub_agents', 'TABLE', to_regclass('public.qhub_agents') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_versions', 'TABLE', to_regclass('public.qhub_agent_versions') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_runs', 'TABLE', to_regclass('public.qhub_agent_runs') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_run_steps', 'TABLE', to_regclass('public.qhub_agent_run_steps') IS NOT NULL, 'TABLE_MISSING'),
    ('table.receipt_bindings', 'TABLE', to_regclass('public.qhub_governed_action_receipt_bindings') IS NOT NULL, 'TABLE_MISSING'),

    -- ── Column contracts (foundation, preserved) ──
    ('column.agents_contract', 'COLUMN', (
      SELECT count(*) = 14 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_agents'
        AND column_name = ANY(ARRAY['agent_id','org_id','qhub_app_id','name','owner_user_id','owning_team',
          'current_version_id','current_lifecycle_state','current_operating_mode','risk_tier','kill_switch_active','created_by','created_at','updated_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.versions_contract', 'COLUMN', (
      SELECT count(*) = 17 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_agent_versions'
        AND column_name = ANY(ARRAY['agent_version_id','agent_id','org_id','qhub_app_id','manifest','manifest_hash','manifest_version',
          'operating_mode','autonomy_level','risk_tier','policy_profile_hash','enforcement_plan_hash','release_candidate_id','release_candidate_hash','deployment_decision_id','frozen','created_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.runs_contract', 'COLUMN', (
      SELECT count(*) = 24 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_agent_runs'
        AND column_name = ANY(ARRAY['run_id','agent_id','agent_version_id','org_id','qhub_app_id','release_candidate_id','release_candidate_hash',
          'initiating_user_id','operating_mode','runtime_provider','runtime_provider_version','current_state','current_step','policy_profile_hash',
          'enforcement_plan_hash','primary_model','input_hash','output_hash','proposed_action_count','idempotency_key','pending_evaluation_id','error_reference','run_hash','started_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.steps_contract', 'COLUMN', (
      SELECT count(*) = 16 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND column_name = ANY(ARRAY['step_id','run_id','org_id','step_index','step_kind','action_type','evaluation_id','decision','reason_codes','input_hash','summary',
          'result_hash','safe_result','previous_step_hash','finalized_at','result_hash_schema_version'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.continuity_types', 'COLUMN', (
      SELECT count(*) = 5 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND ((column_name IN ('result_hash','previous_step_hash','result_hash_schema_version') AND data_type='text')
          OR (column_name='safe_result' AND data_type='jsonb') OR (column_name='finalized_at' AND data_type='timestamp with time zone'))
    ), 'CONTINUITY_TYPE_MISMATCH'),
    ('column.receipt_bindings_contract', 'COLUMN', (
      SELECT count(*) = 27 FROM information_schema.columns WHERE table_schema='public' AND table_name='qhub_governed_action_receipt_bindings'
        AND column_name = ANY(ARRAY['binding_id','receipt_id','receipt_type','receipt_schema_version','receipt_hash','org_id','qhub_app_id','run_id','agent_id',
          'agent_version_id','release_candidate_id','evaluation_id','action_request_id','action_digest','action_type','decision','policy_profile_id','policy_profile_version',
          'policy_profile_hash','enforcement_plan_id','enforcement_plan_version','enforcement_plan_hash','evidence_chain_id','evidence_event_id','evidence_event_hash','evidence_seq','committed_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),

    -- ── Constraints (foundation preserved + receipt binding) ──
    ('constraint.foreign_keys_validated', 'CONSTRAINT', (SELECT n = 13 FROM fk_count), 'FK_MISSING_OR_UNVALIDATED'),
    ('constraint.lifecycle_state_check', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agents' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_lifecycle_state%'), 'CONSTRAINT_MISSING'),
    ('constraint.run_state_check', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_runs' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_state%'), 'CONSTRAINT_MISSING'),
    ('constraint.step_decision_check', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_run_steps' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%decision%'), 'CONSTRAINT_MISSING'),
    ('constraint.receipt_binding_fks', 'CONSTRAINT', (
      SELECT count(*) = 2 FROM pg_constraint WHERE conname IN ('fk_rb_tenant_run','fk_rb_evaluation') AND contype='f' AND convalidated), 'FK_MISSING_OR_UNVALIDATED'),

    -- ── Indexes (exact table/columns/predicate via pinned indexdef; foundation preserved) ──
    ('index.pinned_defs_exact', 'INDEX', (
      SELECT count(*) = 0 FROM pidxmeta WHERE def IS DISTINCT FROM want_def), 'INDEX_MISSING_OR_MISMATCH'),

    -- ── Functions: presence + exact owner + search_path + security mode + body digest ──
    ('function.all_present', 'FUNCTION', (SELECT bool_and(present) FROM pfmeta), 'FUNCTION_MISSING'),
    ('function.owners_pinned', 'FUNCTION', (SELECT bool_and(proowner = (SELECT oid FROM owner_oid)) FROM pfmeta WHERE present), 'FUNCTION_OWNER_DRIFT'),
    ('function.search_paths_pinned', 'FUNCTION', (SELECT bool_and(cfg = ARRAY['search_path=pg_catalog, qhub_private']) FROM pfmeta WHERE present), 'FUNCTION_SEARCH_PATH_DRIFT'),
    ('function.security_modes_pinned', 'FUNCTION', (SELECT bool_and(secdef = want_secdef) FROM pfmeta WHERE present), 'FUNCTION_SECURITY_MODE_DRIFT'),
    ('function.bodies_pinned', 'FUNCTION', (SELECT bool_and(digest = want_digest) FROM pfmeta WHERE present), 'FUNCTION_BODY_DRIFT'),

    -- ── Function privileges (helpers locked; RPCs service-role-only) ──
    ('privilege.helpers_locked', 'FUNCTION', (
      NOT has_function_privilege('anon', (SELECT s FROM hashsig), 'EXECUTE') AND NOT has_function_privilege('service_role', (SELECT s FROM hashsig), 'EXECUTE')
      AND NOT has_function_privilege('anon', (SELECT s FROM computesig), 'EXECUTE') AND NOT has_function_privilege('service_role', (SELECT s FROM computesig), 'EXECUTE')
      AND NOT has_function_privilege('anon', 'qhub_private.qhub_agent_safe_result_valid(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'qhub_private.qhub_agent_safe_result_valid(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'qhub_private.qhub_agent_safe_result_valid(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('anon', 'qhub_private.qhub_agent_canonical_safe_result(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'qhub_private.qhub_agent_canonical_safe_result(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('anon', 'qhub_private.qhub_agent_run_step_guard()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'qhub_private.qhub_agent_run_step_guard()', 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'qhub_private.qhub_agent_run_step_guard()', 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'qhub_private.qhub_receipt_binding_immutable()', 'EXECUTE')
    ), 'HELPER_EXPOSED'),
    ('function.finalize_rpc', 'FUNCTION', (
      NOT has_function_privilege('anon', (SELECT s FROM finalsig), 'EXECUTE') AND NOT has_function_privilege('authenticated', (SELECT s FROM finalsig), 'EXECUTE')
      AND has_function_privilege('service_role', (SELECT s FROM finalsig), 'EXECUTE')), 'FINALIZE_RPC_EXPOSED'),
    ('function.create_step_rpc', 'FUNCTION', (
      NOT has_function_privilege('anon', (SELECT s FROM createsig), 'EXECUTE') AND has_function_privilege('service_role', (SELECT s FROM createsig), 'EXECUTE')), 'CREATE_RPC_EXPOSED'),
    -- Evidence-authority commit RPC: exists, EXECUTE ONLY qhub_evidence_writer (NOT service_role/browser).
    ('function.commit_rpc_authority_only', 'FUNCTION', (
      to_regprocedure((SELECT s FROM commitsig)) IS NOT NULL AND to_regprocedure('public.qhub_commit_evaluation_evidence(uuid,text)') IS NOT NULL
      AND NOT has_function_privilege('anon', (SELECT s FROM commitsig), 'EXECUTE')
      AND NOT has_function_privilege('authenticated', (SELECT s FROM commitsig), 'EXECUTE')
      AND NOT has_function_privilege('service_role', (SELECT s FROM commitsig), 'EXECUTE')
      AND has_function_privilege('qhub_evidence_writer', (SELECT s FROM commitsig), 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'public.qhub_commit_evaluation_evidence(uuid,text)', 'EXECUTE')
      AND NOT has_function_privilege('anon', 'public.qhub_commit_evaluation_evidence(uuid,text)', 'EXECUTE')
      AND has_function_privilege('qhub_evidence_writer', 'public.qhub_commit_evaluation_evidence(uuid,text)', 'EXECUTE')
      AND (SELECT prosecdef AND proconfig = ARRAY['search_path=pg_catalog, qhub_private'] AND proowner = (SELECT oid FROM owner_oid)
             FROM pg_proc WHERE oid='public.qhub_commit_evaluation_evidence(uuid,text)'::regprocedure)), 'COMMIT_RPC_MISSING_OR_EXPOSED'),
    ('function.no_dynamic_sql_in_rpcs', 'FUNCTION', (
      SELECT bool_and(prosrc NOT ILIKE '%execute %') FROM pg_proc WHERE oid IN (
        (SELECT s FROM finalsig)::regprocedure, (SELECT s FROM createsig)::regprocedure, (SELECT s FROM commitsig)::regprocedure,
        'qhub_private.qhub_agent_run_step_guard()'::regprocedure)), 'DYNAMIC_SQL_PRESENT'),

    -- ── R4 evidence-authority role + private schema + COMMITTED guard ──
    ('role.evidence_writer_exists_nologin', 'FUNCTION', (
      EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qhub_evidence_writer' AND NOT rolcanlogin)), 'EVIDENCE_WRITER_ROLE_MISSING_OR_LOGIN'),
    ('role.evidence_writer_not_inherited', 'FUNCTION', (
      -- No client role is a member of qhub_evidence_writer (cannot SET ROLE / inherit).
      NOT pg_has_role('service_role','qhub_evidence_writer','MEMBER')
      AND NOT pg_has_role('anon','qhub_evidence_writer','MEMBER')
      AND NOT pg_has_role('authenticated','qhub_evidence_writer','MEMBER')), 'EVIDENCE_WRITER_MEMBERSHIP_LEAK'),
    ('schema.qhub_private_locked', 'FUNCTION', (
      to_regnamespace('qhub_private') IS NOT NULL
      AND (SELECT nspowner FROM pg_namespace WHERE nspname='qhub_private') = (SELECT oid FROM owner_oid)
      AND NOT has_schema_privilege('service_role','qhub_private','USAGE') AND NOT has_schema_privilege('service_role','qhub_private','CREATE')
      AND NOT has_schema_privilege('anon','qhub_private','USAGE') AND NOT has_schema_privilege('authenticated','qhub_private','USAGE')), 'PRIVATE_SCHEMA_EXPOSED'),
    ('schema.public_create_revoked', 'FUNCTION', (
      NOT has_schema_privilege('service_role','public','CREATE') AND NOT has_schema_privilege('anon','public','CREATE')
      AND NOT has_schema_privilege('authenticated','public','CREATE')), 'PUBLIC_CREATE_EXPOSED'),
    ('privilege.service_role_cannot_commit', 'FUNCTION', (
      -- No column-level UPDATE nor a path for service_role to set COMMITTED (guard trigger present).
      EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_evaluation_commit_guard'
        AND tgrelid='public.qhub_control_evaluations'::regclass AND NOT tgisinternal AND tgtype=19 AND tgenabled='O'
        AND tgfoid='qhub_private.qhub_evaluation_commit_guard()'::regprocedure)), 'COMMITTED_GUARD_MISSING'),

    -- ── Triggers (exact table/timing/events/function/enabled) ──
    ('trigger.step_guard', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
      AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal AND tgtype=23 AND tgenabled='O' AND tgfoid='qhub_private.qhub_agent_run_step_guard()'::regprocedure), 'TRIGGER_MISSING_OR_MISMATCH'),
    ('trigger.run_identity_guard', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
      AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal AND tgtype=19 AND tgenabled='O' AND tgfoid='qhub_private.qhub_agent_run_identity_guard()'::regprocedure), 'RUN_IDENTITY_GUARD_MISSING'),
    ('trigger.version_manifest_guard', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
      AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal AND tgtype=19 AND tgenabled='O' AND tgfoid='qhub_private.qhub_agent_version_manifest_guard()'::regprocedure), 'VERSION_MANIFEST_GUARD_MISSING'),
    ('trigger.receipt_binding_immutable', 'CONSTRAINT', EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_receipt_binding_immutable'
      AND tgrelid='public.qhub_governed_action_receipt_bindings'::regclass AND NOT tgisinternal AND tgtype=19 AND tgenabled='O' AND tgfoid='qhub_private.qhub_receipt_binding_immutable()'::regprocedure), 'RECEIPT_BINDING_TRIGGER_MISSING'),

    -- ── Privileges: no direct writes on steps or receipt bindings ──
    ('privilege.steps_no_direct_write', 'FUNCTION', (
      NOT has_table_privilege('service_role','public.qhub_agent_run_steps','INSERT') AND NOT has_table_privilege('service_role','public.qhub_agent_run_steps','UPDATE')
      AND NOT has_table_privilege('service_role','public.qhub_agent_run_steps','DELETE') AND has_table_privilege('service_role','public.qhub_agent_run_steps','SELECT')), 'STEPS_DIRECT_WRITE_PRESENT'),
    ('privilege.bindings_no_direct_write', 'FUNCTION', (
      NOT has_table_privilege('service_role','public.qhub_governed_action_receipt_bindings','INSERT') AND NOT has_table_privilege('service_role','public.qhub_governed_action_receipt_bindings','UPDATE')
      AND NOT has_table_privilege('service_role','public.qhub_governed_action_receipt_bindings','DELETE') AND has_table_privilege('service_role','public.qhub_governed_action_receipt_bindings','SELECT')), 'BINDINGS_DIRECT_WRITE_PRESENT'),
    ('privilege.browser_roles_denied', 'FUNCTION', (
      SELECT count(*) = 0 FROM information_schema.role_table_grants WHERE table_schema='public'
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps','qhub_governed_action_receipt_bindings')
        AND grantee IN ('PUBLIC','anon','authenticated')), 'BROWSER_PRIVILEGE_BROADENED'),
    ('privilege.service_role_scoped', 'FUNCTION', (
      -- agents/versions/runs SELECT+INSERT+UPDATE (9); steps + bindings SELECT only (2); no DELETE anywhere.
      (SELECT count(*) = 11 FROM information_schema.role_table_grants WHERE table_schema='public' AND grantee='service_role'
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps','qhub_governed_action_receipt_bindings') AND privilege_type IN ('SELECT','INSERT','UPDATE'))
      AND NOT has_table_privilege('service_role','public.qhub_agents','DELETE')), 'SERVICE_ROLE_PRIVILEGE_MISMATCH'),

    -- ── Foundation indexes preserved (run-idempotency MUST remain) ──
    ('index.version_content_unique', 'INDEX', EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_versions_hash' AND i.indisunique), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.run_idempotency_unique', 'INDEX', EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_runs_idem' AND i.indisunique), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_index_unique', 'INDEX', EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_run_steps_run_index' AND i.indisunique), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_result_unique', 'INDEX', EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_run_steps_run_result' AND i.indisunique), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.receipt_binding_unique', 'INDEX', (
      SELECT count(*) = 2 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname IN ('idx_receipt_binding_receipt','idx_receipt_binding_eval') AND i.indisunique), 'INDEX_MISSING_OR_MISMATCH'),

    -- ── RLS + policies (exact restrictive posture; no permissive broadening) ──
    ('rls.enabled_all', 'RLS_ENABLED', (SELECT count(*) = 5 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace JOIN ptab a ON a.name=t.relname WHERE n.nspname='public' AND t.relrowsecurity), 'RLS_DISABLED'),
    ('policy.restrictive_exact', 'RLS_POLICY', (
      -- Every governed table has EXACTLY one policy: RESTRICTIVE, roles {anon,authenticated}, USING false, WITH CHECK false.
      (SELECT count(*) = 5 FROM pg_policy p JOIN pg_class t ON t.oid=p.polrelid JOIN ptab a ON a.name=t.relname
         WHERE p.polpermissive=FALSE AND pg_get_expr(p.polqual, p.polrelid)='false' AND pg_get_expr(p.polwithcheck, p.polrelid)='false'
           AND (SELECT array_agg(rolname::text ORDER BY rolname::text) FROM pg_roles WHERE oid = ANY(p.polroles)) = ARRAY['anon','authenticated'])
      AND (SELECT count(*) = 0 FROM pg_policy p JOIN pg_class t ON t.oid=p.polrelid JOIN ptab a ON a.name=t.relname WHERE p.polpermissive=TRUE)
    ), 'POLICY_MISSING_OR_BROADENED'),

    ('function.agent_verifier', 'FUNCTION',
      to_regprocedure('public.qhub_verify_agent_schema()') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid='public.qhub_verify_agent_schema()'::regprocedure)
      AND NOT has_function_privilege('anon','public.qhub_verify_agent_schema()','EXECUTE')
      AND NOT has_function_privilege('authenticated','public.qhub_verify_agent_schema()','EXECUTE')
      AND has_function_privilege('service_role','public.qhub_verify_agent_schema()','EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED')
),
normalized AS (SELECT identifier, category, ready, CASE WHEN ready THEN 'OK' ELSE reason_code END AS reason_code FROM checks)
SELECT jsonb_build_object(
  'expected_version', '2026-07-29.agent-result-continuity-r4',
  'ready', bool_and(ready),
  'checks', jsonb_agg(jsonb_build_object('identifier', identifier, 'category', category, 'ready', ready, 'reason_code', reason_code) ORDER BY category, identifier)
) FROM normalized
$body$;
BEGIN
  IF to_regprocedure('public.qhub_verify_agent_schema()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_verify_agent_schema() RETURNS JSONB
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_verify_agent_schema()'::regprocedure) IS DISTINCT FROM b THEN
    EXECUTE format($ddl$CREATE OR REPLACE FUNCTION public.qhub_verify_agent_schema() RETURNS JSONB
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, qhub_private AS %L$ddl$, b);
  END IF;
END $mig$;

COMMIT;
