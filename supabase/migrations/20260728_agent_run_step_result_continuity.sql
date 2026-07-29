-- QHUB Agent Framework — AGENT RUN-STEP RESULT CONTINUITY (authoritative, additive)
-- supabase/migrations/20260728_agent_run_step_result_continuity.sql
--
-- Server-owned, DATABASE-ENFORCED terminalization + result-continuity contract for
-- governed run steps, hardened after independent (Codex) review.
--
-- Authorization is PRIVILEGE-BASED, not flag-based: service_role (and PUBLIC/anon/
-- authenticated) hold NO direct INSERT/UPDATE/DELETE on qhub_agent_run_steps — only
-- SELECT. Rows are written EXCLUSIVELY through two SECURITY DEFINER RPCs owned by the
-- migration owner: qhub_create_agent_run_step_pending (nonterminal) and
-- qhub_finalize_agent_run_step (terminal). No caller-settable GUC is trusted. A
-- defensive trigger independently enforces every row invariant and immutability, and
-- recomputes result_hash from authoritative records — it does NOT rely on any path flag.
--
-- The finalization RPC LOCKS and VALIDATES every authoritative record bound into the
-- canonical hash (run, agent+lifecycle, version, release+status, evaluation+decision/
-- event, enforcement plan+status, policy hashes) with full tenant/app/agent/version/
-- release consistency and decision/receipt semantics. Run identity fields (and the
-- version manifest_hash) bound into the hash are made immutable so a finalized
-- preimage cannot be invalidated after the fact.
--
-- Idempotent + NON-destructive: no DROP/TRUNCATE/DELETE, no destructive type change,
-- no fabricated backfill, no browser-role broadening, no forgeable GUC. Every function
-- is catalog-guarded (created only when absent; aborts on drift) so a second run makes
-- ZERO catalog changes (stable function/trigger OID + xmin). Run ONCE in the Supabase
-- SQL editor (project jsjsanmaahvmynblmzkq).

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

-- ─── 2. Canonical-encoding primitives (SECURITY INVOKER; browser-denied) ─────
-- cell(v) = '<utf8-byte-length>:<v>;'  |  '-1:;' for NULL. Byte-identical to the
-- TypeScript `cell` in app/lib/qhub/agent/runtime/safe-result.ts.
DO $mig$
DECLARE b text := $body$
  SELECT CASE WHEN v IS NULL THEN '-1:;' ELSE octet_length(v)::text || ':' || v || ';' END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_agent_hash_cell(text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_hash_cell(v TEXT) RETURNS TEXT
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_hash_cell(text)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_hash_cell drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $mig$
DECLARE b text := $body$
  SELECT public.qhub_agent_hash_cell(CASE WHEN v IS NULL THEN NULL ELSE v::text END)
$body$;
BEGIN
  IF to_regprocedure('public.qhub_agent_hash_intcell(int)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_hash_intcell(v INT) RETURNS TEXT
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_hash_intcell(int)'::regprocedure) IS DISTINCT FROM b THEN
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
  out  TEXT := 'V' || public.qhub_agent_hash_cell('agent-safe-result-1.0.0')
               || public.qhub_agent_hash_cell(sr ->> 'execution_status');
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
    out := out || public.qhub_agent_hash_cell(tv);
  END LOOP;
  RETURN out;
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_agent_canonical_safe_result(jsonb)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_canonical_safe_result(sr JSONB) RETURNS TEXT
      LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_canonical_safe_result(jsonb)'::regprocedure) IS DISTINCT FROM b THEN
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

  IF octet_length(public.qhub_agent_canonical_safe_result(sr)) > 1024 THEN RETURN FALSE; END IF;
  RETURN TRUE;
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_agent_safe_result_valid(jsonb)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_safe_result_valid(sr JSONB) RETURNS BOOLEAN
      LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_safe_result_valid(jsonb)'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_safe_result_valid drift — aborting rather than replacing';
  END IF;
END $mig$;

-- ─── 4. Canonical STEP RESULT HASH (pure; mirrors step-result-hash.ts) ────────
DO $mig$
DECLARE b text := $body$
  SELECT encode(sha256(convert_to(
    public.qhub_agent_hash_cell('agent-step-result-1.0.0')
    || public.qhub_agent_hash_cell(p_org_id)
    || public.qhub_agent_hash_cell(p_qhub_app_id)
    || public.qhub_agent_hash_cell(p_agent_id)
    || public.qhub_agent_hash_cell(p_agent_version_id)
    || public.qhub_agent_hash_cell(p_release_candidate_id)
    || public.qhub_agent_hash_cell(p_release_candidate_hash)
    || public.qhub_agent_hash_cell(p_manifest_hash)
    || public.qhub_agent_hash_cell(p_run_id)
    || public.qhub_agent_hash_cell(p_runtime_provider_id)
    || public.qhub_agent_hash_cell(p_runtime_provider_version)
    || public.qhub_agent_hash_intcell(p_step_index)
    || public.qhub_agent_hash_cell(p_step_kind)
    || public.qhub_agent_hash_cell(p_action_type)
    || public.qhub_agent_hash_cell(p_input_hash)
    || public.qhub_agent_hash_cell(p_decision)
    || public.qhub_agent_hash_cell(p_evaluation_id)
    || public.qhub_agent_hash_cell(p_action_request_id)
    || public.qhub_agent_hash_cell(p_action_digest)
    || public.qhub_agent_hash_cell(p_policy_profile_id)
    || public.qhub_agent_hash_intcell(p_policy_profile_version)
    || public.qhub_agent_hash_cell(p_policy_profile_hash)
    || public.qhub_agent_hash_cell(p_enforcement_plan_id)
    || public.qhub_agent_hash_intcell(p_enforcement_plan_version)
    || public.qhub_agent_hash_cell(p_enforcement_plan_hash)
    || public.qhub_agent_hash_cell(p_receipt_id)
    || public.qhub_agent_hash_cell(CASE WHEN p_safe_result IS NULL THEN NULL
                                        ELSE public.qhub_agent_canonical_safe_result(p_safe_result) END)
    || public.qhub_agent_hash_cell(p_previous_step_hash)
  , 'UTF8')), 'hex')
$body$;
BEGIN
  IF to_regprocedure('public.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_step_result_hash(
      p_org_id TEXT, p_qhub_app_id TEXT, p_agent_id TEXT, p_agent_version_id TEXT, p_release_candidate_id TEXT,
      p_release_candidate_hash TEXT, p_manifest_hash TEXT, p_run_id TEXT, p_runtime_provider_id TEXT,
      p_runtime_provider_version TEXT, p_step_index INT, p_step_kind TEXT, p_action_type TEXT, p_input_hash TEXT,
      p_decision TEXT, p_evaluation_id TEXT, p_action_request_id TEXT, p_action_digest TEXT, p_policy_profile_id TEXT,
      p_policy_profile_version INT, p_policy_profile_hash TEXT, p_enforcement_plan_id TEXT, p_enforcement_plan_version INT,
      p_enforcement_plan_hash TEXT, p_receipt_id TEXT, p_safe_result JSONB, p_previous_step_hash TEXT)
      RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)'::regprocedure) IS DISTINCT FROM b THEN
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

  RETURN public.qhub_agent_step_result_hash(
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
  IF to_regprocedure('public.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_compute_agent_step_result_hash(
      p_run_id UUID, p_step_index INT, p_safe_result JSONB, p_previous_step_hash TEXT, p_decision TEXT,
      p_input_hash TEXT, p_step_kind TEXT, p_action_type TEXT, p_evaluation_id UUID, p_receipt_id TEXT)
      RETURNS TEXT LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)'::regprocedure) IS DISTINCT FROM b THEN
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
    IF NEW.safe_result IS NULL OR NOT public.qhub_agent_safe_result_valid(NEW.safe_result) THEN
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

    recomputed := public.qhub_compute_agent_step_result_hash(
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
  IF to_regprocedure('public.qhub_agent_run_step_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_run_step_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_run_step_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_run_step_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
                 AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_run_step_guard BEFORE INSERT OR UPDATE ON public.qhub_agent_run_steps
      FOR EACH ROW EXECUTE FUNCTION public.qhub_agent_run_step_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
                 AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal
                 AND tgtype = 23 AND tgenabled = 'O'
                 AND tgfoid = 'public.qhub_agent_run_step_guard()'::regprocedure) THEN
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
  IF to_regprocedure('public.qhub_agent_run_identity_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_run_identity_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_run_identity_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_run_identity_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
                 AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_run_identity_guard BEFORE UPDATE ON public.qhub_agent_runs
      FOR EACH ROW EXECUTE FUNCTION public.qhub_agent_run_identity_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
                 AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'public.qhub_agent_run_identity_guard()'::regprocedure) THEN
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
  IF to_regprocedure('public.qhub_agent_version_manifest_guard()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_agent_version_manifest_guard() RETURNS TRIGGER
      LANGUAGE plpgsql SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_agent_version_manifest_guard()'::regprocedure) IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'qhub_agent_version_manifest_guard drift — aborting rather than replacing';
  END IF;
END $mig$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
                 AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER trg_qhub_agent_version_manifest_guard BEFORE UPDATE ON public.qhub_agent_versions
      FOR EACH ROW EXECUTE FUNCTION public.qhub_agent_version_manifest_guard();
  ELSIF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
                 AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal
                 AND tgtype = 19 AND tgenabled = 'O'
                 AND tgfoid = 'public.qhub_agent_version_manifest_guard()'::regprocedure) THEN
    RAISE EXCEPTION 'trg_qhub_agent_version_manifest_guard exists but does not match expected timing/events/function/enabled';
  END IF;
END $$;

-- ─── 8. Nonterminal create-step RPC (service-role only; owner-privileged) ─────
DO $mig$
DECLARE b text := $body$
DECLARE
  run RECORD;
  existing_hash TEXT;
BEGIN
  SELECT current_state INTO run FROM public.qhub_agent_runs WHERE run_id = p_run_id AND org_id = p_org_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'qhub_create_agent_run_step_pending: run % not found for org %', p_run_id, p_org_id; END IF;
  IF run.current_state NOT IN ('RUNNING','AWAITING_APPROVAL') THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: run % not in a writable state (%)', p_run_id, run.current_state;
  END IF;

  SELECT result_hash INTO existing_hash FROM public.qhub_agent_run_steps
   WHERE run_id = p_run_id AND step_index = p_step_index FOR UPDATE;
  IF existing_hash IS NOT NULL THEN
    RAISE EXCEPTION 'qhub_create_agent_run_step_pending: step %/% is already finalized', p_run_id, p_step_index;
  END IF;

  IF FOUND THEN
    UPDATE public.qhub_agent_run_steps
       SET step_kind = p_step_kind, action_type = p_action_type, evaluation_id = p_evaluation_id,
           decision = 'REQUIRE_APPROVAL', reason_codes = COALESCE(p_reason_codes,'{}'),
           input_hash = p_input_hash, summary = p_summary
     WHERE run_id = p_run_id AND step_index = p_step_index;
  ELSE
    INSERT INTO public.qhub_agent_run_steps
      (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, input_hash, summary)
    VALUES (p_run_id, p_org_id, p_step_index, p_step_kind, p_action_type, p_evaluation_id, 'REQUIRE_APPROVAL',
            COALESCE(p_reason_codes,'{}'), p_input_hash, p_summary);
  END IF;

  RETURN jsonb_build_object('recorded', true, 'run_id', p_run_id, 'step_index', p_step_index, 'decision', 'REQUIRE_APPROVAL');
END
$body$;
BEGIN
  IF to_regprocedure('public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_create_agent_run_step_pending(
      p_run_id UUID, p_org_id TEXT, p_step_index INT, p_step_kind TEXT, p_action_type TEXT, p_evaluation_id UUID,
      p_reason_codes TEXT[], p_input_hash TEXT, p_summary TEXT)
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
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
  IF NOT public.qhub_agent_safe_result_valid(p_safe_result) THEN
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
  SELECT org_id, qhub_app_id, action_type, decision, action_event_state, policy_profile_hash,
         enforcement_plan_id, enforcement_plan_hash
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

  -- Receipt semantics (receipts are ledger-durable; the DB-authoritative signal is
  -- the evaluation's committed action-event state — an arbitrary receipt is rejected).
  IF p_decision IN ('EXECUTED','SIMULATED') THEN
    IF p_receipt_id IS NULL THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: decision % requires a receipt', p_decision;
    END IF;
    IF ev.action_event_state <> 'COMMITTED' THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: receipt present but evaluation action-event is not COMMITTED (%)', ev.action_event_state;
    END IF;
  ELSIF p_decision = 'DENY' THEN
    IF p_receipt_id IS NOT NULL THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: DENY step must not carry a receipt';
    END IF;
  ELSIF p_receipt_id IS NOT NULL AND ev.action_event_state <> 'COMMITTED' THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: receipt present but evaluation action-event is not COMMITTED';
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

  new_hash := public.qhub_compute_agent_step_result_hash(
    p_run_id, p_step_index, p_safe_result, prev_hash, p_decision, p_input_hash, p_step_kind, p_action_type, p_evaluation_id, p_receipt_id);

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
           reason_codes = COALESCE(p_reason_codes,'{}'), receipt_id = p_receipt_id, input_hash = p_input_hash,
           summary = p_summary, safe_result = p_safe_result, previous_step_hash = prev_hash, result_hash = new_hash,
           result_hash_schema_version = 'agent-step-result-1.0.0', finalized_at = NOW()
     WHERE run_id = p_run_id AND step_index = p_step_index;
  ELSE
    INSERT INTO public.qhub_agent_run_steps
      (run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision, reason_codes, receipt_id,
       input_hash, summary, safe_result, previous_step_hash, result_hash, result_hash_schema_version, finalized_at)
    VALUES (p_run_id, p_org_id, p_step_index, p_step_kind, p_action_type, p_evaluation_id, p_decision,
            COALESCE(p_reason_codes,'{}'), p_receipt_id, p_input_hash, p_summary, p_safe_result, prev_hash, new_hash,
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
      RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
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
  hashsig      text := 'public.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)';
  finalsig     text := 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)';
  createsig    text := 'public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)';
BEGIN
  IF has_function_privilege('service_role', hashsig, 'EXECUTE')                 -- helper still exposed, OR
     OR NOT has_function_privilege('service_role', finalsig, 'EXECUTE')          -- finalize not yet granted, OR
     OR NOT has_function_privilege('service_role', createsig, 'EXECUTE')         -- create not yet granted, OR
     OR has_table_privilege('service_role','public.qhub_agent_run_steps','INSERT')  -- direct write present, OR
     OR NOT has_table_privilege('service_role','public.qhub_agent_run_steps','SELECT') THEN  -- read missing
    -- Helpers: executable by NO client role (owner-only; called within DEFINER fns).
    REVOKE ALL ON FUNCTION public.qhub_agent_hash_cell(text) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_hash_intcell(int) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_canonical_safe_result(jsonb) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_safe_result_valid(jsonb) FROM PUBLIC, anon, authenticated, service_role;
    EXECUTE 'REVOKE ALL ON FUNCTION ' || hashsig || ' FROM PUBLIC, anon, authenticated, service_role';
    REVOKE ALL ON FUNCTION public.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_run_step_guard() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_run_identity_guard() FROM PUBLIC, anon, authenticated, service_role;
    REVOKE ALL ON FUNCTION public.qhub_agent_version_manifest_guard() FROM PUBLIC, anon, authenticated, service_role;

    -- Write RPCs: executable ONLY by service_role.
    EXECUTE 'REVOKE ALL ON FUNCTION ' || createsig || ' FROM PUBLIC, anon, authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || createsig || ' TO service_role';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || finalsig || ' FROM PUBLIC, anon, authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || finalsig || ' TO service_role';

    -- Verifier: browser-denied, service-role-only (re-asserted after replace).
    REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM PUBLIC, anon, authenticated;
    GRANT EXECUTE ON FUNCTION public.qhub_verify_agent_schema() TO service_role;

    -- Steps table: NO direct terminal write path — SELECT only for service_role.
    REVOKE ALL ON TABLE public.qhub_agent_run_steps FROM PUBLIC, anon, authenticated, service_role;
    GRANT SELECT ON TABLE public.qhub_agent_run_steps TO service_role;
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
END $$;

-- ─── 12. Indexes ─────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_run_steps_run_result
  ON public.qhub_agent_run_steps (run_id, result_hash) WHERE result_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_finalized
  ON public.qhub_agent_run_steps (run_id, step_index) WHERE result_hash IS NOT NULL;

-- ─── 13. Schema verifier — prove the full hardened contract ──────────────────
DO $mig$
DECLARE b text := $body$
WITH agent_tables(name) AS (
  VALUES ('qhub_agents'), ('qhub_agent_versions'), ('qhub_agent_runs'), ('qhub_agent_run_steps')
),
fk_count AS (
  SELECT count(*) AS n FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
  WHERE c.contype='f' AND n.nspname='public'
    AND t.relname IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps') AND c.convalidated
),
hashsig AS (SELECT 'public.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)'::text s),
computesig AS (SELECT 'public.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)'::text s),
finalsig AS (SELECT 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)'::text s),
createsig AS (SELECT 'public.qhub_create_agent_run_step_pending(uuid,text,int,text,text,uuid,text[],text,text)'::text s),
checks(identifier, category, ready, reason_code) AS (
  VALUES
    ('table.qhub_agents', 'TABLE', to_regclass('public.qhub_agents') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_versions', 'TABLE', to_regclass('public.qhub_agent_versions') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_runs', 'TABLE', to_regclass('public.qhub_agent_runs') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_run_steps', 'TABLE', to_regclass('public.qhub_agent_run_steps') IS NOT NULL, 'TABLE_MISSING'),

    ('column.steps_contract', 'COLUMN', (
      SELECT count(*) = 16 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND column_name = ANY(ARRAY['step_id','run_id','org_id','step_index','step_kind','action_type',
          'evaluation_id','decision','reason_codes','input_hash','summary',
          'result_hash','safe_result','previous_step_hash','finalized_at','result_hash_schema_version'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.continuity_types', 'COLUMN', (
      SELECT count(*) = 5 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND ((column_name IN ('result_hash','previous_step_hash','result_hash_schema_version') AND data_type='text')
          OR (column_name='safe_result' AND data_type='jsonb')
          OR (column_name='finalized_at' AND data_type='timestamp with time zone'))
    ), 'CONTINUITY_TYPE_MISMATCH'),

    ('constraint.foreign_keys_validated', 'CONSTRAINT', (SELECT n = 13 FROM fk_count), 'FK_MISSING_OR_UNVALIDATED'),
    ('constraint.step_decision_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_run_steps' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%decision%'
    ), 'CONSTRAINT_MISSING'),

    -- Continuity contract functions exist.
    ('function.safe_result_validator', 'FUNCTION', to_regprocedure('public.qhub_agent_safe_result_valid(jsonb)') IS NOT NULL, 'FUNCTION_MISSING'),
    ('function.canonical_safe_result', 'FUNCTION', to_regprocedure('public.qhub_agent_canonical_safe_result(jsonb)') IS NOT NULL, 'FUNCTION_MISSING'),
    ('function.step_result_hash', 'FUNCTION', to_regprocedure((SELECT s FROM hashsig)) IS NOT NULL, 'FUNCTION_MISSING'),
    ('function.compute_step_result_hash', 'FUNCTION', to_regprocedure((SELECT s FROM computesig)) IS NOT NULL, 'FUNCTION_MISSING'),

    -- Helpers are NOT executable by browser roles OR service_role (no oracle).
    ('privilege.helpers_locked', 'FUNCTION', (
      NOT has_function_privilege('anon', (SELECT s FROM hashsig), 'EXECUTE')
      AND NOT has_function_privilege('authenticated', (SELECT s FROM hashsig), 'EXECUTE')
      AND NOT has_function_privilege('service_role', (SELECT s FROM hashsig), 'EXECUTE')
      AND NOT has_function_privilege('anon', (SELECT s FROM computesig), 'EXECUTE')
      AND NOT has_function_privilege('service_role', (SELECT s FROM computesig), 'EXECUTE')
      AND NOT has_function_privilege('anon', 'public.qhub_agent_safe_result_valid(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('service_role', 'public.qhub_agent_safe_result_valid(jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('anon', 'public.qhub_agent_run_step_guard()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'public.qhub_agent_run_step_guard()', 'EXECUTE')
    ), 'HELPER_EXPOSED'),

    -- Finalizer: exists, DEFINER, fixed search_path, service-role-only.
    ('function.finalize_rpc', 'FUNCTION', (
      to_regprocedure((SELECT s FROM finalsig)) IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid=(SELECT s FROM finalsig)::regprocedure)
      AND (SELECT proconfig IS NOT NULL AND EXISTS(SELECT 1 FROM unnest(proconfig) x WHERE x LIKE 'search_path=%')
             FROM pg_proc WHERE oid=(SELECT s FROM finalsig)::regprocedure)
      AND NOT has_function_privilege('anon', (SELECT s FROM finalsig), 'EXECUTE')
      AND NOT has_function_privilege('authenticated', (SELECT s FROM finalsig), 'EXECUTE')
      AND has_function_privilege('service_role', (SELECT s FROM finalsig), 'EXECUTE')
    ), 'FINALIZE_RPC_MISSING_OR_EXPOSED'),
    -- Create-step RPC: exists, DEFINER, service-role-only.
    ('function.create_step_rpc', 'FUNCTION', (
      to_regprocedure((SELECT s FROM createsig)) IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid=(SELECT s FROM createsig)::regprocedure)
      AND NOT has_function_privilege('anon', (SELECT s FROM createsig), 'EXECUTE')
      AND has_function_privilege('service_role', (SELECT s FROM createsig), 'EXECUTE')
    ), 'CREATE_RPC_MISSING_OR_EXPOSED'),

    -- Defensive guard trigger on steps.
    ('trigger.step_guard', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_step_guard'
        AND tgrelid='public.qhub_agent_run_steps'::regclass AND NOT tgisinternal
        AND tgtype=23 AND tgenabled='O' AND tgfoid='public.qhub_agent_run_step_guard()'::regprocedure
    ), 'TRIGGER_MISSING_OR_MISMATCH'),
    -- Run identity immutability trigger.
    ('trigger.run_identity_guard', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_run_identity_guard'
        AND tgrelid='public.qhub_agent_runs'::regclass AND NOT tgisinternal
        AND tgtype=19 AND tgenabled='O' AND tgfoid='public.qhub_agent_run_identity_guard()'::regprocedure
    ), 'RUN_IDENTITY_GUARD_MISSING'),
    -- Version manifest immutability trigger.
    ('trigger.version_manifest_guard', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname='trg_qhub_agent_version_manifest_guard'
        AND tgrelid='public.qhub_agent_versions'::regclass AND NOT tgisinternal
        AND tgtype=19 AND tgenabled='O' AND tgfoid='public.qhub_agent_version_manifest_guard()'::regprocedure
    ), 'VERSION_MANIFEST_GUARD_MISSING'),

    -- NO direct terminal write privilege for service_role/browser on the steps table.
    ('privilege.steps_no_direct_write', 'FUNCTION', (
      NOT has_table_privilege('service_role','public.qhub_agent_run_steps','INSERT')
      AND NOT has_table_privilege('service_role','public.qhub_agent_run_steps','UPDATE')
      AND NOT has_table_privilege('service_role','public.qhub_agent_run_steps','DELETE')
      AND has_table_privilege('service_role','public.qhub_agent_run_steps','SELECT')
    ), 'STEPS_DIRECT_WRITE_PRESENT'),
    ('privilege.steps_browser_denied', 'FUNCTION', (
      SELECT count(*) = 0 FROM information_schema.role_table_grants
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps' AND grantee IN ('PUBLIC','anon','authenticated')
    ), 'STEPS_BROWSER_PRIVILEGE'),

    ('index.step_result_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_run_steps_run_result' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_index_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_agent_run_steps_run_index' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),

    ('rls.enabled_all', 'RLS_ENABLED', (
      SELECT count(*) = 4 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      JOIN agent_tables a ON a.name=t.relname WHERE n.nspname='public' AND t.relrowsecurity
    ), 'RLS_DISABLED'),
    ('policy.restrictive_service_only', 'RLS_POLICY', (
      SELECT count(*) = 4 FROM pg_policy p JOIN pg_class t ON t.oid=p.polrelid
      JOIN agent_tables a ON a.name=t.relname WHERE p.polpermissive=FALSE
    ), 'POLICY_MISSING_OR_PERMISSIVE'),

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
  'expected_version', '2026-07-28.agent-result-continuity-r2',
  'ready', bool_and(ready),
  'checks', jsonb_agg(jsonb_build_object('identifier', identifier, 'category', category, 'ready', ready, 'reason_code', reason_code) ORDER BY category, identifier)
) FROM normalized
$body$;
BEGIN
  IF to_regprocedure('public.qhub_verify_agent_schema()') IS NULL THEN
    EXECUTE format($ddl$CREATE FUNCTION public.qhub_verify_agent_schema() RETURNS JSONB
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
  ELSIF (SELECT prosrc FROM pg_proc WHERE oid = 'public.qhub_verify_agent_schema()'::regprocedure) IS DISTINCT FROM b THEN
    EXECUTE format($ddl$CREATE OR REPLACE FUNCTION public.qhub_verify_agent_schema() RETURNS JSONB
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS %L$ddl$, b);
  END IF;
END $mig$;

COMMIT;
