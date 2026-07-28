-- QHUB Agent Framework — AGENT RUN-STEP RESULT CONTINUITY (authoritative, additive)
-- supabase/migrations/20260728_agent_run_step_result_continuity.sql
--
-- Server-owned, database-enforced terminalization + result-continuity contract for
-- governed run steps. A terminal step is finalized ONLY through the service-role
-- function qhub_finalize_agent_run_step(...), which validates ownership, the state
-- transition, a STRICT safe_result, and the previous-step hash chain, then computes
-- the canonical result_hash from AUTHORITATIVE database records (never a caller
-- argument). A defensive BEFORE INSERT OR UPDATE trigger re-derives and re-checks the
-- same invariants so no direct table write can bypass the contract, and makes a
-- finalized step's protected fields immutable.
--
-- Continuity fields are additive + nullable: legacy rows keep NULLs and are
-- classified NON_RESUMABLE_LEGACY_CONTINUITY by the runtime (fail closed) — this
-- migration fabricates NO safe results or hashes for existing rows.
--
-- Idempotent and NON-destructive: no DROP, no TRUNCATE, no DELETE, no destructive
-- type change, no browser-role broadening. Re-running is a true no-op (stable
-- trigger identity). Service-role-only + RESTRICTIVE RLS are inherited and
-- re-asserted. Run ONCE in the Supabase SQL editor (project jsjsanmaahvmynblmzkq).

BEGIN;

-- ─── 0. Required parents ─────────────────────────────────────────────────────
DO $$
BEGIN
  IF to_regclass('public.qhub_agent_runs') IS NULL
     OR to_regclass('public.qhub_agent_run_steps') IS NULL
     OR to_regclass('public.qhub_agent_versions') IS NULL
     OR to_regclass('public.qhub_control_evaluations') IS NULL THEN
    RAISE EXCEPTION 'Result-continuity aborted: a required Agent Framework / Gate 04 parent table is missing';
  END IF;
END
$$;

-- ─── 1. Additive continuity columns (nullable; legacy rows keep NULLs) ────────
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS result_hash                TEXT;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS safe_result                JSONB;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS previous_step_hash         TEXT;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS finalized_at               TIMESTAMPTZ;
ALTER TABLE public.qhub_agent_run_steps ADD COLUMN IF NOT EXISTS result_hash_schema_version TEXT;

-- ─── 2. Canonical-encoding primitives (length-prefixed, null-distinguishing) ──
-- cell(v) = '<utf8-byte-length>:<v>;'  |  '-1:;' for NULL. Byte-identical to the
-- TypeScript `cell` in app/lib/qhub/agent/runtime/safe-result.ts. This makes the
-- canonical preimage unambiguous without a trusted separator.
CREATE OR REPLACE FUNCTION public.qhub_agent_hash_cell(v TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
  SELECT CASE WHEN v IS NULL THEN '-1:;' ELSE octet_length(v)::text || ':' || v || ';' END
$$;

CREATE OR REPLACE FUNCTION public.qhub_agent_hash_intcell(v INT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
  SELECT public.qhub_agent_hash_cell(CASE WHEN v IS NULL THEN NULL ELSE v::text END)
$$;

-- ─── 3. Canonical SAFE RESULT serialization + strict validation ───────────────
-- Mirrors app/lib/qhub/agent/runtime/safe-result.ts exactly. Fixed metadata key
-- order: duration_ms, outcome, record_count, result_kind, status_code, truncated.
CREATE OR REPLACE FUNCTION public.qhub_agent_canonical_safe_result(sr JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
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
    ELSIF jsonb_typeof(meta -> k) = 'string' THEN
      tv := 's:' || (meta ->> k);
    ELSIF jsonb_typeof(meta -> k) = 'boolean' THEN
      tv := 'b:' || (meta ->> k);
    ELSIF jsonb_typeof(meta -> k) = 'number' THEN
      tv := 'n:' || (meta ->> k);
    ELSE
      tv := 'absent';
    END IF;

    out := out || public.qhub_agent_hash_cell(tv);
  END LOOP;

  RETURN out;
END
$$;

CREATE OR REPLACE FUNCTION public.qhub_agent_safe_result_valid(sr JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  allowed_meta TEXT[] := ARRAY['duration_ms','outcome','record_count','result_kind','status_code','truncated'];
  es           JSONB;
  meta         JSONB;
  k            TEXT;
  vt           TEXT;
  num          NUMERIC;
BEGIN
  IF sr IS NULL OR jsonb_typeof(sr) <> 'object' THEN
    RETURN FALSE;
  END IF;

  -- strict top-level allowlist
  IF EXISTS (
    SELECT 1 FROM jsonb_object_keys(sr) t(key)
    WHERE t.key NOT IN ('execution_status','safe_metadata')
  ) THEN
    RETURN FALSE;
  END IF;

  -- execution_status: absent | null | bounded string
  es := sr -> 'execution_status';
  IF es IS NOT NULL AND jsonb_typeof(es) NOT IN ('string','null') THEN
    RETURN FALSE;
  END IF;
  IF jsonb_typeof(es) = 'string' AND octet_length(sr ->> 'execution_status') > 64 THEN
    RETURN FALSE;
  END IF;

  -- safe_metadata: optional object of allowlisted scalar keys/values
  IF sr ? 'safe_metadata' THEN
    meta := sr -> 'safe_metadata';

    IF jsonb_typeof(meta) <> 'object' THEN
      RETURN FALSE;
    END IF;

    FOR k IN SELECT jsonb_object_keys(meta) LOOP
      IF NOT (k = ANY(allowed_meta)) THEN
        RETURN FALSE;
      END IF;
      IF octet_length(k) > 64 THEN
        RETURN FALSE;
      END IF;

      vt := jsonb_typeof(meta -> k);

      IF vt = 'string' THEN
        IF octet_length(meta ->> k) > 256 THEN
          RETURN FALSE;
        END IF;
      ELSIF vt = 'boolean' OR vt = 'null' THEN
        -- ok
      ELSIF vt = 'number' THEN
        num := (meta ->> k)::numeric;
        IF num <> trunc(num) OR num < -1000000000000 OR num > 1000000000000 THEN
          RETURN FALSE;
        END IF;
      ELSE
        -- object | array → rejected (no nested structures)
        RETURN FALSE;
      END IF;
    END LOOP;
  END IF;

  -- bounded canonical size (16 KiB)
  IF octet_length(public.qhub_agent_canonical_safe_result(sr)) > 16384 THEN
    RETURN FALSE;
  END IF;

  RETURN TRUE;
END
$$;

-- ─── 4. Canonical STEP RESULT HASH (pure; mirrors step-result-hash.ts) ────────
-- Fixed field order; every field length-prefixed; SHA-256 over UTF-8 bytes.
CREATE OR REPLACE FUNCTION public.qhub_agent_step_result_hash(
  p_org_id                   TEXT,
  p_qhub_app_id              TEXT,
  p_agent_id                 TEXT,
  p_agent_version_id         TEXT,
  p_release_candidate_id     TEXT,
  p_release_candidate_hash   TEXT,
  p_manifest_hash            TEXT,
  p_run_id                   TEXT,
  p_runtime_provider_id      TEXT,
  p_runtime_provider_version TEXT,
  p_step_index               INT,
  p_step_kind                TEXT,
  p_action_type              TEXT,
  p_input_hash               TEXT,
  p_decision                 TEXT,
  p_evaluation_id            TEXT,
  p_action_request_id        TEXT,
  p_action_digest            TEXT,
  p_policy_profile_id        TEXT,
  p_policy_profile_version   INT,
  p_policy_profile_hash      TEXT,
  p_enforcement_plan_id      TEXT,
  p_enforcement_plan_version INT,
  p_enforcement_plan_hash    TEXT,
  p_receipt_id               TEXT,
  p_safe_result              JSONB,
  p_previous_step_hash       TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
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
$$;

-- ─── 5. Authoritative result-hash computation from DB records ─────────────────
-- Loads the run, its version, and (if any) the step's Gate 04 evaluation, then
-- calls the pure hash function. The database — never a caller — assembles the
-- canonical inputs. Shared by the finalization RPC and the defensive trigger.
CREATE OR REPLACE FUNCTION public.qhub_compute_agent_step_result_hash(
  p_run_id             UUID,
  p_step_index         INT,
  p_safe_result        JSONB,
  p_previous_step_hash TEXT,
  p_decision           TEXT,
  p_input_hash         TEXT,
  p_step_kind          TEXT,
  p_action_type        TEXT,
  p_evaluation_id      UUID,
  p_receipt_id         TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  r RECORD;
  v_manifest_hash TEXT;
  e_action_request_id        UUID;
  e_action_digest            TEXT;
  e_policy_profile_id        UUID;
  e_policy_profile_version   INT;
  e_policy_profile_hash      TEXT;
  e_enforcement_plan_id      UUID;
  e_enforcement_plan_version INT;
  e_enforcement_plan_hash    TEXT;
BEGIN
  SELECT org_id, qhub_app_id, agent_id, agent_version_id, release_candidate_id,
         release_candidate_hash, runtime_provider, runtime_provider_version
    INTO r
    FROM public.qhub_agent_runs
   WHERE run_id = p_run_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: run % not found', p_run_id;
  END IF;

  SELECT manifest_hash INTO v_manifest_hash
    FROM public.qhub_agent_versions
   WHERE agent_version_id = r.agent_version_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: version % not found', r.agent_version_id;
  END IF;

  IF p_evaluation_id IS NOT NULL THEN
    SELECT action_request_id, action_digest, policy_profile_id, policy_profile_version,
           policy_profile_hash, enforcement_plan_id, enforcement_plan_version, enforcement_plan_hash
      INTO e_action_request_id, e_action_digest, e_policy_profile_id, e_policy_profile_version,
           e_policy_profile_hash, e_enforcement_plan_id, e_enforcement_plan_version, e_enforcement_plan_hash
      FROM public.qhub_control_evaluations
     WHERE evaluation_id = p_evaluation_id;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'qhub_compute_agent_step_result_hash: evaluation % not found', p_evaluation_id;
    END IF;
  END IF;

  RETURN public.qhub_agent_step_result_hash(
    r.org_id, r.qhub_app_id::text, r.agent_id::text, r.agent_version_id::text,
    r.release_candidate_id::text, r.release_candidate_hash, v_manifest_hash,
    p_run_id::text, r.runtime_provider, r.runtime_provider_version,
    p_step_index, p_step_kind, p_action_type, p_input_hash, p_decision,
    p_evaluation_id::text,
    e_action_request_id::text, e_action_digest, e_policy_profile_id::text,
    e_policy_profile_version, e_policy_profile_hash,
    e_enforcement_plan_id::text, e_enforcement_plan_version, e_enforcement_plan_hash,
    p_receipt_id, p_safe_result, p_previous_step_hash
  );
END
$$;

-- ─── 6. Defensive + immutability trigger ─────────────────────────────────────
-- Direct table writes cannot bypass the finalization contract. A "finalizing"
-- write (result_hash set) is permitted ONLY inside the sanctioned RPC path
-- (transaction-local flag qhub.allow_finalize='1'), must carry a valid strict
-- safe_result and a correct previous-step hash chain, and its result_hash MUST
-- equal the value recomputed from authoritative records (arbitrary caller hashes
-- are rejected). A finalized row's protected fields are immutable thereafter.
CREATE OR REPLACE FUNCTION public.qhub_agent_run_step_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
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
    IF NEW.run_id             IS DISTINCT FROM OLD.run_id
       OR NEW.step_index         IS DISTINCT FROM OLD.step_index
       OR NEW.step_kind          IS DISTINCT FROM OLD.step_kind
       OR NEW.action_type        IS DISTINCT FROM OLD.action_type
       OR NEW.input_hash         IS DISTINCT FROM OLD.input_hash
       OR NEW.decision           IS DISTINCT FROM OLD.decision
       OR NEW.evaluation_id      IS DISTINCT FROM OLD.evaluation_id
       OR NEW.receipt_id         IS DISTINCT FROM OLD.receipt_id
       OR NEW.reason_codes       IS DISTINCT FROM OLD.reason_codes
       OR NEW.summary            IS DISTINCT FROM OLD.summary
       OR NEW.safe_result        IS DISTINCT FROM OLD.safe_result
       OR NEW.result_hash        IS DISTINCT FROM OLD.result_hash
       OR NEW.previous_step_hash IS DISTINCT FROM OLD.previous_step_hash
       OR NEW.result_hash_schema_version IS DISTINCT FROM OLD.result_hash_schema_version
       OR NEW.finalized_at       IS DISTINCT FROM OLD.finalized_at
       OR NEW.org_id             IS DISTINCT FROM OLD.org_id THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized step is immutable (run=%, step_index=%)',
        OLD.run_id, OLD.step_index;
    END IF;

    RETURN NEW; -- unchanged finalized row
  END IF;

  IF NEW.result_hash IS NOT NULL THEN
    -- (B) Finalizing write: must go through the sanctioned RPC path.
    IF current_setting('qhub.allow_finalize', true) IS DISTINCT FROM '1' THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: terminalization is only permitted via qhub_finalize_agent_run_step (run=%, step_index=%)',
        NEW.run_id, NEW.step_index;
    END IF;

    IF NEW.decision NOT IN ('ALLOW','DENY','SIMULATED','EXECUTED') THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: non-terminal decision % cannot be finalized', NEW.decision;
    END IF;

    IF NEW.finalized_at IS NULL OR NEW.result_hash_schema_version IS DISTINCT FROM 'agent-step-result-1.0.0' THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized row requires finalized_at + result_hash_schema_version';
    END IF;

    IF NEW.safe_result IS NULL OR NOT public.qhub_agent_safe_result_valid(NEW.safe_result) THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: finalized row requires a valid strict safe_result';
    END IF;

    -- Action/decision relationship.
    IF NEW.decision IN ('EXECUTED','SIMULATED') AND NEW.receipt_id IS NULL THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: decision % requires a receipt_id', NEW.decision;
    END IF;
    IF NEW.decision = 'DENY' AND NEW.receipt_id IS NOT NULL THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: DENY step must not carry a receipt_id';
    END IF;

    -- Evaluation ownership (when the step is bound to a Gate 04 evaluation).
    IF NEW.evaluation_id IS NOT NULL THEN
      SELECT org_id, qhub_app_id INTO run_org, run_app
        FROM public.qhub_agent_runs WHERE run_id = NEW.run_id;
      SELECT org_id, qhub_app_id INTO eval_org, eval_app
        FROM public.qhub_control_evaluations WHERE evaluation_id = NEW.evaluation_id;
      IF eval_org IS NULL OR eval_org IS DISTINCT FROM run_org OR eval_app IS DISTINCT FROM run_app THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: evaluation % does not belong to this run''s tenant/app', NEW.evaluation_id;
      END IF;
    END IF;

    -- Previous-step hash chain.
    IF NEW.step_index = 0 THEN
      IF NEW.previous_step_hash IS NOT NULL THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: step 0 must have NULL previous_step_hash';
      END IF;
    ELSE
      SELECT result_hash INTO prior_hash
        FROM public.qhub_agent_run_steps
       WHERE run_id = NEW.run_id AND step_index = NEW.step_index - 1;

      IF prior_hash IS NULL THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: previous step %/% is missing or not finalized',
          NEW.run_id, NEW.step_index - 1;
      END IF;
      IF NEW.previous_step_hash IS DISTINCT FROM prior_hash THEN
        RAISE EXCEPTION 'qhub_agent_run_steps: previous_step_hash does not match the prior finalized step';
      END IF;
    END IF;

    -- Recompute from authoritative records; reject any caller-supplied hash.
    recomputed := public.qhub_compute_agent_step_result_hash(
      NEW.run_id, NEW.step_index, NEW.safe_result, NEW.previous_step_hash, NEW.decision,
      NEW.input_hash, NEW.step_kind, NEW.action_type, NEW.evaluation_id, NEW.receipt_id);

    IF NEW.result_hash IS DISTINCT FROM recomputed THEN
      RAISE EXCEPTION 'qhub_agent_run_steps: result_hash is not the authoritative canonical hash';
    END IF;

    RETURN NEW;
  END IF;

  -- (C) Non-finalizing write: continuity fields must stay absent (no partial /
  -- fabricated continuity outside finalization).
  IF NEW.previous_step_hash IS NOT NULL OR NEW.safe_result IS NOT NULL
     OR NEW.finalized_at IS NOT NULL OR NEW.result_hash_schema_version IS NOT NULL THEN
    RAISE EXCEPTION 'qhub_agent_run_steps: continuity fields require finalization via qhub_finalize_agent_run_step';
  END IF;

  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION public.qhub_agent_run_step_guard() FROM PUBLIC, anon, authenticated;

-- Catalog-guarded attach (NO DROP). Create only when absent; otherwise verify the
-- existing trigger matches exactly (row-level BEFORE INSERT OR UPDATE, correct
-- function, enabled) and abort on mismatch. tgtype 23 = ROW|BEFORE|INSERT|UPDATE.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_qhub_agent_run_step_guard'
      AND tgrelid = 'public.qhub_agent_run_steps'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_qhub_agent_run_step_guard
      BEFORE INSERT OR UPDATE ON public.qhub_agent_run_steps
      FOR EACH ROW EXECUTE FUNCTION public.qhub_agent_run_step_guard();
  ELSIF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_qhub_agent_run_step_guard'
      AND tgrelid = 'public.qhub_agent_run_steps'::regclass
      AND NOT tgisinternal
      AND tgtype = 23
      AND tgenabled = 'O'
      AND tgfoid = 'public.qhub_agent_run_step_guard()'::regprocedure
  ) THEN
    RAISE EXCEPTION 'trg_qhub_agent_run_step_guard exists but does not match the expected timing/events/function/enabled state';
  END IF;
END
$$;

-- ─── 7. Atomic finalization RPC (service-role only) ──────────────────────────
CREATE OR REPLACE FUNCTION public.qhub_finalize_agent_run_step(
  p_run_id       UUID,
  p_org_id       TEXT,
  p_step_index   INT,
  p_step_kind    TEXT,
  p_action_type  TEXT,
  p_evaluation_id UUID,
  p_decision     TEXT,
  p_reason_codes TEXT[],
  p_receipt_id   TEXT,
  p_input_hash   TEXT,
  p_summary      TEXT,
  p_safe_result  JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  run              RECORD;
  step             RECORD;
  step_exists      BOOLEAN;
  step_result_hash TEXT;
  prev_hash        TEXT;
  new_hash         TEXT;
BEGIN
  IF p_decision NOT IN ('ALLOW','DENY','SIMULATED','EXECUTED') THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: decision % is not terminal', p_decision;
  END IF;

  -- Lock the authoritative run.
  SELECT * INTO run FROM public.qhub_agent_runs
   WHERE run_id = p_run_id AND org_id = p_org_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: run % not found for org %', p_run_id, p_org_id;
  END IF;

  IF run.current_state NOT IN ('RUNNING','AWAITING_APPROVAL') THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: run % is not in a finalizable state (%)', p_run_id, run.current_state;
  END IF;

  -- Strict safe_result (defense in depth; the trigger re-checks).
  IF NOT public.qhub_agent_safe_result_valid(p_safe_result) THEN
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: safe_result failed strict validation';
  END IF;

  -- Lock the target step (may be a pre-recorded REQUIRE_APPROVAL row or absent).
  -- Capture existence/prior hash immediately: later SELECT INTOs reset FOUND.
  SELECT * INTO step FROM public.qhub_agent_run_steps
   WHERE run_id = p_run_id AND step_index = p_step_index
   FOR UPDATE;
  step_exists := FOUND;
  step_result_hash := CASE WHEN step_exists THEN step.result_hash ELSE NULL END;

  -- Previous-step hash chain (authoritative).
  IF p_step_index = 0 THEN
    prev_hash := NULL;
  ELSE
    SELECT result_hash INTO prev_hash FROM public.qhub_agent_run_steps
     WHERE run_id = p_run_id AND step_index = p_step_index - 1;
    IF prev_hash IS NULL THEN
      RAISE EXCEPTION 'qhub_finalize_agent_run_step: previous step %/% is missing or not finalized',
        p_run_id, p_step_index - 1;
    END IF;
  END IF;

  new_hash := public.qhub_compute_agent_step_result_hash(
    p_run_id, p_step_index, p_safe_result, prev_hash, p_decision,
    p_input_hash, p_step_kind, p_action_type, p_evaluation_id, p_receipt_id);

  -- Idempotency: an EXACT repeat is a no-op; a materially different repeat is rejected.
  IF step_result_hash IS NOT NULL THEN
    IF step_result_hash = new_hash THEN
      RETURN jsonb_build_object(
        'finalized', true, 'idempotent', true, 'run_id', p_run_id, 'step_index', p_step_index,
        'result_hash', new_hash, 'previous_step_hash', prev_hash,
        'result_hash_schema_version', 'agent-step-result-1.0.0');
    END IF;
    RAISE EXCEPTION 'qhub_finalize_agent_run_step: step %/% already finalized with a different result',
      p_run_id, p_step_index;
  END IF;

  -- Sanctioned write: permit the finalizing trigger path for this statement only.
  PERFORM set_config('qhub.allow_finalize', '1', true);

  IF step_exists THEN
    UPDATE public.qhub_agent_run_steps
       SET step_kind = p_step_kind, action_type = p_action_type, evaluation_id = p_evaluation_id,
           decision = p_decision, reason_codes = COALESCE(p_reason_codes, '{}'), receipt_id = p_receipt_id,
           input_hash = p_input_hash, summary = p_summary, safe_result = p_safe_result,
           previous_step_hash = prev_hash, result_hash = new_hash,
           result_hash_schema_version = 'agent-step-result-1.0.0', finalized_at = NOW()
     WHERE run_id = p_run_id AND step_index = p_step_index;
  ELSE
    INSERT INTO public.qhub_agent_run_steps (
      run_id, org_id, step_index, step_kind, action_type, evaluation_id, decision,
      reason_codes, receipt_id, input_hash, summary, safe_result, previous_step_hash,
      result_hash, result_hash_schema_version, finalized_at)
    VALUES (
      p_run_id, p_org_id, p_step_index, p_step_kind, p_action_type, p_evaluation_id, p_decision,
      COALESCE(p_reason_codes, '{}'), p_receipt_id, p_input_hash, p_summary, p_safe_result, prev_hash,
      new_hash, 'agent-step-result-1.0.0', NOW());
  END IF;

  PERFORM set_config('qhub.allow_finalize', '', true);

  RETURN jsonb_build_object(
    'finalized', true, 'idempotent', false, 'run_id', p_run_id, 'step_index', p_step_index,
    'result_hash', new_hash, 'previous_step_hash', prev_hash,
    'result_hash_schema_version', 'agent-step-result-1.0.0');
END
$$;

REVOKE ALL ON FUNCTION public.qhub_finalize_agent_run_step(
  UUID, TEXT, INT, TEXT, TEXT, UUID, TEXT, TEXT[], TEXT, TEXT, TEXT, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_finalize_agent_run_step(
  UUID, TEXT, INT, TEXT, TEXT, UUID, TEXT, TEXT[], TEXT, TEXT, TEXT, JSONB) TO service_role;

-- ─── 8. Indexes ──────────────────────────────────────────────────────────────
-- Preserve unique(run_id, step_index) (from the foundation migration). Add a
-- per-run uniqueness of finalized result_hash (no two steps share a result hash).
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_run_steps_run_result
  ON public.qhub_agent_run_steps (run_id, result_hash) WHERE result_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_finalized
  ON public.qhub_agent_run_steps (run_id, step_index) WHERE result_hash IS NOT NULL;

-- ─── 9. Re-assert RESTRICTIVE service-only RLS + grants (idempotent) ──────────
ALTER TABLE public.qhub_agent_run_steps ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policy
    WHERE polrelid = 'public.qhub_agent_run_steps'::regclass
      AND polname = 'qhub_agent_run_steps_service_only'
  ) THEN
    CREATE POLICY qhub_agent_run_steps_service_only ON public.qhub_agent_run_steps
      AS RESTRICTIVE FOR ALL TO anon, authenticated USING (FALSE) WITH CHECK (FALSE);
  END IF;
END $$;
REVOKE ALL ON TABLE public.qhub_agent_run_steps FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.qhub_agent_run_steps TO service_role;

-- ─── 10. Schema verifier — extend without weakening any prior check ──────────
CREATE OR REPLACE FUNCTION public.qhub_verify_agent_schema()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
WITH agent_tables(name) AS (
  VALUES ('qhub_agents'), ('qhub_agent_versions'), ('qhub_agent_runs'), ('qhub_agent_run_steps')
),
fk_count AS (
  SELECT count(*) AS n
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
  WHERE c.contype = 'f' AND n.nspname = 'public'
    AND t.relname IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
    AND c.convalidated
),
checks(identifier, category, ready, reason_code) AS (
  VALUES
    ('table.qhub_agents', 'TABLE', to_regclass('public.qhub_agents') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_versions', 'TABLE', to_regclass('public.qhub_agent_versions') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_runs', 'TABLE', to_regclass('public.qhub_agent_runs') IS NOT NULL, 'TABLE_MISSING'),
    ('table.qhub_agent_run_steps', 'TABLE', to_regclass('public.qhub_agent_run_steps') IS NOT NULL, 'TABLE_MISSING'),

    ('column.agents_contract', 'COLUMN', (
      SELECT count(*) = 14 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agents'
        AND column_name = ANY(ARRAY['agent_id','org_id','qhub_app_id','name','owner_user_id','owning_team',
          'current_version_id','current_lifecycle_state','current_operating_mode','risk_tier',
          'kill_switch_active','created_by','created_at','updated_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.versions_contract', 'COLUMN', (
      SELECT count(*) = 17 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_versions'
        AND column_name = ANY(ARRAY['agent_version_id','agent_id','org_id','qhub_app_id','manifest','manifest_hash',
          'manifest_version','operating_mode','autonomy_level','risk_tier','policy_profile_hash','enforcement_plan_hash',
          'release_candidate_id','release_candidate_hash','deployment_decision_id','frozen','created_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    ('column.runs_contract', 'COLUMN', (
      SELECT count(*) = 24 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_runs'
        AND column_name = ANY(ARRAY['run_id','agent_id','agent_version_id','org_id','qhub_app_id','release_candidate_id',
          'release_candidate_hash','initiating_user_id','operating_mode','runtime_provider','runtime_provider_version',
          'current_state','current_step','policy_profile_hash','enforcement_plan_hash','primary_model','input_hash',
          'output_hash','proposed_action_count','idempotency_key','pending_evaluation_id','error_reference','run_hash','started_at'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),
    -- Run-step contract now REQUIRES the 5 result-continuity columns (16 named).
    ('column.steps_contract', 'COLUMN', (
      SELECT count(*) = 16 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='qhub_agent_run_steps'
        AND column_name = ANY(ARRAY['step_id','run_id','org_id','step_index','step_kind','action_type',
          'evaluation_id','decision','reason_codes','input_hash','summary',
          'result_hash','safe_result','previous_step_hash','finalized_at','result_hash_schema_version'])
    ), 'COLUMN_MISSING_OR_MISMATCH'),

    ('constraint.foreign_keys_validated', 'CONSTRAINT', (SELECT n = 13 FROM fk_count), 'FK_MISSING_OR_UNVALIDATED'),

    ('constraint.lifecycle_state_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agents' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_lifecycle_state%'
    ), 'CONSTRAINT_MISSING'),
    ('constraint.run_state_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_runs' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%current_state%'
    ), 'CONSTRAINT_MISSING'),
    ('constraint.step_decision_check', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      WHERE t.relname='qhub_agent_run_steps' AND c.contype='c' AND pg_get_constraintdef(c.oid) ILIKE '%decision%'
    ), 'CONSTRAINT_MISSING'),

    -- Result-continuity contract objects.
    ('function.safe_result_validator', 'FUNCTION',
      to_regprocedure('public.qhub_agent_safe_result_valid(jsonb)') IS NOT NULL, 'FUNCTION_MISSING'),
    ('function.canonical_safe_result', 'FUNCTION',
      to_regprocedure('public.qhub_agent_canonical_safe_result(jsonb)') IS NOT NULL, 'FUNCTION_MISSING'),
    ('function.step_result_hash', 'FUNCTION',
      to_regprocedure('public.qhub_agent_step_result_hash(text,text,text,text,text,text,text,text,text,text,int,text,text,text,text,text,text,text,text,int,text,text,int,text,text,jsonb,text)') IS NOT NULL,
      'FUNCTION_MISSING'),
    ('function.compute_step_result_hash', 'FUNCTION',
      to_regprocedure('public.qhub_compute_agent_step_result_hash(uuid,int,jsonb,text,text,text,text,text,uuid,text)') IS NOT NULL,
      'FUNCTION_MISSING'),
    -- Finalization RPC: exists, SECURITY DEFINER, fixed search_path, service-role-only.
    ('function.finalize_rpc', 'FUNCTION', (
      to_regprocedure('public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid = 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)'::regprocedure)
      AND (SELECT proconfig IS NOT NULL AND EXISTS (SELECT 1 FROM unnest(proconfig) x WHERE x LIKE 'search_path=%')
             FROM pg_proc WHERE oid = 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)'::regprocedure)
      AND NOT has_function_privilege('anon', 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)', 'EXECUTE')
      AND has_function_privilege('service_role', 'public.qhub_finalize_agent_run_step(uuid,text,int,text,text,uuid,text,text[],text,text,text,jsonb)', 'EXECUTE')
    ), 'FINALIZE_RPC_MISSING_OR_EXPOSED'),
    -- Defensive trigger: attached to the correct table, row-level BEFORE INSERT|UPDATE,
    -- bound to the guard function, and enabled.
    ('trigger.step_guard', 'CONSTRAINT', EXISTS (
      SELECT 1 FROM pg_trigger
      WHERE tgname = 'trg_qhub_agent_run_step_guard'
        AND tgrelid = 'public.qhub_agent_run_steps'::regclass
        AND NOT tgisinternal
        AND tgtype = 23
        AND tgenabled = 'O'
        AND tgfoid = 'public.qhub_agent_run_step_guard()'::regprocedure
    ), 'TRIGGER_MISSING_OR_MISMATCH'),
    ('privilege.guard_fn_not_exposed', 'FUNCTION', (
      to_regprocedure('public.qhub_agent_run_step_guard()') IS NOT NULL
      AND NOT has_function_privilege('anon', 'public.qhub_agent_run_step_guard()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'public.qhub_agent_run_step_guard()', 'EXECUTE')
    ), 'GUARD_FN_EXPOSED'),

    ('index.version_content_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_versions_hash' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.run_idempotency_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_runs_idem' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_index_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_run_steps_run_index' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),
    ('index.step_result_unique', 'INDEX', EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      WHERE c.relname='idx_agent_run_steps_run_result' AND i.indisunique
    ), 'INDEX_MISSING_OR_MISMATCH'),

    ('rls.enabled_all', 'RLS_ENABLED', (
      SELECT count(*) = 4 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      JOIN agent_tables a ON a.name = t.relname
      WHERE n.nspname='public' AND t.relrowsecurity
    ), 'RLS_DISABLED'),

    ('policy.restrictive_service_only', 'RLS_POLICY', (
      SELECT count(*) = 4 FROM pg_policy p JOIN pg_class t ON t.oid=p.polrelid
      JOIN agent_tables a ON a.name = t.relname
      WHERE p.polpermissive = FALSE
    ), 'POLICY_MISSING_OR_PERMISSIVE'),

    ('privilege.browser_roles_denied', 'FUNCTION', (
      SELECT count(*) = 0 FROM information_schema.role_table_grants
      WHERE table_schema='public' AND grantee IN ('PUBLIC','anon','authenticated')
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
    ), 'BROWSER_PRIVILEGE_BROADENED'),
    ('privilege.service_role_scoped', 'FUNCTION', (
      SELECT count(*) = 12 FROM information_schema.role_table_grants
      WHERE table_schema='public' AND grantee='service_role'
        AND table_name IN ('qhub_agents','qhub_agent_versions','qhub_agent_runs','qhub_agent_run_steps')
        AND privilege_type IN ('SELECT','INSERT','UPDATE')
    ), 'SERVICE_ROLE_PRIVILEGE_MISMATCH'),

    ('function.agent_verifier', 'FUNCTION',
      to_regprocedure('public.qhub_verify_agent_schema()') IS NOT NULL
      AND (SELECT prosecdef FROM pg_proc WHERE oid = 'public.qhub_verify_agent_schema()'::regprocedure)
      AND NOT has_function_privilege('anon', 'public.qhub_verify_agent_schema()', 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'public.qhub_verify_agent_schema()', 'EXECUTE')
      AND has_function_privilege('service_role', 'public.qhub_verify_agent_schema()', 'EXECUTE'),
      'FUNCTION_MISSING_OR_EXPOSED')
),
normalized AS (
  SELECT identifier, category, ready, CASE WHEN ready THEN 'OK' ELSE reason_code END AS reason_code
  FROM checks
)
SELECT jsonb_build_object(
  'expected_version', '2026-07-28.agent-result-continuity',
  'ready', bool_and(ready),
  'checks', jsonb_agg(
    jsonb_build_object('identifier', identifier, 'category', category, 'ready', ready, 'reason_code', reason_code)
    ORDER BY category, identifier
  )
)
FROM normalized
$$;

REVOKE ALL ON FUNCTION public.qhub_verify_agent_schema() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qhub_verify_agent_schema() TO service_role;

COMMENT ON FUNCTION public.qhub_finalize_agent_run_step(
  UUID, TEXT, INT, TEXT, TEXT, UUID, TEXT, TEXT[], TEXT, TEXT, TEXT, JSONB) IS
  'Agent Framework: the ONLY sanctioned path to finalize a terminal run step. Validates ownership, transition, strict safe_result, and the previous-step hash chain, then computes result_hash from authoritative records. Service-role only.';

COMMIT;
