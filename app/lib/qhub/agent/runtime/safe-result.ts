/**
 * QHUB Agent Framework — Canonical SAFE RESULT schema + validation (PURE)
 * app/lib/qhub/agent/runtime/safe-result.ts
 *
 * The single strict, versioned schema for the server-generated `safe_result`
 * persisted on a finalized run step. A safe result carries ONLY a minimal,
 * ENUM-CONSTRAINED, non-sensitive execution summary — never raw prompts,
 * chain-of-thought, customer records, credentials, tokens, keys, cookies,
 * authorization headers, or any secret.
 *
 * CONTENT CONTRACT (Codex hardening — Option 1, enum-only):
 *   - `execution_status` is a controlled allowlist value (or null) — NOT free text.
 *   - `safe_metadata` keys are a fixed allowlist; every value is a controlled enum
 *     (outcome, result_kind), a bounded non-negative integer (record_count,
 *     duration_ms, status_code), or a boolean (truncated).
 *   - There are NO unrestricted free-form string fields, so the database does not
 *     rely on content-scanning arbitrary strings for secrets: a secret literally
 *     cannot be expressed in a valid safe_result.
 *   - The runtime constructs safe results ONLY from these server-generated,
 *     allowlisted, normalized values (see buildSafeResult / normalizeExecutionStatus).
 *
 * This module is the TypeScript half of an EQUIVALENT TS + PostgreSQL contract;
 * `20260728_agent_run_step_result_continuity.sql` implements identical rules in
 * SQL (qhub_agent_safe_result_valid / qhub_agent_canonical_safe_result), and
 * shared fixtures in app/test/agent-safe-result.test.ts pin TS↔SQL parity.
 */

/** Versioned so the schema can evolve without silently accepting old shapes. */
export const SAFE_RESULT_SCHEMA_VERSION = 'agent-safe-result-1.0.0';

/**
 * Defense-in-depth cap on the canonical serialized size. Because every field is
 * enum/bounded-integer/boolean, a VALID safe result is small and cannot approach
 * 16 KiB — the historical 16 KiB claim is intentionally dropped. MAX_SAFE_RESULT_BYTES
 * is a hard ceiling well above the true maximum (see MAX_CANONICAL_SAFE_RESULT_BYTES).
 */
export const MAX_SAFE_RESULT_BYTES = 1024;

/** Controlled allowlist for execution_status (server-generated). */
export const EXECUTION_STATUS_VALUES = [
  'SUCCEEDED',
  'FAILED',
  'SIMULATED_SUCCESS',
  'SIMULATED',
  'EXECUTED',
  'ALLOWED',
  'DENIED',
  'COMPLETED',
  'UNKNOWN',
] as const;

/** Controlled allowlist for safe_metadata.outcome. */
export const OUTCOME_VALUES = ['OK', 'ERROR', 'DISCREPANCY', 'NO_DISCREPANCY', 'PARTIAL', 'SKIPPED'] as const;

/** Controlled allowlist for safe_metadata.result_kind. */
export const RESULT_KIND_VALUES = ['SUMMARY', 'RECEIPT', 'SIMULATION', 'ANALYSIS', 'PROPOSAL'] as const;

/** Bounded non-negative integer ranges for the numeric metadata keys. */
export const MAX_RECORD_COUNT = 1_000_000_000;
export const MAX_DURATION_MS = 1_000_000_000_000;
export const MAX_STATUS_CODE = 599;

export type ExecutionStatus = (typeof EXECUTION_STATUS_VALUES)[number];
export type Outcome = (typeof OUTCOME_VALUES)[number];
export type ResultKind = (typeof RESULT_KIND_VALUES)[number];

/**
 * The FIXED allowlist of safe_metadata keys, in the canonical (sorted) order used
 * for serialization. KEEP IN SYNC with qhub_agent_canonical_safe_result /
 * qhub_agent_safe_result_valid.
 */
export const SAFE_METADATA_KEYS = [
  'duration_ms',
  'outcome',
  'record_count',
  'result_kind',
  'status_code',
  'truncated',
] as const;

export type SafeMetadataKey = (typeof SAFE_METADATA_KEYS)[number];

export interface SafeMetadata {
  duration_ms?: number | null;
  outcome?: Outcome | null;
  record_count?: number | null;
  result_kind?: ResultKind | null;
  status_code?: number | null;
  truncated?: boolean | null;
}

export interface SafeResult {
  execution_status: ExecutionStatus | null;
  safe_metadata?: SafeMetadata;
}

const ALLOWED_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set(['execution_status', 'safe_metadata']);
const ALLOWED_META_KEYS: ReadonlySet<string> = new Set(SAFE_METADATA_KEYS);
const EXECUTION_STATUS_SET: ReadonlySet<string> = new Set(EXECUTION_STATUS_VALUES);
const OUTCOME_SET: ReadonlySet<string> = new Set(OUTCOME_VALUES);
const RESULT_KIND_SET: ReadonlySet<string> = new Set(RESULT_KIND_VALUES);

function byteLen(s: string): number {
  // Matches PostgreSQL octet_length(convert_to(s,'UTF8')).
  return Buffer.byteLength(s, 'utf8');
}

export type SafeResultReason =
  | 'NOT_AN_OBJECT'
  | 'DISALLOWED_TOP_LEVEL_KEY'
  | 'EXECUTION_STATUS_NOT_ALLOWED'
  | 'SAFE_METADATA_TYPE'
  | 'DISALLOWED_METADATA_KEY'
  | 'OUTCOME_NOT_ALLOWED'
  | 'RESULT_KIND_NOT_ALLOWED'
  | 'RECORD_COUNT_OUT_OF_RANGE'
  | 'DURATION_MS_OUT_OF_RANGE'
  | 'STATUS_CODE_OUT_OF_RANGE'
  | 'TRUNCATED_NOT_BOOLEAN'
  | 'CANONICAL_TOO_LARGE';

export interface SafeResultValidation {
  ok: boolean;
  reason?: SafeResultReason;

  /** The canonical serialization (present only when ok). */
  canonical?: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Length-prefixed, null-distinguishing cell used by every canonical encoder. */
export function cell(value: string | null): string {
  return value === null ? '-1:;' : `${byteLen(value)}:${value};`;
}

/**
 * Canonical text for one safe_metadata value. A leading type tag makes an enum
 * string, an integer, and a boolean impossible to confuse, and an absent key is
 * distinct from a present null.
 */
function metaValueText(present: boolean, value: unknown): string {
  if (!present) {
    return 'absent';
  }

  if (value === null || value === undefined) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return `b:${value ? 'true' : 'false'}`;
  }

  if (typeof value === 'number') {
    return `n:${value}`;
  }

  return `s:${String(value)}`;
}

/**
 * The canonical serialization of a VALID safe result. Byte-identical to the SQL
 * qhub_agent_canonical_safe_result(). Only call on a validated value.
 */
export function canonicalSafeResult(safe: SafeResult): string {
  const meta = (safe.safe_metadata ?? {}) as Record<string, unknown>;
  let out = `V${cell(SAFE_RESULT_SCHEMA_VERSION)}` + cell(safe.execution_status ?? null);

  for (const key of SAFE_METADATA_KEYS) {
    const present = Object.prototype.hasOwnProperty.call(meta, key);
    out += cell(metaValueText(present, present ? meta[key] : null));
  }

  return out;
}

/** The exact maximum canonical byte-length a valid safe result can reach. */
export const MAX_CANONICAL_SAFE_RESULT_BYTES = (() => {
  const maximal: SafeResult = {
    execution_status: 'SIMULATED_SUCCESS',
    safe_metadata: {
      duration_ms: MAX_DURATION_MS,
      outcome: 'NO_DISCREPANCY',
      record_count: MAX_RECORD_COUNT,
      result_kind: 'SIMULATION',
      status_code: MAX_STATUS_CODE,
      truncated: true,
    },
  };

  return byteLen(canonicalSafeResult(maximal));
})();

function isSafeInt(v: unknown, max: number): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
}

/**
 * Strictly validate an untrusted candidate against the enum-only safe-result
 * contract. Returns the canonical serialization on success.
 */
export function validateSafeResult(candidate: unknown): SafeResultValidation {
  if (!isPlainObject(candidate)) {
    return { ok: false, reason: 'NOT_AN_OBJECT' };
  }

  for (const key of Object.keys(candidate)) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      return { ok: false, reason: 'DISALLOWED_TOP_LEVEL_KEY' };
    }
  }

  const executionStatus = candidate.execution_status ?? null;

  if (executionStatus !== null && (typeof executionStatus !== 'string' || !EXECUTION_STATUS_SET.has(executionStatus))) {
    return { ok: false, reason: 'EXECUTION_STATUS_NOT_ALLOWED' };
  }

  const safe: SafeResult = { execution_status: executionStatus as ExecutionStatus | null };
  const rawMeta = candidate.safe_metadata;

  if (rawMeta !== undefined) {
    if (!isPlainObject(rawMeta)) {
      return { ok: false, reason: 'SAFE_METADATA_TYPE' };
    }

    const meta: SafeMetadata = {};

    for (const [key, value] of Object.entries(rawMeta)) {
      if (!ALLOWED_META_KEYS.has(key)) {
        return { ok: false, reason: 'DISALLOWED_METADATA_KEY' };
      }

      if (value === null) {
        (meta as Record<string, unknown>)[key] = null;
        continue;
      }

      switch (key as SafeMetadataKey) {
        case 'outcome':
          if (typeof value !== 'string' || !OUTCOME_SET.has(value)) {
            return { ok: false, reason: 'OUTCOME_NOT_ALLOWED' };
          }

          meta.outcome = value as Outcome;
          break;
        case 'result_kind':
          if (typeof value !== 'string' || !RESULT_KIND_SET.has(value)) {
            return { ok: false, reason: 'RESULT_KIND_NOT_ALLOWED' };
          }

          meta.result_kind = value as ResultKind;
          break;
        case 'record_count':
          if (!isSafeInt(value, MAX_RECORD_COUNT)) {
            return { ok: false, reason: 'RECORD_COUNT_OUT_OF_RANGE' };
          }

          meta.record_count = value;
          break;
        case 'duration_ms':
          if (!isSafeInt(value, MAX_DURATION_MS)) {
            return { ok: false, reason: 'DURATION_MS_OUT_OF_RANGE' };
          }

          meta.duration_ms = value;
          break;
        case 'status_code':
          if (!isSafeInt(value, MAX_STATUS_CODE)) {
            return { ok: false, reason: 'STATUS_CODE_OUT_OF_RANGE' };
          }

          meta.status_code = value;
          break;
        case 'truncated':
          if (typeof value !== 'boolean') {
            return { ok: false, reason: 'TRUNCATED_NOT_BOOLEAN' };
          }

          meta.truncated = value;
          break;
      }
    }

    safe.safe_metadata = meta;
  }

  const canonical = canonicalSafeResult(safe);

  if (byteLen(canonical) > MAX_SAFE_RESULT_BYTES) {
    return { ok: false, reason: 'CANONICAL_TOO_LARGE' };
  }

  return { ok: true, canonical };
}

/** Coerce any input to an allowlisted execution_status (defaults to UNKNOWN). */
export function normalizeExecutionStatus(value: unknown): ExecutionStatus {
  return typeof value === 'string' && EXECUTION_STATUS_SET.has(value) ? (value as ExecutionStatus) : 'UNKNOWN';
}

/**
 * Build a safe result from a server-generated execution summary. The ONLY
 * sanctioned construction path for the runtime: execution_status is normalized to
 * the allowlist and metadata is dropped unless it is an allowlisted, in-range
 * scalar. It is impossible to smuggle free-form or secret content through it.
 */
export function buildSafeResult(input: {
  execution_status: unknown;
  safe_metadata?: Record<string, unknown>;
}): SafeResult {
  const safe: SafeResult = { execution_status: normalizeExecutionStatus(input.execution_status) };

  if (input.safe_metadata) {
    const meta: SafeMetadata = {};
    const src = input.safe_metadata;

    if (typeof src.outcome === 'string' && OUTCOME_SET.has(src.outcome)) {
      meta.outcome = src.outcome as Outcome;
    }

    if (typeof src.result_kind === 'string' && RESULT_KIND_SET.has(src.result_kind)) {
      meta.result_kind = src.result_kind as ResultKind;
    }

    if (isSafeInt(src.record_count, MAX_RECORD_COUNT)) {
      meta.record_count = src.record_count;
    }

    if (isSafeInt(src.duration_ms, MAX_DURATION_MS)) {
      meta.duration_ms = src.duration_ms;
    }

    if (isSafeInt(src.status_code, MAX_STATUS_CODE)) {
      meta.status_code = src.status_code;
    }

    if (typeof src.truncated === 'boolean') {
      meta.truncated = src.truncated;
    }

    if (Object.keys(meta).length > 0) {
      safe.safe_metadata = meta;
    }
  }

  return safe;
}
