/**
 * QHUB Agent Framework — Canonical SAFE RESULT schema + validation (PURE)
 * app/lib/qhub/agent/runtime/safe-result.ts
 *
 * The single strict, versioned schema for the server-generated `safe_result`
 * persisted on a finalized run step. A safe result carries ONLY the minimal,
 * non-sensitive execution summary the supervised runtime needs to reconstruct a
 * run — never raw prompts, chain-of-thought, customer records, credentials,
 * tokens, keys, cookies, authorization headers, or any secret.
 *
 * This module is the TypeScript half of an EQUIVALENT TS + PostgreSQL contract.
 * `20260728_agent_run_step_result_continuity.sql` implements the identical rules
 * in SQL (qhub_agent_safe_result_valid / qhub_agent_canonical_safe_result), and
 * adversarial fixtures in app/test/agent-safe-result.test.ts pin TS↔SQL parity.
 *
 * INVARIANTS (identical in SQL):
 *   - strict top-level allowlist: {execution_status, safe_metadata} only
 *   - no additional top-level properties
 *   - execution_status: bounded string or null
 *   - safe_metadata: object whose keys are drawn ONLY from SAFE_METADATA_KEYS
 *   - safe_metadata values: bounded string | safe integer | boolean | null only
 *       (no nested objects, no arrays, no floats — parity-safe scalars only)
 *   - bounded string and metadata lengths
 *   - canonical serialized size <= MAX_SAFE_RESULT_BYTES (16 KiB)
 *
 * The runtime provider MUST NEVER supply an unrestricted safe_result object; the
 * server builds one from an allowlisted execution summary and validates it here
 * (and again in the database) before it is ever persisted.
 */

/** Versioned so the schema can evolve without silently accepting old shapes. */
export const SAFE_RESULT_SCHEMA_VERSION = 'agent-safe-result-1.0.0';

/** Maximum canonical serialized size of a safe result: 16 KiB. */
export const MAX_SAFE_RESULT_BYTES = 16 * 1024;

/** Bounded lengths (bytes) for the individual scalar fields. */
export const MAX_EXECUTION_STATUS_BYTES = 64;
export const MAX_META_KEY_BYTES = 64;
export const MAX_META_STRING_BYTES = 256;

/** Metadata integers are bounded to a parity-safe signed range. */
export const MIN_SAFE_META_INT = -1_000_000_000_000;
export const MAX_SAFE_META_INT = 1_000_000_000_000;

/**
 * The FIXED allowlist of safe_metadata keys, in the canonical (sorted) order used
 * for serialization. Any key outside this set — including anything resembling a
 * raw prompt, secret, token, header, or customer record — is rejected. KEEP IN
 * SYNC with qhub_agent_canonical_safe_result / qhub_agent_safe_result_valid.
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

export type SafeMetadataValue = string | number | boolean | null;

export interface SafeResult {
  execution_status: string | null;
  safe_metadata?: Partial<Record<SafeMetadataKey, SafeMetadataValue>>;
}

const ALLOWED_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set(['execution_status', 'safe_metadata']);
const ALLOWED_META_KEYS: ReadonlySet<string> = new Set(SAFE_METADATA_KEYS);

function byteLen(s: string): number {
  // Matches PostgreSQL octet_length(convert_to(s,'UTF8')).
  return Buffer.byteLength(s, 'utf8');
}

export type SafeResultReason =
  | 'NOT_AN_OBJECT'
  | 'DISALLOWED_TOP_LEVEL_KEY'
  | 'EXECUTION_STATUS_TYPE'
  | 'EXECUTION_STATUS_TOO_LONG'
  | 'SAFE_METADATA_TYPE'
  | 'DISALLOWED_METADATA_KEY'
  | 'METADATA_KEY_TOO_LONG'
  | 'METADATA_VALUE_TYPE'
  | 'METADATA_STRING_TOO_LONG'
  | 'METADATA_NUMBER_NOT_SAFE_INTEGER'
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
 * Canonical text for one safe_metadata value. A leading type tag makes the
 * number 1, the string "1", and the boolean true impossible to confuse, and an
 * absent key is distinct from a present null. Floats are rejected upstream so the
 * integer rendering is byte-identical to PostgreSQL's.
 */
function metaValueText(present: boolean, value: SafeMetadataValue): string {
  if (!present) {
    return 'absent';
  }

  if (value === null) {
    return 'null';
  }

  if (typeof value === 'string') {
    return `s:${value}`;
  }

  if (typeof value === 'boolean') {
    return `b:${value ? 'true' : 'false'}`;
  }

  return `n:${value}`;
}

/**
 * The canonical serialization of a VALID safe result: schema version, the
 * execution status, and every allowlisted metadata key in fixed order (absent
 * keys explicitly marked). Deterministic and byte-identical to the SQL
 * qhub_agent_canonical_safe_result(). Only call on a validated value.
 */
export function canonicalSafeResult(safe: SafeResult): string {
  const meta = safe.safe_metadata ?? {};
  let out = `V${cell(SAFE_RESULT_SCHEMA_VERSION)}` + cell(safe.execution_status ?? null);

  for (const key of SAFE_METADATA_KEYS) {
    const present = Object.prototype.hasOwnProperty.call(meta, key);
    out += cell(metaValueText(present, present ? (meta[key] as SafeMetadataValue) : null));
  }

  return out;
}

/**
 * Strictly validate an untrusted candidate against the safe-result contract.
 * Returns the canonical serialization on success so callers hash exactly what
 * was validated.
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

  if (executionStatus !== null && typeof executionStatus !== 'string') {
    return { ok: false, reason: 'EXECUTION_STATUS_TYPE' };
  }

  if (typeof executionStatus === 'string' && byteLen(executionStatus) > MAX_EXECUTION_STATUS_BYTES) {
    return { ok: false, reason: 'EXECUTION_STATUS_TOO_LONG' };
  }

  const rawMeta = candidate.safe_metadata;
  const safe: SafeResult = { execution_status: executionStatus };

  if (rawMeta !== undefined) {
    if (!isPlainObject(rawMeta)) {
      return { ok: false, reason: 'SAFE_METADATA_TYPE' };
    }

    const meta: Partial<Record<SafeMetadataKey, SafeMetadataValue>> = {};

    for (const [key, value] of Object.entries(rawMeta)) {
      if (!ALLOWED_META_KEYS.has(key)) {
        return { ok: false, reason: 'DISALLOWED_METADATA_KEY' };
      }

      if (byteLen(key) > MAX_META_KEY_BYTES) {
        return { ok: false, reason: 'METADATA_KEY_TOO_LONG' };
      }

      if (value === null || typeof value === 'boolean') {
        meta[key as SafeMetadataKey] = value;
        continue;
      }

      if (typeof value === 'string') {
        if (byteLen(value) > MAX_META_STRING_BYTES) {
          return { ok: false, reason: 'METADATA_STRING_TOO_LONG' };
        }

        meta[key as SafeMetadataKey] = value;
        continue;
      }

      if (typeof value === 'number') {
        if (!Number.isInteger(value) || value < MIN_SAFE_META_INT || value > MAX_SAFE_META_INT) {
          return { ok: false, reason: 'METADATA_NUMBER_NOT_SAFE_INTEGER' };
        }

        meta[key as SafeMetadataKey] = value;
        continue;
      }

      // objects, arrays, functions, symbols, bigints, undefined values → rejected
      return { ok: false, reason: 'METADATA_VALUE_TYPE' };
    }

    safe.safe_metadata = meta;
  }

  const canonical = canonicalSafeResult(safe);

  if (byteLen(canonical) > MAX_SAFE_RESULT_BYTES) {
    return { ok: false, reason: 'CANONICAL_TOO_LARGE' };
  }

  return { ok: true, canonical };
}

/**
 * Build a safe result from an allowlisted execution summary. This is the ONLY
 * sanctioned construction path for the runtime — it drops any key not on the
 * allowlist rather than trusting a provider-supplied object.
 */
export function buildSafeResult(input: {
  execution_status: string | null;
  safe_metadata?: Record<string, unknown>;
}): SafeResult {
  const safe: SafeResult = { execution_status: input.execution_status };

  if (input.safe_metadata) {
    const meta: Partial<Record<SafeMetadataKey, SafeMetadataValue>> = {};

    for (const key of SAFE_METADATA_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(input.safe_metadata, key)) {
        continue;
      }

      const value = input.safe_metadata[key];

      if (
        value === null ||
        typeof value === 'boolean' ||
        typeof value === 'string' ||
        (typeof value === 'number' && Number.isInteger(value))
      ) {
        meta[key] = value as SafeMetadataValue;
      }
    }

    if (Object.keys(meta).length > 0) {
      safe.safe_metadata = meta;
    }
  }

  return safe;
}
