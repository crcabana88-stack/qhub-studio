/**
 * QHUB Schema Contract — BROWSER-SAFE
 * app/lib/qhub/schema-contract.ts
 *
 * The single source of truth for the database schema objects the RUNNING CODE
 * requires. This exists to catch the failure mode discovered during Gate 03
 * live closure: the deployed Studio was pointed at a Supabase project that had
 * never received the Gate-02 classification migration, and persistClassification
 * silently swallowed the "column does not exist" error — masking a
 * project/schema mismatch that should have failed loudly.
 *
 * The list below is the expected-vs-current contract used by:
 *   - schema-check.server.ts   (runtime probe + governance guard + /api/health)
 *   - scripts/schema-smoke-check.mjs (pre/post-deploy gate — keep IN SYNC)
 *
 * Contains NO secrets and NO server-only APIs; safe to import from the browser.
 * Bump EXPECTED_SCHEMA_VERSION whenever a new required object is added.
 */

// ─── Expected schema version ──────────────────────────────────────────────────

/**
 * A human-readable version tag for the schema the current code expects. This is
 * a NON-SECRET diagnostic value — surfaced in /api/health and /api/system/schema-check
 * so an expected-vs-current comparison is trivial. Bump on every schema change.
 */
export const EXPECTED_SCHEMA_VERSION = '2026-07-25.gate03';

// ─── Required objects (probe one representative column per migration) ──────────

export interface RequiredSchemaObject {
  /** Table that must exist in the connected project. */
  table: string;

  /**
   * A representative column probed to confirm the migration ran. Probing one
   * column per migration is enough to detect a project that is behind — the
   * whole ALTER TABLE is atomic.
   */
  column: string;

  /** The migration file that introduces this object. */
  migration: string;

  /** What breaks if this object is absent (used in diagnostics). */
  requiredBy: string;
}

/**
 * Every (table, column) the governance path depends on, keyed to the migration
 * that provides it. Missing any of these means the connected project is behind
 * the code and the governance flow MUST fail closed.
 *
 * KEEP IN SYNC with scripts/schema-smoke-check.mjs.
 */
export const REQUIRED_SCHEMA_OBJECTS: RequiredSchemaObject[] = [
  {
    table: 'qhub_applications',
    column: 'qhub_app_id',
    migration: '20260723_qhub_applications',
    requiredBy: 'QHUB application identity (base table)',
  },
  {
    table: 'qhub_applications',
    column: 'classification',
    migration: '20260725_qhub_classification',
    requiredBy: 'Gate 02 classification snapshot',
  },
  {
    table: 'qhub_applications',
    column: 'policy_profile',
    migration: '20260725_gate03_policy',
    requiredBy: 'Gate 03 policy profile snapshot',
  },
  {
    table: 'qhub_classification_proposals',
    column: 'proposal_id',
    migration: '20260725_gate03_policy',
    requiredBy: 'Gate 03 server-authoritative classification proposals',
  },
];

// ─── Schema-missing error classification ──────────────────────────────────────

/**
 * PostgREST / PostgreSQL error codes that mean "the object the code asked for
 * does not exist in the connected project" — i.e. a schema drift, NOT a
 * transient failure. These are the signals that must trigger fail-closed
 * behaviour rather than a swallowed log line.
 *
 *   PGRST205 — table not found in the PostgREST schema cache (HTTP 404)
 *   PGRST204 — column not found (e.g. on insert/update)   (HTTP 400)
 *   42P01    — undefined_table                             (HTTP 404)
 *   42703    — undefined_column                            (HTTP 400)
 */
export const SCHEMA_MISSING_CODES: ReadonlySet<string> = new Set(['PGRST205', 'PGRST204', '42P01', '42703']);

/** Minimal shape shared by supabase-js errors and PostgREST REST error bodies. */
export interface SchemaErrorLike {
  code?: string | null;
  message?: string | null;
  details?: string | null;
  hint?: string | null;
}

/**
 * True when an error indicates a MISSING schema object (table/column) rather
 * than a transient/auth failure. Checks the structured code first, then falls
 * back to message text for drivers that don't surface a code.
 */
export function isSchemaMissingError(error: SchemaErrorLike | null | undefined): boolean {
  if (!error) {
    return false;
  }

  if (error.code && SCHEMA_MISSING_CODES.has(error.code)) {
    return true;
  }

  const haystack = `${error.message ?? ''} ${error.details ?? ''}`.toLowerCase();

  return (
    haystack.includes('does not exist') || // Postgres: relation/column "x" does not exist
    haystack.includes('could not find') || // PostgREST: "Could not find the 'x' column"
    haystack.includes('schema cache') // PostgREST: "... in the schema cache"
  );
}

// ─── Non-secret project reference extraction ──────────────────────────────────

/**
 * Extract the Supabase project ref (subdomain) from a project URL. This is a
 * NON-SECRET identifier (it appears in every public API URL) and is exactly the
 * value needed to tell WHICH project the code is talking to. Never derive or
 * log keys from this.
 *
 * e.g. https://abcdefghijklmno.supabase.co → 'abcdefghijklmno'
 */
export function projectRefFromUrl(url: string | undefined | null): string | null {
  if (!url) {
    return null;
  }

  try {
    const host = new URL(url).host;
    const ref = host.split('.')[0];

    return ref || null;
  } catch {
    return null;
  }
}
