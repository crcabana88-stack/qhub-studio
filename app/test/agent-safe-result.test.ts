/**
 * QHUB Agent Framework — canonical SAFE RESULT: TS↔SQL parity + adversarial suite
 * app/test/agent-safe-result.test.ts
 *
 * Proves the TypeScript enum-only safe-result validator/serializer (safe-result.ts)
 * and the PostgreSQL qhub_agent_safe_result_valid / qhub_agent_canonical_safe_result
 * agree on a shared adversarial fixture set, and that a secret literally cannot be
 * expressed in a valid safe_result (no free-form strings — enum/int/bool only).
 *
 * Covers required DB test 25 (genuine maximum boundary) + disallowed keys/values.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  validateSafeResult,
  canonicalSafeResult,
  MAX_CANONICAL_SAFE_RESULT_BYTES,
  MAX_SAFE_RESULT_BYTES,
  type SafeResult,
} from '~/lib/qhub/agent/runtime/safe-result';

const MIG = (f: string) => fileURLToPath(new URL(`../../supabase/migrations/${f}`, import.meta.url));
const MIGRATIONS = [
  '20260723_qhub_applications.sql',
  '20260725_gate03_policy.sql',
  '20260725_qhub_classification.sql',
  '20260726_gate04_enforcement.sql',
  '20260726_gate04_schema_assurance_approval_cleanup.sql',
  '20260727_gate05_attestation.sql',
  '20260727_agent_framework_foundation.sql',
  '20260728_agent_run_step_result_continuity.sql',
];

let db: PGlite;

beforeAll(async () => {
  db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );

  for (const f of MIGRATIONS) {
    await db.exec(readFileSync(MIG(f), 'utf8'));
  }
});

afterAll(async () => {
  await db.close();
});

async function sqlValid(value: unknown): Promise<boolean> {
  const r = await db.query<{ ok: boolean }>('select public.qhub_agent_safe_result_valid($1::jsonb) ok', [
    JSON.stringify(value),
  ]);

  return r.rows[0].ok;
}

async function sqlCanonical(value: SafeResult): Promise<string> {
  const r = await db.query<{ c: string }>('select public.qhub_agent_canonical_safe_result($1::jsonb) c', [
    JSON.stringify(value),
  ]);

  return r.rows[0].c;
}

/** [label, value, expectedValid] — evaluated by BOTH TS and SQL. */
const fixtures: Array<[string, unknown, boolean]> = [
  ['minimal null status', { execution_status: null }, true],
  ['enum status', { execution_status: 'COMPLETED' }, true],
  [
    'full allowlisted metadata',
    {
      execution_status: 'SUCCEEDED',
      safe_metadata: {
        outcome: 'OK',
        record_count: 7,
        truncated: true,
        duration_ms: 12,
        status_code: 200,
        result_kind: 'SUMMARY',
      },
    },
    true,
  ],
  ['present-null metadata value', { execution_status: 'SIMULATED', safe_metadata: { truncated: null } }, true],
  ['empty object', {}, true],

  ['disallowed top-level key', { execution_status: 'COMPLETED', extra: 1 }, false],
  ['raw prompt top-level', { execution_status: 'COMPLETED', prompt: 'hello' }, false],
  ['non-enum execution_status (free text)', { execution_status: 'sk-secret-value' }, false],
  ['non-enum outcome', { execution_status: 'COMPLETED', safe_metadata: { outcome: 'leaked-secret' } }, false],
  ['non-enum result_kind', { execution_status: 'COMPLETED', safe_metadata: { result_kind: 'raw_payload' } }, false],
  ['disallowed metadata key', { execution_status: 'COMPLETED', safe_metadata: { secret_token: 'abc' } }, false],
  [
    'credential-like metadata key',
    { execution_status: 'COMPLETED', safe_metadata: { authorization: 'Bearer z' } },
    false,
  ],
  ['non-integer number metadata', { execution_status: 'COMPLETED', safe_metadata: { record_count: 1.5 } }, false],
  ['negative number metadata', { execution_status: 'COMPLETED', safe_metadata: { duration_ms: -5 } }, false],
  ['out-of-range status_code', { execution_status: 'COMPLETED', safe_metadata: { status_code: 9999 } }, false],
  ['nested object metadata', { execution_status: 'COMPLETED', safe_metadata: { outcome: { nested: true } } }, false],
  ['array metadata', { execution_status: 'COMPLETED', safe_metadata: { outcome: ['a', 'b'] } }, false],
  ['string where int expected', { execution_status: 'COMPLETED', safe_metadata: { record_count: '5' } }, false],
  ['not an object (array)', ['execution_status'], false],
  ['not an object (string)', 'nope', false],
  ['safe_metadata not object', { execution_status: 'COMPLETED', safe_metadata: 'nope' }, false],
];

describe('safe-result validation — TS↔SQL parity (enum-only content contract)', () => {
  it('TS and PostgreSQL agree on every adversarial fixture', async () => {
    for (const [label, value, expected] of fixtures) {
      expect(validateSafeResult(value).ok, `TS validity for: ${label}`).toBe(expected);
      expect(await sqlValid(value), `SQL validity for: ${label}`).toBe(expected);
    }
  });

  it('valid values canonicalize identically in TS and SQL', async () => {
    for (const [label, value, expected] of fixtures) {
      if (!expected) {
        continue;
      }

      const safe = value as SafeResult;
      expect(await sqlCanonical(safe), `canonical parity for: ${label}`).toBe(canonicalSafeResult(safe));
    }
  });

  it('has a GENUINE maximum boundary — the largest valid payload, and nothing exceeds it (test 25)', async () => {
    /*
     * Every field is enum/bounded-int/bool, so the maximal VALID payload is fixed
     * and small; there is no free-form field to reach 16 KiB. The cap is a hard
     * ceiling comfortably above that true maximum.
     */
    const maximal: SafeResult = {
      execution_status: 'SIMULATED_SUCCESS',
      safe_metadata: {
        duration_ms: 1_000_000_000_000,
        outcome: 'NO_DISCREPANCY',
        record_count: 1_000_000_000,
        result_kind: 'SIMULATION',
        status_code: 599,
        truncated: true,
      },
    };
    const len = Buffer.byteLength(canonicalSafeResult(maximal), 'utf8');
    expect(len).toBe(MAX_CANONICAL_SAFE_RESULT_BYTES);
    expect(len).toBeLessThan(MAX_SAFE_RESULT_BYTES);
    expect(validateSafeResult(maximal).ok).toBe(true);
    expect(await sqlValid(maximal)).toBe(true);

    // The documented effective maximum is far below the historical 16 KiB.
    expect(MAX_CANONICAL_SAFE_RESULT_BYTES).toBeLessThan(300);
  });
});
