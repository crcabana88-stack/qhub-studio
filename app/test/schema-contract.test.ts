/**
 * QHUB schema contract — fail-closed classifier & object list
 * app/test/schema-contract.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  EXPECTED_SCHEMA_VERSION,
  REQUIRED_SCHEMA_OBJECTS,
  SCHEMA_MISSING_CODES,
  isSchemaMissingError,
  projectRefFromUrl,
} from '~/lib/qhub/schema-contract';

describe('isSchemaMissingError', () => {
  it('flags PostgREST/Postgres missing-object codes', () => {
    for (const code of SCHEMA_MISSING_CODES) {
      expect(isSchemaMissingError({ code })).toBe(true);
    }
  });

  it('flags the messages seen during Gate 03 live closure', () => {
    // Postgres undefined_column, then a PostgREST schema-cache miss.
    expect(isSchemaMissingError({ message: 'column qhub_applications.classification does not exist' })).toBe(true);
    expect(
      isSchemaMissingError({
        message: "Could not find the 'classification' column of 'qhub_applications' in the schema cache",
      }),
    ).toBe(true);
  });

  it('does NOT flag transient / auth / unrelated errors', () => {
    expect(isSchemaMissingError({ code: '23505', message: 'duplicate key value' })).toBe(false);
    expect(isSchemaMissingError({ code: 'PGRST301', message: 'JWT expired' })).toBe(false);
    expect(isSchemaMissingError({ message: 'network timeout' })).toBe(false);
    expect(isSchemaMissingError(null)).toBe(false);
    expect(isSchemaMissingError(undefined)).toBe(false);
    expect(isSchemaMissingError({})).toBe(false);
  });
});

describe('projectRefFromUrl', () => {
  it('extracts the public project ref (never a key)', () => {
    expect(projectRefFromUrl('https://abcdefghijklmno.supabase.co')).toBe('abcdefghijklmno');
    expect(projectRefFromUrl('https://abcdefghijklmno.supabase.co/rest/v1')).toBe('abcdefghijklmno');
  });

  it('returns null for empty / malformed input', () => {
    expect(projectRefFromUrl('')).toBeNull();
    expect(projectRefFromUrl(undefined)).toBeNull();
    expect(projectRefFromUrl('not a url')).toBeNull();
  });
});

describe('REQUIRED_SCHEMA_OBJECTS', () => {
  it('covers every governance migration', () => {
    const migrations = new Set(REQUIRED_SCHEMA_OBJECTS.map((o) => o.migration));
    expect(migrations.has('20260723_qhub_applications')).toBe(true);
    expect(migrations.has('20260725_qhub_classification')).toBe(true);
    expect(migrations.has('20260725_gate03_policy')).toBe(true);
  });

  it('includes the exact objects that masked the Gate 03 mismatch', () => {
    const has = (table: string, column: string) =>
      REQUIRED_SCHEMA_OBJECTS.some((o) => o.table === table && o.column === column);
    expect(has('qhub_applications', 'classification')).toBe(true);
    expect(has('qhub_applications', 'policy_profile')).toBe(true);
    expect(has('qhub_classification_proposals', 'proposal_id')).toBe(true);
  });

  it('has a pinned expected schema version', () => {
    expect(EXPECTED_SCHEMA_VERSION).toMatch(/gate03/);
  });
});
