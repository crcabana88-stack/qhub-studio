import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// eslint-disable-next-line no-restricted-imports
import {
  assertRedactedReportSafe,
  redactForReport,
  validateStagingGuards,
} from '../../scripts/staging/gate04-authenticated-live-matrix.mjs';

const validEnvironment = {
  NODE_ENV: 'test',
  QHUB_ALLOW_STAGING_LIVE_TESTS: '1',
  QHUB_LIVE_TEST_ENV: 'staging',
  QHUB_STAGING_BASE_URL: 'https://qhub-studio.fly.dev',
  SUPABASE_URL: 'https://jsjsanmaahvmynblmzkq.supabase.co',
  SUPABASE_ANON_KEY: 'test-anon-key',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
};

describe('Gate 04 authenticated staging harness', () => {
  it('accepts only the exact approved staging target and project', () => {
    expect(validateStagingGuards(validEnvironment)).toMatchObject({
      target: 'https://qhub-studio.fly.dev',
      projectRef: 'jsjsanmaahvmynblmzkq',
      primaryTenant: 'client-smoke',
      otherTenant: 'other-org-live',
    });

    expect(() =>
      validateStagingGuards({ ...validEnvironment, QHUB_STAGING_BASE_URL: 'https://qhub.example.com' }),
    ).toThrow(/approved staging origin/);
    expect(() =>
      validateStagingGuards({ ...validEnvironment, SUPABASE_URL: 'https://another-project.supabase.co' }),
    ).toThrow(/project ref/);
    expect(() => validateStagingGuards({ ...validEnvironment, QHUB_ALLOW_STAGING_LIVE_TESTS: '0' })).toThrow(
      /live-test flag/,
    );
  });

  it('refuses production markers and customer tenant overrides', () => {
    expect(() => validateStagingGuards({ ...validEnvironment, NODE_ENV: 'production' })).toThrow(/production/);
    expect(() => validateStagingGuards({ ...validEnvironment, QHUB_TEST_TENANT: 'customer-one' })).toThrow(
      /customer tenant/,
    );
  });

  it('redacts authentication material recursively', () => {
    const report = redactForReport({
      decision: 'ALLOW',
      accessToken: 'eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc',
      nested: { cookie: 'private', actorEmail: 'user@example.com' },
    });

    expect(report).toEqual({
      decision: 'ALLOW',
      nested: {},
    });
    expect(assertRedactedReportSafe(report)).toBe(true);
  });

  it('contains no product auth bypass or direct governance-table mutation', () => {
    const testPath = fileURLToPath(import.meta.url);
    const source = readFileSync(
      new URL('../../scripts/staging/gate04-authenticated-live-matrix.mjs', import.meta.url),
      'utf8',
    );
    expect(source).not.toMatch(/from\(['"]qhub_control_approvals['"]\)\s*\.(insert|update|delete|upsert)/);
    expect(source).not.toMatch(/from\(['"]qhub_control_evaluations['"]\)\s*\.(insert|update|delete|upsert)/);
    expect(source).not.toMatch(/Authorization\s*:/);
    expect(source).not.toMatch(/auth(entication)?[-_ ]?bypass/i);
    expect(testPath).toContain('gate04-authenticated-live-matrix.test.ts');
  });
});
