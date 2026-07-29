/**
 * QHUB Commercial Launch R3 — route/service authorization coverage (static)
 * app/test/commercial-route-coverage.test.ts
 *
 * A repository-wide gate: every protected route must enforce an authoritative
 * context (commercial capability OR Quantex-staff-only), no protected route may
 * use the legacy getSession() authority path, and no route may read
 * user_metadata.org_id / user_metadata.role as authorization. This test fails
 * whenever a protected route is added without a guard.
 */

import { readFileSync } from 'node:fs';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const ROUTES = fileURLToPath(new URL('../routes/', import.meta.url));
const read = (f: string) => readFileSync(`${ROUTES}${f}`, 'utf8');

const GUARDS = /requireStaff|requireCommercialContext|requireCommercialProject/;

/** Protected routes that MUST resolve an authoritative context before acting. */
const PROTECTED = [
  'api.chat.ts',
  'api.agent.ts',
  'api.enforce.ts',
  'api.enforcement.ts',
  'api.governance.ts',
  'api.classify.ts',
  'api.llmcall.ts',
  'api.supabase.query.ts',
  'api.netlify-deploy.ts',
  'api.release.ts',
  'api.system.build-info.ts',
  'api.system.schema-check.ts',
  'api.entitlements.ts',
  'api.billing.checkout.ts',
  'api.billing.portal.ts',
  'api.commercial.build.ts',
  'api.commercial.projects.ts',
  'build.tsx',
  'agents.tsx',
];

describe('protected route authorization coverage', () => {
  for (const f of PROTECTED) {
    it(`${f} enforces an authoritative guard`, () => {
      expect(GUARDS.test(read(f)), `${f} missing an authorization guard`).toBe(true);
    });

    it(`${f} does not use the legacy getSession() authority path`, () => {
      expect(/getSession\s*\(/.test(read(f)), `${f} still calls getSession()`).toBe(false);
    });
  }
});

describe('no route uses user_metadata for authorization', () => {
  const files = readdirSync(ROUTES).filter((f) => f.endsWith('.ts') || f.endsWith('.tsx'));

  for (const f of files) {
    it(`${f} does not read user_metadata.org_id / .role`, () => {
      const src = read(f);
      expect(/user_metadata\s*[.?[]\s*['"]?(org_id|role)/.test(src), `${f} references user_metadata authority`).toBe(
        false,
      );
    });
  }
});

describe('webhook route is signature-authenticated (no user context needed)', () => {
  it('api.billing.webhook verifies over raw bytes', () => {
    const src = read('api.billing.webhook.ts');
    expect(src).toMatch(/verifyAndParseWebhook/);
    expect(src).toMatch(/request\.text\(\)/); // raw bytes, not reserialized
  });
});
