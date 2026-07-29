/**
 * QHUB Commercial Launch R4 — AUTOMATIC protected-route authorization coverage
 * app/test/commercial-route-coverage.test.ts
 *
 * Rather than a hand-maintained allowlist, this test SCANS the route filesystem and
 * classifies every route by content signature. A route that can invoke a model,
 * deploy/publish, mutate MCP/connector config, run an agent, call enforcement, run
 * raw SQL, export keys, or mutate commercial/entitlement state is "protected" and
 * MUST declare a machine-checkable boundary: an authoritative guard
 * (requireStaff / requireCommercialContext / requireCommercialProject /
 * getVerifiedUser) or an explicit `@qhub-boundary: PUBLIC_SAFE` opt-out. Adding a new
 * protected route without a boundary fails this test.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const ROUTES = fileURLToPath(new URL('../routes/', import.meta.url));
const read = (f: string) => readFileSync(`${ROUTES}${f}`, 'utf8');

// A route is PROTECTED when its source touches any of these sensitive capabilities.
const SENSITIVE = [
  /streamText|generateText|LLMManager|invokeCommercialModel/, // model invocation
  /MCPService|mcp-update-config/, // MCP / connector mutation
  /netlify|vercel|freezeReleaseCandidate|Deploy/i, // deployment / publication
  /runAgent|resumeAgentRun|buildAgentManifest/, // agents
  /enforceGovernedAction|createGovernanceService|grantApproval/, // enforcement / approval
  /supabase\.query|executeQuery|from\('qhub_/, // raw SQL / direct table access
  /export-api-keys|getApiKeysFromCookie/, // key export
  /createCommercialProject|acceptInvitation|decideReviewAtomic|reconcileCheckout|createCheckoutIntent|classifyApplication/, // commercial mutation
];

const GUARD = /requireStaff|requireCommercialContext|requireCommercialProject|getVerifiedUser/;

/*
 * Reviewed non-guard boundaries: PUBLIC_SAFE (read-only / non-secret / self-scoped by
 * the user's own connection token) and SIGNATURE_AUTH (authenticated by a verified
 * provider signature, e.g. the Stripe webhook — not a user session).
 */
const PUBLIC_SAFE = /@qhub-boundary:\s*(PUBLIC_SAFE|SIGNATURE_AUTH)/;

function isProtected(src: string): boolean {
  return SENSITIVE.some((re) => re.test(src));
}

const routeFiles = readdirSync(ROUTES).filter((f) => (f.endsWith('.ts') || f.endsWith('.tsx')) && !f.endsWith('.d.ts'));

describe('automatic protected-route boundary coverage', () => {
  for (const f of routeFiles) {
    const src = read(f);

    if (!isProtected(src)) {
      continue;
    }

    it(`${f} declares an authoritative boundary (guard or PUBLIC_SAFE)`, () => {
      const ok = GUARD.test(src) || PUBLIC_SAFE.test(src);
      expect(ok, `${f} is protected but declares no boundary`).toBe(true);
    });

    it(`${f} does not use the legacy getSession() authority path`, () => {
      expect(/getSession\s*\(/.test(src), `${f} still calls getSession()`).toBe(false);
    });
  }

  it('discovers a meaningful number of protected routes (sanity)', () => {
    const protectedCount = routeFiles.filter((f) => isProtected(read(f))).length;
    expect(protectedCount).toBeGreaterThan(10);
  });
});

describe('specific R4-hardened routes are guarded', () => {
  const MUST = [
    'api.enhancer.ts',
    'api.vercel-deploy.ts',
    'api.mcp-update-config.ts',
    'api.export-api-keys.ts',
    'api.llmcall.ts',
    'api.supabase.query.ts',
    'api.netlify-deploy.ts',
    'api.commercial.build.ts',
    'api.commercial.projects.ts',
    'api.commercial.reviews.ts',
    'api.internal.commercial.reviews.$requestId.decision.ts',
    'api.commercial.invitations.accept.ts',
  ];

  for (const f of MUST) {
    it(`${f} enforces a guard`, () => {
      expect(GUARD.test(read(f)), `${f} missing a guard`).toBe(true);
    });
  }

  it('api.export-api-keys never returns raw key values', () => {
    const src = read('api.export-api-keys.ts');
    expect(src).toMatch(/requireStaff/);

    // Returns only provider names + a boolean configured status.
    expect(src).toMatch(/configured/);
    expect(src).not.toMatch(/apiKeys\[provider\.name\]\s*=\s*envValue/);
  });
});

describe('no route reads user_metadata for authorization', () => {
  for (const f of routeFiles) {
    it(`${f} does not read user_metadata.org_id / .role`, () => {
      expect(
        /user_metadata\s*[.?[]\s*['"]?(org_id|role)/.test(read(f)),
        `${f} references user_metadata authority`,
      ).toBe(false);
    });
  }
});
