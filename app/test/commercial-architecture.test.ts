/**
 * QHUB Commercial Launch R4 — AST-BASED SERVICE + ROUTE ARCHITECTURE COVERAGE
 * app/test/commercial-architecture.test.ts
 *
 * Replaces textual guard detection with parser-based (TypeScript AST) architecture
 * checks that make the readiness boundary non-bypassable:
 *
 *  - every exported commercial SERVICE function declares exactly one classification
 *    (@qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN | REQUIRES_STAFF_CONTEXT |
 *     PURE_NO_IO | INTERNAL_SERVER_ONLY); token-classified functions must take a
 *     required (non-optional) CommercialReadyToken parameter; PURE_NO_IO functions do no I/O
 *  - every commercial ROUTE declares exactly one classification (@qhub-route:
 *    PUBLIC_SAFE | SIGNATURE_AUTH | COMMERCIAL_READY | STAFF_ONLY | INTERNAL_SERVER_ONLY);
 *    a COMMERCIAL_READY route must call requireCommercialReady, use its result (guard +
 *    return), and perform NO protected work before it, with the readiness call NOT buried
 *    in a swallowing try/catch
 *  - no `as CommercialReadyToken` cast outside the readiness module + tests
 *  - no direct qhub_verify_commercial_schema call outside the readiness service, the
 *    predeploy script, and tests
 *
 * Synthetic fixtures prove each rule actually rejects the corresponding violation.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, it, expect } from 'vitest';

const APP = fileURLToPath(new URL('../', import.meta.url));

function parse(name: string, src: string): ts.SourceFile {
  return ts.createSourceFile(name, src, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);
}

const SERVICE_CLASSES = [
  'REQUIRES_COMMERCIAL_READY_TOKEN',
  'REQUIRES_STAFF_CONTEXT',
  'PURE_NO_IO',
  'INTERNAL_SERVER_ONLY',
] as const;

const ROUTE_CLASSES = [
  'PUBLIC_SAFE',
  'SIGNATURE_AUTH',
  'COMMERCIAL_READY',
  'STAFF_ONLY',
  'INTERNAL_SERVER_ONLY',
] as const;

// Protected calls that constitute "protected work" in a route body.
const PROTECTED_CALLS = [
  'createCheckoutIntent',
  'createCommercialProject',
  'invokeCommercialModel',
  'acceptInvitation',
  'decideReviewAtomic',
  'createReviewRequest',
  'claimWebhookEvent',
  'reconcileCheckout',
  'applySubscriptionEvent',
  'setWebhookState',
  'consumeBuildCredit',
  'createProjectAtomic',
  'upsertDeclaration',
  'acknowledgeProject',
  'exportCommercialProject',
  'requestCommercialPublication',
  'setStaffOverride',
  'decideReviewRequest',
  'createInvitation',
  'consumeCheckoutIntent',
  '.createCheckoutSession',
  '.createBillingPortalSession',
];

function leadingComment(sf: ts.SourceFile, node: ts.Node): string {
  const full = sf.getFullText();
  const ranges = ts.getLeadingCommentRanges(full, node.getFullStart()) ?? [];

  return ranges.map((r) => full.slice(r.pos, r.end)).join('\n');
}

function isExported(node: ts.FunctionDeclaration): boolean {
  return !!node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

// ─── Service module checker ─────────────────────────────────────────────────────

function checkServiceModule(name: string, src: string): string[] {
  const sf = parse(name, src);
  const violations: string[] = [];

  for (const stmt of sf.statements) {
    if (!ts.isFunctionDeclaration(stmt) || !isExported(stmt) || !stmt.name) {
      continue;
    }

    const fn = stmt.name.text;
    const comment = leadingComment(sf, stmt);
    const found = SERVICE_CLASSES.filter((c) => comment.includes(`@qhub-service: ${c}`));

    if (found.length === 0) {
      violations.push(`${name}:${fn} exported service function has no @qhub-service classification`);
      continue;
    }

    if (found.length > 1) {
      violations.push(`${name}:${fn} declares multiple @qhub-service classifications`);
    }

    const cls = found[0];

    if (cls === 'REQUIRES_COMMERCIAL_READY_TOKEN') {
      const tokenParams = stmt.parameters.filter((p) => p.type?.getText(sf) === 'CommercialReadyToken');

      if (tokenParams.length === 0) {
        violations.push(`${name}:${fn} REQUIRES_COMMERCIAL_READY_TOKEN but has no CommercialReadyToken parameter`);
      }

      if (tokenParams.some((p) => p.questionToken)) {
        violations.push(`${name}:${fn} readiness token parameter must not be optional`);
      }
    }

    if (cls === 'PURE_NO_IO') {
      const body = stmt.body?.getText(sf) ?? '';

      if (/\b(admin|mutator|createClient)\s*\(|\.rpc\(|\.from\(|\bfetch\s*\(/.test(body)) {
        violations.push(`${name}:${fn} classified PURE_NO_IO but performs I/O`);
      }
    }
  }

  return violations;
}

// ─── Route checker ──────────────────────────────────────────────────────────────

function routeClassifications(src: string): string[] {
  return ROUTE_CLASSES.filter((c) => new RegExp(`@qhub-route:\\s*${c}\\b`).test(src));
}

/** Find the exported action/loader function body node, if any. */
function findHandlerBody(sf: ts.SourceFile): ts.Node | null {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && ['action', 'loader'].includes(stmt.name.text)) {
      return stmt.body ?? null;
    }

    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (
          ts.isIdentifier(d.name) &&
          ['action', 'loader'].includes(d.name.text) &&
          d.initializer &&
          (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
        ) {
          return d.initializer.body ?? null;
        }
      }
    }
  }

  return null;
}

function hasAncestorTry(node: ts.Node, stopAt: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;

  while (cur && cur !== stopAt) {
    if (ts.isTryStatement(cur)) {
      return true;
    }

    cur = cur.parent;
  }

  return false;
}

function checkRouteFile(name: string, src: string): string[] {
  const violations: string[] = [];
  const classes = routeClassifications(src);

  if (classes.length !== 1) {
    violations.push(`${name} must declare exactly one @qhub-route classification (found ${classes.length})`);

    return violations; // nothing else is meaningful without a classification
  }

  // No route may call the verifier directly (that is the readiness service's job).
  if (/qhub_verify_commercial_schema/.test(src)) {
    violations.push(`${name} calls the commercial verifier directly`);
  }

  if (classes[0] !== 'COMMERCIAL_READY') {
    return violations;
  }

  const sf = parse(name, src);
  const body = findHandlerBody(sf);

  if (!body) {
    violations.push(`${name} COMMERCIAL_READY route has no action/loader handler`);

    return violations;
  }

  let readinessCall: ts.CallExpression | null = null;
  let readinessVar = '';
  let firstProtectedPos = Number.POSITIVE_INFINITY;

  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);

      if (exprText === 'requireCommercialReady') {
        readinessCall = node;

        // const <var> = await requireCommercialReady(...)
        let p: ts.Node = node;

        while (p.parent && !ts.isVariableDeclaration(p.parent)) {
          p = p.parent;
        }

        if (p.parent && ts.isVariableDeclaration(p.parent) && ts.isIdentifier(p.parent.name)) {
          readinessVar = p.parent.name.text;
        }
      } else if (PROTECTED_CALLS.some((c) => (c.startsWith('.') ? exprText.endsWith(c) : exprText === c))) {
        firstProtectedPos = Math.min(firstProtectedPos, node.getStart(sf));
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(body);

  if (!readinessCall) {
    violations.push(`${name} COMMERCIAL_READY route never calls requireCommercialReady`);

    return violations;
  }

  const readinessPos = (readinessCall as ts.CallExpression).getStart(sf);

  // Readiness must come BEFORE any protected work (no late guard).
  if (firstProtectedPos < readinessPos) {
    violations.push(`${name} performs protected work BEFORE the readiness gate (late guard)`);
  }

  // Readiness must not be buried in a swallowing try/catch.
  if (hasAncestorTry(readinessCall as ts.CallExpression, body)) {
    violations.push(`${name} readiness gate is inside a try/catch (swallowed guard)`);
  }

  // The readiness result must be USED (guard + fail-closed return), not ignored.
  if (!readinessVar) {
    violations.push(`${name} readiness result is not bound to a variable (ignored)`);
  } else {
    const usesGuard = new RegExp(`!\\s*${readinessVar}\\.ok`).test(src);
    const returnsResponse = new RegExp(`return\\s+${readinessVar}\\.response`).test(src);

    if (!usesGuard || !returnsResponse) {
      violations.push(`${name} readiness result is ignored (no fail-closed guard/return)`);
    }
  }

  return violations;
}

// ─── Global scans ───────────────────────────────────────────────────────────────

function allTsFiles(dir: string): string[] {
  const out: string[] = [];

  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}${e.name}`;

    if (e.isDirectory()) {
      out.push(...allTsFiles(`${p}/`));
    } else if ((e.name.endsWith('.ts') || e.name.endsWith('.tsx')) && !e.name.endsWith('.d.ts')) {
      out.push(p);
    }
  }

  return out;
}

// ─── Real-source assertions ─────────────────────────────────────────────────────

const SERVICE_MODULES = [
  'lib/qhub/commercial/commercial-store.server.ts',
  'lib/qhub/commercial/commercial-service.server.ts',
  'lib/qhub/commercial/review.server.ts',
  'lib/qhub/commercial/governance-essentials.server.ts',
];

const COMMERCIAL_ROUTES = [
  'routes/api.billing.checkout.ts',
  'routes/api.billing.portal.ts',
  'routes/api.billing.webhook.ts',
  'routes/api.commercial.build.ts',
  'routes/api.commercial.projects.ts',
  'routes/api.commercial.reviews.ts',
  'routes/api.internal.commercial.reviews.$requestId.decision.ts',
  'routes/api.commercial.invitations.accept.ts',
  'routes/api.system.schema-check.ts',
];

describe('service modules: every export is classified and token-guarded (AST)', () => {
  for (const rel of SERVICE_MODULES) {
    it(`${rel} passes the service architecture contract`, () => {
      const src = readFileSync(`${APP}${rel}`, 'utf8');
      expect(checkServiceModule(rel, src)).toEqual([]);
    });
  }
});

describe('commercial routes: classified + readiness-before-work (AST)', () => {
  for (const rel of COMMERCIAL_ROUTES) {
    it(`${rel} passes the route architecture contract`, () => {
      const src = readFileSync(`${APP}${rel}`, 'utf8');
      expect(checkRouteFile(rel, src)).toEqual([]);
    });
  }
});

describe('global: token cast + direct verifier are confined to allowed files', () => {
  const files = allTsFiles(APP);

  it('no `as CommercialReadyToken` cast outside the readiness module + tests', () => {
    const offenders = files.filter((f) => {
      if (f.includes('commercial-schema-check.server.ts') || f.includes(`${APP}test/`)) {
        return false;
      }

      return /as\s+CommercialReadyToken/.test(readFileSync(f, 'utf8'));
    });
    expect(offenders).toEqual([]);
  });

  it('no direct qhub_verify_commercial_schema call outside the readiness service + tests', () => {
    const offenders = files.filter((f) => {
      if (f.includes('commercial-schema-check.server.ts') || f.includes(`${APP}test/`)) {
        return false;
      }

      return /\.rpc\(\s*['"]qhub_verify_commercial_schema/.test(readFileSync(f, 'utf8'));
    });
    expect(offenders).toEqual([]);
  });
});

// ─── Synthetic fixtures: prove the checker REJECTS each violation ────────────────

describe('fixtures: the architecture checker rejects violations', () => {
  it('unclassified service export → rejected', () => {
    const src = `export async function writeThing(env) { const sb = admin(env); await sb.from('x').insert({}); }`;
    expect(checkServiceModule('fixture.ts', src).join()).toMatch(/no @qhub-service classification/);
  });

  it('unguarded store mutation (token classification but no token param) → rejected', () => {
    const src = `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function writeThing(input, env) { return 1; }`;
    expect(checkServiceModule('fixture.ts', src).join()).toMatch(/has no CommercialReadyToken parameter/);
  });

  it('optional readiness token → rejected', () => {
    const src = `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function writeThing(token?: CommercialReadyToken, env?) { return 1; }`;
    expect(checkServiceModule('fixture.ts', src).join()).toMatch(/must not be optional/);
  });

  it('PURE_NO_IO that performs I/O → rejected', () => {
    const src = `/** @qhub-service: PURE_NO_IO */\nexport function calc(env) { const sb = admin(env); return sb.from('x'); }`;
    expect(checkServiceModule('fixture.ts', src).join()).toMatch(/PURE_NO_IO but performs I\/O/);
  });

  it('unclassified route → rejected', () => {
    const src = `export async function action() { return null; }`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/exactly one @qhub-route classification/);
  });

  it('hard-coded READY (no requireCommercialReady call) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  const ready = { ok: true, token: {} };\n  await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/never calls requireCommercialReady/);
  });

  it('late guard (protected work before readiness) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  await createCheckoutIntent(null, {}, env);\n  const ready = await requireCommercialReady(env);\n  if (!ready.ok) return ready.response;\n}`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/protected work BEFORE the readiness gate/);
  });

  it('swallowed guard (readiness inside try/catch) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  let ready;\n  try { ready = await requireCommercialReady(env); if (!ready.ok) return ready.response; } catch (e) { /* ignore */ }\n}`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/inside a try\/catch/);
  });

  it('ignored readiness result (no fail-closed return) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  const ready = await requireCommercialReady(env);\n  await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/readiness result is ignored/);
  });

  it('direct verifier call in a route → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  const ready = await requireCommercialReady(env);\n  if (!ready.ok) return ready.response;\n  await sb.rpc('qhub_verify_commercial_schema');\n}`;
    expect(checkRouteFile('fixture.ts', src).join()).toMatch(/calls the commercial verifier directly/);
  });

  it('a valid COMMERCIAL_READY route fixture passes', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n  const ready = await requireCommercialReady(env);\n  if (!ready.ok) return ready.response;\n  await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('fixture.ts', src)).toEqual([]);
  });
});
