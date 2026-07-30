/**
 * QHUB Commercial Launch R6 — REPOSITORY-WIDE AST ARCHITECTURE INVENTORY
 * app/test/commercial-architecture.test.ts
 *
 * Discovery is filesystem-wide, not filename-filtered:
 *   - EVERY route under app/routes/ ** /*.{ts,tsx} must carry exactly one literal
 *     @qhub-route classification; the expected count is derived from the filesystem.
 *   - EVERY server module under app/lib/ ** /*.server.ts must carry an AST-readable
 *     __QHUB_MODULE_CLASSIFICATION literal; the expected count is derived from the filesystem.
 *
 * The COMMERCIAL boundary (app/lib/qhub/commercial) is enforced strictly: token-classified
 * exports (function declarations AND arrow-function exports) must take a required
 * CommercialReadyToken and validate it before any side effect; any exported DB mutation must
 * be token-guarded; a protected implementation may not be re-exported through a barrel; and
 * there is exactly ONE review-decision mutation path (the atomic RPC — no service updates
 * qhub_manual_review_requests). Repo-wide, no `as CommercialReadyToken` cast and no direct
 * commercial-verifier call escape the readiness module. Synthetic fixtures prove each rule.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, it, expect } from 'vitest';

const APP = fileURLToPath(new URL('../', import.meta.url));

function parse(name: string, src: string): ts.SourceFile {
  return ts.createSourceFile(name, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

const SERVICE_EXPORT_CLASSES = [
  'REQUIRES_COMMERCIAL_READY_TOKEN',
  'REQUIRES_STAFF_CONTEXT',
  'PURE_NO_IO',
  'INTERNAL_SERVER_ONLY',
] as const;
const MODULE_CLASSES = [...SERVICE_EXPORT_CLASSES, 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION'] as const;
const ROUTE_CLASSES = [
  'PUBLIC_SAFE',
  'SIGNATURE_AUTH',
  'COMMERCIAL_READY',
  'STAFF_ONLY',
  'INTERNAL_SERVER_ONLY',
] as const;

const ANY_DB_OP = /\.(from|rpc|insert|update|upsert|delete)\s*\(/;
const TOKEN_TYPE = 'CommercialReadyToken';
const COMMERCIAL_GUARDS = /requireCommercialContext|requireCommercialProject|requireCommercialReady|requireStaff/;

/** Protected I/O a PUBLIC_SAFE route may never contain (matches the classifier signals). */
const SENSITIVE_ROUTE_IO =
  /\.(insert|update|upsert|delete)\s*\(|\.rpc\s*\(|streamText|generateText|LLMManager|createClient|SERVICE_ROLE|getApiKeysFromCookie|requireStaff|requireCommercial|getSession|getVerifiedUser|Deploy|netlify|vercel|MCPService/;

/** A Supabase DB MUTATION (not the read-only verifier; `.update(` needs a `.from(` nearby). */
function mutates(text: string): boolean {
  return (
    /\.(insert|upsert|delete)\s*\(/.test(text) ||
    /\.rpc\(\s*['"]qhub_(?!verify_commercial_schema)/.test(text) ||
    (/\.from\s*\(/.test(text) && /\.update\s*\(/.test(text))
  );
}

function firstMatchPos(body: string, re: RegExp): number {
  const m = re.exec(body);
  return m ? m.index : Number.POSITIVE_INFINITY;
}

function walk(dir: string): string[] {
  const out: string[] = [];

  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}${e.name}`;

    if (e.isDirectory()) {
      out.push(...walk(`${p}/`));
    } else if ((e.name.endsWith('.ts') || e.name.endsWith('.tsx')) && !e.name.endsWith('.d.ts')) {
      out.push(p);
    }
  }

  return out;
}

// ─── generic AST helpers ────────────────────────────────────────────────────────

function leadingComment(sf: ts.SourceFile, node: ts.Node): string {
  const full = sf.getFullText();
  const ranges = ts.getLeadingCommentRanges(full, node.getFullStart()) ?? [];

  return ranges.map((r) => full.slice(r.pos, r.end)).join('\n');
}

/** All exported callables: function declarations AND exported arrow/function-expression consts. */
interface ExportedCallable {
  name: string;
  params: readonly ts.ParameterDeclaration[];
  body: string;
  comment: string;
}

function exportedCallables(sf: ts.SourceFile): ExportedCallable[] {
  const out: ExportedCallable[] = [];

  for (const stmt of sf.statements) {
    const isExport = (n: ts.Node) =>
      ts.canHaveModifiers(n) && ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

    if (ts.isFunctionDeclaration(stmt) && stmt.name && isExport(stmt)) {
      out.push({
        name: stmt.name.text,
        params: stmt.parameters,
        body: stmt.body?.getText(sf) ?? '',
        comment: leadingComment(sf, stmt),
      });
    }

    if (ts.isVariableStatement(stmt) && isExport(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (
          ts.isIdentifier(d.name) &&
          d.initializer &&
          (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
        ) {
          out.push({
            name: d.name.text,
            params: d.initializer.parameters,
            body: (d.initializer.body?.getText(sf) ?? '') || '',
            comment: leadingComment(sf, stmt),
          });
        }
      }
    }
  }

  return out;
}

function moduleClassification(sf: ts.SourceFile): string | 'MISSING' | 'DYNAMIC' {
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) {
      continue;
    }

    for (const d of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(d.name) || d.name.text !== '__QHUB_MODULE_CLASSIFICATION' || !d.initializer) {
        continue;
      }

      let init: ts.Node = d.initializer;

      if (ts.isAsExpression(init)) {
        init = init.expression;
      }

      return ts.isStringLiteral(init) ? init.text : 'DYNAMIC';
    }
  }
  return 'MISSING';
}

// ─── commercial service module checker (strict) ─────────────────────────────────

function checkCommercialServiceModule(name: string, src: string): string[] {
  const sf = parse(name, src);
  const violations: string[] = [];
  const mod = moduleClassification(sf);

  if (mod === 'MISSING') {
    return [`${name} has no __QHUB_MODULE_CLASSIFICATION`];
  }

  if (mod === 'DYNAMIC' || !(MODULE_CLASSES as readonly string[]).includes(mod)) {
    return [`${name} __QHUB_MODULE_CLASSIFICATION is not a literal reviewed value`];
  }

  // A protected implementation must not be re-exported through a barrel.
  if (/export\s+\{[^}]*\}\s+from\s+/.test(src) && mod !== 'INTERNAL_SERVER_ONLY') {
    violations.push(`${name} re-exports through a barrel from a non-internal module`);
  }

  // Exactly one review-decision mutation path: no service updates the review-request table.
  if (/\.from\(\s*['"]qhub_manual_review_requests['"]\)[\s\S]{0,200}?\.update\s*\(/.test(src)) {
    violations.push(`${name} performs a non-atomic review-request UPDATE (only the atomic RPC may decide)`);
  }

  for (const fn of exportedCallables(sf)) {
    const tokenParams = fn.params.filter((p) => p.type?.getText(sf) === TOKEN_TYPE);
    const mutatesBody = mutates(fn.body);
    const cls =
      mod === 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION'
        ? SERVICE_EXPORT_CLASSES.find((c) => fn.comment.includes(`@qhub-service: ${c}`))
        : mod;

    if (mod === 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' && !cls) {
      violations.push(`${name}:${fn.name} (mixed module) exported function lacks a @qhub-service classification`);
      continue;
    }

    if (mutatesBody && (cls !== 'REQUIRES_COMMERCIAL_READY_TOKEN' || tokenParams.length === 0)) {
      violations.push(`${name}:${fn.name} performs a DB mutation but is not a token-guarded export`);
    }

    if (cls === 'REQUIRES_COMMERCIAL_READY_TOKEN') {
      if (tokenParams.length === 0) {
        violations.push(`${name}:${fn.name} REQUIRES_COMMERCIAL_READY_TOKEN but has no CommercialReadyToken parameter`);
        continue;
      }

      if (tokenParams.some((p) => p.questionToken || p.initializer)) {
        violations.push(`${name}:${fn.name} readiness token parameter must not be optional/defaulted`);
      }

      const tok = ts.isIdentifier(tokenParams[0].name) ? tokenParams[0].name.text : '';
      const validationPos = firstMatchPos(fn.body, new RegExp(`(mutator|assertReadyToken|tokenValid)\\(\\s*${tok}\\b`));

      if (!Number.isFinite(validationPos)) {
        violations.push(`${name}:${fn.name} accepts a token but never validates it`);
        continue;
      }

      if (firstMatchPos(fn.body, ANY_DB_OP) < validationPos) {
        violations.push(`${name}:${fn.name} performs a side effect BEFORE token validation`);
      }
    }

    if (cls === 'PURE_NO_IO' && /\b(admin|mutator|createClient)\s*\(|\.rpc\(|\.from\(|\bfetch\s*\(/.test(fn.body)) {
      violations.push(`${name}:${fn.name} classified PURE_NO_IO but performs I/O`);
    }
  }

  return violations;
}

// ─── repo-wide (light) module checker ───────────────────────────────────────────

function checkModuleClassificationPresent(name: string, src: string): string[] {
  const mod = moduleClassification(parse(name, src));

  if (mod === 'MISSING') {
    return [`${name} has no __QHUB_MODULE_CLASSIFICATION`];
  }

  if (mod === 'DYNAMIC' || !(MODULE_CLASSES as readonly string[]).includes(mod)) {
    return [`${name} __QHUB_MODULE_CLASSIFICATION is not a literal reviewed value`];
  }

  return [];
}

// ─── route checker ──────────────────────────────────────────────────────────────

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
  'createInvitation',
  'consumeCheckoutIntent',
  '.createCheckoutSession',
  '.createBillingPortalSession',
];

function routeClassifications(src: string): string[] {
  return ROUTE_CLASSES.filter((c) => new RegExp(`@qhub-route:\\s*${c}\\b`).test(src));
}

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
    return [`${name} must declare exactly one @qhub-route classification (found ${classes.length})`];
  }

  if (/\brpc\(\s*['"]qhub_verify_commercial_schema/.test(src)) {
    violations.push(`${name} calls the commercial verifier directly`);
  }

  const cls = classes[0];

  if (cls === 'PUBLIC_SAFE' && SENSITIVE_ROUTE_IO.test(src)) {
    violations.push(`${name} PUBLIC_SAFE route performs protected I/O`);
  }

  if (cls === 'STAFF_ONLY' && !/requireStaff\s*\(/.test(src)) {
    violations.push(`${name} STAFF_ONLY route does not use requireStaff`);
  }

  if (cls === 'SIGNATURE_AUTH') {
    const sigPos = firstMatchPos(src, /verifyAndParseWebhook|verifySignature|stripe-signature/);
    const mutPos = firstMatchPos(src, /\.(insert|update|upsert|delete)\s*\(|\.rpc\s*\(/);

    if (!Number.isFinite(sigPos) || mutPos < sigPos) {
      violations.push(`${name} SIGNATURE_AUTH route mutates before verifying the signature`);
    }
  }

  if (cls !== 'COMMERCIAL_READY') {
    return violations;
  }

  if (!COMMERCIAL_GUARDS.test(src)) {
    violations.push(`${name} COMMERCIAL_READY route uses no commercial guard`);
  }

  const sf = parse(name, src);
  const body = findHandlerBody(sf);

  if (!body) {
    return [...violations, `${name} COMMERCIAL_READY route has no action/loader handler`];
  }

  let readinessCall: ts.CallExpression | null = null;
  let readinessVar = '';
  let firstProtectedPos = Number.POSITIVE_INFINITY;

  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);

      if (exprText === 'requireCommercialReady') {
        readinessCall = node;

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

  const doesProtectedWork = Number.isFinite(firstProtectedPos);

  if (!readinessCall) {
    if (doesProtectedWork) {
      violations.push(`${name} performs protected work with no readiness gate`);
    }

    return violations;
  }

  const readinessPos = (readinessCall as ts.CallExpression).getStart(sf);

  if (firstProtectedPos < readinessPos) {
    violations.push(`${name} performs protected work BEFORE the readiness gate (late guard)`);
  }

  if (hasAncestorTry(readinessCall as ts.CallExpression, body)) {
    violations.push(`${name} readiness gate is inside a try/catch (swallowed guard)`);
  }

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

// ─── discovery ──────────────────────────────────────────────────────────────────

const allRoutes = walk(`${APP}routes/`);
const allServerModules = walk(`${APP}lib/`).filter((f) => f.endsWith('.server.ts'));
const commercialServiceModules = allServerModules.filter((f) => f.includes('/qhub/commercial/'));

// ─── real-source assertions ─────────────────────────────────────────────────────

describe('repository-wide route inventory (AST)', () => {
  it('every route file under app/routes is discovered (count from filesystem)', () => {
    expect(allRoutes.length).toBeGreaterThanOrEqual(60);

    const names = allRoutes.map((f) => f.slice(APP.length));
    expect(names).toContain('routes/api.commercial.reviews.$requestId.ts'); // omitted route now included
    expect(names).toContain('routes/home.tsx'); // a legacy/marketing route is included too
  });

  for (const f of allRoutes) {
    it(`${f.slice(APP.length)} passes the route architecture contract`, () => {
      expect(checkRouteFile(f.slice(APP.length), readFileSync(f, 'utf8'))).toEqual([]);
    });
  }
});

describe('repository-wide service inventory (AST)', () => {
  it('every *.server.ts under app/lib is discovered + classified (count from filesystem)', () => {
    expect(allServerModules.length).toBeGreaterThanOrEqual(20);

    for (const f of allServerModules) {
      expect(checkModuleClassificationPresent(f.slice(APP.length), readFileSync(f, 'utf8'))).toEqual([]);
    }
  });

  for (const f of commercialServiceModules) {
    it(`${f.slice(APP.length)} passes the STRICT commercial service contract`, () => {
      expect(checkCommercialServiceModule(f.slice(APP.length), readFileSync(f, 'utf8'))).toEqual([]);
    });
  }
});

describe('global: token cast + direct verifier confined to allowed files', () => {
  const files = walk(APP);

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

  it('no exported non-atomic review-decision path exists in commercial services', () => {
    for (const f of commercialServiceModules) {
      const src = readFileSync(f, 'utf8');
      expect(
        /\.from\(\s*['"]qhub_manual_review_requests['"]\)[\s\S]{0,200}?\.update\s*\(/.test(src),
        `${f.slice(APP.length)} has a non-atomic review UPDATE`,
      ).toBe(false);
    }
  });
});

// ─── synthetic fixtures ─────────────────────────────────────────────────────────

describe('fixtures: the AST checker rejects violations', () => {
  const svc = (body: string) =>
    `export const __QHUB_MODULE_CLASSIFICATION = 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' as const;\n${body}`;

  it('module without classification → rejected', () => {
    expect(checkCommercialServiceModule('f.ts', `export function x() {}`).join()).toMatch(
      /no __QHUB_MODULE_CLASSIFICATION/,
    );
  });

  it('computed/dynamic module classification → rejected', () => {
    expect(
      checkCommercialServiceModule('f.ts', `export const __QHUB_MODULE_CLASSIFICATION = compute();`).join(),
    ).toMatch(/not a literal/);
  });

  it('unclassified export in a mixed module → rejected', () => {
    expect(
      checkCommercialServiceModule(
        'f.ts',
        svc(`export async function w(env) { const sb = admin(env); await sb.from('x').select(); }`),
      ).join(),
    ).toMatch(/lacks a @qhub-service classification/);
  });

  it('exported DB mutation without a token → rejected', () => {
    const src = svc(
      `/** @qhub-service: INTERNAL_SERVER_ONLY */\nexport async function w(env) { const sb = admin(env); await sb.from('x').insert({}); }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/not a token-guarded export/);
  });

  it('token export with no token param → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(input, env) { return 1; }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/has no CommercialReadyToken parameter/);
  });

  it('optional/defaulted token → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(token?: CommercialReadyToken, env?) { assertReadyToken(token, env); }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/must not be optional\/defaulted/);
  });

  it('ARROW-FUNCTION token export not validated → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport const w = async (token: CommercialReadyToken, env) => { return 1; };`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/accepts a token but never validates it/);
  });

  it('side effect before token validation → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(token: CommercialReadyToken, env) { const sb = admin(env); await sb.from('x').insert({}); mutator(token, env); }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/side effect BEFORE token validation/);
  });

  it('barrel re-export of a protected impl → rejected', () => {
    const src = svc(`export { doProtectedThing } from './secret-impl';`);
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/re-exports through a barrel/);
  });

  it('alternate non-atomic review decision path → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function decide(token: CommercialReadyToken, env) { mutator(token, env); await admin(env).from('qhub_manual_review_requests').update({ status: 'approved' }); }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/non-atomic review-request UPDATE/);
  });

  it('PURE_NO_IO that performs I/O → rejected', () => {
    const src = svc(`/** @qhub-service: PURE_NO_IO */\nexport function w(env) { return admin(env).from('x'); }`);
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/PURE_NO_IO but performs I\/O/);
  });

  it('unclassified route → rejected', () => {
    expect(checkRouteFile('f.ts', `export async function action() {}`).join()).toMatch(/exactly one @qhub-route/);
  });

  it('duplicate route classification → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\n// @qhub-route: PUBLIC_SAFE\nexport async function action() {}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/exactly one @qhub-route/);
  });

  it('PUBLIC_SAFE route doing protected I/O → rejected', () => {
    const src = `// @qhub-route: PUBLIC_SAFE\nexport async function action(env) { await createClient(env).from('x').insert({}); }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/PUBLIC_SAFE route performs protected I\/O/);
  });

  it('STAFF_ONLY route without requireStaff → rejected', () => {
    expect(checkRouteFile('f.ts', `// @qhub-route: STAFF_ONLY\nexport async function loader() {}`).join()).toMatch(
      /does not use requireStaff/,
    );
  });

  it('SIGNATURE_AUTH route mutating before signature verify → rejected', () => {
    const src = `// @qhub-route: SIGNATURE_AUTH\nexport async function action(sb) { await sb.from('x').insert({}); await verifyAndParseWebhook(); }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/mutates before verifying the signature/);
  });

  it('hard-coded READY (no requireCommercialReady) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n await createCheckoutIntent(null, {}, env);\n}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/protected work with no readiness gate/);
  });

  it('late guard → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n await createCheckoutIntent(null, {}, env);\n const ready = await requireCommercialReady(env);\n if (!ready.ok) return ready.response;\n}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/BEFORE the readiness gate/);
  });

  it('swallowed guard → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n let ready;\n try { ready = await requireCommercialReady(env); if (!ready.ok) return ready.response; } catch (e) {}\n}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/inside a try\/catch/);
  });

  it('ignored guard result → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n const ready = await requireCommercialReady(env);\n await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/readiness result is ignored/);
  });

  it('a valid COMMERCIAL_READY route fixture passes', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n const ready = await requireCommercialReady(env);\n if (!ready.ok) return ready.response;\n await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('f.ts', src)).toEqual([]);
  });
});
