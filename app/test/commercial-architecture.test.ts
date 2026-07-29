/**
 * QHUB Commercial Launch R5 — AST ARCHITECTURE INVENTORY (auto-discovered)
 * app/test/commercial-architecture.test.ts
 *
 * TRUE automatic inventory — no hard-coded filename arrays. Commercial routes are
 * discovered by scanning app/routes recursively and matching the commercial path pattern
 * (api.billing.* / api.commercial.* / api.internal.commercial.* / api.system.schema-check),
 * so a NEW commercial route (or the previously-omitted api.commercial.reviews.$requestId.ts)
 * is included automatically. Commercial server modules are discovered by globbing
 * app/lib/qhub/commercial/ ** / *.server.ts.
 *
 * Every commercial route carries exactly one literal @qhub-route classification; every
 * commercial server module carries an AST-readable __QHUB_MODULE_CLASSIFICATION constant.
 * The checks are AST + flow based: token-classified exports must take a required
 * CommercialReadyToken and validate it before any side effect; any exported DB mutation
 * without a token fails; readiness in a COMMERCIAL_READY route must precede protected work,
 * be used, and not be swallowed; no `as CommercialReadyToken` cast or direct verifier call
 * escapes the readiness module. Synthetic fixtures prove each rule rejects its violation.
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

/**
 * A Supabase DB MUTATION — insert/upsert/delete, a qhub_ RPC (not the read-only verifier),
 * or an `.update(` used on a query builder (guarded by a `.from(` in the same scope so the
 * hashing `createHash(...).update(...)` is not a false positive).
 */
function mutates(text: string): boolean {
  return (
    /\.(insert|upsert|delete)\s*\(/.test(text) ||
    /\.rpc\(\s*['"]qhub_(?!verify_commercial_schema)/.test(text) ||
    (/\.from\s*\(/.test(text) && /\.update\s*\(/.test(text))
  );
}

// ─── generic AST helpers ────────────────────────────────────────────────────────

function leadingComment(sf: ts.SourceFile, node: ts.Node): string {
  const full = sf.getFullText();
  const ranges = ts.getLeadingCommentRanges(full, node.getFullStart()) ?? [];

  return ranges.map((r) => full.slice(r.pos, r.end)).join('\n');
}

function isExportedFn(node: ts.Node): node is ts.FunctionDeclaration {
  return (
    ts.isFunctionDeclaration(node) &&
    !!node.name &&
    !!node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
  );
}

/** Read the AST-declared module classification constant, or a marker for missing/dynamic. */
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

function firstMatchPos(body: string, re: RegExp): number {
  const m = re.exec(body);

  return m ? m.index : Number.POSITIVE_INFINITY;
}

// ─── service module checker ─────────────────────────────────────────────────────

function checkServiceModule(name: string, src: string): string[] {
  const sf = parse(name, src);
  const violations: string[] = [];
  const mod = moduleClassification(sf);

  if (mod === 'MISSING') {
    return [`${name} has no __QHUB_MODULE_CLASSIFICATION`];
  }

  if (mod === 'DYNAMIC' || !(MODULE_CLASSES as readonly string[]).includes(mod)) {
    return [`${name} __QHUB_MODULE_CLASSIFICATION is not a literal reviewed value`];
  }

  for (const stmt of sf.statements) {
    if (!isExportedFn(stmt)) {
      continue;
    }

    const fn = stmt.name!.text;
    const body = stmt.body?.getText(sf) ?? '';
    const tokenParams = stmt.parameters.filter((p) => p.type?.getText(sf) === TOKEN_TYPE);
    const mutatesBody = mutates(body);

    // A whole-module (non-mixed) class assigns the same authority to every export.
    const cls =
      mod === 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION'
        ? SERVICE_EXPORT_CLASSES.find((c) => leadingComment(sf, stmt).includes(`@qhub-service: ${c}`))
        : mod;

    if (mod === 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' && !cls) {
      violations.push(`${name}:${fn} (mixed module) exported function lacks a @qhub-service classification`);
      continue;
    }

    // HARD security rule: any exported DB mutation MUST be token-classified + take a token.
    if (mutatesBody && (cls !== 'REQUIRES_COMMERCIAL_READY_TOKEN' || tokenParams.length === 0)) {
      violations.push(`${name}:${fn} performs a DB mutation but is not a token-guarded export`);
    }

    if (cls === 'REQUIRES_COMMERCIAL_READY_TOKEN') {
      if (tokenParams.length === 0) {
        violations.push(`${name}:${fn} REQUIRES_COMMERCIAL_READY_TOKEN but has no CommercialReadyToken parameter`);
        continue;
      }

      if (tokenParams.some((p) => p.questionToken || p.initializer)) {
        violations.push(`${name}:${fn} readiness token parameter must not be optional/defaulted`);
      }

      const tok = ts.isIdentifier(tokenParams[0].name) ? tokenParams[0].name.text : '';
      const validationRe = new RegExp(`(mutator|assertReadyToken|tokenValid)\\(\\s*${tok}\\b`);
      const validationPos = firstMatchPos(body, validationRe);

      // Token must actually be validated (not accepted-and-ignored).
      if (!Number.isFinite(validationPos)) {
        violations.push(`${name}:${fn} accepts a token but never validates it`);
        continue;
      }

      // No protected side effect before validation.
      const sideEffectPos = firstMatchPos(body, ANY_DB_OP);

      if (sideEffectPos < validationPos) {
        violations.push(`${name}:${fn} performs a side effect BEFORE token validation`);
      }
    }

    if (cls === 'PURE_NO_IO') {
      if (/\b(admin|mutator|createClient)\s*\(|\.rpc\(|\.from\(|\bfetch\s*\(/.test(body)) {
        violations.push(`${name}:${fn} classified PURE_NO_IO but performs I/O`);
      }
    }
  }

  return violations;
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
  'decideReviewRequest',
  'createInvitation',
  'consumeCheckoutIntent',
  '.createCheckoutSession',
  '.createBillingPortalSession',
];

const COMMERCIAL_GUARDS = /requireCommercialContext|requireCommercialProject|requireCommercialReady|requireStaff/;

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

  if (cls === 'STAFF_ONLY' && !/requireStaff\s*\(/.test(src)) {
    violations.push(`${name} STAFF_ONLY route does not use requireStaff`);
  }

  if (cls === 'PUBLIC_SAFE' && (mutates(src) || COMMERCIAL_GUARDS.test(src))) {
    violations.push(`${name} PUBLIC_SAFE route performs protected I/O`);
  }

  if (cls !== 'COMMERCIAL_READY') {
    return violations;
  }

  /*
   * COMMERCIAL_READY: must use a commercial guard; any protected mutation must be preceded
   * by requireCommercialReady, whose result is used (guard + return) and not swallowed.
   */
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
    // A guarded READ (no protected mutation) is allowed without a readiness token.
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

// ─── filesystem discovery ───────────────────────────────────────────────────────

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

const COMMERCIAL_ROUTE_RE = /(^|\/)api\.(billing|commercial|internal\.commercial)\.|(^|\/)api\.system\.schema-check\./;

const allRoutes = walk(`${APP}routes/`);
const commercialRoutes = allRoutes.filter((f) => COMMERCIAL_ROUTE_RE.test(f));
const commercialServiceModules = walk(`${APP}lib/qhub/commercial/`).filter((f) => f.endsWith('.server.ts'));

// ─── real-source assertions ─────────────────────────────────────────────────────

describe('auto-discovered commercial routes are classified + readiness-correct (AST)', () => {
  it('discovers commercial routes from the filesystem (incl. the reviews status route)', () => {
    const names = commercialRoutes.map((f) => f.slice(APP.length));
    expect(names).toContain('routes/api.commercial.reviews.$requestId.ts');
    expect(commercialRoutes.length).toBeGreaterThanOrEqual(9);
  });

  for (const f of commercialRoutes) {
    it(`${f.slice(APP.length)} passes the route architecture contract`, () => {
      expect(checkRouteFile(f.slice(APP.length), readFileSync(f, 'utf8'))).toEqual([]);
    });
  }
});

describe('auto-discovered commercial server modules are classified + token-guarded (AST)', () => {
  it('discovers every commercial *.server.ts from the filesystem', () => {
    expect(commercialServiceModules.length).toBe(10);
  });

  for (const f of commercialServiceModules) {
    it(`${f.slice(APP.length)} passes the service architecture contract`, () => {
      expect(checkServiceModule(f.slice(APP.length), readFileSync(f, 'utf8'))).toEqual([]);
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
});

// ─── synthetic fixtures ─────────────────────────────────────────────────────────

describe('fixtures: the AST checker rejects violations', () => {
  const svc = (body: string) =>
    `export const __QHUB_MODULE_CLASSIFICATION = 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' as const;\n${body}`;

  it('module without classification → rejected', () => {
    expect(checkServiceModule('f.ts', `export function x() {}`).join()).toMatch(/no __QHUB_MODULE_CLASSIFICATION/);
  });

  it('computed/dynamic module classification → rejected', () => {
    const src = `export const __QHUB_MODULE_CLASSIFICATION = computeIt();\nexport function x() {}`;
    expect(checkServiceModule('f.ts', src).join()).toMatch(/not a literal reviewed value/);
  });

  it('unclassified export in a mixed module → rejected', () => {
    expect(
      checkServiceModule(
        'f.ts',
        svc(`export async function w(env) { const sb = admin(env); await sb.from('x').select(); }`),
      ).join(),
    ).toMatch(/lacks a @qhub-service classification/);
  });

  it('exported DB mutation without a token → rejected', () => {
    const src = svc(
      `/** @qhub-service: INTERNAL_SERVER_ONLY */\nexport async function w(env) { const sb = admin(env); await sb.from('x').insert({}); }`,
    );
    expect(checkServiceModule('f.ts', src).join()).toMatch(/DB mutation but is not a token-guarded export/);
  });

  it('token export with no token param → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(input, env) { return 1; }`,
    );
    expect(checkServiceModule('f.ts', src).join()).toMatch(/has no CommercialReadyToken parameter/);
  });

  it('optional/defaulted token → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(token?: CommercialReadyToken, env?) { assertReadyToken(token, env); }`,
    );
    expect(checkServiceModule('f.ts', src).join()).toMatch(/must not be optional\/defaulted/);
  });

  it('token accepted but never validated → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(token: CommercialReadyToken, env) { return 1; }`,
    );
    expect(checkServiceModule('f.ts', src).join()).toMatch(/accepts a token but never validates it/);
  });

  it('side effect before token validation → rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport async function w(token: CommercialReadyToken, env) { const sb = admin(env); await sb.from('x').insert({}); mutator(token, env); }`,
    );
    expect(checkServiceModule('f.ts', src).join()).toMatch(/side effect BEFORE token validation/);
  });

  it('PURE_NO_IO that performs I/O → rejected', () => {
    const src = svc(`/** @qhub-service: PURE_NO_IO */\nexport function w(env) { return admin(env).from('x'); }`);
    expect(checkServiceModule('f.ts', src).join()).toMatch(/PURE_NO_IO but performs I\/O/);
  });

  it('unclassified route → rejected', () => {
    expect(checkRouteFile('f.ts', `export async function action() {}`).join()).toMatch(/exactly one @qhub-route/);
  });

  it('duplicate route classification → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\n// @qhub-route: PUBLIC_SAFE\nexport async function action() {}`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/exactly one @qhub-route/);
  });

  it('hard-coded READY (no requireCommercialReady) → rejected', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n const ready = { ok: true, token: {} };\n await createCheckoutIntent(ready.token, {}, env);\n}`;
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

  it('STAFF_ONLY route without requireStaff → rejected', () => {
    const src = `// @qhub-route: STAFF_ONLY\nexport async function loader() { return null; }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/does not use requireStaff/);
  });

  it('a valid COMMERCIAL_READY route fixture passes', () => {
    const src = `// @qhub-route: COMMERCIAL_READY\nexport async function action(env) {\n const g = await requireCommercialContext();\n const ready = await requireCommercialReady(env);\n if (!ready.ok) return ready.response;\n await createCheckoutIntent(ready.token, {}, env);\n}`;
    expect(checkRouteFile('f.ts', src)).toEqual([]);
  });
});
