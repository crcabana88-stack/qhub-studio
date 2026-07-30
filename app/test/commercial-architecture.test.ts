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

function scriptKind(name: string): ts.ScriptKind {
  return name.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
}

function parse(name: string, src: string): ts.SourceFile {
  return ts.createSourceFile(name, src, ts.ScriptTarget.Latest, true, scriptKind(name));
}

/** R8 §4: parse diagnostics must be EMPTY — a parse failure is a hard test failure, never ignored. */
function parseDiagnostics(name: string, src: string): readonly ts.Diagnostic[] {
  const sf = parse(name, src);
  return (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
}

/**
 * R8 §1: a server-secret env NAME. A PUBLIC_SAFE route may never READ one from the server
 * environment (process.env / cloudflare.env / context.env). The public anon key is browser-safe
 * by design and explicitly excluded; non-secret operational vars (build info, deploy env, price
 * IDs, CF Pages markers) do not match the name pattern.
 */
const SECRET_ENV_NAME = /(TOKEN|SECRET|CREDENTIAL|PASSWORD|APIKEY|ACCESS_KEY|SERVICE_ROLE|PRIVATE|_KEY$|_KEY_)/;
const PUBLIC_ENV_NAMES = new Set(['SUPABASE_ANON_KEY']);

/** Names of server-secret env vars READ (from any env object) anywhere in a source file. */
function serverSecretEnvReads(src: string): string[] {
  const hits = new Set<string>();

  for (const line of src.split('\n')) {
    if (!/\.env\b/.test(line)) {
      continue;
    }

    for (const m of line.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)) {
      const name = m[1];

      if (!PUBLIC_ENV_NAMES.has(name) && SECRET_ENV_NAME.test(name)) {
        hits.add(name);
      }
    }
  }

  return [...hits];
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

/** Authoritative auth guards — an INTERNAL_SERVER_ONLY route must gate the handler on one. */
const AUTH_GUARDS =
  /requireStaff|requireCommercialContext|requireCommercialProject|requireCommercialReady|getSession|getVerifiedUser|requireInternalService/;

/**
 * R7 PROTECTED-I/O DATAFLOW — detect protected COMMERCIAL behaviour by I/O CATEGORY / import,
 * NOT by a fixed function-name list, so a renamed protected wrapper is still caught (the
 * underlying DB mutation, model-generation call, Stripe/billing import, deploy action, secret
 * VALUE export, or agent/enforcement/approval call remains). These are the categories a
 * genuinely PUBLIC_SAFE route may never touch. (Benign reads — env-var reads, model listing,
 * git info, a supabase read client, getSession — are NOT commercial-protected and do not
 * disqualify a public route.)
 */
const PROTECTED_IO_CATEGORY =
  /\.(insert|update|upsert|delete)\s*\(|\.rpc\(\s*['"]qhub_(?!verify_commercial_schema)|SERVICE_ROLE_KEY\b|\bstreamText\b|\bgenerateText\b|invokeCommercialModel|createBillingProvider|stripe-provider\.server|netlify-deploy|vercel-deploy|freezeReleaseCandidate|mcp-update-config|export-api-keys|runAgent|resumeAgentRun|buildAgentManifest|enforceGovernedAction|createGovernanceService|grantApproval/;

/** A route classified PUBLIC_SAFE may contain none of the above (commercial-protected) I/O. */
function routeHasProtectedIO(src: string): boolean {
  return PROTECTED_IO_CATEGORY.test(src);
}

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

/**
 * Every EXPORTED callable, across ALL export forms: function declarations, arrow /
 * function-expression consts, default exports (function/arrow), and exported class methods
 * (instance + static) + constructors. Each is returned with its params, body, and leading
 * comment so the classifier can enforce authority regardless of the export syntax.
 */
function exportedCallables(sf: ts.SourceFile): ExportedCallable[] {
  const out: ExportedCallable[] = [];
  const isExport = (n: ts.Node) =>
    ts.canHaveModifiers(n) && ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

  const pushFn = (name: string, params: readonly ts.ParameterDeclaration[], body: string, comment: string) =>
    out.push({ name, params, body, comment });

  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && isExport(stmt)) {
      pushFn(stmt.name?.text ?? 'default', stmt.parameters, stmt.body?.getText(sf) ?? '', leadingComment(sf, stmt));
    }

    if (ts.isVariableStatement(stmt) && isExport(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (
          ts.isIdentifier(d.name) &&
          d.initializer &&
          (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
        ) {
          pushFn(
            d.name.text,
            d.initializer.parameters,
            d.initializer.body?.getText(sf) ?? '',
            leadingComment(sf, stmt),
          );
        }
      }
    }

    // export default () => {}  /  export default function(){}
    if (ts.isExportAssignment(stmt) && stmt.expression) {
      const e = stmt.expression;

      if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) {
        pushFn('default', e.parameters, e.body?.getText(sf) ?? '', leadingComment(sf, stmt));
      }
    }

    // export class X { m(){} static s(){} constructor(){} get g(){} set s(v){} }
    if (ts.isClassDeclaration(stmt) && isExport(stmt)) {
      pushClassMembers(sf, stmt, pushFn);
    }

    // export default class X { ... }
    if (ts.isClassDeclaration(stmt) && stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) {
      pushClassMembers(sf, stmt, pushFn);
    }

    // export namespace N { export function f(){} export const g = () => {} }
    if (ts.isModuleDeclaration(stmt) && isExport(stmt) && stmt.body && ts.isModuleBlock(stmt.body)) {
      const ns = (stmt.name as ts.Identifier)?.text ?? 'namespace';

      for (const s of stmt.body.statements) {
        if (ts.isFunctionDeclaration(s) && isExport(s) && s.body) {
          pushFn(`${ns}.${s.name?.text ?? 'default'}`, s.parameters, s.body.getText(sf), leadingComment(sf, s));
        }

        if (ts.isVariableStatement(s) && isExport(s)) {
          for (const d of s.declarationList.declarations) {
            if (
              ts.isIdentifier(d.name) &&
              d.initializer &&
              (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
            ) {
              pushFn(
                `${ns}.${d.name.text}`,
                d.initializer.parameters,
                d.initializer.body?.getText(sf) ?? '',
                leadingComment(sf, s),
              );
            }
          }
        }
      }
    }
  }

  return out;
}

/** All callable members of a class — methods, constructors, and getters/setters (R8 §4). */
function pushClassMembers(
  sf: ts.SourceFile,
  stmt: ts.ClassDeclaration,
  pushFn: (name: string, params: readonly ts.ParameterDeclaration[], body: string, comment: string) => void,
): void {
  const cname = stmt.name?.text ?? 'default';

  for (const m of stmt.members) {
    if (
      (ts.isMethodDeclaration(m) ||
        ts.isConstructorDeclaration(m) ||
        ts.isGetAccessorDeclaration(m) ||
        ts.isSetAccessorDeclaration(m)) &&
      m.body
    ) {
      const mname = ts.isConstructorDeclaration(m)
        ? 'constructor'
        : ts.isGetAccessorDeclaration(m)
          ? `get_${(m.name as ts.Identifier)?.text ?? 'accessor'}`
          : ts.isSetAccessorDeclaration(m)
            ? `set_${(m.name as ts.Identifier)?.text ?? 'accessor'}`
            : ((m.name as ts.Identifier)?.text ?? 'method');
      pushFn(`${cname}.${mname}`, m.parameters, m.body.getText(sf), leadingComment(sf, m));
    }
  }
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

  /*
   * A protected implementation must not be re-exported through a barrel (named, aliased, or
   * export-star) from a non-internal module.
   */
  if (
    (/export\s+\{[^}]*\}\s+from\s+/.test(src) || /export\s+\*\s+from\s+/.test(src)) &&
    mod !== 'INTERNAL_SERVER_ONLY'
  ) {
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

  if (cls === 'PUBLIC_SAFE' && routeHasProtectedIO(src)) {
    violations.push(`${name} PUBLIC_SAFE route performs protected I/O`);
  }

  // R8 §1: a PUBLIC_SAFE route must never read a server secret from the environment.
  if (cls === 'PUBLIC_SAFE') {
    const secrets = serverSecretEnvReads(src);

    if (secrets.length > 0) {
      violations.push(`${name} PUBLIC_SAFE route reads a server secret from env (${secrets.join(', ')})`);
    }
  }

  if (cls === 'STAFF_ONLY' && !/requireStaff\s*\(/.test(src)) {
    violations.push(`${name} STAFF_ONLY route does not use requireStaff`);
  }

  /*
   * R7: an INTERNAL_SERVER_ONLY route must NOT be anonymously browser-reachable — it must
   * gate its HTTP handler on an authoritative auth guard (a strong internal-service boundary).
   */
  if (cls === 'INTERNAL_SERVER_ONLY' && !AUTH_GUARDS.test(src)) {
    violations.push(`${name} INTERNAL_SERVER_ONLY route is browser-reachable (no authoritative auth guard)`);
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

/*
 * R8 §4: server-module discovery covers BOTH the *.server.ts naming convention AND the
 * app/lib/.server/** shared server-only directory (whose files do NOT end in .server.ts). A
 * new module in either place enters the inventory automatically.
 */
const allServerModules = (() => {
  const set = new Set<string>();

  for (const f of walk(`${APP}lib/`)) {
    if (f.endsWith('.server.ts') || f.endsWith('.server.tsx') || /\/\.server\//.test(f)) {
      set.add(f);
    }
  }

  return [...set];
})();
const commercialServiceModules = allServerModules.filter((f) => f.includes('/qhub/commercial/'));

// Every discovered source that the architecture inventory parses (for the parse-diagnostic gate).
const allInventorySources = [...allRoutes, ...allServerModules];

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

describe('repository-wide parse-diagnostic gate (R8 §4)', () => {
  it('every discovered route + server module parses with ZERO parse diagnostics', () => {
    const offenders: string[] = [];

    for (const f of allInventorySources) {
      const diags = parseDiagnostics(f.slice(APP.length), readFileSync(f, 'utf8'));

      if (diags.length > 0) {
        offenders.push(`${f.slice(APP.length)} (${diags.length} parse diagnostics)`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('the parse-diagnostic gate actually catches a malformed source (fixture)', () => {
    expect(parseDiagnostics('bad.ts', 'export function (').length).toBeGreaterThan(0);
  });

  it('the app/lib/.server shared server-only directory is discovered', () => {
    expect(
      allServerModules.some((f) => /\/\.server\//.test(f)),
      'no app/lib/.server module discovered',
    ).toBe(true);
  });
});

describe('repository-wide service inventory (AST)', () => {
  it('every *.server.ts + app/lib/.server module is discovered + classified (count from filesystem)', () => {
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

  // ── R7 additions ──────────────────────────────────────────────────────────────

  it('INTERNAL_SERVER_ONLY route with NO auth guard (browser-reachable) → rejected', () => {
    const src = `// @qhub-route: INTERNAL_SERVER_ONLY\nexport async function action(env) { await createClient(env).from('x').insert({}); }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/browser-reachable \(no authoritative auth guard\)/);
  });

  it('a guarded INTERNAL_SERVER_ONLY route passes', () => {
    const src = `// @qhub-route: INTERNAL_SERVER_ONLY\nexport async function action(req, env) { const s = await requireStaff(req, env); if (!s.ok) return s.response; await createClient(env).from('x').insert({}); }`;
    expect(checkRouteFile('f.ts', src)).toEqual([]);
  });

  it('protected I/O is detected by CATEGORY even when the DB wrapper is renamed', () => {
    // A renamed protected wrapper still performs the underlying DB mutation → caught.
    const src = `// @qhub-route: PUBLIC_SAFE\nexport async function action(env) { const put = (t) => sb.from(t).insert({}); await put('x'); }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/PUBLIC_SAFE route performs protected I\/O/);
  });

  it('protected I/O is detected for a server-secret VALUE export category', () => {
    const src = `// @qhub-route: PUBLIC_SAFE\nimport { exportKeys } from '~/routes/api.export-api-keys';\nexport async function loader() { return exportKeys(); }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/protected I\/O/);
  });

  it('protected I/O is detected for a renamed model-generation / stripe / deploy category', () => {
    for (const io of [
      'await gen()  /* streamText */ streamText(x)',
      "import { createBillingProvider } from '~/x'",
      'await deploy() // netlify-deploy',
    ]) {
      const src = `// @qhub-route: PUBLIC_SAFE\nexport async function action() { ${io} }`;
      expect(checkRouteFile('f.ts', src).join(), io).toMatch(/protected I\/O/);
    }
  });

  it('DEFAULT-export token function is discovered + checked', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport default async function (token: CommercialReadyToken, env) { return 1; }`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/accepts a token but never validates it/);
  });

  it('CLASS-METHOD mutation without a token is discovered + rejected', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport class Repo {\n /** @qhub-service: INTERNAL_SERVER_ONLY */\n async write(env) { await admin(env).from('x').insert({}); }\n}`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/not a token-guarded export/);
  });

  it('export-star barrel from a non-internal module → rejected', () => {
    const src = svc(`export * from './secret-impl';`);
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/re-exports through a barrel/);
  });

  // ── R8 additions ────────────────────────────────────────────────────────────────

  it('PUBLIC_SAFE route that READS a server secret from env → rejected (R8 §1)', () => {
    for (const read of [
      'const t = process.env.GITHUB_TOKEN;',
      'const t = context?.cloudflare?.env?.VITE_SUPABASE_ACCESS_TOKEN;',
      'const t = (context.cloudflare.env as any).STRIPE_SECRET_KEY;',
      'const t = context.env?.NETLIFY_TOKEN;',
    ]) {
      const src = `// @qhub-route: PUBLIC_SAFE\nexport async function loader({ context }) { ${read} return t; }`;
      expect(checkRouteFile('f.ts', src).join(), read).toMatch(/reads a server secret from env/);
    }
  });

  it('a generic diagnostic route that serializes an env secret must not be PUBLIC_SAFE (R8 §1)', () => {
    const src = `// @qhub-route: PUBLIC_SAFE\nexport async function loader() { return { key: process.env.SUPABASE_SERVICE_ROLE_KEY }; }`;
    expect(checkRouteFile('f.ts', src).join()).toMatch(/reads a server secret from env/);
  });

  it('the public anon key + non-secret operational env vars are NOT flagged as secrets (R8 §1)', () => {
    const src = `// @qhub-route: PUBLIC_SAFE\nexport async function loader({ context }) { const a = context.cloudflare.env.SUPABASE_ANON_KEY; const b = process.env.QHUB_BUILD_ARTIFACT_HASH; const c = process.env.CF_PAGES_URL; const d = process.env.STRIPE_ACCOUNT_ID; return [a,b,c,d]; }`;
    expect(checkRouteFile('f.ts', src)).toEqual([]);
  });

  it('GETTER performing I/O under a PURE_NO_IO class is discovered + rejected (R8 §4)', () => {
    const src = svc(
      `/** @qhub-service: PURE_NO_IO */\nexport class C {\n /** @qhub-service: PURE_NO_IO */\n get thing() { return admin(this.env).from('x'); }\n}`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/PURE_NO_IO but performs I\/O/);
  });

  it('SETTER performing a DB mutation without a token is discovered + rejected (R8 §4)', () => {
    const src = svc(
      `/** @qhub-service: INTERNAL_SERVER_ONLY */\nexport class C {\n /** @qhub-service: INTERNAL_SERVER_ONLY */\n set val(v) { admin(this.env).from('x').insert({ v }); }\n}`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/not a token-guarded export/);
  });

  it('NAMESPACE-exported DB mutation without a token is discovered + rejected (R8 §4)', () => {
    const src = svc(
      `/** @qhub-service: INTERNAL_SERVER_ONLY */\nexport namespace N {\n /** @qhub-service: INTERNAL_SERVER_ONLY */\n export function w(env) { admin(env).from('x').insert({}); }\n}`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/not a token-guarded export/);
  });

  it('DEFAULT-CLASS token method not validated is discovered + rejected (R8 §4)', () => {
    const src = svc(
      `/** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\nexport default class {\n /** @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN */\n async run(token: CommercialReadyToken, env) { return 1; }\n}`,
    );
    expect(checkCommercialServiceModule('f.ts', src).join()).toMatch(/accepts a token but never validates it/);
  });
});
