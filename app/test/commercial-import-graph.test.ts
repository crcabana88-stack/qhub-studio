/**
 * QHUB Commercial Launch R9 §8/§9 — IMPORT-GRAPH SERVER-MODULE DISCOVERY
 * app/test/commercial-import-graph.test.ts
 *
 * Discovery is not limited to the *.server naming convention. Starting from every route (a server
 * entry point), the import graph is traversed and EVERY reachable app module is parsed. Rules:
 *   - a parser diagnostic on any reachable module is a HARD failure (fail closed);
 *   - an app-code import that does not resolve to a real module is a HARD failure (no silent skip);
 *   - a reachable module that performs HARD server-only I/O (a service-role Supabase client, a
 *     qhub_* RPC, or a mutation on a qhub_* table) MUST carry an AST-readable
 *     __QHUB_MODULE_CLASSIFICATION — so a server module that dropped the `.server` suffix, or is
 *     re-exported through a barrel, can never escape classification.
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, it, expect } from 'vitest';

const APP = fileURLToPath(new URL('../', import.meta.url));

function walkAll(dir: string): string[] {
  const out: string[] = [];

  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}${e.name}`;

    if (e.isDirectory()) {
      out.push(...walkAll(`${p}/`));
    } else {
      out.push(p);
    }
  }

  return out;
}

function scriptKind(name: string): ts.ScriptKind {
  return name.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
}

function parseDiagnostics(name: string, src: string): readonly ts.Diagnostic[] {
  const sf = ts.createSourceFile(name, src, ts.ScriptTarget.Latest, true, scriptKind(name));
  return (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
}

/*
 * Static import + re-export specifiers (barrels followed via `export ... from`), require('literal'),
 * AND dynamic import('literal'). Aliased/named/default/namespace forms all resolve to the same
 * module specifier string, so they are covered by the `from '...'` match.
 */
function importSpecifiers(src: string): string[] {
  const specs: string[] = [];
  const patterns = [
    /(?:import|export)\b[^;]*?\bfrom\s*['"]([^'"]+)['"]/g, // static import/export ... from '...'
    /\bimport\s*['"]([^'"]+)['"]/g, // bare `import '...'`
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // dynamic import('literal')
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // require('literal')
  ];

  for (const re of patterns) {
    let m: RegExpExecArray | null;

    while ((m = re.exec(src))) {
      specs.push(m[1]);
    }
  }

  return specs;
}

/*
 * A NON-literal dynamic `import(expr)` where expr is not a string literal. (The ESM codebase has no
 * module `require()`; a bare `require(cond, code)` seen in the tree is a local assertion helper, so
 * only the `import()` form is treated as a module load here.)
 */
function hasNonLiteralDynamicImport(src: string): boolean {
  return /\bimport\s*\(\s*(?!['"\s)])/.test(src);
}

const ASSET_EXT = /\.(css|scss|sass|less|json|svg|png|jpe?g|webp|gif|woff2?|ttf|eot|txt|md|wasm|mjs)$/;

/** Resolve an APP-code specifier to a real .ts/.tsx module, or signal that it is unresolved. */
function resolveSpec(fromFile: string, spec: string): { path?: string; unresolved?: boolean } {
  // Bare specifiers (node_modules) and asset/virtual imports are not app code — skip them.
  if (spec.includes('?') || ASSET_EXT.test(spec) || spec.startsWith('virtual:')) {
    return {};
  }

  let base: string | null = null;

  if (spec.startsWith('~/')) {
    base = APP + spec.slice(2);
  } else if (spec.startsWith('./') || spec.startsWith('../')) {
    base = resolvePath(dirname(fromFile), spec);
  } else {
    return {}; // bare specifier
  }

  /*
   * The Remix server build output (functions/[[path]].ts → `../build/server`) is a reviewed,
   * generated bundle, not app source — it is not present in the test tree and is not app code.
   */
  if (/[/\\]build[/\\]/.test(base)) {
    return {};
  }

  // A `.js`/`.jsx` specifier maps to the `.ts`/`.tsx` source (TS module-resolution convention).
  const noExt = base.replace(/\.(jsx?|tsx?)$/, '');
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${noExt}.ts`,
    `${noExt}.tsx`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
    `${noExt}/index.ts`,
    `${noExt}/index.tsx`,
  ];

  for (const c of candidates) {
    if (existsSync(c) && statSync(c).isFile() && (c.endsWith('.ts') || c.endsWith('.tsx'))) {
      return { path: c };
    }
  }

  return { unresolved: true };
}

const HARD_SERVER_IO =
  /SUPABASE_SERVICE_ROLE_KEY|\.rpc\(\s*['"]qhub_|\.from\(\s*['"]qhub_[a-z_]+['"]\)[\s\S]{0,200}?\.(insert|update|upsert|delete)\s*\(/;

function hasModuleClassification(src: string): boolean {
  return /export\s+const\s+__QHUB_MODULE_CLASSIFICATION\s*=/.test(src);
}

/*
 * R10 §8 — EFFECT-based protected-I/O categories, detected from operations/imports rather than a
 * fixed function name. A renamed wrapper still performs the underlying operation, so the category
 * remains detectable. These are the effects a genuinely PUBLIC_SAFE / unclassified server module
 * may not silently perform.
 */
const EFFECT_CATEGORIES: Array<{ label: string; re: RegExp }> = [
  {
    label: 'service-role / DB mutation',
    re: /SERVICE_ROLE_KEY|\.rpc\(\s*['"]qhub_|\.(insert|update|upsert|delete)\s*\(/,
  },
  { label: 'raw SQL', re: /\b(executeQuery|sql`|query\(\s*['"`]\s*(SELECT|INSERT|UPDATE|DELETE))/i },
  {
    label: 'generic external HTTP',
    re: /\b(fetch|undici|axios|got|superagent|ky)\s*[.(]|from\s*['"](undici|axios|got|ky)['"]/,
  },
  { label: 'stripe', re: /\bstripe\b|STRIPE_SECRET_KEY|api\.stripe\.com/i },
  {
    label: 'model/provider client',
    re: /\b(streamText|generateText|invokeCommercialModel|createAnthropic|createOpenAI)\b|LLMManager/,
  },
  {
    label: 'deployment/publication',
    re: /netlify-deploy|vercel-deploy|freezeReleaseCandidate|pages\s+deploy|api\.netlify\.com|api\.vercel\.com/,
  },
  { label: 'MCP/connector mutation', re: /mcp-update-config|MCPService|connector.*mutate/i },
  {
    label: 'dynamic secret read',
    re: /process\.env\s*\[|\.env\s*\[|Object\.(entries|keys|values)\s*\(\s*[^)]*\benv\b/,
  },
  {
    label: 'filesystem write',
    re: /\b(writeFile|writeFileSync|appendFile|mkdir|rm|rmdir|unlink|createWriteStream)\b|from\s*['"]node:fs['"]/,
  },
  {
    label: 'child process',
    re: /\b(child_process|execSync|spawnSync|spawn|execFile)\b|from\s*['"]node:child_process['"]/,
  },
  {
    label: 'queue/event publish',
    re: /\b(publish|enqueue|sendMessage|producer\.send|emit)\s*\(|from\s*['"](bullmq|amqplib|kafkajs)['"]/,
  },
  {
    label: 'agent/enforcement/approval mutation',
    re: /runAgent|resumeAgentRun|enforceGovernedAction|grantApproval|freezeReleaseCandidate/,
  },
];

function detectEffects(src: string): string[] {
  return EFFECT_CATEGORIES.filter(({ re }) => re.test(src)).map(({ label }) => label);
}

/*
 * ─── seed from EVERY server entry point (R11 §7) ────────────────────────────────
 * Discovery must not start only from routes. A worker/function request entry, the Remix server
 * entry, a *.server module, a `.server/**` module, or a deploy script can each pull server-only
 * code into a deployed surface. Seed the graph from all of them so nothing escapes the traversal.
 */

const REPO = `${resolvePath(APP, '..')}/`;
const IS_TS = (f: string) => (f.endsWith('.ts') || f.endsWith('.tsx')) && !f.endsWith('.d.ts');
const IS_SERVER_ENTRY_SCRIPT = (f: string) => f.endsWith('.mjs') || f.endsWith('.js') || IS_TS(f);

function filesUnder(dir: string, pred: (f: string) => boolean): string[] {
  return existsSync(dir) ? walkAll(dir).filter(pred) : [];
}

const routeEntries = filesUnder(`${APP}routes/`, IS_TS);

/*
 * *.server.ts(x) and anything under a `.server/` directory, anywhere in app/ — seeded directly so a
 * server module that is not reachable from a route is still parsed, classified and effect-analysed.
 */
const serverModuleEntries = filesUnder(
  APP,
  (f) => IS_TS(f) && (/\.server\.tsx?$/.test(f) || /[/\\]\.server[/\\]/.test(f)),
);
const entryServer = existsSync(`${APP}entry.server.tsx`) ? [`${APP}entry.server.tsx`] : [];

// Cloudflare Pages Functions / workers — the actual request entry of the deployed app.
const functionEntries = filesUnder(`${REPO}functions/`, IS_SERVER_ENTRY_SCRIPT);

// Deploy / build / preflight scripts run with full host privilege during release.
const scriptEntries = filesUnder(`${REPO}scripts/`, IS_SERVER_ENTRY_SCRIPT);

const ENTRY_POINTS = [
  ...new Set([...routeEntries, ...serverModuleEntries, ...entryServer, ...functionEntries, ...scriptEntries]),
];

interface GraphResult {
  visited: Set<string>;
  parseFailures: string[];
  unresolved: string[];
  undiscoveredProtected: string[];
  nonLiteralDynamic: string[];
  effects: Map<string, string[]>;
}

function traverse(entryPoints: string[]): GraphResult {
  const visited = new Set<string>();
  const parseFailures: string[] = [];
  const unresolved: string[] = [];
  const undiscoveredProtected: string[] = [];
  const nonLiteralDynamic: string[] = [];

  // R11 §8 — effect analysis is applied to EVERY visited module, not a sampled subset.
  const effects = new Map<string, string[]>();

  // Canonicalize separators so the same module reached via two path spellings is one visited node.
  const canon = (f: string) => f.replace(/\\/g, '/');
  const queue = entryPoints.map(canon);

  while (queue.length) {
    const file = queue.pop() as string;

    if (visited.has(file)) {
      continue;
    }

    visited.add(file);

    const src = readFileSync(file, 'utf8');
    const rel = canon(file).slice(canon(REPO).length);

    if (parseDiagnostics(rel, src).length > 0) {
      parseFailures.push(rel);
    }

    // Effect analysis runs on every module the moment it is visited — no module is skipped.
    effects.set(rel, detectEffects(src));

    /*
     * R10 §7: a non-literal dynamic import in server-reachable code is fail-closed (unresolvable
     * statically → cannot be classified). None are allowlisted.
     */
    if (hasNonLiteralDynamicImport(src)) {
      nonLiteralDynamic.push(rel);
    }

    // A reachable app/lib module doing HARD server-only I/O must be classified.
    if (/[/\\]lib[/\\]/.test(file) && HARD_SERVER_IO.test(src) && !hasModuleClassification(src)) {
      undiscoveredProtected.push(rel);
    }

    for (const spec of importSpecifiers(src)) {
      const r = resolveSpec(file, spec);

      if (r.unresolved) {
        unresolved.push(`${rel} → ${spec}`);
      } else if (r.path && !visited.has(canon(r.path))) {
        queue.push(canon(r.path));
      }
    }
  }

  return { visited, parseFailures, unresolved, undiscoveredProtected, nonLiteralDynamic, effects };
}

const graph = traverse(ENTRY_POINTS);

/*
 * ─── R12 §5/§6/§7 — EFFECT AUTHORIZATION (detection → fail-closed rule) ──────────
 * Detection alone is not enough: a route/module's classification must AUTHORIZE the protected effects
 * reachable through its import graph. A renamed or barrel-re-exported wrapper carries its effect into
 * the reachable set, so it cannot evade the boundary.
 */

const ROUTE_CLASSES = [
  'PUBLIC_SAFE',
  'SIGNATURE_AUTH',
  'COMMERCIAL_READY',
  'STAFF_ONLY',
  'INTERNAL_SERVER_ONLY',
] as const;

/** A route's single declared classification (`@qhub-route: X`), or undefined for a non-route module. */
function routeClassification(src: string): string | undefined {
  const found = ROUTE_CLASSES.filter((c) => new RegExp(`@qhub-route:\\s*${c}\\b`).test(src));
  return found.length === 1 ? found[0] : found.length > 1 ? 'AMBIGUOUS' : undefined;
}

/** A module's declared classification literal (`__QHUB_MODULE_CLASSIFICATION = 'X'`), or undefined. */
function moduleClassificationValue(src: string): string | undefined {
  const m = /export\s+const\s+__QHUB_MODULE_CLASSIFICATION\s*=\s*'([A-Z_]+)'/.exec(src);
  return m?.[1];
}

/** Strip // line and /* … *​/ block comments so a comment MENTION of a protected symbol is not an effect. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/*
 * R13 §4 — ONE canonical broad protected-effect taxonomy for BOTH fixtures and real code. Comments are
 * stripped first so an inert mention is not an effect, but string/property/alias/wrapper text is kept so
 * a renamed/re-exported wrapper still carries its real effect.
 */
function detectEffectsStripped(src: string): string[] {
  return detectEffects(stripComments(src));
}

/*
 * R13 §6 — sensitive-logging detector. A reachable server module must not log Headers objects,
 * request/response headers, authorization/x-authorization, cookies, or token/secret/api-key values, nor
 * dump a raw request-metadata-bearing error. Line-scoped (comments stripped) and covers console.* +
 * logger.* alias helpers.
 */
const SENSITIVE_LOG_CALL = /\b(?:console\.(?:log|info|warn|error|debug|trace)|logger\.\w+|log\.\w+)\s*\(/;
const SENSITIVE_LOG_PAYLOAD =
  /request\.headers|response\.headers|\.headers\b|headers\.entries|fromEntries\s*\([^)]*headers|\bauthorization\b|x-authorization|\bset-cookie\b|\bcookie\b|\bx-api-key\b|\bapi[-_]?key\b|\bbearer\b|\bsecret\b|\btoken\b/i;

/** Remove string/template-literal CONTENTS so a benign quoted message ("no secret configured") is not a leak. */
function stripStringContents(line: string): string {
  return line
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

function logsSensitive(src: string): string[] {
  const hits: string[] = [];

  for (const line of stripComments(src).split('\n')) {
    /*
     * A leak logs an EXPRESSION (a headers object, a header/token value), not a quoted message — so test
     * the payload with string literals stripped out.
     */
    if (SENSITIVE_LOG_CALL.test(line) && SENSITIVE_LOG_PAYLOAD.test(stripStringContents(line))) {
      hits.push(line.trim().slice(0, 120));
    }
  }

  return hits;
}

/*
 * A genuinely server-executed module: a *.server module, anything under a `.server/` dir, a Cloudflare
 * Pages Function, a deploy/build script, or the Remix server entry. These carry protected capability and
 * are the surface R13 §5 requires full effect-authorization over — not the browser CLIENT graph.
 */
function isServerModule(path: string): boolean {
  const p = path.replace(/\\/g, '/');
  return (
    /\.server\.tsx?$/.test(p) ||
    /\/\.server\//.test(p) ||
    /\/functions\//.test(p) ||
    /\/scripts\//.test(p) ||
    /\/app\/entry\.server\.tsx$/.test(p)
  );
}

/*
 * R13 §5 — machine-readable, narrow effect exemptions: server ENTRY points that carry privilege by
 * position (not by a `__QHUB_MODULE_CLASSIFICATION` literal) get an explicit SERVER_ENTRY classification,
 * each tied to an exact module pattern + a reason. Every exemption is covered by a positive + negative test.
 */
const SERVER_ENTRY_EXEMPTIONS: Array<{ match: RegExp; classification: 'SERVER_ENTRY'; reason: string }> = [
  {
    match: /\/functions\//,
    classification: 'SERVER_ENTRY',
    reason: 'Cloudflare Pages Function request entry (server-privileged)',
  },
  {
    match: /\/scripts\//,
    classification: 'SERVER_ENTRY',
    reason: 'deploy/build/preflight script (server-privileged, not browser-reachable)',
  },
  {
    match: /\/app\/entry\.server\.tsx$/,
    classification: 'SERVER_ENTRY',
    reason: 'Remix server render entry (server-privileged)',
  },
];

/*
 * R13 §5 — narrow, machine-readable PUBLIC-boundary exemptions: an exact imported SERVER module + an
 * exact effect a PUBLIC_SAFE route is allowed to reach, each with a reason. Covered by positive +
 * negative tests. (A PUBLIC_SAFE route's OWN-source protected I/O is governed by commercial-architecture
 * .test.ts's PROTECTED_IO_CATEGORY, R8-reviewed; the import graph governs the transitive-import evasion.)
 */
const SCHEMA_VERIFIER = /\/app\/lib\/qhub\/schema-check\.server\.ts$/;
const PUBLIC_IMPORT_EFFECT_EXEMPTIONS: Array<{ module: RegExp; effect: string; reason: string }> = [
  {
    module: SCHEMA_VERIFIER,
    effect: 'service-role / DB mutation',
    reason:
      'read-only schema verifier: reads the service-role key ONLY to run qhub_verify_commercial_schema() (a READ-only RPC); performs no insert/update/delete',
  },
  {
    module: SCHEMA_VERIFIER,
    effect: 'generic external HTTP',
    reason:
      'read-only schema verifier: the only outbound call is the fixed Supabase REST endpoint for the READ-only verifier RPC; the /api/health route reports readiness from it',
  },
];

function isPublicExempt(moduleRel: string, effect: string): boolean {
  return PUBLIC_IMPORT_EFFECT_EXEMPTIONS.some((e) => e.module.test(`/${moduleRel}`) && e.effect === effect);
}

/** Classes permitted to perform ANY protected effect (they carry their own runtime authorization). */
const SERVER_AUTHORIZED_CLASSES = new Set([
  'INTERNAL_SERVER_ONLY',
  'COMMERCIAL_READY',
  'STAFF_ONLY',
  'SIGNATURE_AUTH',
  'REQUIRES_COMMERCIAL_READY_TOKEN',
  'REQUIRES_STAFF_CONTEXT',
  'MIXED_EXPLICIT_EXPORT_CLASSIFICATION',
  'SERVER_ENTRY',
]);

// Every other class (PUBLIC_SAFE, PURE_NO_IO, unclassified, ambiguous) may perform NO protected effect.

/** Resolve the classification of a visited file (route marker, module literal, or server-entry exemption). */
function classifyFile(rel: string, src: string): string | undefined {
  if (rel.startsWith('app/routes/')) {
    return routeClassification(src);
  }

  const mod = moduleClassificationValue(src);

  if (mod) {
    return mod;
  }

  return SERVER_ENTRY_EXEMPTIONS.find((e) => e.match.test(`/${rel}`))?.classification;
}

/** Effects a classification does NOT authorize (fail-closed: unknown/undefined class authorizes nothing). */
function unauthorizedEffects(classification: string | undefined, effectLabels: string[]): string[] {
  if (classification && SERVER_AUTHORIZED_CLASSES.has(classification)) {
    return [];
  }

  // PUBLIC_SAFE / PURE_NO_IO / unclassified / ambiguous → every protected effect is unauthorized.
  return effectLabels;
}

/** The set of modules reachable from a single entry file (its transitive import closure, incl. itself). */
function reachableFrom(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry.replace(/\\/g, '/')];

  while (queue.length) {
    const file = queue.pop() as string;

    if (seen.has(file) || !existsSync(file)) {
      continue;
    }

    seen.add(file);

    for (const spec of importSpecifiers(readFileSync(file, 'utf8'))) {
      const r = resolveSpec(file, spec);

      if (r.path) {
        queue.push(r.path.replace(/\\/g, '/'));
      }
    }
  }

  return [...seen];
}

/**
 * Authorize a repository-shaped fixture graph with the SAME broad taxonomy + fail-closed rule used for
 * real code: traverse the module map, union every reachable module's effects (propagating through
 * aliases/wrappers/barrels/re-exports), and return the effects unauthorized for the seed's classification.
 */
function authorizeFixtureGraph(
  entryClass: string | undefined,
  modules: Record<string, string>,
  entry: string,
): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  const union = new Set<string>();

  while (queue.length) {
    const key = queue.pop() as string;

    if (seen.has(key) || !(key in modules)) {
      continue;
    }

    seen.add(key);

    const src = modules[key];

    for (const e of detectEffectsStripped(src)) {
      union.add(e);
    }

    for (const spec of importSpecifiers(src)) {
      if (spec in modules) {
        queue.push(spec);
      }
    }
  }

  return unauthorizedEffects(entryClass, [...union]);
}

/*
 * R13 §5 — COMPLETE-GRAPH effect authorization over every visited module. Each module gets an
 * authorization RESULT; every server module + server entry point is ENFORCED (unauthorized effect or
 * sensitive logging → violation). A PUBLIC_SAFE route may reach no protected effect through the server
 * modules in its closure (renamed/re-exported wrappers included).
 */
interface EffectAuthReport {
  results: Map<string, { classification?: string; effects: string[]; enforced: boolean }>;
  serverModulesEnforced: number;
  serverViolations: string[];
  publicRoutes: number;
  publicBoundaryViolations: string[];
}

function runEffectAuthorization(): EffectAuthReport {
  const results = new Map<string, { classification?: string; effects: string[]; enforced: boolean }>();
  const serverViolations: string[] = [];
  const publicBoundaryViolations: string[] = [];
  let serverModulesEnforced = 0;
  let publicRoutes = 0;

  // 1. Every visited module receives an authorization result; every server module is enforced.
  for (const file of graph.visited) {
    const rel = file.slice(REPO.length);
    const src = readFileSync(file, 'utf8');
    const effects = detectEffectsStripped(src);
    const classification = classifyFile(rel, src);
    const enforced = isServerModule(file);
    results.set(rel, { classification, effects, enforced });

    if (!enforced) {
      continue;
    }

    serverModulesEnforced += 1;

    const unauth = unauthorizedEffects(classification, effects);

    if (unauth.length) {
      serverViolations.push(`${rel} [${classification ?? 'UNCLASSIFIED'}] unauthorized: ${unauth.join(', ')}`);
    }

    const sens = logsSensitive(src);

    if (sens.length) {
      serverViolations.push(`${rel} logs sensitive value: ${sens[0]}`);
    }
  }

  // 2. PUBLIC_SAFE route boundary: no protected effect through its transitively-reachable SERVER modules.
  for (const entry of routeEntries) {
    const rel = entry.replace(/\\/g, '/').slice(REPO.length);

    if (routeClassification(readFileSync(entry, 'utf8')) !== 'PUBLIC_SAFE') {
      continue;
    }

    publicRoutes += 1;

    const canonEntry = entry.replace(/\\/g, '/');

    for (const mod of reachableFrom(entry)) {
      /*
       * Own-source protected I/O is the architecture test's domain (R8). The import graph enforces the
       * TRANSITIVE-IMPORT evasion: an imported SERVER module (a renamed/re-exported wrapper) that carries
       * a protected effect the route's PUBLIC classification does not authorize.
       */
      if (mod === canonEntry || !isServerModule(mod)) {
        continue;
      }

      const modRel = mod.slice(REPO.length);

      for (const effect of detectEffectsStripped(readFileSync(mod, 'utf8'))) {
        if (!isPublicExempt(modRel, effect)) {
          publicBoundaryViolations.push(`${rel} → ${modRel} :: ${effect}`);
        }
      }
    }
  }

  return { results, serverModulesEnforced, serverViolations, publicRoutes, publicBoundaryViolations };
}

const effectAuth = runEffectAuthorization();

describe('import-graph server-module discovery (R9 §8/§9, R11 §7/§8)', () => {
  it('reaches a meaningful slice of the app/lib server layer from the entry points', () => {
    const libModules = [...graph.visited].filter((f) => /[/\\]lib[/\\]/.test(f));
    expect(libModules.length).toBeGreaterThan(30);
  });

  it('every reachable module parses with ZERO parser diagnostics (fail closed)', () => {
    expect(graph.parseFailures, graph.parseFailures.join('\n')).toEqual([]);
  });

  it('no app-code import is unresolved (no server import silently skipped)', () => {
    expect(graph.unresolved, graph.unresolved.slice(0, 20).join('\n')).toEqual([]);
  });

  it('every reachable HARD server-IO module carries a module classification (suffix-independent)', () => {
    expect(graph.undiscoveredProtected, graph.undiscoveredProtected.join('\n')).toEqual([]);
  });

  it('NO server-reachable module uses a non-literal dynamic import (fail closed, R10 §7)', () => {
    expect(graph.nonLiteralDynamic, graph.nonLiteralDynamic.join('\n')).toEqual([]);
  });

  // R11 §7 — the graph is seeded from EVERY server entry point, not only routes.
  it('seeds from the Cloudflare Pages Function / worker request entry', () => {
    const rels = [...graph.visited].map((f) => f.slice(REPO.length).replace(/\\/g, '/'));
    expect(rels).toContain('functions/[[path]].ts');
  });

  it('seeds from the Remix server entry (app/entry.server.tsx)', () => {
    const rels = [...graph.visited].map((f) => f.slice(REPO.length).replace(/\\/g, '/'));
    expect(rels).toContain('app/entry.server.tsx');
  });

  it('seeds from deploy/build/preflight scripts (full-privilege release surface)', () => {
    const rels = [...graph.visited].map((f) => f.slice(REPO.length).replace(/\\/g, '/'));

    for (const s of ['scripts/build-with-identity.mjs', 'scripts/startup-preflight.mjs', 'scripts/deploy-env.mjs']) {
      expect(rels, `missing seed: ${s}`).toContain(s);
    }
  });

  // R11 §8 — effect analysis is applied to EVERY visited module (no sampled subset).
  it('applies effect analysis to every single visited module', () => {
    const missing = [...graph.visited]
      .map((f) => f.slice(REPO.length).replace(/\\/g, '/'))
      .filter((rel) => !graph.effects.has(rel));
    expect(missing, missing.join('\n')).toEqual([]);
    expect(graph.effects.size).toBe(graph.visited.size);
  });

  /*
   * R11 §2/§9 — the sole authoritative acknowledgment resolver is reachable, classified, and its
   * effects are surfaced by the analysis (it is not an unclassified silent side-effect module).
   */
  it('reaches and classifies the sole authoritative ack/review resolver module', () => {
    const resolver = [...graph.visited].find((f) =>
      f.replace(/\\/g, '/').endsWith('lib/qhub/commercial/governance-essentials.server.ts'),
    );
    expect(resolver, 'governance-essentials.server.ts not reached from any entry point').toBeTruthy();

    const src = readFileSync(resolver as string, 'utf8');
    expect(hasModuleClassification(src)).toBe(true);
    expect(HARD_SERVER_IO.test(src)).toBe(true);
  });
});

describe('R13 §5 — broad effect authorization is ENFORCED over the complete server graph', () => {
  it('every visited module receives an authorization result (test 34, none skipped)', () => {
    expect(effectAuth.results.size).toBe(graph.visited.size);

    for (const file of graph.visited) {
      expect(effectAuth.results.has(file.slice(REPO.length)), file).toBe(true);
    }
  });

  it('enforces a meaningful population of server modules + PUBLIC_SAFE routes', () => {
    expect(effectAuth.serverModulesEnforced).toBeGreaterThan(20);
    expect(effectAuth.publicRoutes).toBeGreaterThan(10);
  });

  it('NO server module performs an unauthorized effect or logs sensitive values (fail closed)', () => {
    expect(effectAuth.serverViolations, effectAuth.serverViolations.slice(0, 30).join('\n')).toEqual([]);
  });

  it('NO PUBLIC_SAFE route reaches a protected effect through its server closure (broad taxonomy)', () => {
    expect(effectAuth.publicBoundaryViolations, effectAuth.publicBoundaryViolations.slice(0, 30).join('\n')).toEqual(
      [],
    );
  });

  it('the hardened git-proxy is enforced as a server module with an authorized class and NO sensitive logging', () => {
    const proxy = effectAuth.results.get('app/lib/qhub/git-proxy.server.ts');
    expect(proxy, 'git-proxy.server.ts not visited').toBeTruthy();
    expect(proxy?.enforced).toBe(true);

    // Reclassified from the legacy PUBLIC_SAFE open proxy to an authenticated server-only relay.
    expect(proxy?.classification).toBe('INTERNAL_SERVER_ONLY');
    expect(unauthorizedEffects(proxy?.classification, proxy?.effects ?? [])).toEqual([]);

    // The redesigned relay logs NOTHING sensitive (the legacy proxy logged request/response headers).
    expect(logsSensitive(readFileSync(`${REPO}app/lib/qhub/git-proxy.server.ts`, 'utf8'))).toEqual([]);
  });

  it('PUBLIC-import exemptions are narrow (exact module + exact effect + reason) with pos/neg coverage', () => {
    // Positive: the exact read-only schema verifier module + its two exact effects are exempt.
    expect(isPublicExempt('app/lib/qhub/schema-check.server.ts', 'service-role / DB mutation')).toBe(true);
    expect(isPublicExempt('app/lib/qhub/schema-check.server.ts', 'generic external HTTP')).toBe(true);

    // Negative: a DIFFERENT module, or a DIFFERENT effect on the exempt module, is NOT exempt (fail closed).
    expect(isPublicExempt('app/lib/qhub/schema-check.server.ts', 'deployment/publication')).toBe(false);
    expect(isPublicExempt('app/lib/qhub/commercial/commercial-store.server.ts', 'service-role / DB mutation')).toBe(
      false,
    );

    for (const e of PUBLIC_IMPORT_EFFECT_EXEMPTIONS) {
      expect(e.reason.length).toBeGreaterThan(20);
    }
  });

  it('server-entry exemptions are narrow, machine-readable, and cover an exact module + reason', () => {
    // Positive: a functions/scripts/entry.server module resolves to SERVER_ENTRY.
    expect(classifyFile('functions/[[path]].ts', 'export const onRequest = () => {}')).toBe('SERVER_ENTRY');
    expect(classifyFile('scripts/build-with-identity.mjs', 'const x = 1;')).toBe('SERVER_ENTRY');
    expect(classifyFile('app/entry.server.tsx', 'export default 1;')).toBe('SERVER_ENTRY');

    // Negative: an ordinary unclassified server-path module is NOT auto-exempted → undefined → fail closed.
    expect(classifyFile('app/lib/qhub/random-helper.ts', 'export const f = () => fetch(1);')).toBeUndefined();
    expect(unauthorizedEffects(undefined, ['generic external HTTP'])).toEqual(['generic external HTTP']);

    // Every exemption carries a reason.
    for (const e of SERVER_ENTRY_EXEMPTIONS) {
      expect(e.reason.length).toBeGreaterThan(10);
    }
  });
});

describe('R13 §8 — real-graph adversarial effect tests (repository-shaped)', () => {
  /*
   * Repository-shaped: a PUBLIC_SAFE route file + imported wrapper/barrel modules run through the REAL
   * engine (authorizeFixtureGraph = same broad taxonomy + fail-closed rule as the live sweep).
   */
  const PUBLIC = '/** @qhub-route: PUBLIC_SAFE */\n';

  it('test 19 — PUBLIC_SAFE route with DIRECT fetch fails', () => {
    const modules = { route: `${PUBLIC}export const loader = () => fetch('https://x');` };
    expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route')).toContain('generic external HTTP');
  });

  it('test 20 — PUBLIC_SAFE route with a RENAMED fetch wrapper fails', () => {
    const modules = {
      route: `${PUBLIC}import { get } from './w';\nexport const loader = () => get('x');`,
      './w': `export const get = (u) => fetch(u);`,
    };
    expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route')).toContain('generic external HTTP');
  });

  it('test 21 — PUBLIC_SAFE route with a BARREL-re-exported fetch fails', () => {
    const modules = {
      route: `${PUBLIC}import { get } from './barrel';\nexport const loader = () => get('x');`,
      './barrel': `export * from './w';`,
      './w': `export const get = (u) => fetch(u);`,
    };
    expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route')).toContain('generic external HTTP');
  });

  const effectProbes: Array<[string, string, string]> = [
    ['test 22 — secret-reader wrapper', 'dynamic secret read', `export const s = (k) => process.env[k];`],
    ['test 23 — provider client', 'model/provider client', `export const g = (p) => generateText(p);`],
    ['test 24 — deployment wrapper', 'deployment/publication', `export const d = () => freezeReleaseCandidate();`],
    [
      'test 25 — connector wrapper',
      'MCP/connector mutation',
      `export const c = () => new MCPService().connectorMutate();`,
    ],
    [
      'test 26 — filesystem write',
      'filesystem write',
      `import { writeFile } from 'node:fs'; export const w = () => writeFile('a','b',()=>{});`,
    ],
    [
      'test 27 — child_process',
      'child process',
      `import { spawn } from 'node:child_process'; export const r = () => spawn('x');`,
    ],
    ['test 28 — queue publish', 'queue/event publish', `export const q = (j) => producer.send(j);`],
  ];

  for (const [label, effect, wrapperSrc] of effectProbes) {
    it(`${label} reached from PUBLIC_SAFE fails; allowed under a server class`, () => {
      const modules = {
        route: `${PUBLIC}import { x } from './w';\nexport const loader = () => x();`,
        './w': wrapperSrc,
      };
      expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route')).toContain(effect);
      expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', modules, 'route')).toEqual([]);
    });
  }

  it('test 29 — a public route logging authorization / header objects fails the sensitive-log detector', () => {
    expect(
      logsSensitive(`export const loader = () => console.log('h', Object.fromEntries(request.headers.entries()));`),
    ).not.toEqual([]);
    expect(
      logsSensitive(`export const loader = () => console.log('auth', req.headers.get('authorization'));`),
    ).not.toEqual([]);

    // A benign log is NOT flagged.
    expect(logsSensitive(`export const loader = () => console.log('status', res.status);`)).toEqual([]);
  });

  it('test 30/31 — functions/** + worker/job entry with an unauthorized effect fails under PUBLIC_SAFE', () => {
    const fn = {
      'functions/[[path]].ts': `import { h } from './h';\nexport const onRequest = () => h();`,
      './h': `export const h = () => freezeReleaseCandidate();`,
    };
    expect(authorizeFixtureGraph('SERVER_ENTRY', fn, 'functions/[[path]].ts')).toEqual([]);
    expect(authorizeFixtureGraph('PUBLIC_SAFE', fn, 'functions/[[path]].ts')).toContain('deployment/publication');
  });

  it('test 32 — a deployment/CLI entry receives an explicit classification decision', () => {
    expect(classifyFile('scripts/build-with-identity.mjs', 'const x = 1;')).toBe('SERVER_ENTRY');
    expect(unauthorizedEffects('SERVER_ENTRY', ['child process', 'filesystem write'])).toEqual([]);
  });

  it('test 33 — an approved server-only module with a declared effect passes', () => {
    const modules = {
      svc: `export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY';\nexport const put = (t) => sb.from(t).insert({});`,
    };
    expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', modules, 'svc')).toEqual([]);
  });

  it('test 35 — unresolved import / parser error / non-literal dynamic import fail closed (real graph)', () => {
    expect(graph.unresolved).toEqual([]); // an unresolved app import is a hard failure
    expect(graph.parseFailures).toEqual([]); // a parse error is a hard failure
    expect(graph.nonLiteralDynamic).toEqual([]); // a non-literal dynamic import is a hard failure
    // The detector itself flags a non-literal dynamic import.
    expect(hasNonLiteralDynamicImport(`await import(userPath)`)).toBe(true);
  });
});

describe('R13 §6 — wrapper / re-export effect propagation fails closed under an insufficient class', () => {
  /*
   * Each probe: a protected effect reached from a PUBLIC_SAFE seed through a renamed wrapper, a barrel
   * re-export, or an alias. Enforcement must reject it; the same effect under a server-authorized class
   * is allowed.
   */
  const probes: Array<{ label: string; effect: string; wrapperSrc: string }> = [
    {
      label: 'renamed HTTP wrapper',
      effect: 'generic external HTTP',
      wrapperSrc: `export const callGateway = (u) => fetch(u);`,
    },
    {
      label: 'renamed provider wrapper',
      effect: 'model/provider client',
      wrapperSrc: `export const runModel = (p) => streamText(p);`,
    },
    {
      label: 'deployment wrapper',
      effect: 'deployment/publication',
      wrapperSrc: `export const ship = () => freezeReleaseCandidate();`,
    },
    {
      label: 'connector/MCP wrapper',
      effect: 'MCP/connector mutation',
      wrapperSrc: `export const sync = () => new MCPService().connectorMutate();`,
    },
    {
      label: 'dynamic secret wrapper',
      effect: 'dynamic secret read',
      wrapperSrc: `export const getSecret = (k) => process.env[k];`,
    },
    {
      label: 'filesystem write wrapper',
      effect: 'filesystem write',
      wrapperSrc: `import { writeFile } from 'node:fs'; export const save = (p, d) => writeFile(p, d, () => {});`,
    },
    {
      label: 'child-process wrapper',
      effect: 'child process',
      wrapperSrc: `import { spawn } from 'node:child_process'; export const run = (c) => spawn(c);`,
    },
    {
      label: 'queue/event wrapper',
      effect: 'queue/event publish',
      wrapperSrc: `export const emitJob = (j) => producer.send(j);`,
    },
    {
      label: 'service-role DB wrapper',
      effect: 'service-role / DB mutation',
      wrapperSrc: `export const put = (t, r) => sb.from(t).insert(r);`,
    },
  ];

  for (const { label, effect, wrapperSrc } of probes) {
    it(`${label}: rejected when reached from PUBLIC_SAFE through a rename + barrel re-export`, () => {
      // route → barrel (re-export) → wrapper (renamed). The effect lives only in the wrapper module.
      const modules: Record<string, string> = {
        route: `/** @qhub-route: PUBLIC_SAFE */\nimport { thing } from './barrel';\nexport const loader = () => thing();`,
        './barrel': `export * from './wrapper';`,
        './wrapper': wrapperSrc,
      };
      const unauth = authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route');
      expect(unauth, `${label} should be unauthorized under PUBLIC_SAFE`).toContain(effect);

      // The SAME graph under a server-authorized class (INTERNAL_SERVER_ONLY) is allowed.
      expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', modules, 'route')).toEqual([]);
    });
  }

  it('an UNKNOWN/unclassified module carrying a protected effect fails closed (test 24)', () => {
    const modules: Record<string, string> = {
      entry: `import { w } from './w';\nexport const x = () => w();`, // no classification
      './w': `export const w = () => fetch('https://x');`,
    };
    expect(authorizeFixtureGraph(undefined, modules, 'entry')).toContain('generic external HTTP');
  });

  it('an approved effect under the correct (server-authorized) classification passes (test 25)', () => {
    const modules: Record<string, string> = {
      entry: `/** @qhub-route: COMMERCIAL_READY */\nimport { put } from './svc';\nexport const action = () => put();`,
      './svc': `export const put = (t) => sb.from(t).insert({});`,
    };
    expect(authorizeFixtureGraph('COMMERCIAL_READY', modules, 'entry')).toEqual([]);
  });

  it('enforcement is defined for functions/** and worker/job entries (test 26)', () => {
    /*
     * A worker/function entry is server-authorized (not PUBLIC_SAFE); a protected effect it reaches is
     * allowed, but the SAME effect under a PUBLIC_SAFE reclassification of that entry is rejected.
     */
    const modules: Record<string, string> = {
      'functions/[[path]].ts': `import { h } from './h';\nexport const onRequest = () => h();`,
      './h': `export const h = () => freezeReleaseCandidate();`,
    };
    expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', modules, 'functions/[[path]].ts')).toEqual([]);
    expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'functions/[[path]].ts')).toContain('deployment/publication');
  });
});

describe('R10 §7/§8: dynamic-import + effect-category detection (fixtures)', () => {
  it('a literal dynamic import / require is discovered as a specifier', () => {
    expect(importSpecifiers(`const x = await import('~/lib/qhub/commercial/commercial-store.server');`)).toContain(
      '~/lib/qhub/commercial/commercial-store.server',
    );
    expect(importSpecifiers(`const y = require('./thing');`)).toContain('./thing');
  });

  it('a NON-literal dynamic import is detected (fail closed)', () => {
    expect(hasNonLiteralDynamicImport(`const m = await import(userSuppliedPath);`)).toBe(true);
    expect(hasNonLiteralDynamicImport(`const m = await import(name + '.js');`)).toBe(true);

    // A literal is NOT flagged; a local require(cond, code) helper is not a module load.
    expect(hasNonLiteralDynamicImport(`const m = await import('~/lib/x');`)).toBe(false);
    expect(hasNonLiteralDynamicImport(`require(cond, 'E_CODE', x);`)).toBe(false);
  });

  it('effect-based detection catches RENAMED wrappers across every protected category', () => {
    const cases: Array<[string, string]> = [
      ['generic external HTTP', `const call = (u) => fetch(u);`],
      ['generic external HTTP', `import axios from 'axios';`],
      ['service-role / DB mutation', `const put = (t) => sb.from(t).insert({});`],
      ['filesystem write', `import { writeFile } from 'node:fs';`],
      ['child process', `import { spawn } from 'node:child_process';`],
      ['queue/event publish', `import { Queue } from 'bullmq';`],
      ['stripe', `const s = 'https://api.stripe.com/v1/charges';`],
      ['deployment/publication', `await callNetlify(); // api.netlify.com`],
      ['dynamic secret read', `const v = process.env[key];`],
      ['model/provider client', `const gen = () => streamText(x);`],
    ];

    for (const [label, src] of cases) {
      expect(detectEffects(src), `${label}: ${src}`).toContain(label);
    }
  });

  it('a pure module with no protected effect yields no categories', () => {
    expect(detectEffects(`export function add(a: number, b: number) { return a + b; }`)).toEqual([]);
  });

  /*
   * R11 §7 — a worker/function request entry that pulls server code through a literal dynamic import
   * is discoverable; a non-literal dynamic import in that same shape fails closed.
   */
  it('a worker/function entry with a literal dynamic import is traversable; a non-literal one fails closed', () => {
    const literalEntry = `export const onRequest = async (c) => { const b = await import('../build/server'); return b; };`;
    expect(hasNonLiteralDynamicImport(literalEntry)).toBe(false);
    expect(importSpecifiers(literalEntry)).toContain('../build/server');

    const dynamicEntry = `export const onRequest = async (c) => { const m = await import(c.env.HANDLER); return m; };`;
    expect(hasNonLiteralDynamicImport(dynamicEntry)).toBe(true);
  });

  // R11 §8 — a renamed HTTP/provider/connector/deploy wrapper still carries its underlying effect.
  it('renamed HTTP / provider / connector / deploy / agent wrappers inherit their effects', () => {
    const renamed: Array<[string, string]> = [
      ['generic external HTTP', `export const callGateway = (u) => fetch(u, { method: 'POST' });`],
      ['model/provider client', `export const runModel = (p) => invokeCommercialModel(p);`],
      ['MCP/connector mutation', `export const syncConnector = () => new MCPService().connectorMutate();`],
      ['deployment/publication', `export const ship = () => freezeReleaseCandidate();`],
      ['agent/enforcement/approval mutation', `export const proceed = (r) => resumeAgentRun(r);`],
    ];

    for (const [label, src] of renamed) {
      expect(detectEffects(src), `${label}: ${src}`).toContain(label);
    }
  });
});

describe('fixtures: the import-graph detectors catch violations', () => {
  it('a suffix-less module doing service-role I/O with NO classification is flagged', () => {
    const src = `import { createClient } from '@supabase/supabase-js';\nexport function w(env){ return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY); }`;
    expect(HARD_SERVER_IO.test(src) && !hasModuleClassification(src)).toBe(true);
  });

  it('a qhub_* RPC / table-mutation module with NO classification is flagged', () => {
    for (const io of [
      `await sb.rpc('qhub_decide_review', {})`,
      `await sb.from('qhub_manual_review_requests').update({})`,
    ]) {
      expect(HARD_SERVER_IO.test(io) && !hasModuleClassification(io)).toBe(true);
    }
  });

  it('a classified module is NOT flagged', () => {
    const src = `export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;\nawait sb.rpc('qhub_decide_review', {});`;
    expect(HARD_SERVER_IO.test(src) && !hasModuleClassification(src)).toBe(false);
  });

  it('an unresolved app-code import is detected; assets/bare specifiers are skipped', () => {
    const here = fileURLToPath(import.meta.url);
    expect(resolveSpec(here, '~/lib/does/not/exist').unresolved).toBe(true);
    expect(resolveSpec(here, '@remix-run/cloudflare').unresolved).toBeUndefined();
    expect(resolveSpec(here, '~/styles/index.scss').unresolved).toBeUndefined();
  });
});
