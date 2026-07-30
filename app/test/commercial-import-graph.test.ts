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

/*
 * R14 §4 — machine-readable per-route OWN-effect exemptions for the R8-reviewed legacy provider routes:
 * each calls a FIXED provider origin with a server-constructed request and a caller-cookie token (no
 * caller-controlled destination — so it is PUBLIC_SAFE-appropriate under the existing model). Exact route
 * + exact effect + reason, covered by positive + negative tests. Any other route/effect fails closed.
 */
const FIXED_PROVIDER_HTTP =
  'fixed provider origin (api.<provider>.com); server-constructed request; caller-cookie token only; no caller-controlled destination (R8-reviewed)';
const ROUTE_OWN_EFFECT_EXEMPTIONS: Array<{ route: RegExp; effect: string; reason: string }> = [
  // Fixed-provider HTTP proxies — a fixed api.<provider>.com origin, caller-cookie token, no caller URL.
  { route: /api\.github-branches\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.github-stats\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.github-template\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },

  /*
   * R15: the api.gitlab-branches / api.gitlab-projects exemptions are REMOVED. They falsely claimed a
   * fixed origin while the production code built the destination from a caller-supplied `gitlabUrl` and
   * forwarded a browser token to it. Both routes are now disabled (a constant feature-disabled response
   * with zero effects), so they need no exemption at all — the gate evaluates them on their real source.
   */
  { route: /api\.supabase-user\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.supabase\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.supabase\.variables\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.system\.git-info\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.netlify-user\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },
  { route: /api\.vercel-user\.ts$/, effect: 'generic external HTTP', reason: FIXED_PROVIDER_HTTP },

  /*
   * netlify-user / vercel-user: the effect-name matches api.netlify.com / api.vercel.com, but the call is a
   * read of the connected account ("get current user") — no publish/deploy is performed.
   */
  {
    route: /api\.netlify-user\.ts$/,
    effect: 'deployment/publication',
    reason:
      'reads the connected Netlify account via a fixed api.netlify.com origin (caller-cookie token); performs no deploy/publish (R8-reviewed)',
  },
  {
    route: /api\.vercel-user\.ts$/,
    effect: 'deployment/publication',
    reason:
      'reads the connected Vercel account via a fixed api.vercel.com origin (caller-cookie token); performs no deploy/publish (R8-reviewed)',
  },

  // models: lists AVAILABLE provider models (read); no generation/invoke.
  {
    route: /api\.models\.ts$/,
    effect: 'model/provider client',
    reason:
      'lists available provider models (read-only listing); performs no model generation/invocation (R8-reviewed)',
  },

  // mcp-check: reads/validates connector config; the effect-name matches but no connector is mutated.
  {
    route: /api\.mcp-check\.ts$/,
    effect: 'MCP/connector mutation',
    reason:
      'reads/validates MCP connector configuration (no connector mutation despite the effect-name match) (R8-reviewed)',
  },

  // git-info / disk-info: FIXED local system commands with NO caller input (command-injection-safe), dev-only.
  {
    route: /api\.git-info\.ts$/,
    effect: 'child process',
    reason:
      'runs FIXED local git commands (git rev-parse/status/log) with NO caller input — command-injection-safe local repo status (dev feature) (R8-reviewed)',
  },
  {
    route: /api\.system\.disk-info\.ts$/,
    effect: 'child process',
    reason:
      'runs the FIXED "df -k" command with NO caller input — local disk usage (dev feature, guarded off on Cloudflare) (R8-reviewed)',
  },
];

function isRouteExempt(routeRel: string, effect: string): boolean {
  return ROUTE_OWN_EFFECT_EXEMPTIONS.some((e) => e.route.test(routeRel) && e.effect === effect);
}

/*
 * Classes that carry their own runtime authorization and may perform any protected effect. NOTE:
 * SERVER_ENTRY is deliberately NOT here — R14 §6 removes the blanket "server code may do anything" grant;
 * each server entry point is instead held to an EXACT allowed-effect set (SERVER_ENTRY_ALLOWED below).
 */
const SERVER_AUTHORIZED_CLASSES = new Set([
  'INTERNAL_SERVER_ONLY',
  'COMMERCIAL_READY',
  'STAFF_ONLY',
  'SIGNATURE_AUTH',
  'REQUIRES_COMMERCIAL_READY_TOKEN',
  'REQUIRES_STAFF_CONTEXT',
  'MIXED_EXPLICIT_EXPORT_CLASSIFICATION',
]);

/*
 * R14 §6 — EXACT allowed-effect set per server-entry group (machine-readable, reasoned). An entry that
 * performs an effect outside its declared set fails closed. Derived from the actual entry sources.
 */
const SERVER_ENTRY_ALLOWED: Array<{ match: RegExp; allowed: string[]; reason: string }> = [
  {
    match: /\/functions\//,
    allowed: [],
    reason:
      'Cloudflare Pages Function request entry: delegates to the built server bundle via a literal dynamic import; performs no direct protected effect',
  },
  {
    match: /\/scripts\//,
    allowed: [
      'service-role / DB mutation',
      'generic external HTTP',
      'dynamic secret read',
      'filesystem write',
      'child process',
    ],
    reason:
      'deploy/build/preflight scripts run at release time with host privilege: filesystem, child processes, the service-role schema verifier (read-only), and its Supabase HTTP call',
  },
  {
    match: /\/app\/entry\.server\.tsx$/,
    allowed: ['queue/event publish'],
    reason:
      'Remix server render entry: react-dom/server streaming surfaces an emit()-shaped call; no network/secret/db/fs/process effect',
  },
];

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

  // PUBLIC_SAFE / PURE_NO_IO / SERVER_ENTRY / unclassified / ambiguous → every protected effect is unauthorized here.
  return effectLabels;
}

/**
 * File-scoped authorization: SERVER_ENTRY is held to its EXACT allowed-effect set (by module glob);
 * everything else defers to the class rule. An undeclared server-entry effect fails closed.
 */
function unauthorizedForFile(rel: string, classification: string | undefined, effectLabels: string[]): string[] {
  if (classification === 'SERVER_ENTRY') {
    const entry = SERVER_ENTRY_ALLOWED.find((e) => e.match.test(`/${rel}`));
    const allowed = entry?.allowed ?? [];

    return effectLabels.filter((e) => !allowed.includes(e));
  }

  return unauthorizedEffects(classification, effectLabels);
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
 * R13 §5 + R14 §4/§6 — COMPLETE-GRAPH effect authorization. Every visited module gets a result. Every
 * server module + server entry point is enforced against its class (SERVER_ENTRY against its EXACT set).
 * EVERY route is enforced against its OWN-source direct effects COMBINED with its transitive imported
 * effects (no isServerModule filter excludes route-owned effects) + a sensitive-logging check.
 */
interface RouteVerdict {
  classification?: string;
  direct: string[];
  transitive: string[];
  unauthorized: string[];
  sensitiveLog: boolean;
}
interface EffectAuthReport {
  results: Map<string, { classification?: string; effects: string[]; enforced: boolean }>;
  routeVerdicts: Map<string, RouteVerdict>;
  serverModulesEnforced: number;
  serverViolations: string[];
  publicRoutes: number;
  routeViolations: string[];
}

function runEffectAuthorization(): EffectAuthReport {
  const results = new Map<string, { classification?: string; effects: string[]; enforced: boolean }>();
  const routeVerdicts = new Map<string, RouteVerdict>();
  const serverViolations: string[] = [];
  const routeViolations: string[] = [];
  let serverModulesEnforced = 0;
  let publicRoutes = 0;

  // 1. Every visited module receives a result; every server MODULE (not routes — handled in step 2) is enforced.
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

    const unauth = unauthorizedForFile(rel, classification, effects);

    if (unauth.length) {
      serverViolations.push(`${rel} [${classification ?? 'UNCLASSIFIED'}] unauthorized: ${unauth.join(', ')}`);
    }

    if (logsSensitive(src).length) {
      serverViolations.push(`${rel} logs sensitive value`);
    }
  }

  // 2. EVERY route: enforce its OWN-source direct effects combined with its transitive imported effects.
  for (const entry of routeEntries) {
    const canonEntry = entry.replace(/\\/g, '/');
    const rel = canonEntry.slice(REPO.length);
    const ownSrc = readFileSync(entry, 'utf8');
    const classification = routeClassification(ownSrc);

    const direct = detectEffectsStripped(ownSrc);
    const transitive: string[] = [];

    for (const mod of reachableFrom(entry)) {
      if (mod !== canonEntry && isServerModule(mod)) {
        for (const e of detectEffectsStripped(readFileSync(mod, 'utf8'))) {
          if (!transitive.includes(e) && !isPublicExempt(mod.slice(REPO.length), e)) {
            transitive.push(e);
          }
        }
      }
    }

    const combined = [...new Set([...direct, ...transitive])];
    const unauthorized = combined.filter(
      (e) => unauthorizedForFile(rel, classification, [e]).length > 0 && !isRouteExempt(rel, e),
    );
    const sensitiveLog = logsSensitive(ownSrc).length > 0;

    routeVerdicts.set(rel, { classification, direct, transitive, unauthorized, sensitiveLog });

    if (classification === 'PUBLIC_SAFE') {
      publicRoutes += 1;
    }

    if (unauthorized.length) {
      routeViolations.push(`${rel} [${classification ?? 'UNCLASSIFIED'}] unauthorized: ${unauthorized.join(', ')}`);
    }

    if (sensitiveLog) {
      routeViolations.push(`${rel} [${classification ?? 'UNCLASSIFIED'}] logs sensitive value`);
    }
  }

  return { results, routeVerdicts, serverModulesEnforced, serverViolations, publicRoutes, routeViolations };
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

describe('R13 §5 + R14 §4/§6 — effect authorization ENFORCED over the complete graph incl. route own-source', () => {
  it('every visited module receives an authorization result (test 34, none skipped)', () => {
    expect(effectAuth.results.size).toBe(graph.visited.size);

    for (const file of graph.visited) {
      expect(effectAuth.results.has(file.slice(REPO.length)), file).toBe(true);
    }
  });

  it('EVERY route receives an authorization verdict with direct + transitive effects (R14 §4, test 33)', () => {
    const routeRels = routeEntries.map((f) => f.replace(/\\/g, '/').slice(REPO.length));
    expect(effectAuth.routeVerdicts.size).toBe(routeRels.length);

    for (const rel of routeRels) {
      const v = effectAuth.routeVerdicts.get(rel);
      expect(v, `no verdict for ${rel}`).toBeTruthy();
      expect(Array.isArray(v?.direct)).toBe(true); // direct-effect result present
      expect(Array.isArray(v?.transitive)).toBe(true); // transitive-effect result present
    }
  });

  it('enforces a meaningful population of server modules + PUBLIC_SAFE routes', () => {
    expect(effectAuth.serverModulesEnforced).toBeGreaterThan(20);
    expect(effectAuth.publicRoutes).toBeGreaterThan(10);
  });

  it('NO server module performs an unauthorized effect or logs sensitive values (fail closed)', () => {
    expect(effectAuth.serverViolations, effectAuth.serverViolations.slice(0, 30).join('\n')).toEqual([]);
  });

  it('NO route performs an unauthorized OWN-source or transitive effect, and none logs sensitive values', () => {
    expect(effectAuth.routeViolations, effectAuth.routeViolations.slice(0, 40).join('\n')).toEqual([]);
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

  it('route OWN-effect exemptions are narrow (exact route + exact effect + reason) with pos/neg coverage', () => {
    // Positive: an R8-reviewed fixed-provider route is exempt for its exact reviewed effect.
    expect(isRouteExempt('app/routes/api.github-branches.ts', 'generic external HTTP')).toBe(true);
    expect(isRouteExempt('app/routes/api.git-info.ts', 'child process')).toBe(true);
    expect(isRouteExempt('app/routes/api.models.ts', 'model/provider client')).toBe(true);

    // Negative: a DIFFERENT effect on an exempt route, or a non-exempt route, is NOT exempt (fail closed).
    expect(isRouteExempt('app/routes/api.github-branches.ts', 'service-role / DB mutation')).toBe(false);
    expect(isRouteExempt('app/routes/api.web-search.ts', 'generic external HTTP')).toBe(false);
    expect(isRouteExempt('app/routes/pricing.tsx', 'generic external HTTP')).toBe(false);

    for (const e of ROUTE_OWN_EFFECT_EXEMPTIONS) {
      expect(e.reason.length).toBeGreaterThan(20);
    }
  });

  it('R15 test 18/19/20 — the GitLab fixed-origin exemptions are gone; the gate judges both routes on real source', () => {
    // 18: no exemption may claim these routes are fixed-origin any more.
    for (const effect of ['generic external HTTP', 'dynamic secret read']) {
      expect(isRouteExempt('app/routes/api.gitlab-projects.ts', effect)).toBe(false);
      expect(isRouteExempt('app/routes/api.gitlab-branches.ts', effect)).toBe(false);
    }

    // 19: the OLD vulnerable shape (PUBLIC_SAFE + caller-host fetch + bearer token) is REJECTED.
    const vulnerable = `/** @qhub-route: PUBLIC_SAFE */
      export const action = async ({ request }) => {
        const { token, gitlabUrl } = await request.json();
        return fetch(\`\${gitlabUrl}/api/v4/projects\`, { headers: { Authorization: \`Bearer \${token}\` } });
      };`;
    expect(authorizeFixtureGraph('PUBLIC_SAFE', { route: vulnerable }, 'route')).toContain('generic external HTTP');

    // 20: the CORRECTED shape (the real disabled routes) is ACCEPTED — zero effects, no exemption needed.
    for (const rel of ['app/routes/api.gitlab-projects.ts', 'app/routes/api.gitlab-branches.ts']) {
      const verdict = effectAuth.routeVerdicts.get(rel);
      expect(verdict, `no verdict for ${rel}`).toBeTruthy();
      expect(verdict?.classification).toBe('PUBLIC_SAFE');
      expect(verdict?.direct, `${rel} still carries a direct effect`).toEqual([]);
      expect(verdict?.unauthorized).toEqual([]);
      expect(verdict?.sensitiveLog).toBe(false);
    }
  });

  it('the reclassified web-search route is INTERNAL_SERVER_ONLY (no PUBLIC arbitrary outbound fetch)', () => {
    const v = effectAuth.routeVerdicts.get('app/routes/api.web-search.ts');
    expect(v?.classification).toBe('INTERNAL_SERVER_ONLY');
    expect(v?.unauthorized).toEqual([]); // an authenticated server route may reach the SSRF-safe fetcher
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

  it('test 30/31/35/36 — functions/** + worker/job entries get EXACT-effect enforcement (R14 §6)', () => {
    // functions/** allowed set is empty → a deployment effect in a functions entry fails closed.
    expect(unauthorizedForFile('functions/[[path]].ts', 'SERVER_ENTRY', ['deployment/publication'])).toEqual([
      'deployment/publication',
    ]);

    // scripts/** exact allowed set: child_process/filesystem/http/service-role/dynamic-secret pass...
    expect(
      unauthorizedForFile('scripts/build-with-identity.mjs', 'SERVER_ENTRY', ['child process', 'filesystem write']),
    ).toEqual([]);

    // ...but an UNDECLARED effect (e.g. stripe, queue publish) in a script fails closed (no blanket grant).
    expect(unauthorizedForFile('scripts/build-with-identity.mjs', 'SERVER_ENTRY', ['stripe'])).toEqual(['stripe']);
    expect(unauthorizedForFile('app/entry.server.tsx', 'SERVER_ENTRY', ['queue/event publish'])).toEqual([]);
    expect(unauthorizedForFile('app/entry.server.tsx', 'SERVER_ENTRY', ['generic external HTTP'])).toEqual([
      'generic external HTTP',
    ]);
  });

  it('test 32 — a deployment/CLI entry receives an explicit classification + exact-effect decision', () => {
    expect(classifyFile('scripts/build-with-identity.mjs', 'const x = 1;')).toBe('SERVER_ENTRY');

    // The decision is EXACT, not a blanket allow: the script's declared effects pass, others do not.
    expect(unauthorizedForFile('scripts/build-with-identity.mjs', 'SERVER_ENTRY', ['child process'])).toEqual([]);
    expect(
      unauthorizedForFile('scripts/build-with-identity.mjs', 'SERVER_ENTRY', ['agent/enforcement/approval mutation']),
    ).toEqual(['agent/enforcement/approval mutation']);

    // Every server-entry allowed set carries a reason.
    for (const e of SERVER_ENTRY_ALLOWED) {
      expect(e.reason.length).toBeGreaterThan(20);
    }
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

describe('R14 §9 — route OWN-source direct-effect enforcement (repository-shaped)', () => {
  const PUBLIC = '/** @qhub-route: PUBLIC_SAFE */\n';

  /*
   * A repository-shaped route file (single module) run through the real engine — its OWN-source effects
   * are combined into the verdict even with no imported module carrying the effect.
   */
  const directProbes: Array<[string, string, string]> = [
    ['test 23 — direct fetch', 'generic external HTTP', `export const loader = () => fetch('https://x');`],
    ['test 24 — direct secret read', 'dynamic secret read', `export const loader = (c) => c.env['SECRET_KEY'];`],
    [
      'test 26 — direct filesystem',
      'filesystem write',
      `import { writeFile } from 'node:fs';\nexport const action = () => writeFile('a','b',()=>{});`,
    ],
    [
      'test 27 — direct child_process',
      'child process',
      `import { execSync } from 'node:child_process';\nexport const loader = () => execSync('ls');`,
    ],
    ['test 28 — direct queue publish', 'queue/event publish', `export const action = (j) => producer.send(j);`],
    ['test 29a — direct provider', 'model/provider client', `export const loader = (p) => streamText(p);`],
    ['test 29b — direct deployment', 'deployment/publication', `export const action = () => freezeReleaseCandidate();`],
    [
      'test 29c — direct connector',
      'MCP/connector mutation',
      `export const action = () => new MCPService().connectorMutate();`,
    ],
    [
      'test 29d — direct service-role write',
      'service-role / DB mutation',
      `export const action = (t) => sb.from(t).insert({});`,
    ],
  ];

  for (const [label, effect, body] of directProbes) {
    it(`${label} in a PUBLIC_SAFE route fails; the same route as INTERNAL_SERVER_ONLY passes`, () => {
      const src = `${PUBLIC}${body}`;
      expect(authorizeFixtureGraph('PUBLIC_SAFE', { route: src }, 'route')).toContain(effect);
      expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', { route: src }, 'route')).toEqual([]);
    });
  }

  it('test 25 — a PUBLIC_SAFE route logging request.headers fails the sensitive-log detector', () => {
    expect(
      logsSensitive(`export const loader = ({ request }) => console.log('h', Object.fromEntries(request.headers));`),
    ).not.toEqual([]);
  });

  it('test 30 — a route with safe direct source and safe imports passes', () => {
    const modules = {
      route: `/** @qhub-route: PUBLIC_SAFE */\nimport { fmt } from './u';\nexport const loader = () => fmt(1);`,
      './u': `export const fmt = (n) => String(n);`,
    };
    expect(authorizeFixtureGraph('PUBLIC_SAFE', modules, 'route')).toEqual([]);
  });

  it('test 31 — an authenticated/internal route with an explicitly allowed effect passes', () => {
    const src = `/** @qhub-route: INTERNAL_SERVER_ONLY */\nexport const action = (t) => sb.from(t).insert({});`;
    expect(authorizeFixtureGraph('INTERNAL_SERVER_ONLY', { route: src }, 'route')).toEqual([]);
  });

  it('test 32/33/34 — route-owned + transitive effects both appear in a real verdict; no route is filtered out', () => {
    // Every real route has a verdict carrying BOTH a direct and a transitive effect array.
    let withDirect = 0;
    let withTransitive = 0;

    for (const v of effectAuth.routeVerdicts.values()) {
      expect(Array.isArray(v.direct)).toBe(true);
      expect(Array.isArray(v.transitive)).toBe(true);

      if (v.direct.length) {
        withDirect += 1;
      }

      if (v.transitive.length) {
        withTransitive += 1;
      }
    }

    /*
     * The verdict set covers routes that carry direct effects (e.g. the R8-reviewed provider routes) AND
     * routes that only reach effects transitively — proving neither is excluded by isServerModule.
     */
    expect(withDirect).toBeGreaterThan(0);
    expect(withTransitive).toBeGreaterThan(0);
    expect(effectAuth.routeVerdicts.size).toBe(routeEntries.length);
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
