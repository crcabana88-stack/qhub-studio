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
