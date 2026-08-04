/**
 * QHUB R15.6.6 — diagnostic 28 output-growth bound on adversarial role graphs
 * app/test/commercial-r15-6-diagnostic-bounded-expansion.test.ts
 *
 * The independent review rejected R15.6.5 because exhaustive simple-path
 * enumeration is exponential in the SHAPE of the role graph, not merely large.
 * Their disposable fixture — 33 roles, 116 membership edges — produced 87,380
 * simple paths, 13 temporary files and ~85.7 MB of spill for a count-only
 * aggregate. The committed query would have returned all 87,380 rows.
 *
 * That fixture is reproduced here exactly. Its shape is one LOGIN role feeding
 * eight fully connected layers of four roles:
 *   roles  = 1 + 8*4                       = 33
 *   edges  = 4 + 7*(4*4)                   = 116
 *   simple paths = sum(4^k) for k = 1..8   = 87,380
 *
 * This suite proves the bounded design on that graph and on a deliberately
 * denser one:
 *   * the exponential expansion is real (measured, not assumed);
 *   * the bounded diagnostic does not reproduce it;
 *   * every direct edge is still present exactly once;
 *   * MEMBER/USAGE/SET still agree with PostgreSQL;
 *   * output growth follows the documented polynomial bound;
 *   * no temporary spill is produced and the run completes well inside an
 *     external timeout.
 *
 * Harness: disposable localhost PostgreSQL. SKIPS loudly when absent.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { acquireClusterLock, releaseClusterLock } from './helpers/pg-cluster-lock';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const DIAG = `${REPO}docs/release/r15-6-migration-history/28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql`;

const PG_BIN =
  process.env.QHUB_SCRATCH_PG_BIN ??
  'C:/Users/ccaba/AppData/Local/Temp/claude/C--Users-ccaba-qhub-studio/2af3a231-f755-4857-b22e-7cfdcdf5792d/scratchpad/pg/pgsql/bin';
const PORT = process.env.QHUB_SCRATCH_PG_PORT ?? '54329';
const PSQL = `${PG_BIN}/psql.exe`;
const ARGS = ['-h', '127.0.0.1', '-p', PORT, '-U', 'scratch', '-X', '-A', '-F', '|', '-v', 'ON_ERROR_STOP=1'];
const DB = 'bounded28_vitest';
const NSP = 'supabase_migrations';
const TBL = 'supabase_migrations.schema_migrations';

/** Reviewer fixture: 1 root + LAYERS layers of WIDTH, fully connected. */
const WIDTH = 4;
const LAYERS = 8;

/** Denser second graph, same construction. */
const DENSE_WIDTH = 6;
const DENSE_LAYERS = 8;

function harnessAvailable(): boolean {
  if (!existsSync(PSQL)) {
    return false;
  }

  try {
    execFileSync(PSQL, [...ARGS, '-d', 'postgres', '-c', 'SELECT 1;'], { encoding: 'utf8', timeout: 4000 });

    return true;
  } catch {
    return false;
  }
}

const HAVE_PG = harnessAvailable();

if (!HAVE_PG) {
  console.warn(
    '[commercial-r15-6-diagnostic-bounded-expansion] SKIPPED: no local scratch PostgreSQL harness ' +
      `(looked for ${PSQL} on port ${PORT}). The output-growth bound must be measured wherever the ` +
      'harness exists — a skip is not a pass.',
  );
}

const run = (sql: string, db = DB) =>
  execFileSync(PSQL, [...ARGS, '-d', db, '-c', sql], { encoding: 'utf8', timeout: 300000 });
const scalar = (sql: string, db = DB) => run(sql, db).split(/\r?\n/)[1]?.trim();

/**
 * Runs a single scalar query under a server-side statement_timeout, so a
 * pathological plan in the DEMONSTRATION query (never in the diagnostic) can
 * never hang the suite. PGOPTIONS keeps the SQL itself a single statement, so
 * the first output line is still the value.
 */
function scalarGuarded(sql: string, timeout: string, db = DB): string {
  const out = execFileSync(PSQL, [...ARGS, '-t', '-d', db, '-c', sql], {
    encoding: 'utf8',
    timeout: 300000,
    env: { ...process.env, PGOPTIONS: `-c statement_timeout=${timeout}` },
  });

  return out.split(/\r?\n/)[0].trim();
}

/** Builds a layered, fully connected acyclic role graph with a LOGIN root. */
function layeredGraph(prefix: string, width: number, layers: number): string {
  const parts = [`CREATE ROLE ${prefix}_root LOGIN;`];

  for (let l = 1; l <= layers; l += 1) {
    for (let n = 1; n <= width; n += 1) {
      parts.push(`CREATE ROLE ${prefix}_l${l}_${n} NOLOGIN;`);
    }
  }

  for (let n = 1; n <= width; n += 1) {
    parts.push(`GRANT ${prefix}_l1_${n} TO ${prefix}_root;`);
  }

  for (let l = 1; l < layers; l += 1) {
    for (let a = 1; a <= width; a += 1) {
      for (let b = 1; b <= width; b += 1) {
        parts.push(`GRANT ${prefix}_l${l + 1}_${b} TO ${prefix}_l${l}_${a};`);
      }
    }
  }

  return parts.join('\n');
}

function dropGraph(prefix: string, width: number, layers: number): string {
  const parts: string[] = [`DROP ROLE IF EXISTS ${prefix}_root;`];

  for (let l = 1; l <= layers; l += 1) {
    for (let n = 1; n <= width; n += 1) {
      parts.push(`DROP ROLE IF EXISTS ${prefix}_l${l}_${n};`);
    }
  }

  return parts.join('\n');
}

interface Row {
  [k: string]: string;
}

function resultSet(out: string, distinctiveColumn: string): Row[] {
  const lines = out.split(/\r?\n/);
  const start = lines.findIndex((l) => l.includes('|') && l.split('|').includes(distinctiveColumn));

  if (start < 0) {
    return [];
  }

  const header = lines[start].split('|');
  const rows: Row[] = [];

  for (let i = start + 1; i < lines.length; i += 1) {
    const l = lines[i];

    if (!l || !l.includes('|') || /^\(\d+ rows?\)$/.test(l)) {
      break;
    }

    const v = l.split('|');
    rows.push(Object.fromEntries(header.map((h, j) => [h, v[j]])) as Row);
  }

  return rows;
}

/** Total data rows the diagnostic returned, read from psql's own row counters. */
function totalDiagnosticRows(out: string): number {
  return [...out.matchAll(/^\((\d+) rows?\)$/gm)].reduce((sum, m) => sum + Number(m[1]), 0);
}

describe.skipIf(!HAVE_PG)('R15.6.6 diagnostic 28 — output growth is bounded on adversarial graphs', () => {
  let diagOut = '';
  let elapsedMs = 0;
  let simplePathCount = 0;
  let denseRows = 0;
  let denseElapsedMs = 0;
  let catalogEdgesAtCapture = 0;
  let candidatesAtCapture = 0;
  let rolesAtCapture = 0;

  beforeAll(async () => {
    await acquireClusterLock();

    try {
      run(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`, 'postgres');
    } catch {
      /* n/a */
    }

    try {
      run(`${dropGraph('bx', WIDTH, LAYERS)}\n${dropGraph('dx', DENSE_WIDTH, DENSE_LAYERS)}`, 'postgres');
    } catch {
      /* none */
    }

    run(`CREATE DATABASE ${DB};`, 'postgres');

    /*
     * The diagnostic reads these two objects; it never reads a row from them.
     * No migration is needed here — this suite measures output growth, not the
     * commercial contract.
     */
    run(`CREATE SCHEMA ${NSP};
      CREATE TABLE ${TBL} (version text NOT NULL PRIMARY KEY, statements text[], name text);
      CREATE TABLE public.qhub_manual_review_requests (id int);`);
    run(layeredGraph('bx', WIDTH, LAYERS), 'postgres');

    /*
     * MEASURE the expansion the review reported. This is a COUNT-only
     * aggregate — it never materialises the 19-column rows the withdrawn
     * design would have transmitted — and it is guarded by a statement_timeout
     * so a pathological plan cannot hang the suite.
     */
    simplePathCount = Number(
      scalarGuarded(
        `WITH RECURSIVE cand AS (
          SELECT oid FROM pg_roles WHERE rolcanlogin AND rolname LIKE 'bx\\_%'
        ), p AS (
          SELECT c.oid AS cand_oid, m.roleid AS granted_oid, ARRAY[c.oid, m.roleid] AS path_oids
            FROM cand c JOIN pg_auth_members m ON m.member = c.oid
          UNION ALL
          SELECT p.cand_oid, m.roleid, p.path_oids || m.roleid
            FROM p JOIN pg_auth_members m ON m.member = p.granted_oid
           WHERE NOT (m.roleid = ANY (p.path_oids))
        )
        SELECT count(*) FROM p;`,
        '120s',
      ),
    );

    const started = Date.now();
    diagOut = execFileSync(PSQL, [...ARGS, '-d', DB, '-f', DIAG], { encoding: 'utf8', timeout: 120000 });
    elapsedMs = Date.now() - started;

    // Catalog sizes AT THE MOMENT diagOut was captured, for the bound checks.
    catalogEdgesAtCapture = Number(scalar(`SELECT count(*) FROM pg_auth_members;`));
    rolesAtCapture = Number(scalar(`SELECT count(*) FROM pg_roles;`));
    candidatesAtCapture = Number(
      scalar(`SELECT count(*) FROM pg_roles r
           WHERE NOT r.rolsuper
             AND r.oid <> (SELECT relowner FROM pg_class WHERE oid = 'public.qhub_manual_review_requests'::regclass)
             AND (r.rolcanlogin OR r.rolname IN ('anon','authenticated','service_role'));`),
    );

    // Denser graph: same construction, width 6.
    run(layeredGraph('dx', DENSE_WIDTH, DENSE_LAYERS), 'postgres');

    const denseStarted = Date.now();
    const denseOut = execFileSync(PSQL, [...ARGS, '-d', DB, '-f', DIAG], { encoding: 'utf8', timeout: 120000 });
    denseElapsedMs = Date.now() - denseStarted;
    denseRows = totalDiagnosticRows(denseOut);
  }, 900_000);

  afterAll(() => {
    try {
      run(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`, 'postgres');
    } catch {
      /* n/a */
    }

    try {
      run(`${dropGraph('bx', WIDTH, LAYERS)}\n${dropGraph('dx', DENSE_WIDTH, DENSE_LAYERS)}`, 'postgres');
    } catch {
      /* already gone */
    }

    releaseClusterLock();
  }, 300_000);

  it('b1 — the reviewer fixture is reproduced exactly: 33 roles, 116 edges, 87,380 simple paths', () => {
    expect(Number(scalar(`SELECT count(*) FROM pg_roles WHERE rolname LIKE 'bx\\_%';`))).toBe(33);
    expect(
      Number(
        scalar(`SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
             WHERE r.rolname LIKE 'bx\\_%';`),
      ),
    ).toBe(116);

    // sum(4^k) for k = 1..8
    const expected = Array.from({ length: LAYERS }, (_, k) => WIDTH ** (k + 1)).reduce((a, b) => a + b, 0);
    expect(expected).toBe(87_380);
    expect(simplePathCount, 'the exponential expansion is real, not hypothetical').toBe(87_380);
  });

  it('b2 — the bounded diagnostic returns orders of magnitude fewer rows than 87,380', () => {
    const total = totalDiagnosticRows(diagOut);
    expect(total, `diagnostic returned ${total} rows`).toBeLessThan(2_000);
    expect(total).toBeLessThan(simplePathCount / 100);
  });

  it('b3 — every one of the 116 direct edges is represented exactly once', () => {
    const edges = resultSet(diagOut, 'edge_member_oid');
    const bx = edges.filter((e) => e.edge_member_role.startsWith('bx_'));
    expect(bx.length).toBe(116);

    const keys = bx.map((e) => `${e.edge_member_oid}/${e.edge_granted_oid}/${e.edge_grantor_oid}`);
    expect(new Set(keys).size, 'no edge duplicated or missing').toBe(116);

    /*
     * The inventory is the WHOLE catalog as it stood at capture time, not just
     * the fixture's edges.
     */
    expect(edges.length).toBe(catalogEdgesAtCapture);
  });

  it('b4 — MEMBER/USAGE/SET still agree with PostgreSQL across the branching graph', () => {
    const reach = resultSet(diagOut, 'membership_exists').filter((r) => r.candidate_role === 'bx_root');
    expect(reach.length).toBeGreaterThan(0);

    for (const r of reach.filter((x) => x.related_role.startsWith('bx_'))) {
      expect(
        scalar(`SELECT pg_has_role('bx_root','${r.related_role}','MEMBER')::text || '/'
             || pg_has_role('bx_root','${r.related_role}','USAGE')::text  || '/'
             || pg_has_role('bx_root','${r.related_role}','SET')::text;`),
        r.related_role,
      ).toBe(
        `${r.membership_exists === 't'}/${r.privileges_inherited_without_set_role === 't'}/${
          r.set_role_permitted === 't'
        }`,
      );
    }

    // All 32 non-root fixture roles are reachable, and reported as such.
    expect(reach.filter((r) => r.related_role.startsWith('bx_') && r.membership_exists === 't').length).toBe(32);
  });

  it('b5 — every result set respects its documented row bound', () => {
    const reach = resultSet(diagOut, 'membership_exists');
    const edges = resultSet(diagOut, 'edge_member_oid');
    const candidateRows = resultSet(diagOut, 'reaches_protected_objects');
    const routeRows = resultSet(diagOut, 'usable_without_set_role');

    // QUERY 2: exactly C. QUERY 3: at most 9C. QUERY 4: exactly E. QUERY 5: <= C*R.
    expect(candidateRows.length, 'QUERY 2 = C').toBe(candidatesAtCapture);
    expect(routeRows.length, 'QUERY 3 <= 9C').toBeLessThanOrEqual(9 * candidatesAtCapture);
    expect(edges.length, 'QUERY 4 = E').toBe(catalogEdgesAtCapture);
    expect(reach.length, `QUERY 5 <= ${candidatesAtCapture} * ${rolesAtCapture}`).toBeLessThanOrEqual(
      candidatesAtCapture * rolesAtCapture,
    );

    // And the documented total bound holds end to end.
    const bound =
      1 +
      candidatesAtCapture +
      9 * candidatesAtCapture +
      catalogEdgesAtCapture +
      candidatesAtCapture * rolesAtCapture +
      64;
    expect(totalDiagnosticRows(diagOut)).toBeLessThanOrEqual(bound);
  });

  it('b6 — a denser graph completes within the external timeout and stays polynomial', () => {
    /*
     * Width 6 x 8 layers = 49 roles and 6 + 7*36 = 258 edges, whose simple-path
     * count is sum(6^k) k=1..8 = 2,015,538 — an order of magnitude beyond the
     * fixture that already spilled 85 MB. The bounded diagnostic is unmoved.
     */
    const densePaths = Array.from({ length: DENSE_LAYERS }, (_, k) => DENSE_WIDTH ** (k + 1)).reduce(
      (a, b) => a + b,
      0,
    );
    expect(densePaths).toBeGreaterThan(2_000_000);

    expect(denseRows, `dense graph returned ${denseRows} rows`).toBeLessThan(5_000);
    expect(denseElapsedMs, `dense run took ${denseElapsedMs}ms`).toBeLessThan(60_000);
  });

  it('b7 — growth from the sparse to the dense graph is polynomial, not exponential', () => {
    const sparseRows = totalDiagnosticRows(diagOut);

    /*
     * Roles roughly 2.5x (33 -> 82 including both graphs); simple paths grow
     * ~23x. If output were route-driven, rows would explode; the bound says
     * they may only grow with C*R + E, so a small constant multiple is the
     * ceiling here.
     */
    expect(denseRows / sparseRows, 'row growth must stay a small multiple').toBeLessThan(25);
  });

  it('b8 — the run produces no temporary spill and completes promptly', () => {
    /*
     * The withdrawn design wrote 13 temporary files and ~85.7 MB of spill on
     * this very graph. Measured over the diagnostic itself via the database's
     * own counters, the bounded version writes nothing at all.
     */
    const before = Number(scalar(`SELECT temp_files FROM pg_stat_database WHERE datname = '${DB}';`));
    const beforeBytes = Number(scalar(`SELECT temp_bytes FROM pg_stat_database WHERE datname = '${DB}';`));

    const started = Date.now();
    execFileSync(PSQL, [...ARGS, '-d', DB, '-f', DIAG], { encoding: 'utf8', timeout: 120000 });

    const took = Date.now() - started;

    const after = Number(scalar(`SELECT temp_files FROM pg_stat_database WHERE datname = '${DB}';`));
    const afterBytes = Number(scalar(`SELECT temp_bytes FROM pg_stat_database WHERE datname = '${DB}';`));

    expect(after - before, 'no temporary files written').toBe(0);
    expect(afterBytes - beforeBytes, 'no temporary bytes spilled').toBe(0);
    expect(took, `run took ${took}ms`).toBeLessThan(60_000);
    expect(elapsedMs, `first run took ${elapsedMs}ms`).toBeLessThan(60_000);
  });

  it('b9 — no effective privilege is lost: the branching root still reports its real access', () => {
    /*
     * Give the deepest layer real access and confirm the root — reachable only
     * through 8 transitive hops across a graph with 87,380 alternative routes —
     * is still reported as reaching the protected objects.
     */
    run(`GRANT USAGE ON SCHEMA ${NSP} TO bx_l${LAYERS}_1;
      GRANT SELECT ON ${TBL} TO bx_l${LAYERS}_1;`);

    const out = execFileSync(PSQL, [...ARGS, '-d', DB, '-f', DIAG], { encoding: 'utf8', timeout: 120000 });
    const root = resultSet(out, 'reaches_protected_objects').find((c) => c.candidate_role === 'bx_root')!;

    expect(scalar(`SELECT has_table_privilege('bx_root','${TBL}','SELECT');`)).toBe('t');
    expect(root.privileges_usable_without_set_role, 'transitive reach survives without path rows').toBe('t');
    expect(root.reaches_protected_objects).toBe('t');

    const sel = resultSet(out, 'usable_without_set_role').find(
      (r) => r.candidate_role === 'bx_root' && r.object_kind === 'table' && r.privilege === 'SELECT',
    )!;
    expect(sel.usable_without_set_role).toBe('t');
    expect(totalDiagnosticRows(out), 'still bounded with access present').toBeLessThan(5_000);

    run(`REVOKE SELECT ON ${TBL} FROM bx_l${LAYERS}_1;
      REVOKE USAGE ON SCHEMA ${NSP} FROM bx_l${LAYERS}_1;`);
  });
});
