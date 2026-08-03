/**
 * QHUB R15.6.4 — READ-ONLY MANAGED-ROLE DIAGNOSTIC (28) VALIDATION
 * app/test/commercial-r15-6-managed-role-diagnostic.test.ts
 *
 * The authorized live PRE 25 run returned UNEXPECTED_MIGRATION_HISTORY_STOP
 * with one failing condition and three named access paths (cli_login_postgres,
 * supabase_etl_admin, supabase_read_only_user). Diagnostic 28 collects the
 * catalog evidence a reviewer needs to judge those paths. It authorizes
 * nothing.
 *
 * These tests model every required pattern against real PostgreSQL and prove:
 *   * the diagnostic is read-only and leaves protected objects byte-equivalent
 *   * it discovers candidates from the catalog, not from names
 *   * it reports direct, inherited, SET-ROLE-only, predefined-role, ownership,
 *     explicit-ACL and PUBLIC routes distinctly
 *   * a dormant predefined role with no data privileges is NOT reported as an
 *     access path, while a login that can assume a data-privileged role IS
 *
 * Static assertions additionally prove the file contains no mutating SQL.
 * Harness: localhost scratch PostgreSQL (see the analysis document); the suite
 * SKIPS loudly when absent — a skip is not a pass.
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const DIR = `${REPO}docs/release/r15-6-migration-history/`;
const DIAG = `${DIR}28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql`;
const DIAG_SQL = readFileSync(DIAG, 'utf8');
const MIGRATION = `${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`;

const PG_BIN =
  process.env.QHUB_SCRATCH_PG_BIN ??
  'C:/Users/ccaba/AppData/Local/Temp/claude/C--Users-ccaba-qhub-studio/2af3a231-f755-4857-b22e-7cfdcdf5792d/scratchpad/pg/pgsql/bin';
const PORT = process.env.QHUB_SCRATCH_PG_PORT ?? '54329';
const PSQL = `${PG_BIN}/psql.exe`;
const ARGS = ['-h', '127.0.0.1', '-p', PORT, '-U', 'scratch', '-X', '-A', '-F', '|', '-v', 'ON_ERROR_STOP=1'];
const DB = 'diag28_vitest';
const TBL = 'supabase_migrations.schema_migrations';

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
    '[commercial-r15-6-managed-role-diagnostic] SKIPPED: no local scratch PostgreSQL harness ' +
      `(looked for ${PSQL} on port ${PORT}). The diagnostic evidence proofs must be executed ` +
      'wherever the harness exists — a skip is not a pass.',
  );
}

const run = (sql: string, db = DB) =>
  execFileSync(PSQL, [...ARGS, '-d', db, '-c', sql], { encoding: 'utf8', timeout: 120000 });
const runFile = (path: string) =>
  execFileSync(PSQL, [...ARGS, '-d', DB, '-f', path], { encoding: 'utf8', timeout: 180000 });

/** Fingerprint of everything the diagnostic touches: rows, ACLs, owners, RLS. */
const protectedFingerprint = () =>
  run(`SELECT md5(
     coalesce((SELECT string_agg(to_jsonb(m.*)::text, '|' ORDER BY m.version) FROM ${TBL} m), '-') || '::' ||
     coalesce((SELECT n.nspacl::text FROM pg_namespace n WHERE n.nspname = 'supabase_migrations'), '-') || '::' ||
     coalesce((SELECT c.relacl::text FROM pg_class c WHERE c.oid = '${TBL}'::regclass), '-') || '::' ||
     (SELECT c.relowner::text || c.relrowsecurity::text FROM pg_class c WHERE c.oid = '${TBL}'::regclass) || '::' ||
     (SELECT n.nspowner::text FROM pg_namespace n WHERE n.nspname = 'supabase_migrations') || '::' ||
     coalesce((SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles), '-'));`)
    .split('\n')[1]
    ?.trim();

interface Row {
  [k: string]: string;
}

/**
 * Parse a psql result set identified by a column that is UNIQUE to that set.
 * QUERY 2, 3 and 4 all begin with candidate_role, so a first-column match is
 * ambiguous; keying on a distinctive column selects the right block.
 */
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

const ROLE_FIXTURE = `
  CREATE ROLE diag_direct_reader LOGIN;
  GRANT USAGE ON SCHEMA supabase_migrations TO diag_direct_reader;
  GRANT SELECT ON ${TBL} TO diag_direct_reader;

  CREATE ROLE diag_direct_writer LOGIN;
  GRANT INSERT, UPDATE, DELETE ON ${TBL} TO diag_direct_writer;

  CREATE ROLE diag_read_all LOGIN;  GRANT pg_read_all_data TO diag_read_all;
  CREATE ROLE diag_write_all LOGIN; GRANT pg_write_all_data TO diag_write_all;

  CREATE ROLE diag_cap_custom NOLOGIN; GRANT SELECT ON ${TBL} TO diag_cap_custom;
  CREATE ROLE diag_via_custom LOGIN;   GRANT diag_cap_custom TO diag_via_custom;

  CREATE ROLE diag_tier_b NOLOGIN; GRANT TRUNCATE ON ${TBL} TO diag_tier_b;
  CREATE ROLE diag_tier_a NOLOGIN; GRANT diag_tier_b TO diag_tier_a;
  CREATE ROLE diag_transitive LOGIN; GRANT diag_tier_a TO diag_transitive;

  CREATE ROLE diag_noinh_cap NOLOGIN; GRANT REFERENCES ON ${TBL} TO diag_noinh_cap;
  CREATE ROLE diag_noinherit LOGIN NOINHERIT; GRANT diag_noinh_cap TO diag_noinherit;

  CREATE ROLE diag_owner_assumer LOGIN; GRANT scratch TO diag_owner_assumer;

  CREATE ROLE diag_bystander LOGIN;
  CREATE ROLE diag_monitor_only LOGIN; GRANT pg_monitor TO diag_monitor_only;
`;

const ROLE_TEARDOWN = `
  DROP ROLE IF EXISTS diag_direct_reader; DROP ROLE IF EXISTS diag_direct_writer;
  DROP ROLE IF EXISTS diag_read_all; DROP ROLE IF EXISTS diag_write_all;
  DROP ROLE IF EXISTS diag_via_custom; DROP ROLE IF EXISTS diag_cap_custom;
  DROP ROLE IF EXISTS diag_transitive; DROP ROLE IF EXISTS diag_tier_a; DROP ROLE IF EXISTS diag_tier_b;
  DROP ROLE IF EXISTS diag_noinherit; DROP ROLE IF EXISTS diag_noinh_cap;
  DROP ROLE IF EXISTS diag_owner_assumer; DROP ROLE IF EXISTS diag_bystander;
  DROP ROLE IF EXISTS diag_monitor_only;
`;

// ─── static contract ──────────────────────────────────────────────────────────

describe('R15.6.4 diagnostic 28 — static contract', () => {
  it('d-st1 — one REPEATABLE READ, READ ONLY transaction and no mutating SQL', () => {
    expect(DIAG_SQL).toMatch(/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;/);
    expect((DIAG_SQL.match(/^BEGIN;$/gm) ?? []).length).toBe(1);
    expect((DIAG_SQL.match(/^COMMIT;$/gm) ?? []).length).toBe(1);

    const exec = DIAG_SQL.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');
    expect(exec).not.toMatch(/^\s*(INSERT|UPDATE|DELETE|TRUNCATE|CREATE|ALTER|DROP|GRANT|REVOKE|LOCK)\b/im);
    expect(exec).not.toMatch(/\bEXECUTE\b/i);
    expect(exec).not.toMatch(/ON CONFLICT/i);
  });

  it('d-st2 — it authorizes nothing and declares no role trusted', () => {
    const exec = DIAG_SQL.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');
    expect(exec).not.toMatch(/SAFE_TO_RECORD_MIGRATION_HISTORY/);
    expect(exec).not.toMatch(/ALREADY_RECORDED_EXACTLY/);
    expect(exec).not.toMatch(/MIGRATION_20260729_HISTORY_RECONCILED/);

    // No executable construct emits a trust/authorization verdict of any kind.
    expect(exec).not.toMatch(/verdict|authoriz|trusted|whitelist/i);
  });

  it('d-st3 — candidates are catalog-derived; the three observed names are never special-cased', () => {
    const exec = DIAG_SQL.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');

    for (const observed of ['cli_login_postgres', 'supabase_etl_admin', 'supabase_read_only_user']) {
      expect(exec, `${observed} must not appear in executable SQL`).not.toContain(observed);
    }

    expect(exec).toMatch(/rolcanlogin/);
    expect(exec).toMatch(/pg_has_role\([^)]*'MEMBER'\)/);
  });

  it('d-st4 — it reads no application data, secrets, or unrelated schemas', () => {
    const exec = DIAG_SQL.split('\n')
      .filter((l) => !/^\s*--/.test(l))
      .join('\n');

    /*
     * The only non-catalog relations named are the two protected objects; the
     * pinned-owner lookup touches pg_class metadata for a public table, never its rows.
     */
    const fromTargets = [
      ...exec.replace(/IS DISTINCT FROM/gi, 'IS_DISTINCT_FROM').matchAll(/\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)/gi),
    ].map((m) => m[1].toLowerCase());
    const allowed = new Set([
      'pg_roles',
      'pg_auth_members',
      'pg_namespace',
      'pg_class',
      'pg_default_acl',
      'aclexplode',
      'privs',
      'ids',
      'cand',
      'reach',
      'hits',
      'pg_authid',
    ]);

    for (const t of fromTargets) {
      expect(allowed.has(t), `unexpected FROM/JOIN target: ${t}`).toBe(true);
    }

    expect(exec).not.toMatch(/qhub_[a-z_]*\s+(m|c|r)\b/i);
    expect(exec).not.toMatch(/auth\.users|storage\.|secrets?|token|password|credential/i);
  });

  it('d-st5 — the diagnostic hash is recorded in the analysis document', () => {
    const analysis = readFileSync(`${DIR}MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md`, 'utf8');
    expect(analysis).toContain(createHash('sha256').update(readFileSync(DIAG)).digest('hex'));
  });
});

// ─── real PostgreSQL evidence ────────────────────────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.4 diagnostic 28 — evidence on real PostgreSQL', () => {
  let out = '';
  let fpBefore = '';
  let fpAfter = '';

  beforeAll(() => {
    for (const role of ['anon NOLOGIN', 'authenticated NOLOGIN', 'service_role NOLOGIN BYPASSRLS']) {
      try {
        run(`CREATE ROLE ${role};`, 'postgres');
      } catch {
        /* exists */
      }
    }

    /*
     * Drop the database FIRST: role grants live inside it, so DROP ROLE would
     * fail on dependencies while it exists. Roles are cluster-scoped, so this
     * also clears anything a previously aborted run left behind.
     */
    try {
      run(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`, 'postgres');
    } catch {
      /* n/a */
    }

    try {
      run(ROLE_TEARDOWN, 'postgres');
    } catch {
      /* none */
    }

    run(`CREATE DATABASE ${DB};`, 'postgres');
    run(`ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`);
    execFileSync(PSQL, [...ARGS, '-d', DB, '-f', MIGRATION], { encoding: 'utf8', timeout: 300000 });
    run(`CREATE SCHEMA supabase_migrations;
      CREATE TABLE ${TBL} (version text NOT NULL PRIMARY KEY);
      ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS statements text[];
      ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS name text;
      INSERT INTO ${TBL} (version, name) VALUES ('20260723','qhub_applications');`);
    run(ROLE_FIXTURE);

    fpBefore = protectedFingerprint();
    out = runFile(DIAG);
    fpAfter = protectedFingerprint();
  }, 900_000);

  // Roles are CLUSTER-scoped: leaving them behind would corrupt other suites.
  afterAll(() => {
    try {
      run(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE);`, 'postgres');
    } catch {
      /* n/a */
    }

    try {
      run(ROLE_TEARDOWN, 'postgres');
    } catch {
      /* already gone */
    }
  }, 300_000);

  it('d1 — running the diagnostic leaves protected objects byte-equivalent', () => {
    expect(fpAfter).toBe(fpBefore);
  });

  it('d2 — QUERY 1 reports exact owners, ACLs and RLS for the protected objects only', () => {
    const [row] = resultSet(out, 'schema_name');
    expect(row.schema_name).toBe('supabase_migrations');
    expect(row.schema_owner).toBe('scratch');
    expect(row.table_owner).toBe('scratch');
    expect(row.pinned_contract_owner).toBe('scratch');
    expect(row.table_rls_enabled_forced).toBe('false/false');
    expect(row.table_relacl).toContain('diag_direct_reader');
  });

  it('d3 — QUERY 2 flags every modeled access path and no benign role', () => {
    const rows = resultSet(out, 'reaches_protected_objects');
    const reaching = new Set(rows.filter((r) => r.reaches_protected_objects === 't').map((r) => r.candidate_role));

    for (const r of [
      'diag_direct_reader',
      'diag_direct_writer',
      'diag_read_all',
      'diag_write_all',
      'diag_via_custom',
      'diag_transitive',
      'diag_noinherit',
      'diag_owner_assumer',
    ]) {
      expect(reaching.has(r), `${r} must be reported`).toBe(true);
    }

    for (const r of ['diag_bystander', 'diag_monitor_only', 'anon', 'authenticated', 'service_role']) {
      expect(reaching.has(r), `${r} must NOT be reported`).toBe(false);
    }
  });

  it('d4 — QUERY 2 reports role attributes, owner/superuser assumption and predefined reachability', () => {
    const rows = resultSet(out, 'reaches_protected_objects');
    const by = (n: string) => rows.find((r) => r.candidate_role === n)!;

    expect(by('diag_noinherit').inherits).toBe('f');
    expect(by('diag_direct_reader').inherits).toBe('t');
    expect(by('diag_owner_assumer').can_assume_pinned_owner).toBe('t');
    expect(by('diag_owner_assumer').can_assume_a_superuser).toBe('t');
    expect(by('diag_direct_reader').can_assume_pinned_owner).toBe('f');
    expect(by('diag_read_all').predefined_roles_reachable).toContain('pg_read_all_data');
    expect(by('diag_write_all').predefined_roles_reachable).toContain('pg_write_all_data');
    expect(by('diag_monitor_only').predefined_roles_reachable).toContain('pg_monitor');
    expect(by('diag_transitive').all_assumable_roles).toContain('diag_tier_b');
    expect(by('service_role').bypassrls).toBe('t');
  });

  it('d5 — QUERY 3 attributes each privilege to its exact route', () => {
    const rows = resultSet(out, 'granting_roles');
    const find = (role: string, kind: string, priv: string) =>
      rows.find((r) => r.candidate_role === role && r.object_kind === kind && r.privilege === priv);

    // Direct explicit ACL grant.
    const directSelect = find('diag_direct_reader', 'table', 'SELECT')!;
    expect(directSelect.direct_or_inherited).toBe('t');
    expect(directSelect.set_role_only).toBe('f');
    expect(directSelect.via_explicit_acl).toBe('t');
    expect(directSelect.via_predefined_role).toBe('f');

    // Predefined capability role.
    const readAll = find('diag_read_all', 'table', 'SELECT')!;
    expect(readAll.via_predefined_role).toBe('t');
    expect(readAll.via_explicit_acl).toBe('f');
    expect(readAll.granting_roles).toContain('pg_read_all_data');

    // SET-ROLE-only (NOINHERIT) path is distinguished from inherited access.
    const noinherit = find('diag_noinherit', 'table', 'REFERENCES')!;
    expect(noinherit.direct_or_inherited).toBe('f');
    expect(noinherit.set_role_only).toBe('t');
    expect(noinherit.granting_roles).toContain('diag_noinh_cap');

    // Transitive chain names every granting role.
    const transitive = find('diag_transitive', 'table', 'TRUNCATE')!;
    expect(transitive.granting_roles).toContain('diag_tier_b');

    // Ownership route.
    const owner = find('diag_owner_assumer', 'table', 'TRIGGER')!;
    expect(owner.via_owner_role).toBe('t');

    // Write privileges via pg_write_all_data.
    for (const priv of ['INSERT', 'UPDATE', 'DELETE']) {
      expect(find('diag_write_all', 'table', priv)?.via_predefined_role, priv).toBe('t');
    }

    // A benign role contributes no rows at all.
    expect(rows.some((r) => r.candidate_role === 'diag_bystander')).toBe(false);
    expect(rows.some((r) => r.candidate_role === 'diag_monitor_only')).toBe(false);
  });

  it('d6 — QUERY 4 exposes the membership edges behind each path', () => {
    const rows = resultSet(out, 'granted_role');
    const edge = (c: string, g: string) => rows.find((r) => r.candidate_role === c && r.granted_role === g);

    expect(edge('diag_read_all', 'pg_read_all_data')?.granted_role_is_predefined).toBe('t');
    expect(edge('diag_noinherit', 'diag_noinh_cap')?.usable_without_set_role).toBe('f');
    expect(edge('diag_noinherit', 'diag_noinh_cap')?.assumable_via_set_role).toBe('t');
    expect(edge('diag_via_custom', 'diag_cap_custom')?.usable_without_set_role).toBe('t');
    expect(edge('diag_owner_assumer', 'scratch')?.granted_role_is_superuser).toBe('t');
  });
});
