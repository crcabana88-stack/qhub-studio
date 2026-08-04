/**
 * QHUB R15.6.4 — READ-ONLY MANAGED-ROLE DIAGNOSTIC (28) VALIDATION, CORRECTED
 * app/test/commercial-r15-6-managed-role-diagnostic.test.ts
 *
 * The authorized live PRE 25 run returned UNEXPECTED_MIGRATION_HISTORY_STOP
 * with one failing condition and three named access paths (cli_login_postgres,
 * supabase_etl_admin, supabase_read_only_user). Diagnostic 28 collects the
 * catalog evidence a reviewer needs to judge those paths. It authorizes
 * nothing.
 *
 * INDEPENDENT-REVIEW CORRECTION. The first revision treated
 * pg_has_role(candidate, role, 'MEMBER') as proof of inheritance or SET ROLE
 * authority. PostgreSQL 16 separates these, as this suite proves against a live
 * server AND against real SET ROLE attempts:
 *
 *   membership grant              MEMBER USAGE SET  priv?  SET ROLE?
 *   INHERIT FALSE, SET FALSE        t      f     f    no     DENIED
 *   INHERIT FALSE, SET TRUE         t      f     t    no     OK
 *   INHERIT TRUE,  SET FALSE        t      t     f    yes    DENIED
 *   INHERIT TRUE,  SET TRUE         t      t     t    yes    OK
 *   ADMIN TRUE only                 t      f     f    no     DENIED
 *
 * Every reachability claim the diagnostic makes is asserted here against what
 * the server actually permits, not against pg_has_role alone.
 *
 * Harness: disposable localhost PostgreSQL (see the analysis document). The
 * suite SKIPS loudly when absent — a skip is not a pass.
 *   QHUB_SCRATCH_PG_BIN   directory containing psql.exe
 *   QHUB_SCRATCH_PG_PORT  port (default 54329)
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { acquireClusterLock, releaseClusterLock } from './helpers/pg-cluster-lock';

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
const BASE = ['-h', '127.0.0.1', '-p', PORT, '-X', '-A', '-F', '|', '-v', 'ON_ERROR_STOP=1'];
const ARGS = [...BASE, '-U', 'scratch'];
const DB = 'diag28_vitest';
const TBL = 'supabase_migrations.schema_migrations';
const NSP = 'supabase_migrations';

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

/** Execute as a specific role; report whether the server actually allowed it. */
function asRole(role: string, sql: string): { ok: boolean; message: string } {
  try {
    const out = execFileSync(PSQL, [...BASE, '-U', role, '-d', DB, '-c', sql], {
      encoding: 'utf8',
      timeout: 60000,
    });

    return { ok: true, message: out.trim() };
  } catch (e) {
    const err = e as { stderr?: string; message?: string };

    return { ok: false, message: String(err.stderr ?? err.message).split('\n')[0] };
  }
}

const scalar = (sql: string) => run(sql).split(/\r?\n/)[1]?.trim();

/** Fingerprint of everything the diagnostic reads: rows, ACLs, owners, RLS, role graph. */
const protectedFingerprint = () =>
  scalar(`SELECT md5(
     coalesce((SELECT string_agg(to_jsonb(m.*)::text, '|' ORDER BY m.version) FROM ${TBL} m), '-') || '::' ||
     coalesce((SELECT n.nspacl::text FROM pg_namespace n WHERE n.nspname = '${NSP}'), '-') || '::' ||
     coalesce((SELECT c.relacl::text FROM pg_class c WHERE c.oid = '${TBL}'::regclass), '-') || '::' ||
     (SELECT c.relowner::text || c.relrowsecurity::text FROM pg_class c WHERE c.oid = '${TBL}'::regclass) || '::' ||
     (SELECT n.nspowner::text FROM pg_namespace n WHERE n.nspname = '${NSP}') || '::' ||
     coalesce((SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles), '-') || '::' ||
     coalesce((SELECT string_agg(member::text || roleid::text || admin_option::text
                                 || inherit_option::text || set_option::text, ',' ORDER BY member, roleid)
                 FROM pg_auth_members), '-'));`);

interface Row {
  [k: string]: string;
}

/** Parse the psql result set whose header contains a column unique to that set. */
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

/**
 * The full adversarial fixture. Case numbers match the correction brief.
 * cap_read/cap_write hold real privileges; the membership OPTIONS vary.
 */
const ROLE_FIXTURE = `
  CREATE ROLE cap_read NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO cap_read;
  GRANT SELECT ON ${TBL} TO cap_read;
  -- schema USAGE is required alongside INSERT for a real write to succeed
  CREATE ROLE cap_write NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO cap_write;
  GRANT INSERT ON ${TBL} TO cap_write;

  -- case 1: INHERIT false, SET false  -> inactive membership
  CREATE ROLE c1_none LOGIN;    GRANT cap_read TO c1_none    WITH INHERIT FALSE, SET FALSE;
  -- case 2: INHERIT false, SET true   -> set-role-only
  CREATE ROLE c2_setonly LOGIN; GRANT cap_read TO c2_setonly WITH INHERIT FALSE, SET TRUE;
  -- case 3: INHERIT true, SET false   -> inherited, never settable
  CREATE ROLE c3_inhonly LOGIN; GRANT cap_read TO c3_inhonly WITH INHERIT TRUE,  SET FALSE;
  -- case 4/5: owner (also the superuser here) membership with SET disabled
  CREATE ROLE c4_owner_noset LOGIN; GRANT scratch TO c4_owner_noset WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c5_super_noset LOGIN; GRANT scratch TO c5_super_noset WITH INHERIT FALSE, SET FALSE;
  -- case 6: ADMIN true, INHERIT/SET false
  CREATE ROLE c6_admin_only LOGIN; GRANT cap_read TO c6_admin_only WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
  -- case 7: transitive with an intermediate role (all options on)
  CREATE ROLE c7_mid NOLOGIN;   GRANT cap_write TO c7_mid   WITH INHERIT TRUE, SET TRUE;
  CREATE ROLE c7_login LOGIN;   GRANT c7_mid TO c7_login    WITH INHERIT TRUE, SET TRUE;
  -- case 7b: transitive where the SECOND edge blocks inheritance and SET
  CREATE ROLE c7b_mid NOLOGIN;  GRANT cap_read TO c7b_mid   WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c7b_login LOGIN;  GRANT c7b_mid TO c7b_login  WITH INHERIT TRUE, SET TRUE;
  -- case 8: two conflicting paths to the same capability
  CREATE ROLE c8_alt NOLOGIN;   GRANT cap_read TO c8_alt    WITH INHERIT TRUE, SET TRUE;
  CREATE ROLE c8_login LOGIN;
  GRANT cap_read TO c8_login WITH INHERIT FALSE, SET FALSE;
  GRANT c8_alt   TO c8_login WITH INHERIT TRUE,  SET TRUE;
  -- case 9: direct self privileges
  CREATE ROLE c9_direct LOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO c9_direct;
  GRANT SELECT, UPDATE ON ${TBL} TO c9_direct;
  -- case 10: predefined roles with differing options
  CREATE ROLE c10_read_inh LOGIN;  GRANT pg_read_all_data  TO c10_read_inh  WITH INHERIT TRUE,  SET FALSE;
  CREATE ROLE c10_read_set LOGIN;  GRANT pg_read_all_data  TO c10_read_set  WITH INHERIT FALSE, SET TRUE;
  CREATE ROLE c10_read_none LOGIN; GRANT pg_read_all_data  TO c10_read_none WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c10_write_inh LOGIN; GRANT pg_write_all_data TO c10_write_inh WITH INHERIT TRUE,  SET FALSE;
  -- case 12: role validity
  CREATE ROLE c12_never LOGIN;
  CREATE ROLE c12_future LOGIN VALID UNTIL '2099-01-01';
  CREATE ROLE c12_expired LOGIN VALID UNTIL '2000-01-01';
  -- benign controls
  CREATE ROLE z_bystander LOGIN;
  CREATE ROLE z_monitor LOGIN; GRANT pg_monitor TO z_monitor WITH INHERIT TRUE, SET TRUE;
`;

const FIXTURE_ROLES = [
  'c1_none',
  'c2_setonly',
  'c3_inhonly',
  'c4_owner_noset',
  'c5_super_noset',
  'c6_admin_only',
  'c7_login',
  'c7_mid',
  'c7b_login',
  'c7b_mid',
  'c8_login',
  'c8_alt',
  'c9_direct',
  'c10_read_inh',
  'c10_read_set',
  'c10_read_none',
  'c10_write_inh',
  'c12_never',
  'c12_future',
  'c12_expired',
  'z_bystander',
  'z_monitor',
  'cap_read',
  'cap_write',
];

const ROLE_TEARDOWN = FIXTURE_ROLES.map((r) => `DROP ROLE IF EXISTS ${r};`).join('\n');

// ─── static contract ──────────────────────────────────────────────────────────

describe('R15.6.4 diagnostic 28 — static contract', () => {
  const exec = DIAG_SQL.split('\n')
    .filter((l) => !/^\s*--/.test(l))
    .join('\n');

  it('d-st1 — one REPEATABLE READ, READ ONLY transaction and no mutating or dynamic SQL', () => {
    expect(DIAG_SQL).toMatch(/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;/);
    expect((DIAG_SQL.match(/^BEGIN;$/gm) ?? []).length).toBe(1);
    expect((DIAG_SQL.match(/^COMMIT;$/gm) ?? []).length).toBe(1);
    expect(exec).not.toMatch(/^\s*(INSERT|UPDATE|DELETE|TRUNCATE|CREATE|ALTER|DROP|GRANT|REVOKE|LOCK)\b/im);
    expect(exec).not.toMatch(/\bEXECUTE\b/i);
    expect(exec).not.toMatch(/\bDO\s*\$/i);
    expect(exec).not.toMatch(/ON CONFLICT/i);
  });

  it('d-st2 — it authorizes nothing and declares no role trusted', () => {
    expect(exec).not.toMatch(/SAFE_TO_RECORD_MIGRATION_HISTORY/);
    expect(exec).not.toMatch(/ALREADY_RECORDED_EXACTLY/);
    expect(exec).not.toMatch(/MIGRATION_20260729_HISTORY_RECONCILED/);
    expect(exec).not.toMatch(/verdict|authoriz|trusted|whitelist/i);
  });

  it('d-st3 — candidates are catalog-derived; the three observed names are never special-cased', () => {
    for (const observed of ['cli_login_postgres', 'supabase_etl_admin', 'supabase_read_only_user']) {
      expect(exec, `${observed} must not appear in executable SQL`).not.toContain(observed);
    }

    expect(exec).toMatch(/rolcanlogin/);
  });

  it('d-st4 — MEMBER is never used as proof of inheritance or SET ROLE authority', () => {
    /*
     * Every MEMBER test must be paired with explicit NOT USAGE / NOT SET, i.e.
     * MEMBER is only ever used to classify an INACTIVE membership.
     */
    const memberUses = [...exec.matchAll(/pg_has_role\([^)]*'MEMBER'\)/g)];
    expect(memberUses.length).toBeGreaterThan(0);

    for (const m of memberUses) {
      const window = exec.slice(m.index!, m.index! + 400);

      /*
       * A MEMBER test is legitimate in exactly two shapes: labelled raw
       * membership evidence (authoritative_member / inactive_membership_*), or
       * an inactive-membership classification explicitly qualified by NOT USAGE
       * and NOT SET. It is never allowed to stand alone as reachability.
       */
      const isLabelledEvidence = /AS\s+(authoritative_member|inactive_membership_of_pinned_owner)\b/.test(
        window.slice(0, 120),
      );

      if (!isLabelledEvidence) {
        expect(window, 'MEMBER must be qualified by NOT USAGE and NOT SET').toMatch(/NOT pg_has_role\([^)]*'USAGE'\)/);
        expect(window).toMatch(/NOT pg_has_role\([^)]*'SET'\)/);
      }
    }

    // The misleading "assumable" vocabulary is gone.
    expect(exec).not.toMatch(/all_assumable_roles|assumable_via_set_role/);
    expect(exec).toMatch(/roles_settable_via_set_role/);
    expect(exec).toMatch(/roles_inactive_membership_only/);
  });

  it('d-st5 — admin_option is reported but never used in a reachability predicate', () => {
    expect(exec).toMatch(/admin_option/);
    expect(exec).not.toMatch(/admin_option\s+AND/i);
    expect(exec).not.toMatch(/AND\s+\w*\.?admin_option/i);
  });

  it('d-st6 — it reads no application data, secrets, or unrelated schemas', () => {
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
      'holder',
      'routed',
      'holds',
      'paths',
    ]);

    for (const t of fromTargets) {
      expect(allowed.has(t), `unexpected FROM/JOIN target: ${t}`).toBe(true);
    }

    expect(exec).not.toMatch(/rolpassword|auth\.users|storage\.|secrets?|token|credential/i);
  });

  it('d-st7 — the diagnostic hash is recorded in the analysis document', () => {
    const analysis = readFileSync(`${DIR}MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md`, 'utf8');
    expect(analysis).toContain(createHash('sha256').update(readFileSync(DIAG)).digest('hex'));
  });
});

// ─── real PostgreSQL 16 adversarial evidence ─────────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.4 diagnostic 28 — PostgreSQL 16 adversarial evidence', () => {
  let out = '';
  let outPublic = '';
  let fpBefore = '';
  let fpAfter = '';
  let candidates: Row[] = [];
  let routes: Row[] = [];
  let paths: Row[] = [];
  let acls: Row[] = [];
  let aclsPublic: Row[] = [];
  let routesPublic: Row[] = [];

  const cand = (n: string) => candidates.find((r) => r.candidate_role === n)!;
  const route = (n: string, kind: string, priv: string) =>
    routes.find((r) => r.candidate_role === n && r.object_kind === kind && r.privilege === priv);

  beforeAll(async () => {
    /*
     * Roles are cluster-scoped: this suite's fixture roles would otherwise be
     * visible as unauthorized access paths inside a sibling suite's database.
     */
    await acquireClusterLock();

    for (const role of ['anon NOLOGIN', 'authenticated NOLOGIN', 'service_role NOLOGIN BYPASSRLS']) {
      try {
        run(`CREATE ROLE ${role};`, 'postgres');
      } catch {
        /* exists */
      }
    }

    // Database first: role grants live inside it, so DROP ROLE would fail while it exists.
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
    run(`CREATE SCHEMA ${NSP};
      CREATE TABLE ${TBL} (version text NOT NULL PRIMARY KEY);
      ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS statements text[];
      ALTER TABLE ${TBL} ADD COLUMN IF NOT EXISTS name text;
      INSERT INTO ${TBL} (version, name) VALUES ('20260723','qhub_applications');`);
    run(ROLE_FIXTURE);

    fpBefore = protectedFingerprint();
    out = runFile(DIAG);
    fpAfter = protectedFingerprint();

    /*
     * Case 11 is captured separately: a PUBLIC grant confers real access on
     * EVERY role, which would mask the per-membership cases above.
     */
    run(`GRANT REFERENCES ON ${TBL} TO PUBLIC;`);
    outPublic = runFile(DIAG);
    run(`REVOKE REFERENCES ON ${TBL} FROM PUBLIC;`);

    candidates = resultSet(out, 'reaches_protected_objects');
    routes = resultSet(out, 'usable_without_set_role');
    paths = resultSet(out, 'path_permits_set_role');
    acls = resultSet(out, 'grantee_is_public');
    aclsPublic = resultSet(outPublic, 'grantee_is_public');
    routesPublic = resultSet(outPublic, 'usable_without_set_role');
  }, 900_000);

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

    releaseClusterLock();
  }, 300_000);

  it('d0 — the diagnostic mutates nothing: protected objects and role graph byte-equivalent', () => {
    expect(fpAfter).toBe(fpBefore);
    expect(candidates.length).toBeGreaterThan(0);
    expect(paths.length).toBeGreaterThan(0);
    expect(routes.length).toBeGreaterThan(0);
    expect(acls.length).toBeGreaterThan(0);
  });

  it('case 1 — INHERIT false / SET false: MEMBER only, no privilege, SET ROLE actually DENIED', () => {
    expect(scalar(`SELECT pg_has_role('c1_none','cap_read','MEMBER');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('c1_none','cap_read','USAGE');`)).toBe('f');
    expect(scalar(`SELECT pg_has_role('c1_none','cap_read','SET');`)).toBe('f');
    expect(asRole('c1_none', 'SET ROLE cap_read;').ok, 'server must deny SET ROLE').toBe(false);
    expect(asRole('c1_none', `SELECT count(*) FROM ${TBL};`).ok, 'server must deny SELECT').toBe(false);

    const c = cand('c1_none');
    expect(c.privileges_usable_without_set_role).toBe('f');
    expect(c.privileges_via_set_role).toBe('f');
    expect(c.reaches_protected_objects, 'inactive membership is NOT access').toBe('f');
    expect(c.roles_settable_via_set_role).toBe('{}');
    expect(c.roles_inactive_membership_only).toContain('cap_read');
    expect(c.inactive_memberships_with_access).toContain('cap_read');

    const r = route('c1_none', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('f');
    expect(r.inactive_membership_only).toBe('t');
    expect(r.inactive_membership_roles).toContain('cap_read');
  });

  it('case 2 — INHERIT false / SET true: no inherited privilege, SET ROLE actually SUCCEEDS', () => {
    expect(scalar(`SELECT pg_has_role('c2_setonly','cap_read','USAGE');`)).toBe('f');
    expect(scalar(`SELECT pg_has_role('c2_setonly','cap_read','SET');`)).toBe('t');
    expect(asRole('c2_setonly', 'SET ROLE cap_read;').ok, 'server must allow SET ROLE').toBe(true);
    expect(asRole('c2_setonly', `SELECT count(*) FROM ${TBL};`).ok, 'no access before SET ROLE').toBe(false);
    expect(asRole('c2_setonly', `SET ROLE cap_read; SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    const c = cand('c2_setonly');
    expect(c.privileges_usable_without_set_role).toBe('f');
    expect(c.privileges_via_set_role).toBe('t');
    expect(c.reaches_protected_objects).toBe('t');
    expect(c.roles_settable_via_set_role).toContain('cap_read');

    const r = route('c2_setonly', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('t');
    expect(r.settable_roles).toContain('cap_read');
  });

  it('case 3 — INHERIT true / SET false: privilege usable without SET ROLE, SET ROLE actually DENIED', () => {
    expect(scalar(`SELECT pg_has_role('c3_inhonly','cap_read','USAGE');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('c3_inhonly','cap_read','SET');`)).toBe('f');
    expect(asRole('c3_inhonly', 'SET ROLE cap_read;').ok, 'server must deny SET ROLE').toBe(false);
    expect(asRole('c3_inhonly', `SELECT count(*) FROM ${TBL};`).ok, 'privilege inherited').toBe(true);

    const c = cand('c3_inhonly');
    expect(c.privileges_usable_without_set_role).toBe('t');
    expect(c.reaches_protected_objects).toBe('t');
    expect(c.roles_settable_via_set_role, 'never described as settable').toBe('{}');
    expect(c.roles_inherited_from).toContain('cap_read');

    const r = route('c3_inhonly', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('t');
    expect(r.reachable_via_set_role).toBe('f');
    expect(r.inheriting_roles).toContain('cap_read');
    expect(r.settable_roles).toBe('{}');
  });

  it('case 4 — owner membership with SET disabled: no owner-assumption flag, SET ROLE DENIED', () => {
    expect(asRole('c4_owner_noset', 'SET ROLE scratch;').ok).toBe(false);

    const c = cand('c4_owner_noset');
    expect(c.can_set_role_to_pinned_owner).toBe('f');
    expect(c.inherits_from_pinned_owner).toBe('f');
    expect(c.inactive_membership_of_pinned_owner, 'membership still visible as evidence').toBe('t');
    expect(c.reaches_protected_objects).toBe('f');
  });

  it('case 5 — superuser membership with SET disabled: no superuser-assumption flag, SET ROLE DENIED', () => {
    expect(asRole('c5_super_noset', 'SET ROLE scratch;').ok).toBe(false);

    const c = cand('c5_super_noset');
    expect(c.can_set_role_to_a_superuser).toBe('f');
    expect(c.inherits_from_a_superuser).toBe('f');
    expect(c.reaches_protected_objects).toBe('f');
  });

  it('case 6 — ADMIN true with INHERIT/SET false: no privilege and no assumption authority', () => {
    expect(scalar(`SELECT pg_has_role('c6_admin_only','cap_read','MEMBER');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('c6_admin_only','cap_read','USAGE');`)).toBe('f');
    expect(scalar(`SELECT pg_has_role('c6_admin_only','cap_read','SET');`)).toBe('f');
    expect(asRole('c6_admin_only', 'SET ROLE cap_read;').ok).toBe(false);
    expect(asRole('c6_admin_only', `SELECT count(*) FROM ${TBL};`).ok).toBe(false);

    const c = cand('c6_admin_only');
    expect(c.reaches_protected_objects).toBe('f');
    expect(c.roles_inactive_membership_only).toContain('cap_read');

    const edge = paths.find((p) => p.candidate_role === 'c6_admin_only' && p.edge_granted_role === 'cap_read')!;
    expect(edge.edge_admin_option).toBe('t');
    expect(edge.path_permits_inheritance).toBe('f');
    expect(edge.path_permits_set_role).toBe('f');
  });

  it('case 7 — transitive paths: intermediate roles reported, options compose along the path', () => {
    expect(asRole('c7_login', `INSERT INTO ${TBL} (version) VALUES ('probe7');`).ok).toBe(true);
    run(`DELETE FROM ${TBL} WHERE version = 'probe7';`);

    const c7 = cand('c7_login');
    expect(c7.privileges_usable_without_set_role).toBe('t');
    expect(c7.roles_inherited_from).toContain('cap_write');

    const deep = paths.filter((p) => p.candidate_role === 'c7_login' && p.path_depth === '2');
    expect(deep.length).toBeGreaterThan(0);
    expect(deep[0].path).toContain('c7_mid');
    expect(deep[0].path_permits_inheritance).toBe('t');

    // Chain blocked at the second edge: membership exists, access does not.
    expect(asRole('c7b_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(false);
    expect(asRole('c7b_login', 'SET ROLE cap_read;').ok).toBe(false);

    const c7b = cand('c7b_login');
    expect(c7b.reaches_protected_objects).toBe('f');
    expect(c7b.roles_inactive_membership_only).toContain('cap_read');

    const blocked = paths.find(
      (p) => p.candidate_role === 'c7b_login' && p.edge_granted_role === 'cap_read' && p.path_depth === '2',
    )!;
    expect(blocked.path_permits_inheritance).toBe('f');
    expect(blocked.path_permits_set_role).toBe('f');
    expect(blocked.authoritative_member).toBe('t');
    expect(blocked.authoritative_usage).toBe('f');
    expect(blocked.authoritative_set).toBe('f');
  });

  it('case 8 — conflicting paths are reported separately, not collapsed into one boolean', () => {
    const toCapRead = paths.filter((p) => p.candidate_role === 'c8_login' && p.edge_granted_role === 'cap_read');
    expect(toCapRead.length, 'both the direct and the via-c8_alt path must appear').toBeGreaterThanOrEqual(2);

    const direct = toCapRead.find((p) => p.path_depth === '1')!;
    const viaAlt = toCapRead.find((p) => p.path_depth === '2')!;
    expect(direct.path_permits_inheritance).toBe('f');
    expect(direct.path_permits_set_role).toBe('f');
    expect(viaAlt.path).toContain('c8_alt');
    expect(viaAlt.path_permits_inheritance).toBe('t');
    expect(viaAlt.path_permits_set_role).toBe('t');

    // The live server agrees the active path wins.
    expect(asRole('c8_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);
    expect(asRole('c8_login', 'SET ROLE cap_read;').ok).toBe(true);
    expect(cand('c8_login').privileges_usable_without_set_role).toBe('t');
  });

  it('case 9 — direct self privileges are attributed to the candidate itself and to the ACL', () => {
    const r = route('c9_direct', 'table', 'UPDATE')!;
    expect(r.usable_without_set_role).toBe('t');
    expect(r.held_directly_or_inherited_by_self).toBe('t');
    expect(r.inheriting_roles).toContain('c9_direct');
    expect(r.via_explicit_acl).toBe('t');
    expect(asRole('c9_direct', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);
  });

  it('case 10 — predefined capability roles split by INHERIT/SET; a blocked one confers nothing', () => {
    expect(cand('c10_read_inh').predefined_roles_inherited).toContain('pg_read_all_data');
    expect(cand('c10_read_inh').predefined_roles_settable).toBe('{}');
    expect(route('c10_read_inh', 'table', 'SELECT')!.via_predefined_role_inherited).toBe('t');
    expect(asRole('c10_read_inh', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);
    expect(asRole('c10_read_inh', 'SET ROLE pg_read_all_data;').ok).toBe(false);

    expect(cand('c10_read_set').predefined_roles_settable).toContain('pg_read_all_data');
    expect(cand('c10_read_set').privileges_usable_without_set_role).toBe('f');
    expect(cand('c10_read_set').privileges_via_set_role).toBe('t');
    expect(asRole('c10_read_set', 'SET ROLE pg_read_all_data;').ok).toBe(true);

    expect(cand('c10_read_none').predefined_roles_inactive_membership).toContain('pg_read_all_data');
    expect(asRole('c10_read_none', 'SET ROLE pg_read_all_data;').ok).toBe(false);

    expect(route('c10_write_inh', 'table', 'INSERT')!.via_predefined_role_inherited).toBe('t');
  });

  it('case 11 — structured ACL evidence: grantee, grantor, privilege, grantability, PUBLIC', () => {
    // The PUBLIC-grant capture; the baseline capture has no PUBLIC entry at all.
    expect(
      acls.some((a) => a.grantee_is_public === 't'),
      'baseline has no PUBLIC grant',
    ).toBe(false);

    const pub = aclsPublic.find((a) => a.grantee_is_public === 't' && a.privilege_type === 'REFERENCES')!;
    expect(pub.object_type).toBe('table');
    expect(pub.object_identity).toBe(TBL);
    expect(pub.grantee_oid).toBe('0');
    expect(pub.grantor_name).toBe('scratch');
    expect(pub.is_grantable).toBe('f');

    const schemaAcl = acls.find((a) => a.object_type === 'schema' && a.grantee_name === 'cap_read')!;
    expect(schemaAcl.privilege_type).toBe('USAGE');
    expect(schemaAcl.grantor_name).toBe('scratch');

    const tableAcl = acls.find((a) => a.object_type === 'table' && a.grantee_name === 'c9_direct')!;
    expect(['SELECT', 'UPDATE']).toContain(tableAcl.privilege_type);

    // PUBLIC attribution also surfaces in the route evidence for every role.
    const bystanderRef = routesPublic.find(
      (r) => r.candidate_role === 'z_bystander' && r.object_kind === 'table' && r.privilege === 'REFERENCES',
    )!;
    expect(bystanderRef.via_public_grant).toBe('t');
    expect(bystanderRef.usable_without_set_role).toBe('t');
  });

  it('case 12 — role validity is exact: NULL, future and expired are distinguished', () => {
    const never = cand('c12_never');
    expect(never.rolvaliduntil).toBe('(null)');
    expect(never.never_expires).toBe('t');
    expect(never.currently_valid).toBe('t');
    expect(never.expired).toBe('f');

    const future = cand('c12_future');
    expect(future.rolvaliduntil).toContain('2099');
    expect(future.never_expires).toBe('f');
    expect(future.currently_valid).toBe('t');
    expect(future.expired).toBe('f');

    const expired = cand('c12_expired');
    expect(expired.rolvaliduntil).toContain('2000');
    expect(expired.currently_valid).toBe('f');
    expect(expired.expired).toBe('t');
    expect(expired.can_login).toBe('t');
  });

  it('d-final — path evidence never claims more than PostgreSQL allows', () => {
    for (const p of paths) {
      if (p.path_permits_inheritance === 't') {
        expect(p.authoritative_usage, `path claims inheritance: ${p.path}`).toBe('t');
      }

      if (p.path_permits_set_role === 't') {
        expect(p.authoritative_set, `path claims SET ROLE: ${p.path}`).toBe('t');
      }
    }

    /*
     * Benign controls hold nothing in the baseline capture: a role with no
     * grants, and a role whose only membership (pg_monitor) carries no data
     * privileges, are never reported as reaching the protected objects.
     */
    for (const benign of ['z_bystander', 'z_monitor', 'anon', 'authenticated', 'service_role', 'c12_never']) {
      const c = candidates.find((r) => r.candidate_role === benign);
      expect(c, `${benign} must appear in the inventory`).toBeDefined();
      expect(c!.reaches_protected_objects, `${benign} must not be reported as reaching`).toBe('f');
    }
  });
});
