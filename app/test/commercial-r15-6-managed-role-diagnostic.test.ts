/**
 * QHUB R15.6.5 — READ-ONLY MANAGED-ROLE DIAGNOSTIC (28) VALIDATION
 * app/test/commercial-r15-6-managed-role-diagnostic.test.ts
 *
 * The authorized live PRE 25 run returned UNEXPECTED_MIGRATION_HISTORY_STOP
 * with one failing condition and three named access paths (cli_login_postgres,
 * supabase_etl_admin, supabase_read_only_user). Diagnostic 28 collects the
 * catalog evidence a reviewer needs to judge those paths. It authorizes
 * nothing.
 *
 * R15.6.4 CORRECTION (retained): MEMBER != USAGE != SET on PostgreSQL 16.
 *
 *   membership grant              MEMBER USAGE SET  priv?  SET ROLE?
 *   INHERIT FALSE, SET FALSE        t      f     f    no     DENIED
 *   INHERIT FALSE, SET TRUE         t      f     t    no     OK
 *   INHERIT TRUE,  SET FALSE        t      t     f    yes    DENIED
 *   INHERIT TRUE,  SET TRUE         t      t     t    yes    OK
 *   ADMIN TRUE only                 t      f     f    no     DENIED
 *
 * R15.6.5 CORRECTIONS (this revision, after the second independent review):
 *   P1-1  the membership-path recursion silently truncated at depth 16, so a
 *         valid 17-edge route with full USAGE/SET authority vanished from the
 *         path output. The cutoff is removed; recursion terminates only
 *         through cycle prevention, and depths 15/16/17/20 are proven here.
 *   P1-2  via_explicit_acl could be true for an ACL held by an UNREACHABLE
 *         holder (inactive MEMBER-only membership). Attribution is now
 *         reachability-gated (self / USAGE / SET), inactive ACL evidence is a
 *         separate field, inactive_membership_only is never true when an
 *         active route coexists, and owner attribution compares against the
 *         ACTUAL owner of each object rather than the pinned contract owner.
 *
 * Every reachability claim the diagnostic makes is asserted against what the
 * server actually permits — real connections AS the candidate role (genuine
 * session_user, not a superuser-backed session), real privilege checks before
 * and after SET ROLE, and real SET ROLE success or denial.
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

/**
 * Execute AS a specific role over a genuine connection: psql authenticates as
 * that LOGIN role, so session_user is the candidate and nothing is backed by
 * the harness superuser. Reports whether the server actually allowed it.
 */
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
                                 || inherit_option::text || set_option::text || grantor::text, ',' ORDER BY member, roleid, grantor)
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

const DEEP = Array.from({ length: 20 }, (_, i) => `dp_r${String(i + 1).padStart(2, '0')}`);

/**
 * The full adversarial fixture. Case numbers match the correction brief.
 * cap_* roles hold real privileges; the membership OPTIONS vary per candidate.
 * own_schema / own_table / oc_selfown own NOTHING in the baseline capture —
 * they receive ownership only inside the dedicated owner-attribution captures.
 */
const ROLE_FIXTURE = `
  CREATE ROLE cap_read NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO cap_read;
  GRANT SELECT ON ${TBL} TO cap_read;
  -- schema USAGE is required alongside INSERT for a real write to succeed
  CREATE ROLE cap_write NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO cap_write;
  GRANT INSERT ON ${TBL} TO cap_write;

  -- matrix 1: INHERIT false, SET false  -> inactive membership
  CREATE ROLE c1_none LOGIN;    GRANT cap_read TO c1_none    WITH INHERIT FALSE, SET FALSE;
  -- matrix 2: INHERIT false, SET true   -> set-role-only
  CREATE ROLE c2_setonly LOGIN; GRANT cap_read TO c2_setonly WITH INHERIT FALSE, SET TRUE;
  -- matrix 3: INHERIT true, SET false   -> inherited, never settable
  CREATE ROLE c3_inhonly LOGIN; GRANT cap_read TO c3_inhonly WITH INHERIT TRUE,  SET FALSE;
  -- matrix 5/7: owner (also a superuser here) membership with SET disabled
  CREATE ROLE c4_owner_noset LOGIN; GRANT scratch TO c4_owner_noset WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c5_super_noset LOGIN; GRANT scratch TO c5_super_noset WITH INHERIT FALSE, SET FALSE;
  -- matrix 6: owner membership with SET enabled (pinned owner is scratch here)
  CREATE ROLE c4b_owner_set LOGIN; GRANT scratch TO c4b_owner_set WITH INHERIT FALSE, SET TRUE;
  -- matrix 9: ADMIN true, INHERIT/SET false
  CREATE ROLE c6_admin_only LOGIN; GRANT cap_read TO c6_admin_only WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
  -- matrix 11: transitive with an intermediate role (all options on)
  CREATE ROLE c7_mid NOLOGIN;   GRANT cap_write TO c7_mid   WITH INHERIT TRUE, SET TRUE;
  CREATE ROLE c7_login LOGIN;   GRANT c7_mid TO c7_login    WITH INHERIT TRUE, SET TRUE;
  -- transitive where the SECOND edge blocks inheritance and SET
  CREATE ROLE c7b_mid NOLOGIN;  GRANT cap_read TO c7b_mid   WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c7b_login LOGIN;  GRANT c7b_mid TO c7b_login  WITH INHERIT TRUE, SET TRUE;
  -- matrix 12: two conflicting paths to the same capability
  CREATE ROLE c8_alt NOLOGIN;   GRANT cap_read TO c8_alt    WITH INHERIT TRUE, SET TRUE;
  CREATE ROLE c8_login LOGIN;
  GRANT cap_read TO c8_login WITH INHERIT FALSE, SET FALSE;
  GRANT c8_alt   TO c8_login WITH INHERIT TRUE,  SET TRUE;
  -- matrix 10: direct self privileges
  CREATE ROLE c9_direct LOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO c9_direct;
  GRANT SELECT, UPDATE ON ${TBL} TO c9_direct;
  -- matrix 15-20: predefined capability roles with differing options
  CREATE ROLE c10_read_inh LOGIN;   GRANT pg_read_all_data  TO c10_read_inh   WITH INHERIT TRUE,  SET FALSE;
  CREATE ROLE c10_read_set LOGIN;   GRANT pg_read_all_data  TO c10_read_set   WITH INHERIT FALSE, SET TRUE;
  CREATE ROLE c10_read_none LOGIN;  GRANT pg_read_all_data  TO c10_read_none  WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE c10_write_inh LOGIN;  GRANT pg_write_all_data TO c10_write_inh  WITH INHERIT TRUE,  SET FALSE;
  CREATE ROLE c10_write_set LOGIN;  GRANT pg_write_all_data TO c10_write_set  WITH INHERIT FALSE, SET TRUE;
  CREATE ROLE c10_write_none LOGIN; GRANT pg_write_all_data TO c10_write_none WITH INHERIT FALSE, SET FALSE;
  -- matrix 32: role validity - expiry bounds PASSWORD AUTH ONLY, so the
  -- expired role deliberately keeps real catalog authority
  CREATE ROLE c12_never LOGIN;
  CREATE ROLE c12_future LOGIN VALID UNTIL '2099-01-01';
  CREATE ROLE c12_expired LOGIN VALID UNTIL '2000-01-01';
  GRANT cap_read TO c12_expired;
  -- matrix 28/29: benign controls
  CREATE ROLE z_bystander LOGIN;
  CREATE ROLE z_monitor LOGIN; GRANT pg_monitor TO z_monitor WITH INHERIT TRUE, SET TRUE;

  -- all nine privileges through one custom capability role
  CREATE ROLE cap_all NOLOGIN;
  GRANT USAGE, CREATE ON SCHEMA ${NSP} TO cap_all;
  GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ${TBL} TO cap_all;
  CREATE ROLE all_login LOGIN; GRANT cap_all TO all_login;

  -- P1-1 (matrix 13/14): a 20-edge membership chain; only the terminal role
  -- holds real access. Every prefix is a distinct path (depths 1..20).
  ${DEEP.map((r) => `CREATE ROLE ${r} NOLOGIN;`).join('\n  ')}
  GRANT USAGE ON SCHEMA ${NSP} TO ${DEEP[19]};
  GRANT SELECT ON ${TBL} TO ${DEEP[19]};
  ${DEEP.slice(0, 19)
    .map((r, i) => `GRANT ${DEEP[i + 1]} TO ${r};`)
    .join('\n  ')}
  CREATE ROLE dp_login LOGIN; GRANT ${DEEP[0]} TO dp_login;
  -- multiple paths to the same terminal where one is deeper than 16
  CREATE ROLE mp_login LOGIN; GRANT ${DEEP[0]} TO mp_login; GRANT ${DEEP[19]} TO mp_login;

  -- P1-2 (matrix 22/23/27): one explicit-ACL holder reachable three ways
  CREATE ROLE aclh NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO aclh;
  GRANT SELECT ON ${TBL} TO aclh;
  CREATE ROLE ac_inh LOGIN;   GRANT aclh TO ac_inh   WITH INHERIT TRUE,  SET FALSE;
  CREATE ROLE ac_set LOGIN;   GRANT aclh TO ac_set   WITH INHERIT FALSE, SET TRUE;
  CREATE ROLE ac_inact LOGIN; GRANT aclh TO ac_inact WITH INHERIT FALSE, SET FALSE;

  -- matrix 25/26: WITH GRANT OPTION + a second, distinct grantor.
  -- granter2 must be a NON-superuser: a GRANT issued while SET ROLE to a
  -- superuser is recorded with the OBJECT OWNER as grantor, so a superuser
  -- can never produce a distinct grantor (proven on PG16).
  CREATE ROLE wg_holder NOLOGIN;
  GRANT SELECT ON ${TBL} TO wg_holder WITH GRANT OPTION;
  CREATE ROLE granter2 NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO granter2;
  GRANT UPDATE ON ${TBL} TO granter2 WITH GRANT OPTION;
  GRANT cap_read TO granter2 WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
  SET ROLE granter2;
  GRANT UPDATE ON ${TBL} TO wg_holder;
  RESET ROLE;

  -- matrix 33a: active + inactive membership paths to the SAME holder
  -- (separate grants require distinct grantors - PG16 keys memberships on
  -- roleid, member, grantor)
  CREATE ROLE dual_login LOGIN;
  GRANT cap_read TO dual_login WITH INHERIT TRUE, SET FALSE;
  SET ROLE granter2;
  GRANT cap_read TO dual_login WITH INHERIT FALSE, SET FALSE;
  RESET ROLE;

  -- matrix 33b: active + inactive paths to DIFFERENT holders, same privilege
  CREATE ROLE cap_read2 NOLOGIN;
  GRANT USAGE ON SCHEMA ${NSP} TO cap_read2;
  GRANT SELECT ON ${TBL} TO cap_read2;
  CREATE ROLE mix_login LOGIN;
  GRANT cap_read  TO mix_login WITH INHERIT TRUE,  SET FALSE;
  GRANT cap_read2 TO mix_login WITH INHERIT FALSE, SET FALSE;

  -- matrix 34: explicit ACL + predefined-role access on the same candidate
  CREATE ROLE combo_login LOGIN;
  GRANT pg_read_all_data TO combo_login WITH INHERIT TRUE, SET FALSE;
  GRANT USAGE ON SCHEMA ${NSP} TO combo_login;
  GRANT SELECT ON ${TBL} TO combo_login;

  -- matrix 7/8: genuine-session superuser SET ROLE fixtures
  CREATE ROLE su_target SUPERUSER NOLOGIN;
  CREATE ROLE su_set LOGIN;   GRANT su_target TO su_set   WITH INHERIT FALSE, SET TRUE;
  CREATE ROLE su_noset LOGIN; GRANT su_target TO su_noset WITH INHERIT FALSE, SET FALSE;

  -- matrix 31: actual-owner attribution roles (own nothing in the baseline)
  CREATE ROLE own_schema NOLOGIN;
  CREATE ROLE own_table NOLOGIN;
  CREATE ROLE oc_inh_s LOGIN;   GRANT own_schema TO oc_inh_s;
  CREATE ROLE oc_inh_t LOGIN;   GRANT own_table  TO oc_inh_t;
  CREATE ROLE oc_set_t LOGIN;   GRANT own_table  TO oc_set_t  WITH INHERIT FALSE, SET TRUE;
  GRANT SELECT ON ${TBL} TO oc_set_t;
  CREATE ROLE oc_inact_t LOGIN; GRANT own_table  TO oc_inact_t WITH INHERIT FALSE, SET FALSE;
  CREATE ROLE oc_selfown LOGIN;
`;

/**
 * Teardown order matters: member/login roles first (dropping a member removes
 * its membership grants), capability/target roles next, and granter2 LAST -
 * PG16 records it as grantor of the duplicate-edge memberships, so it can only
 * be dropped after those members are gone. The database is dropped before any
 * role, which removes every database-local grant.
 */
const FIXTURE_ROLES = [
  'c1_none',
  'c2_setonly',
  'c3_inhonly',
  'c4_owner_noset',
  'c4b_owner_set',
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
  'c10_write_set',
  'c10_write_none',
  'c12_never',
  'c12_future',
  'c12_expired',
  'z_bystander',
  'z_monitor',
  'all_login',
  'dp_login',
  'mp_login',
  'ac_inh',
  'ac_set',
  'ac_inact',
  'dual_login',
  'mix_login',
  'combo_login',
  'su_set',
  'su_noset',
  'oc_inh_s',
  'oc_inh_t',
  'oc_set_t',
  'oc_inact_t',
  'oc_selfown',
  'cap_read',
  'cap_write',
  'cap_all',
  'cap_read2',
  'aclh',
  'wg_holder',
  ...DEEP,
  'own_schema',
  'own_table',
  'su_target',
  'granter2',
];

const ROLE_TEARDOWN = FIXTURE_ROLES.map((r) => `DROP ROLE IF EXISTS ${r};`).join('\n');

/*
 * FILE-SCOPED harness lifecycle. Several describes below execute the
 * diagnostic against the same database, so the cluster lock, the database and
 * the role fixture must outlive any single describe — a describe-scoped
 * afterAll would drop the database out from under its successors.
 */
beforeAll(async () => {
  if (!HAVE_PG) {
    return;
  }

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
}, 900_000);

afterAll(() => {
  if (!HAVE_PG) {
    return;
  }

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

// ─── static contract ──────────────────────────────────────────────────────────

describe('R15.6.5 diagnostic 28 — static contract', () => {
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
      'aclmap',
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

  it('d-st8 — the path recursion has NO depth cutoff and keeps OID-path cycle prevention', () => {
    expect(exec, 'no numeric depth comparison may bound the recursion').not.toMatch(/depth\s*[<>]=?\s*\d/i);
    expect(exec).toMatch(/NOT \(m\.roleid = ANY \(p\.path_oids\)\)/);
  });

  it('d-st9 — role validity is never a reachability input', () => {
    /*
     * rolvaliduntil bounds password authentication only; an expired role keeps
     * all catalog authority. It may appear only in the labelled validity
     * columns, never inside a reachability or attribution predicate.
     */
    const uses = [...exec.matchAll(/rolvaliduntil/g)];
    expect(uses.length).toBeGreaterThan(0);

    for (const m of uses) {
      const window = exec.slice(Math.max(0, m.index! - 200), m.index! + 200);
      expect(window).not.toMatch(/pg_has_role|has_schema_privilege|has_table_privilege|reaches|usable|settable/i);
    }
  });
});

// ─── real PostgreSQL 16 adversarial evidence ─────────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — PostgreSQL 16 adversarial evidence', () => {
  let out = '';
  let outPublic = '';
  let fpBefore = '';
  let fpAfter = '';
  let candidates: Row[] = [];
  let routes: Row[] = [];
  let paths: Row[] = [];
  let acls: Row[] = [];
  let q1: Row[] = [];
  let aclsPublic: Row[] = [];
  let routesPublic: Row[] = [];

  const cand = (n: string) => candidates.find((r) => r.candidate_role === n)!;
  const route = (n: string, kind: string, priv: string) =>
    routes.find((r) => r.candidate_role === n && r.object_kind === kind && r.privilege === priv);

  beforeAll(() => {
    fpBefore = protectedFingerprint();
    out = runFile(DIAG);
    fpAfter = protectedFingerprint();

    /*
     * PUBLIC capture (matrix 24): a PUBLIC grant confers real access on EVERY
     * role, which would mask the per-membership cases above.
     */
    run(`GRANT REFERENCES ON ${TBL} TO PUBLIC;`);
    outPublic = runFile(DIAG);
    run(`REVOKE REFERENCES ON ${TBL} FROM PUBLIC;`);

    candidates = resultSet(out, 'reaches_protected_objects');
    routes = resultSet(out, 'usable_without_set_role');
    paths = resultSet(out, 'path_permits_set_role');
    acls = resultSet(out, 'grantee_is_public');
    q1 = resultSet(out, 'pinned_contract_owner');
    aclsPublic = resultSet(outPublic, 'grantee_is_public');
    routesPublic = resultSet(outPublic, 'usable_without_set_role');
  }, 900_000);

  it('d0 — the diagnostic mutates nothing: protected objects and role graph byte-equivalent', () => {
    expect(fpAfter).toBe(fpBefore);
    expect(candidates.length).toBeGreaterThan(0);
    expect(paths.length).toBeGreaterThan(0);
    expect(routes.length).toBeGreaterThan(0);
    expect(acls.length).toBeGreaterThan(0);

    // Baseline Q1: all three owner identities coincide here, and that is said explicitly.
    expect(q1[0].schema_owner_matches_pinned_contract_owner).toBe('t');
    expect(q1[0].table_owner_matches_pinned_contract_owner).toBe('t');
    expect(q1[0].schema_owner_matches_table_owner).toBe('t');
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
    expect(r.inactive_membership_evidence_present).toBe('t');
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
    expect(r.explicit_acl_usable_without_set_role).toBe('t');
    expect(r.explicit_acl_inactive_membership_evidence).toBe('f');
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

  it('case 12 — role validity is exact, and expiry does NOT surrender catalog authority', () => {
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

    /*
     * rolvaliduntil bounds PASSWORD AUTHENTICATION only. The expired role
     * still holds its inherited privilege — and under non-password auth it
     * can still connect and use it. Expiry is not evidence of harmlessness.
     */
    expect(expired.privileges_usable_without_set_role).toBe('t');
    expect(expired.roles_inherited_from).toContain('cap_read');
    expect(asRole('c12_expired', `SELECT count(*) FROM ${TBL};`).ok, 'expired role retains real access').toBe(true);
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

// ─── P1-1: complete membership-path enumeration ──────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — P1-1 complete path enumeration (no depth cutoff)', () => {
  /*
   * Describes in this file run sequentially against the database the first
   * describe's beforeAll built. This one re-derives its rows from a fresh
   * diagnostic execution so it does not depend on captured module state.
   */
  let paths: Row[] = [];

  beforeAll(() => {
    paths = resultSet(runFile(DIAG), 'path_permits_set_role');
  }, 300_000);

  const dpPath = (depth: number) =>
    paths.find((p) => p.candidate_role === 'dp_login' && p.path_depth === String(depth));

  it('p1 — depths 15, 16, 17 and 20 are ALL enumerated, ending at the right roles', () => {
    for (const [depth, terminal] of [
      [15, 'dp_r15'],
      [16, 'dp_r16'],
      [17, 'dp_r17'],
      [20, 'dp_r20'],
    ] as const) {
      const p = dpPath(depth);
      expect(p, `depth-${depth} path must be enumerated`).toBeDefined();
      expect(p!.edge_granted_role).toBe(terminal);
      expect(p!.path_permits_inheritance).toBe('t');
      expect(p!.path_permits_set_role).toBe('t');
    }
  });

  it('p2 — the depth-17 defect is closed: the deep terminal, its full route and every edge appear', () => {
    const p17 = dpPath(17)!;
    const p20 = dpPath(20)!;

    // Complete path identity: every intermediate role is present, in order.
    for (const inter of DEEP.slice(0, 17)) {
      expect(p17.path).toContain(inter);
    }

    expect(p17.path_identity.split(',').length, '17 edges = 18 oids').toBe(18);
    expect(p20.path_identity.split(',').length).toBe(21);
    expect(p20.path.startsWith('dp_login -> dp_r01 -> dp_r02')).toBe(true);
    expect(p20.edge_member_role).toBe('dp_r19');
    expect(p20.edge_granted_role).toBe('dp_r20');
  });

  it('p3 — the terminal role authority matches PostgreSQL: USAGE, SET, real SELECT, real SET ROLE', () => {
    expect(scalar(`SELECT pg_has_role('dp_login','dp_r20','MEMBER');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('dp_login','dp_r20','USAGE');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('dp_login','dp_r20','SET');`)).toBe('t');
    expect(scalar(`SELECT has_table_privilege('dp_login','${TBL}','SELECT');`)).toBe('t');
    expect(asRole('dp_login', `SELECT count(*) FROM ${TBL};`).ok, 'real SELECT through 20 edges').toBe(true);
    expect(asRole('dp_login', `SET ROLE dp_r20; SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    const p20 = dpPath(20)!;
    expect(p20.authoritative_usage).toBe('t');
    expect(p20.authoritative_set).toBe('t');
  });

  it('p4 — multiple paths to one terminal where one is deeper than 16: both rows, never collapsed', () => {
    const toTerminal = paths.filter((p) => p.candidate_role === 'mp_login' && p.edge_granted_role === 'dp_r20');
    const depths = toTerminal.map((p) => Number(p.path_depth)).sort((a, b) => a - b);
    expect(depths[0]).toBe(1);
    expect(depths[depths.length - 1]).toBe(20);
    expect(toTerminal.length).toBeGreaterThanOrEqual(2);
  });

  it('p5 — recursion cannot loop: the role graph is acyclic BY SERVER RULE and the guard excludes repeats', () => {
    /*
     * PostgreSQL itself refuses circular role grants, so pg_auth_members can
     * never contain a cycle — proven live, not assumed:
     */
    let message = '';

    try {
      run(`GRANT dp_login TO dp_r20;`);
    } catch (e) {
      message = String((e as { stderr?: string }).stderr ?? e);
    }

    expect(message, 'the server must reject the circular grant').toMatch(/is a member of role/);

    /*
     * Diamond convergence (two branches to one node) also terminates finitely:
     * c8_login reaches cap_read both directly and via c8_alt, and the deep
     * chain enumerates exactly its 20 simple paths (plus nothing repeated).
     */
    const dpRows = paths.filter((p) => p.candidate_role === 'dp_login');
    expect(dpRows.length).toBe(20);
    expect(new Set(dpRows.map((p) => p.path_identity)).size).toBe(20);
  });

  it('p6 — ordering of the path result is fully deterministic', () => {
    const again = resultSet(runFile(DIAG), 'path_permits_set_role');
    expect(again.map((p) => `${p.candidate_role}#${p.path_identity}#${p.edge_grantor}`)).toEqual(
      paths.map((p) => `${p.candidate_role}#${p.path_identity}#${p.edge_grantor}`),
    );
  });
});

// ─── P1-2: reachability-gated attribution ────────────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — P1-2 reachability-gated ACL and owner attribution', () => {
  let routes: Row[] = [];
  let acls: Row[] = [];

  const route = (n: string, kind: string, priv: string) =>
    routes.find((r) => r.candidate_role === n && r.object_kind === kind && r.privilege === priv);

  beforeAll(() => {
    const out = runFile(DIAG);
    routes = resultSet(out, 'usable_without_set_role');
    acls = resultSet(out, 'grantee_is_public');
  }, 300_000);

  it('a1 — ACL through USAGE: effective, attributed as usable without SET ROLE', () => {
    expect(asRole('ac_inh', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    const r = route('ac_inh', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('t');
    expect(r.explicit_acl_usable_without_set_role).toBe('t');
    expect(r.explicit_acl_reachable_via_set_role).toBe('f');
    expect(r.explicit_acl_inactive_membership_evidence).toBe('f');

    const s = route('ac_inh', 'schema', 'USAGE')!;
    expect(s.explicit_acl_usable_without_set_role, 'same rule for schema ACLs').toBe('t');
  });

  it('a2 — ACL through SET only: effective after SET ROLE, attributed exactly that way', () => {
    expect(asRole('ac_set', `SELECT count(*) FROM ${TBL};`).ok, 'nothing before SET ROLE').toBe(false);
    expect(asRole('ac_set', `SET ROLE aclh; SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    const r = route('ac_set', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('t');
    expect(r.explicit_acl_usable_without_set_role).toBe('f');
    expect(r.explicit_acl_reachable_via_set_role).toBe('t');
    expect(r.explicit_acl_inactive_membership_evidence).toBe('f');
  });

  it('a3 — THE REVIEWED DEFECT: an ACL behind an inactive membership is evidence, never an effective route', () => {
    // The reviewer's exact configuration, reproduced live:
    expect(scalar(`SELECT pg_has_role('ac_inact','aclh','MEMBER');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('ac_inact','aclh','USAGE');`)).toBe('f');
    expect(scalar(`SELECT pg_has_role('ac_inact','aclh','SET');`)).toBe('f');
    expect(asRole('ac_inact', `SELECT count(*) FROM ${TBL};`).ok, 'direct SELECT denied').toBe(false);
    expect(asRole('ac_inact', 'SET ROLE aclh;').ok, 'SET ROLE denied').toBe(false);

    const r = route('ac_inact', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('f');
    expect(r.explicit_acl_usable_without_set_role, 'no effective ACL attribution').toBe('f');
    expect(r.explicit_acl_reachable_via_set_role).toBe('f');
    expect(r.explicit_acl_inactive_membership_evidence, 'the ACL stays visible as evidence').toBe('t');
    expect(r.inactive_membership_only).toBe('t');

    const s = route('ac_inact', 'schema', 'USAGE')!;
    expect(s.explicit_acl_usable_without_set_role, 'schema ACL under the same rule').toBe('f');
    expect(s.explicit_acl_inactive_membership_evidence).toBe('t');
  });

  it('a4 — active + inactive paths to the SAME holder: access wins, both edges stay visible', () => {
    expect(asRole('dual_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    const r = route('dual_login', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('t');
    expect(r.inactive_membership_only, 'NEVER "inactive only" while an active route exists').toBe('f');
    expect(r.explicit_acl_usable_without_set_role).toBe('t');

    // Both conflicting depth-1 edges appear as separate path rows.
    const paths = resultSet(runFile(DIAG), 'path_permits_set_role').filter(
      (p) => p.candidate_role === 'dual_login' && p.edge_granted_role === 'cap_read',
    );
    expect(paths.length).toBe(2);

    const opts = paths.map((p) => p.edge_inherit_option).sort();
    expect(opts).toEqual(['f', 't']);
    expect(new Set(paths.map((p) => p.edge_grantor)).size, 'distinct grantors reported').toBe(2);
  });

  it('a5 — active + inactive paths to DIFFERENT holders: both kinds of evidence, correctly separated', () => {
    const r = route('mix_login', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('t');
    expect(r.inactive_membership_evidence_present).toBe('t');
    expect(r.inactive_membership_only).toBe('f');
    expect(r.inheriting_roles).toContain('cap_read');
    expect(r.inactive_membership_roles).toContain('cap_read2');
    expect(r.inheriting_roles).not.toContain('cap_read2');
  });

  it('a6 — ACL plus predefined-role access on one candidate: both attributions true', () => {
    const r = route('combo_login', 'table', 'SELECT')!;
    expect(r.explicit_acl_usable_without_set_role).toBe('t');
    expect(r.via_predefined_role_inherited).toBe('t');
    expect(asRole('combo_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);

    // Predefined attribution obeys the same reachability gate.
    const inact = route('c10_read_none', 'table', 'SELECT')!;
    expect(inact.via_predefined_role_inherited).toBe('f');
    expect(inact.via_predefined_role_settable).toBe('f');
    expect(inact.via_predefined_role_inactive_membership).toBe('t');
  });

  it('a7 — WITH GRANT OPTION and multiple grantors are exact in the structured ACL evidence', () => {
    const wgSelect = acls.find((a) => a.grantee_name === 'wg_holder' && a.privilege_type === 'SELECT')!;
    expect(wgSelect.is_grantable).toBe('t');
    expect(wgSelect.grantor_name).toBe('scratch');

    const wgUpdate = acls.find((a) => a.grantee_name === 'wg_holder' && a.privilege_type === 'UPDATE')!;
    expect(wgUpdate.is_grantable).toBe('f');
    expect(wgUpdate.grantor_name, 'the second grantor is reported verbatim').toBe('granter2');
  });
});

// ─── actual owners vs the pinned contract owner ──────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — actual-owner attribution', () => {
  /*
   * Captures the diagnostic while the schema owner, table owner, and pinned
   * contract owner genuinely DIFFER (own_table also receives schema USAGE so
   * real probes can reach the table at all), then while a candidate LOGIN role
   * itself owns the table. Ownership and grants are fully restored before the
   * captures are consumed, and again defensively in afterAll.
   */
  let q1Owners: Row[] = [];
  let candidatesOwners: Row[] = [];
  let routesOwners: Row[] = [];
  let q1SelfOwn: Row[] = [];
  let candidatesSelfOwn: Row[] = [];
  let routesSelfOwn: Row[] = [];

  const routeIn = (rows: Row[], n: string, kind: string, priv: string) =>
    rows.find((r) => r.candidate_role === n && r.object_kind === kind && r.privilege === priv);

  beforeAll(() => {
    run(`ALTER SCHEMA ${NSP} OWNER TO own_schema;
      ALTER TABLE ${TBL} OWNER TO own_table;
      GRANT USAGE ON SCHEMA ${NSP} TO own_table;`);

    const outOwners = runFile(DIAG);
    const probeInh = asRole('oc_inh_t', `SELECT count(*) FROM ${TBL};`);
    const probeSet = asRole('oc_set_t', `SET ROLE own_table; SELECT count(*) FROM ${TBL};`);
    const probeInactSelect = asRole('oc_inact_t', `SELECT count(*) FROM ${TBL};`);
    const probeInactSet = asRole('oc_inact_t', 'SET ROLE own_table;');
    run(`REVOKE USAGE ON SCHEMA ${NSP} FROM own_table;
      ALTER TABLE ${TBL} OWNER TO scratch;
      ALTER SCHEMA ${NSP} OWNER TO scratch;`);

    run(`ALTER TABLE ${TBL} OWNER TO oc_selfown;
      GRANT USAGE ON SCHEMA ${NSP} TO oc_selfown;`);

    const outSelfOwn = runFile(DIAG);
    const probeSelf = asRole('oc_selfown', `SELECT count(*) FROM ${TBL};`);
    run(`REVOKE USAGE ON SCHEMA ${NSP} FROM oc_selfown;
      ALTER TABLE ${TBL} OWNER TO scratch;`);

    q1Owners = resultSet(outOwners, 'pinned_contract_owner');
    candidatesOwners = resultSet(outOwners, 'reaches_protected_objects');
    routesOwners = resultSet(outOwners, 'usable_without_set_role');
    q1SelfOwn = resultSet(outSelfOwn, 'pinned_contract_owner');
    candidatesSelfOwn = resultSet(outSelfOwn, 'reaches_protected_objects');
    routesSelfOwn = resultSet(outSelfOwn, 'usable_without_set_role');

    expect(probeInh.ok, 'inherited owner access is real').toBe(true);
    expect(probeSet.ok, 'SET-only owner access is real after SET ROLE').toBe(true);
    expect(probeInactSelect.ok, 'inactive owner membership confers no SELECT').toBe(false);
    expect(probeInactSet.ok, 'inactive owner membership confers no SET ROLE').toBe(false);
    expect(probeSelf.ok, 'the self-owning candidate has real access').toBe(true);
  }, 600_000);

  afterAll(() => {
    // Belt and suspenders: certain restoration even if an assertion failed.
    try {
      run(`REVOKE USAGE ON SCHEMA ${NSP} FROM own_table;
        REVOKE USAGE ON SCHEMA ${NSP} FROM oc_selfown;
        ALTER TABLE ${TBL} OWNER TO scratch;
        ALTER SCHEMA ${NSP} OWNER TO scratch;`);
    } catch {
      /* database may already be gone */
    }
  }, 120_000);

  it('o1 — Q1 reports ACTUAL owners and pinned-owner conformity as separate facts', () => {
    const q = q1Owners[0];
    expect(q.schema_owner).toBe('own_schema');
    expect(q.table_owner).toBe('own_table');
    expect(q.pinned_contract_owner).toBe('scratch');
    expect(q.schema_owner_matches_pinned_contract_owner).toBe('f');
    expect(q.table_owner_matches_pinned_contract_owner).toBe('f');
    expect(q.schema_owner_matches_table_owner).toBe('f');
  });

  it('o2 — schema-owner access is attributed against the ACTUAL schema owner', () => {
    const s = routeIn(routesOwners, 'oc_inh_s', 'schema', 'USAGE')!;
    expect(s.object_owner_role).toBe('own_schema');
    expect(s.object_owner_is_pinned_contract_owner).toBe('f');
    expect(s.via_object_owner_usable_without_set_role).toBe('t');
    expect(s.usable_without_set_role).toBe('t');

    const c = candidatesOwners.find((r) => r.candidate_role === 'oc_inh_s')!;
    expect(c.inherits_from_schema_owner).toBe('t');
    expect(c.can_set_role_to_schema_owner).toBe('t');
    expect(c.inherits_from_pinned_owner, 'pinned-owner facts stay separate').toBe('f');
  });

  it('o3 — inherited table-owner access: attributed to the actual table owner, effective without SET ROLE', () => {
    const r = routeIn(routesOwners, 'oc_inh_t', 'table', 'SELECT')!;
    expect(r.object_owner_role).toBe('own_table');
    expect(r.object_owner_is_pinned_contract_owner).toBe('f');
    expect(r.via_object_owner_usable_without_set_role).toBe('t');
    expect(r.via_object_owner_reachable_via_set_role, 'default grant also permits SET ROLE').toBe('t');
    expect(r.usable_without_set_role).toBe('t');
  });

  it('o4 — SET-only table-owner access: attributed as reachable via SET ROLE, not as usable', () => {
    const r = routeIn(routesOwners, 'oc_set_t', 'table', 'UPDATE')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('t');
    expect(r.via_object_owner_reachable_via_set_role).toBe('t');
    expect(r.via_object_owner_usable_without_set_role).toBe('f');
  });

  it('o5 — simultaneous owner and ACL routes on one candidate/privilege are both reported', () => {
    // oc_set_t holds its own SELECT ACL AND can SET ROLE to the table owner.
    const r = routeIn(routesOwners, 'oc_set_t', 'table', 'SELECT')!;
    expect(r.usable_without_set_role, 'own explicit ACL').toBe('t');
    expect(r.explicit_acl_usable_without_set_role).toBe('t');
    expect(r.via_object_owner_reachable_via_set_role, 'owner route via SET ROLE').toBe('t');
  });

  it('o6 — inactive owner membership: evidence only, both reach flags false', () => {
    const r = routeIn(routesOwners, 'oc_inact_t', 'table', 'SELECT')!;
    expect(r.usable_without_set_role).toBe('f');
    expect(r.reachable_via_set_role).toBe('f');
    expect(r.via_object_owner_inactive_membership).toBe('t');
    expect(r.inactive_membership_only).toBe('t');
  });

  it('o7 — candidate self-ownership: the owning login role is fully visible', () => {
    const q = q1SelfOwn[0];
    expect(q.table_owner).toBe('oc_selfown');
    expect(q.table_owner_matches_pinned_contract_owner).toBe('f');

    const c = candidatesSelfOwn.find((r) => r.candidate_role === 'oc_selfown')!;
    expect(c.is_actual_table_owner).toBe('t');
    expect(c.reaches_protected_objects).toBe('t');

    const r = routeIn(routesSelfOwn, 'oc_selfown', 'table', 'SELECT')!;
    expect(r.held_directly_or_inherited_by_self).toBe('t');
    expect(r.via_object_owner_usable_without_set_role).toBe('t');
    expect(r.object_owner_role).toBe('oc_selfown');
  });

  it('o8 — every ownership change and helper grant was fully restored', () => {
    expect(scalar(`SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '${NSP}';`)).toBe('scratch');
    expect(scalar(`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = '${TBL}'::regclass;`)).toBe('scratch');
    expect(
      scalar(`SELECT count(*) FROM pg_namespace n, aclexplode(n.nspacl) ae
         WHERE n.nspname = '${NSP}'
           AND ae.grantee IN ('own_table'::regrole, 'oc_selfown'::regrole);`),
    ).toBe('0');
  });
});

// ─── genuine-session superuser SET ROLE ──────────────────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — genuine-session superuser SET ROLE', () => {
  let candidates: Row[] = [];

  beforeAll(() => {
    candidates = resultSet(runFile(DIAG), 'reaches_protected_objects');
  }, 300_000);

  const cand = (n: string) => candidates.find((r) => r.candidate_role === n)!;

  it('s1 — SET-enabled superuser membership, proven from a session AUTHENTICATED AS the candidate', () => {
    /*
     * The connection authenticates as su_set itself — session_user is the
     * candidate, and nothing is inherited from the harness superuser session.
     */
    const identity = asRole('su_set', `SELECT session_user || '/' || current_user;`);
    expect(identity.ok).toBe(true);
    expect(identity.message).toContain('su_set/su_set');

    expect(scalar(`SELECT pg_has_role('su_set','su_target','SET');`)).toBe('t');
    expect(scalar(`SELECT pg_has_role('su_set','su_target','USAGE');`)).toBe('f');

    // Superuser-only capability is unavailable BEFORE the switch...
    expect(asRole('su_set', 'SELECT count(*) FROM pg_authid;').ok, 'pg_authid denied before SET ROLE').toBe(false);

    // ...the switch itself succeeds exactly as PostgreSQL 16 specifies...
    const after = asRole('su_set', `SET ROLE su_target; SELECT session_user || '/' || current_user;`);
    expect(after.ok).toBe(true);
    expect(after.message, 'current_user becomes the superuser role; session_user stays the candidate').toContain(
      'su_set/su_target',
    );

    // ...and the SUPERUSER attribute is usable only after it.
    expect(asRole('su_set', `SET ROLE su_target; SELECT count(*) FROM pg_authid;`).ok).toBe(true);

    // RESET ROLE restores the original identity safely.
    const reset = asRole('su_set', `SET ROLE su_target; RESET ROLE; SELECT session_user || '/' || current_user;`);
    expect(reset.ok).toBe(true);
    expect(reset.message).toContain('su_set/su_set');

    const c = cand('su_set');
    expect(c.can_set_role_to_a_superuser).toBe('t');
    expect(c.inherits_from_a_superuser).toBe('f');
    expect(c.reaches_protected_objects, 'a settable superuser reaches everything').toBe('t');
  });

  it('s2 — SET-disabled superuser membership: genuine session, SET ROLE denied, flagged only as evidence', () => {
    const identity = asRole('su_noset', `SELECT session_user || '/' || current_user;`);
    expect(identity.ok).toBe(true);
    expect(identity.message).toContain('su_noset/su_noset');

    expect(scalar(`SELECT pg_has_role('su_noset','su_target','SET');`)).toBe('f');
    expect(asRole('su_noset', 'SET ROLE su_target;').ok, 'server must deny').toBe(false);
    expect(asRole('su_noset', 'SELECT count(*) FROM pg_authid;').ok).toBe(false);

    const c = cand('su_noset');
    expect(c.can_set_role_to_a_superuser).toBe('f');
    expect(c.inherits_from_a_superuser).toBe('f');
    expect(c.reaches_protected_objects).toBe('f');
  });

  it('s3 — owner membership with SET enabled: real switch to the pinned owner from the candidate session', () => {
    expect(scalar(`SELECT pg_has_role('c4b_owner_set','scratch','SET');`)).toBe('t');

    const sw = asRole('c4b_owner_set', `SET ROLE scratch; SELECT session_user || '/' || current_user;`);
    expect(sw.ok).toBe(true);
    expect(sw.message).toContain('c4b_owner_set/scratch');

    const c = cand('c4b_owner_set');
    expect(c.can_set_role_to_pinned_owner).toBe('t');
    expect(c.inherits_from_pinned_owner).toBe('f');
    expect(c.can_set_role_to_a_superuser, 'the pinned owner is also a superuser here').toBe('t');
    expect(c.reaches_protected_objects).toBe('t');
  });
});

// ─── the complete PostgreSQL 16 adversarial matrix ───────────────────────────

describe.skipIf(!HAVE_PG)('R15.6.5 diagnostic 28 — complete adversarial matrix (34 cases, 9 privileges)', () => {
  let candidates: Row[] = [];
  let routes: Row[] = [];

  const cand = (n: string) => candidates.find((r) => r.candidate_role === n)!;
  const route = (n: string, kind: string, priv: string) =>
    routes.find((r) => r.candidate_role === n && r.object_kind === kind && r.privilege === priv);

  beforeAll(() => {
    const out = runFile(DIAG);
    candidates = resultSet(out, 'reaches_protected_objects');
    routes = resultSet(out, 'usable_without_set_role');
  }, 300_000);

  const trio = (member: string, target: string) =>
    scalar(`SELECT pg_has_role('${member}','${target}','MEMBER')::text || '/'
         || pg_has_role('${member}','${target}','USAGE')::text  || '/'
         || pg_has_role('${member}','${target}','SET')::text;`);

  it('m01-m04 — the four INHERIT x SET combinations against real privilege and SET ROLE outcomes', () => {
    expect(trio('c1_none', 'cap_read')).toBe('true/false/false');
    expect(cand('c1_none').reaches_protected_objects).toBe('f');

    expect(trio('c2_setonly', 'cap_read')).toBe('true/false/true');
    expect(cand('c2_setonly').privileges_via_set_role).toBe('t');

    expect(trio('c3_inhonly', 'cap_read')).toBe('true/true/false');
    expect(cand('c3_inhonly').privileges_usable_without_set_role).toBe('t');

    // m04: INHERIT true, SET true (default grant) — both routes real.
    expect(trio('all_login', 'cap_all')).toBe('true/true/true');
    expect(asRole('all_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);
    expect(asRole('all_login', 'SET ROLE cap_all;').ok).toBe(true);
    expect(cand('all_login').privileges_usable_without_set_role).toBe('t');
    expect(cand('all_login').privileges_via_set_role).toBe('t');
  });

  it('m05-m08 — owner and superuser memberships, SET disabled and enabled (genuine sessions)', () => {
    // m05/m07: SET disabled — covered adversarially above; assert the summary.
    expect(cand('c4_owner_noset').can_set_role_to_pinned_owner).toBe('f');
    expect(cand('c5_super_noset').can_set_role_to_a_superuser).toBe('f');

    // m06: owner membership with SET enabled.
    expect(cand('c4b_owner_set').can_set_role_to_pinned_owner).toBe('t');

    // m08: superuser membership with SET enabled.
    expect(cand('su_set').can_set_role_to_a_superuser).toBe('t');
    expect(cand('su_noset').can_set_role_to_a_superuser).toBe('f');
  });

  it('m09-m12 — admin-only, direct self, transitive, conflicting paths', () => {
    expect(trio('c6_admin_only', 'cap_read')).toBe('true/false/false');
    expect(cand('c6_admin_only').reaches_protected_objects).toBe('f');
    expect(route('c9_direct', 'table', 'SELECT')!.held_directly_or_inherited_by_self).toBe('t');
    expect(cand('c7_login').roles_inherited_from).toContain('cap_write');
    expect(cand('c8_login').privileges_usable_without_set_role).toBe('t');
  });

  it('m13-m14 — depth 16, depth 17 and deeper are enumerated with effective terminal authority', () => {
    const paths = resultSet(runFile(DIAG), 'path_permits_set_role');
    const dp = (d: number) => paths.find((p) => p.candidate_role === 'dp_login' && p.path_depth === String(d));
    expect(dp(16), 'depth 16').toBeDefined();
    expect(dp(17), 'depth 17').toBeDefined();
    expect(dp(20), 'depth 20').toBeDefined();
    expect(dp(17)!.authoritative_usage).toBe('t');
    expect(dp(17)!.authoritative_set).toBe('t');
    expect(cand('dp_login').privileges_usable_without_set_role).toBe('t');
  });

  it('m15-m20 — pg_read_all_data / pg_write_all_data through INHERIT, SET-only, and inactive', () => {
    expect(cand('c10_read_inh').predefined_roles_inherited).toContain('pg_read_all_data');
    expect(cand('c10_read_set').predefined_roles_settable).toContain('pg_read_all_data');
    expect(cand('c10_read_none').predefined_roles_inactive_membership).toContain('pg_read_all_data');
    expect(cand('c10_read_none').reaches_protected_objects).toBe('f');

    expect(cand('c10_write_inh').predefined_roles_inherited).toContain('pg_write_all_data');
    expect(asRole('c10_write_inh', `BEGIN; INSERT INTO ${TBL}(version) VALUES ('m18probe'); ROLLBACK;`).ok).toBe(true);

    expect(cand('c10_write_set').predefined_roles_settable).toContain('pg_write_all_data');
    expect(cand('c10_write_set').privileges_usable_without_set_role).toBe('f');
    expect(cand('c10_write_set').privileges_via_set_role).toBe('t');
    expect(asRole('c10_write_set', `INSERT INTO ${TBL}(version) VALUES ('m19probe');`).ok).toBe(false);
    expect(
      asRole(
        'c10_write_set',
        `BEGIN; SET ROLE pg_write_all_data; INSERT INTO ${TBL}(version) VALUES ('m19probe'); ROLLBACK;`,
      ).ok,
    ).toBe(true);

    expect(cand('c10_write_none').predefined_roles_inactive_membership).toContain('pg_write_all_data');
    expect(cand('c10_write_none').reaches_protected_objects).toBe('f');
    expect(asRole('c10_write_none', 'SET ROLE pg_write_all_data;').ok).toBe(false);
  });

  it('m21-m27 — custom capability, explicit schema/table ACLs, PUBLIC, GRANT OPTION, grantors, inactive-holder ACL', () => {
    expect(cand('c3_inhonly').roles_inherited_from).toContain('cap_read');
    expect(route('ac_inh', 'schema', 'USAGE')!.explicit_acl_usable_without_set_role).toBe('t');
    expect(route('ac_inh', 'table', 'SELECT')!.explicit_acl_usable_without_set_role).toBe('t');

    /*
     * m24 PUBLIC is proven in the dedicated PUBLIC capture (case 11).
     * m25/m26 in the structured-ACL suite (a7). m27:
     */
    expect(route('ac_inact', 'table', 'SELECT')!.explicit_acl_inactive_membership_evidence).toBe('t');
    expect(route('ac_inact', 'table', 'SELECT')!.explicit_acl_usable_without_set_role).toBe('f');
  });

  it('m28-m30 — dormant pg_monitor, bystander, and the three platform roles hold nothing', () => {
    for (const benign of ['z_monitor', 'z_bystander', 'anon', 'authenticated', 'service_role']) {
      expect(cand(benign).reaches_protected_objects, benign).toBe('f');
    }

    expect(cand('z_monitor').predefined_roles_inherited).toContain('pg_monitor');
    expect(asRole('z_bystander', `SELECT count(*) FROM ${TBL};`).ok).toBe(false);
  });

  it('m31-m34 — split owners, validity, coexisting paths, ACL+predefined (see dedicated suites)', () => {
    /*
     * m31 is proven in the actual-owner capture suite (o1-o7); m32 in case 12;
     * m33 in a4/a5; m34 in a6. Assert the summary facts here so the matrix is
     * complete in one place.
     */
    expect(cand('c12_expired').expired).toBe('t');
    expect(cand('c12_expired').privileges_usable_without_set_role).toBe('t');
    expect(route('mix_login', 'table', 'SELECT')!.inactive_membership_only).toBe('f');
    expect(route('combo_login', 'table', 'SELECT')!.via_predefined_role_inherited).toBe('t');
    expect(route('combo_login', 'table', 'SELECT')!.explicit_acl_usable_without_set_role).toBe('t');
  });

  it('m-priv — all nine protected-object privileges: catalog claim vs real execution', () => {
    /*
     * all_login inherits cap_all, which holds schema USAGE+CREATE and all
     * seven table privileges. Every reach is exercised for real (inside
     * rolled-back transactions where the action would mutate).
     */
    for (const [kind, priv] of [
      ['schema', 'USAGE'],
      ['schema', 'CREATE'],
      ['table', 'SELECT'],
      ['table', 'INSERT'],
      ['table', 'UPDATE'],
      ['table', 'DELETE'],
      ['table', 'TRUNCATE'],
      ['table', 'REFERENCES'],
      ['table', 'TRIGGER'],
    ] as const) {
      const r = route('all_login', kind, priv);
      expect(r, `${kind}/${priv} row must exist`).toBeDefined();
      expect(r!.usable_without_set_role, `${kind}/${priv} usable`).toBe('t');
    }

    expect(asRole('all_login', `SELECT count(*) FROM ${TBL};`).ok).toBe(true);
    expect(asRole('all_login', `BEGIN; CREATE TABLE ${NSP}.zz_probe_t(i int); ROLLBACK;`).ok).toBe(true);
    expect(asRole('all_login', `BEGIN; INSERT INTO ${TBL}(version) VALUES ('zz_probe_all'); ROLLBACK;`).ok).toBe(true);
    expect(asRole('all_login', `BEGIN; UPDATE ${TBL} SET name = name; ROLLBACK;`).ok).toBe(true);
    expect(asRole('all_login', `BEGIN; DELETE FROM ${TBL}; ROLLBACK;`).ok).toBe(true);
    expect(asRole('all_login', `BEGIN; TRUNCATE ${TBL}; ROLLBACK;`).ok).toBe(true);
    expect(
      asRole('all_login', `BEGIN; CREATE TABLE ${NSP}.zz_probe_fk(v text REFERENCES ${TBL}(version)); ROLLBACK;`).ok,
    ).toBe(true);
    expect(
      asRole(
        'all_login',
        `BEGIN; CREATE TRIGGER zz_probe_trg BEFORE UPDATE ON ${TBL}
           FOR EACH ROW EXECUTE FUNCTION suppress_redundant_updates_trigger(); ROLLBACK;`,
      ).ok,
    ).toBe(true);

    // The bystander is denied the same nine for real.
    expect(asRole('z_bystander', `BEGIN; CREATE TABLE ${NSP}.zz_probe_t(i int); ROLLBACK;`).ok).toBe(false);
    expect(asRole('z_bystander', `BEGIN; TRUNCATE ${TBL}; ROLLBACK;`).ok).toBe(false);
  });
});
