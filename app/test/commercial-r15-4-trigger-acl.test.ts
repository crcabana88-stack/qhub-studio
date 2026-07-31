/**
 * QHUB R15.4 — SUPABASE-NATIVE TRIGGER ACL NORMALIZATION (PGlite)
 * app/test/commercial-r15-4-trigger-acl.test.ts
 *
 * THE DEFECT THIS SUITE LOCKS DOWN (reproduced before anything was changed):
 *   The migration stated no ACL for public.qhub_row_immutable(), so the resulting ACL was
 *   whatever the platform's default privileges produced — and the two environments this
 *   project uses disagreed:
 *     plain PostgreSQL / PGlite -> proacl IS NULL
 *     Supabase                  -> five rows (PUBLIC, anon, authenticated, owner, service_role)
 *   R15.3C's precheck STOPPED live on the five-row set because the contract, derived under
 *   PGlite, required NULL. That was an environment-contract defect, not tampering.
 *
 * R15.4 states the contract explicitly in the migration so both environments converge on
 * ONE reviewed least-privilege ACL: exactly the owner's own EXECUTE.
 *
 * WHY REVOKING IS SAFE — proven here, not assumed. PostgreSQL checks EXECUTE on a trigger
 * function at CREATE TRIGGER time, NOT at fire time, so revoking EXECUTE from every
 * application role leaves trigger enforcement fully intact.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const R3 = `${REPO}docs/release/r15-3-body-restoration/`;
const R2C = `${REPO}docs/release/r15-2-verifier-patch/`;

const MIGRATION = readFileSync(`${REPO}supabase/migrations/20260729_commercial_launch_foundation.sql`, 'utf8');
const PRE10 = readFileSync(`${R3}10_PRE_RESTORE_LIVE_BODY_VERIFY.sql`, 'utf8');
const RESTORE11 = readFileSync(`${R3}11_RESTORE_REVIEWED_PROTECTED_BODIES.sql`, 'utf8');
const POST12 = readFileSync(`${R3}12_POST_RESTORE_BODY_VERIFY.sql`, 'utf8');
const PRE07 = readFileSync(`${R2C}07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql`, 'utf8');
const PATCH08 = readFileSync(`${R2C}08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql`, 'utf8');
const POST09 = readFileSync(`${R2C}09_POST_PATCH_VERIFY.sql`, 'utf8');

const RI = 'public.qhub_row_immutable()';

/** Supabase ships these; plain PostgreSQL/PGlite does not. */
const SUPABASE_DEFAULT_PRIVILEGES = `ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;`;

/** The migration as it stood BEFORE R15.4 — what actually created the live database. */
const PRE_R154_MIGRATION = MIGRATION.replace(
  /REVOKE ALL PRIVILEGES ON FUNCTION public\.qhub_row_immutable\(\)[^\n]*\n/g,
  '',
).replace(/DO \$qhub_row_immutable_owner_grant\$[\s\S]*?\$qhub_row_immutable_owner_grant\$;\n/, '');

const CP1252: Record<number, number> = {
  0x80: 0x20ac,
  0x82: 0x201a,
  0x83: 0x0192,
  0x84: 0x201e,
  0x85: 0x2026,
  0x86: 0x2020,
  0x87: 0x2021,
  0x88: 0x02c6,
  0x89: 0x2030,
  0x8a: 0x0160,
  0x8b: 0x2039,
  0x8c: 0x0152,
  0x8e: 0x017d,
  0x91: 0x2018,
  0x92: 0x2019,
  0x93: 0x201c,
  0x94: 0x201d,
  0x95: 0x2022,
  0x96: 0x2013,
  0x97: 0x2014,
  0x98: 0x02dc,
  0x99: 0x2122,
  0x9a: 0x0161,
  0x9b: 0x203a,
  0x9c: 0x0153,
  0x9e: 0x017e,
  0x9f: 0x0178,
};

function mangle(s: string): string {
  let out = '';

  for (const b of Buffer.from(s, 'utf8')) {
    out += String.fromCodePoint(CP1252[b] ?? b);
  }

  return out;
}

function lastStatement(sql: string): string {
  return sql
    .split(/;\s*\n/)
    .map((c) =>
      c
        .split('\n')
        .filter((l) => !/^\s*--/.test(l))
        .join('\n')
        .trim(),
    )
    .filter(Boolean)
    .filter((s) => !/^(BEGIN|COMMIT|SET TRANSACTION)/i.test(s))
    .at(-1)!;
}

const V10 = lastStatement(PRE10);
const V12 = lastStatement(POST12);
const V07 = lastStatement(PRE07);
const V09 = lastStatement(POST09);

async function open(sql: string, supabaseDefaults: boolean): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    'CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;',
  );

  if (supabaseDefaults) {
    await db.exec(SUPABASE_DEFAULT_PRIVILEGES);
  }

  await db.exec(sql);

  return db;
}

/** Exactly the live database: Supabase defaults + the pre-R15.4 migration + mojibake. */
const openLiveLike = () => open(mangle(PRE_R154_MIGRATION.replace(/\r?\n/g, '\r\n')), true);

const aclRows = async (db: PGlite, sig = RI) =>
  (
    await db.query<{ grantee: string; privilege_type: string; grantor: string; is_grantable: boolean }>(
      `select pg_get_userbyid(ae.grantee) grantee, ae.privilege_type, pg_get_userbyid(ae.grantor) grantor,
              ae.is_grantable
         from pg_proc p, aclexplode(p.proacl) ae
        where p.oid = to_regprocedure($1) order by 1`,
      [sig],
    )
  ).rows;

const OWNER_ONLY = [{ grantee: 'postgres', privilege_type: 'EXECUTE', grantor: 'postgres', is_grantable: false }];

async function rollback(db: PGlite): Promise<void> {
  try {
    await db.exec('ROLLBACK');
  } catch {
    // no transaction open
  }
}

const run = async (db: PGlite, sql: string, asRole?: string) => {
  try {
    if (asRole) {
      await db.exec(`SET ROLE ${asRole}`);
    }

    const r = await db.query(sql);

    if (asRole) {
      await db.exec('RESET ROLE');
    }

    return { ok: true, rows: r.rows.length, message: '' };
  } catch (e) {
    await rollback(db);

    try {
      await db.exec('RESET ROLE');
    } catch {
      // already reset
    }

    return { ok: false, rows: 0, message: String((e as Error).message).split('\n')[0] };
  }
};

// ─── environment portability ───────────────────────────────────────────────────

describe('R15.4 — the migration reaches ONE reviewed ACL in both environments', () => {
  it('e1 — plain PostgreSQL defaults reach the owner-only target', async () => {
    const db = await open(MIGRATION, false);

    try {
      expect(await aclRows(db)).toEqual(OWNER_ONLY);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('e2 — Supabase-like default privileges reach the SAME owner-only target', async () => {
    const db = await open(MIGRATION, true);

    try {
      expect(await aclRows(db)).toEqual(OWNER_ONLY);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('e3 — the two environments produce byte-identical normalized ACL rows', async () => {
    const a = await open(MIGRATION, false);
    const b = await open(MIGRATION, true);

    try {
      expect(await aclRows(a)).toEqual(await aclRows(b));
      expect(await aclRows(a, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)')).toEqual(
        await aclRows(b, 'public.qhub_decide_review(uuid,text,boolean,text,text,text)'),
      );
    } finally {
      await a.close();
      await b.close();
    }
  }, 240_000);

  it('e4 — WITHOUT the R15.4 statements the environments genuinely disagree (the original defect)', async () => {
    const plain = await open(PRE_R154_MIGRATION, false);
    const supa = await open(PRE_R154_MIGRATION, true);

    try {
      expect(await aclRows(plain), 'plain PostgreSQL: proacl IS NULL').toEqual([]);
      expect(await aclRows(supa)).toHaveLength(5);
      expect((await aclRows(supa)).map((r) => r.grantee).sort()).toEqual([
        'anon',
        'authenticated',
        'postgres',
        'service_role',
        'unknown (OID=0)',
      ]);
    } finally {
      await plain.close();
      await supa.close();
    }
  }, 240_000);

  it('e5 — no application role holds EXECUTE after normalization', async () => {
    const db = await open(MIGRATION, true);

    try {
      const eff = (
        await db.query<{ rolname: string; e: boolean }>(
          `select r.rolname, has_function_privilege(r.oid, to_regprocedure($1), 'EXECUTE') e
             from pg_roles r where r.rolname in ('postgres','anon','authenticated','service_role') order by 1`,
          [RI],
        )
      ).rows;
      expect(eff).toEqual([
        { rolname: 'anon', e: false },
        { rolname: 'authenticated', e: false },
        { rolname: 'postgres', e: true },
        { rolname: 'service_role', e: false },
      ]);
    } finally {
      await db.close();
    }
  }, 120_000);
});

// ─── trigger runtime behaviour ─────────────────────────────────────────────────

describe('R15.4 — triggers still fire with EXECUTE revoked from every application role', () => {
  const seed = `insert into public.qhub_acknowledgments
                  (org_id, project_id, user_id, ack_type, ack_version, required_version, status)
                values ('o1','11111111-1111-1111-1111-111111111111','u1','terms','v1','v1','ACTIVE');`;

  it('t1 — service_role: protected-field UPDATE is rejected BY THE TRIGGER', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(seed);

      const r = await run(
        db,
        `update public.qhub_acknowledgments set user_id='u2' where user_id='u1' returning 1`,
        'service_role',
      );
      expect(r.ok).toBe(false);
      expect(r.message, 'the trigger fired — not a privilege error').toContain('authority fields are immutable');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t2 — service_role: the allowed ACTIVE->REVOKED lifecycle transition still succeeds', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(seed);

      const r = await run(
        db,
        `update public.qhub_acknowledgments set status='REVOKED', revoked_at=now() where user_id='u1' returning status`,
        'service_role',
      );
      expect(r.ok, 'trigger permitted the reviewed transition').toBe(true);
      expect(r.rows).toBe(1);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t3 — service_role: a reverse transition is still rejected by the trigger', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(seed);
      await run(
        db,
        `update public.qhub_acknowledgments set status='REVOKED', revoked_at=now() where user_id='u1' returning 1`,
        'service_role',
      );

      const r = await run(
        db,
        `update public.qhub_acknowledgments set status='ACTIVE', revoked_at=null where user_id='u1' returning 1`,
        'service_role',
      );
      expect(r.ok).toBe(false);
      expect(r.message).toContain('controlled ACTIVE->REVOKED/SUPERSEDED lifecycle transition');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t4 — the owner is still subject to the trigger', async () => {
    const db = await open(MIGRATION, true);

    try {
      await db.exec(seed);

      const r = await run(db, `update public.qhub_acknowledgments set org_id='o2' where user_id='u1' returning 1`);
      expect(r.ok).toBe(false);
      expect(r.message).toContain('authority fields are immutable');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t5 — a role with table rights but NO function EXECUTE still triggers enforcement', async () => {
    const db = await open(MIGRATION, true);

    try {
      // Generic portability proof: PostgreSQL checks EXECUTE at CREATE TRIGGER time.
      await db.exec(`
        CREATE TABLE public.r154_probe(id int primary key, v text);
        CREATE TRIGGER r154_probe_immutable BEFORE UPDATE OR DELETE ON public.r154_probe
          FOR EACH ROW EXECUTE FUNCTION public.qhub_row_immutable();
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.r154_probe TO anon;
        INSERT INTO public.r154_probe VALUES (1,'a');
      `);

      const hasExec = (
        await db.query<{ e: boolean }>(`select has_function_privilege('anon', to_regprocedure($1), 'EXECUTE') e`, [RI])
      ).rows[0].e;
      expect(hasExec, 'anon must NOT hold EXECUTE').toBe(false);

      const upd = await run(db, `update public.r154_probe set v='b' where id=1 returning 1`, 'anon');
      expect(upd.ok).toBe(false);
      expect(upd.message).toContain('rows are immutable');

      const del = await run(db, `delete from public.r154_probe where id=1 returning 1`, 'anon');
      expect(del.ok).toBe(false);
      expect(del.message).toContain('rows are immutable');
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t6 — direct invocation remains impossible for every role', async () => {
    const db = await open(MIGRATION, true);

    try {
      const owner = await run(db, `select ${RI}`);
      expect(owner.ok).toBe(false);
      expect(owner.message).toContain('trigger functions can only be called as triggers');

      for (const role of ['service_role', 'anon', 'authenticated']) {
        const r = await run(db, `select ${RI}`, role);
        expect(r.ok, `${role} must not be able to call it`).toBe(false);
      }
    } finally {
      await db.close();
    }
  }, 120_000);

  it('t7 — a live-patched database and a fresh install behave identically', async () => {
    const fresh = await open(MIGRATION, true);
    const patched = await openLiveLike();

    try {
      await patched.exec(RESTORE11);

      expect(await aclRows(patched)).toEqual(await aclRows(fresh));

      for (const db of [fresh, patched]) {
        await db.exec(seed);
      }

      const probe = `update public.qhub_acknowledgments set user_id='u2' where user_id='u1' returning 1`;
      const a = await run(fresh, probe, 'service_role');
      const b = await run(patched, probe, 'service_role');
      expect(b.ok).toBe(a.ok);
      expect(b.message).toBe(a.message);
    } finally {
      await fresh.close();
      await patched.close();
    }
  }, 240_000);
});

// ─── the live transition ───────────────────────────────────────────────────────

describe('R15.4 — the package authorizes exactly the documented ACL transition', () => {
  it('L1 — the documented live state (5-row ACL + mojibake) is SAFE', async () => {
    const db = await openLiveLike();

    try {
      expect(await aclRows(db)).toHaveLength(5);
      await db.exec(PRE10);
      expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');
    } finally {
      await db.close();
    }
  }, 120_000);

  const START_DRIFT: Array<[string, string]> = [
    ['L2 — an unexpected sixth ACL row', `CREATE ROLE r154_x NOLOGIN; GRANT EXECUTE ON FUNCTION ${RI} TO r154_x;`],
    ['L3 — a missing expected ACL row', `REVOKE EXECUTE ON FUNCTION ${RI} FROM anon;`],
    ['L4 — grant-option drift', `GRANT EXECUTE ON FUNCTION ${RI} TO service_role WITH GRANT OPTION;`],
    ['L5 — the owner row removed', `REVOKE EXECUTE ON FUNCTION ${RI} FROM postgres;`],
  ];

  for (const [name, drift] of START_DRIFT) {
    it(`${name} => STOP, and 11 refuses`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(drift);

        await db.exec(PRE10);
        expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

        const before = await aclRows(db);
        await expect(db.exec(RESTORE11)).rejects.toThrow(/unexpected_function_(acl_state|state)/);
        await rollback(db);
        expect(await aclRows(db), 'drift survives as evidence').toEqual(before);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('L6 — 11 restores bodies and normalizes the ACL atomically', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      expect(await aclRows(db)).toEqual(OWNER_ONLY);

      const rows = await (async () => {
        await db.exec(POST12);

        return (await db.query<Record<string, unknown>>(V12)).rows;
      })();
      expect(rows[0].final_status).toBe('R15_3_REVIEWED_BODIES_RESTORED');
      expect(rows.every((r) => r.function_ok === true)).toBe(true);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('L7 — a mangled transfer of 11 rolls BOTH the bodies and the ACL back', async () => {
    const db = await openLiveLike();

    try {
      const snapshot = async () =>
        JSON.stringify({
          acl: await aclRows(db),
          bodies: (
            await db.query<{ proname: string; m: string }>(
              `select p.proname, md5(p.prosrc) m from pg_proc p join pg_namespace n on n.oid=p.pronamespace
                where n.nspname='public' and p.proname in ('qhub_decide_review','qhub_row_immutable') order by 1`,
            )
          ).rows,
        });
      const before = await snapshot();

      await expect(db.exec(mangle(RESTORE11))).rejects.toThrow(/R15\.3/);
      await rollback(db);

      expect(await snapshot(), 'bodies AND ACL revert together').toBe(before);
    } finally {
      await db.close();
    }
  }, 120_000);

  it('L8 — a second application is idempotent under the final reviewed state', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(RESTORE11);
      await db.exec(RESTORE11);

      expect(await aclRows(db)).toEqual(OWNER_ONLY);
      await db.exec(POST12);
      expect((await db.query<Record<string, unknown>>(V12)).rows[0].final_status).toBe(
        'R15_3_REVIEWED_BODIES_RESTORED',
      );
    } finally {
      await db.close();
    }
  }, 120_000);

  const POST_DRIFT: Array<[string, string]> = [
    ['L9 — PUBLIC granted after the patch', `GRANT EXECUTE ON FUNCTION ${RI} TO PUBLIC;`],
    ['L10 — anon granted after the patch', `GRANT EXECUTE ON FUNCTION ${RI} TO anon;`],
    ['L11 — authenticated granted after the patch', `GRANT EXECUTE ON FUNCTION ${RI} TO authenticated;`],
    ['L12 — service_role granted after the patch', `GRANT EXECUTE ON FUNCTION ${RI} TO service_role;`],
    ['L13 — the trigger detached', `DROP TRIGGER trg_qhub_acknowledgments_immutable ON public.qhub_acknowledgments;`],
  ];

  for (const [name, drift] of POST_DRIFT) {
    it(`${name} => R15_3_BODY_RESTORE_NOT_READY`, async () => {
      const db = await openLiveLike();

      try {
        await db.exec(RESTORE11);
        await db.exec(drift);
        await db.exec(POST12);

        const rows = (await db.query<Record<string, unknown>>(V12)).rows;
        expect(rows[0].final_status).toBe('R15_3_BODY_RESTORE_NOT_READY');
        expect(
          rows.every((r) => r.body_reviewed === true),
          'the bodies are still correct — only the ACL/trigger failed',
        ).toBe(true);
      } finally {
        await db.close();
      }
    }, 120_000);
  }

  it('L14 — the full sequence reaches R15_2_VERIFIER_READY', async () => {
    const db = await openLiveLike();

    try {
      await db.exec(PRE10);
      expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('SAFE_TO_RESTORE_REVIEWED_BODIES');

      await db.exec(RESTORE11);
      await db.exec(POST12);
      expect((await db.query<Record<string, unknown>>(V12)).rows[0].final_status).toBe(
        'R15_3_REVIEWED_BODIES_RESTORED',
      );

      await db.exec(PRE07);
      expect((await db.query<{ verdict: string }>(V07)).rows[0].verdict).toBe('SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH');

      await db.exec(PATCH08);
      await db.exec(POST09);

      const r = (await db.query<Record<string, unknown>>(V09)).rows[0];
      expect(r.final_status).toBe('R15_2_VERIFIER_READY');
      expect(r.product_ready).toBe('true');
      expect(r.product_failed_count).toBe('0');
      expect(r.product_version).toBe('2026-07-30.commercial-launch-r8');
    } finally {
      await db.close();
    }
  }, 300_000);

  it('L15 — ACL drift blocks the R15.2C continuation', async () => {
    const db = await openLiveLike();

    try {
      /*
       * anon already holds EXECUTE in the documented start state, so granting it again
       * would be a no-op. Removing an expected row is the real drift.
       */
      await db.exec(`REVOKE EXECUTE ON FUNCTION ${RI} FROM anon;`);
      await db.exec(PRE10);
      expect((await db.query<{ verdict: string }>(V10)).rows[0].verdict).toBe('UNEXPECTED_LIVE_BODY_STOP');

      // and the bodies remain mojibake, so R15.2C's own precheck also refuses
      await db.exec(PRE07);
      expect((await db.query<{ verdict: string }>(V07)).rows[0].verdict).toBe('UNEXPECTED_FUNCTION_BODY_STOP');
    } finally {
      await db.close();
    }
  }, 120_000);
});
