/**
 * QHUB Commercial Launch R11 — FINAL AUTHORITY CLOSURE adversarial contract (PGlite)
 * app/test/commercial-r11-authority.test.ts
 *
 * Reproduces and pins the eight R10 blockers R11 repairs:
 *   §5  the decision RPC FULLY revalidates current authority BEFORE every return — including an exact
 *       terminal repeat — so a revoked/superseded acknowledgment after approval makes a repeat FAIL,
 *       not return idempotent success;
 *   §1  a single atomic server-only acknowledgment RPC is the sole authority path;
 *   §2  the acknowledgment lifecycle trigger protects every authority field + enforces exact
 *       status/timestamp consistency and one-way transitions;
 *   §3  the review-create RPC resolves ALL authority in the DB (no trusted authority parameters) and
 *       binds classification identity/version into the canonical hash;
 *   §6  the verifier R7 pins ack immutability, canon_cells, RPC owners, service_role EXECUTE, forced
 *       RLS, broad-policy absence, and the DB-authoritative config row — material drift → NOT READY;
 *   and the TS ↔ DB config parity of the authoritative version/classification identities.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';
import {
  currentReviewPolicyVersion,
  currentRequiredAcknowledgmentVersion,
  currentGovernancePolicyCardVersion,
  GOVERNANCE_CLASSIFICATION_SCHEME_ID,
  GOVERNANCE_CLASSIFICATION_SCHEME_VERSION,
} from '~/lib/qhub/commercial/governance-essentials';

const MIG = fileURLToPath(
  new URL('../../supabase/migrations/20260729_commercial_launch_foundation.sql', import.meta.url),
);
const sql = readFileSync(MIG, 'utf8');

const POL = currentReviewPolicyVersion();
const ACK = currentRequiredAcknowledgmentVersion();
const CARD = currentGovernancePolicyCardVersion();
const H64 = 'a'.repeat(64);

async function freshDb(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  `);
  await db.exec(sql);

  return db;
}

async function verify(db: PGlite): Promise<{ expected_version: string; ready: boolean; failed: string[] }> {
  const r = await db.query<{ v: { expected_version: string; ready: boolean; failed: string[] } }>(
    `select public.qhub_verify_commercial_schema() v`,
  );

  return r.rows[0].v;
}

/**
 * A REVIEW_REQUIRED project whose Governance record is bound to an ACTIVE acknowledgment through the
 * ONLY authority path (qhub_record_acknowledgment), plus an active reviewer. Nothing is written to the
 * ack/governance authority columns directly.
 */
async function seedAcknowledged(db: PGlite) {
  const pid = '5a000000-0000-0000-0000-000000000001';
  const gid = '6a000000-0000-0000-0000-000000000001';
  await db.exec(`
    insert into public.qhub_org_members (org_id, user_id, role, status) values ('o1','u1','builder','active');
    insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
    insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true);
    insert into public.qhub_governance_essentials
      (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash, policy_card_version, data_classes, declaration_complete)
      values ('${gid}','${pid}','o1','manual_review','requested', 4, '${H64}', '${CARD}', '["personal"]'::jsonb, true);
  `);

  // Bind the ack via the sole atomic RPC (never a direct table write).
  const ack = await db.query<{ v: { ok: boolean; record_id: string } }>(
    `select public.qhub_record_acknowledgment('o1','${pid}','u1','ACKNOWLEDGE') v`,
  );
  expect(ack.rows[0].v.ok).toBe(true);

  return { pid, gid, aid: ack.rows[0].v.record_id };
}

async function createReview(db: PGlite, pid: string, key = 'k1', reason = 'sensitive data') {
  const c = await db.query<{ v: { ok: boolean; request_id: string; reason?: string } }>(
    `select public.qhub_create_review_request('o1','${pid}','u1','${reason}','${key}') v`,
  );

  return c.rows[0].v;
}

// ─── §1/§2 — acknowledgment authority model ──────────────────────────────────────

describe('R11 §1/§2 — acknowledgment authority model', () => {
  it('ACKNOWLEDGE creates ONE ACTIVE ack; an exact retry is idempotent (same record, no duplicate)', async () => {
    const db = await freshDb();

    try {
      const { pid, aid } = await seedAcknowledged(db);

      const retry = await db.query<{ v: { idempotent: boolean; record_id: string } }>(
        `select public.qhub_record_acknowledgment('o1','${pid}','u1','ACKNOWLEDGE') v`,
      );
      expect(retry.rows[0].v.idempotent).toBe(true);
      expect(retry.rows[0].v.record_id).toBe(aid);

      const n = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_acknowledgments where project_id='${pid}' and status='ACTIVE'`,
      );
      expect(n.rows[0].n).toBe(1);
    } finally {
      await db.close();
    }
  });

  it('a direct authority-field mutation of an ack is rejected by the immutability trigger', async () => {
    const db = await freshDb();

    try {
      const { aid } = await seedAcknowledged(db);

      // Type-valid replacements per column, so the immutability trigger (not a cast error) is what rejects.
      const mutations: Array<[string, string]> = [
        ['ack_version', `'CHANGED'`],
        ['required_version', `'CHANGED'`],
        ['user_id', `'someone_else'`],
        ['org_id', `'other_org'`],
        ['project_id', `'00000000-0000-0000-0000-0000000000aa'::uuid`],
        ['governance_record_id', `'00000000-0000-0000-0000-0000000000bb'::uuid`],
      ];

      for (const [col, val] of mutations) {
        await expect(db.exec(`update public.qhub_acknowledgments set ${col}=${val} where id='${aid}'`)).rejects.toThrow(
          /immutable/,
        );
      }
    } finally {
      await db.close();
    }
  });

  it('a direct DELETE of an ack row is rejected by the immutability trigger', async () => {
    const db = await freshDb();

    try {
      const { aid } = await seedAcknowledged(db);
      await expect(db.exec(`delete from public.qhub_acknowledgments where id='${aid}'`)).rejects.toThrow(/immutable/);
    } finally {
      await db.close();
    }
  });

  it('an inconsistent lifecycle status/timestamp combination is rejected by the CHECK constraint', async () => {
    const db = await freshDb();

    try {
      await seedAcknowledged(db);

      const base = `insert into public.qhub_acknowledgments (org_id, user_id, ack_type, ack_version, project_id, required_version, status`;

      // ACTIVE must have revoked_at NULL + superseded_at NULL.
      await expect(
        db.exec(
          `${base}, revoked_at) values ('o2','u9','acceptable_use','${ACK}','5a000000-0000-0000-0000-0000000000ff','${ACK}','ACTIVE', now())`,
        ),
      ).rejects.toThrow(/chk_qhub_ack_lifecycle/);

      // REVOKED must have revoked_at NOT NULL.
      await expect(
        db.exec(
          `${base}) values ('o3','u9','acceptable_use','${ACK}','5a000000-0000-0000-0000-0000000000fe','${ACK}','REVOKED')`,
        ),
      ).rejects.toThrow(/chk_qhub_ack_lifecycle/);

      // SUPERSEDED must have superseded_at NOT NULL (and revoked_at NULL).
      await expect(
        db.exec(
          `${base}) values ('o4','u9','acceptable_use','${ACK}','5a000000-0000-0000-0000-0000000000fd','${ACK}','SUPERSEDED')`,
        ),
      ).rejects.toThrow(/chk_qhub_ack_lifecycle/);
    } finally {
      await db.close();
    }
  });

  it('ACTIVE→REVOKED succeeds via the RPC and unbinds the Governance record', async () => {
    const db = await freshDb();

    try {
      const { pid, gid, aid } = await seedAcknowledged(db);

      const rev = await db.query<{ v: { ok: boolean; status: string } }>(
        `select public.qhub_record_acknowledgment('o1','${pid}','u1','REVOKE') v`,
      );
      expect(rev.rows[0].v.ok).toBe(true);
      expect(rev.rows[0].v.status).toBe('REVOKED');

      const ack = await db.query<{ status: string; revoked: boolean }>(
        `select status, revoked_at is not null revoked from public.qhub_acknowledgments where id='${aid}'`,
      );
      expect(ack.rows[0].status).toBe('REVOKED');
      expect(ack.rows[0].revoked).toBe(true);

      const gov = await db.query<{ acked: boolean; bound: boolean }>(
        `select acknowledged acked, acknowledgment_record_id is not null bound from public.qhub_governance_essentials where id='${gid}'`,
      );
      expect(gov.rows[0].acked).toBe(false);
      expect(gov.rows[0].bound).toBe(false);
    } finally {
      await db.close();
    }
  });

  it('re-acknowledging after the Governance binding drifts SUPERSEDES the prior ACTIVE and creates a new one', async () => {
    const db = await freshDb();

    try {
      const { pid, gid, aid } = await seedAcknowledged(db);

      /*
       * The Governance record is re-opened (binding cleared) while an ACTIVE ack remains — re-acknowledging
       * must SUPERSEDE the now-orphaned ACTIVE row and bind a fresh one, never leave two ACTIVE rows.
       */
      await db.exec(
        `update public.qhub_governance_essentials set acknowledged=false, acknowledgment_record_id=NULL, acknowledgment_version=NULL, record_version=5 where id='${gid}'`,
      );

      const again = await db.query<{ v: { ok: boolean; idempotent: boolean; record_id: string } }>(
        `select public.qhub_record_acknowledgment('o1','${pid}','u1','ACKNOWLEDGE') v`,
      );
      expect(again.rows[0].v.ok).toBe(true);
      expect(again.rows[0].v.idempotent).toBe(false);
      expect(again.rows[0].v.record_id).not.toBe(aid);

      const prior = await db.query<{ status: string; sup: boolean }>(
        `select status, superseded_at is not null sup from public.qhub_acknowledgments where id='${aid}'`,
      );
      expect(prior.rows[0].status).toBe('SUPERSEDED');
      expect(prior.rows[0].sup).toBe(true);

      const active = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_acknowledgments where project_id='${pid}' and status='ACTIVE'`,
      );
      expect(active.rows[0].n).toBe(1);
    } finally {
      await db.close();
    }
  });

  it('a reverse transition (REVOKED→ACTIVE) is forbidden by the lifecycle trigger', async () => {
    const db = await freshDb();

    try {
      const { pid, aid } = await seedAcknowledged(db);
      await db.query(`select public.qhub_record_acknowledgment('o1','${pid}','u1','REVOKE')`);

      await expect(
        db.exec(`update public.qhub_acknowledgments set status='ACTIVE', revoked_at=NULL where id='${aid}'`),
      ).rejects.toThrow(/immutable/);
    } finally {
      await db.close();
    }
  });

  it('a second ACTIVE ack for the same scope is rejected by the one-active partial unique index', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);

      await expect(
        db.exec(
          `insert into public.qhub_acknowledgments (org_id, user_id, ack_type, ack_version, project_id, required_version, status)
             values ('o1','u1','acceptable_use','${ACK}','${pid}','${ACK}','ACTIVE')`,
        ),
      ).rejects.toThrow(/uq_qhub_ack_one_active|unique/i);
    } finally {
      await db.close();
    }
  });
});

// ─── §5 (P0 #1) — decision revalidates authority BEFORE every return ─────────────

describe('R11 §5 (P0 #1) — decision revalidates current authority before EVERY return', () => {
  it('after approval, an exact repeat while the ack is still ACTIVE returns idempotent', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);
      const rid = (await createReview(db, pid)).request_id;

      const ok = await db.query<{ v: { ok: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);

      const rep = await db.query<{ v: { idempotent: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.idempotent).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('after approval, revoking the acknowledgment makes an exact repeat FAIL (not idempotent success)', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);
      const rid = (await createReview(db, pid)).request_id;

      await db.query(`select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}')`);

      // The authorizing acknowledgment is revoked AFTER approval (through the sole authority RPC).
      await db.query(`select public.qhub_record_acknowledgment('o1','${pid}','u1','REVOKE')`);

      const rep = await db.query<{ v: { ok: boolean; idempotent?: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.ok).toBe(false);
      expect(rep.rows[0].v.idempotent).toBeUndefined();
      expect(rep.rows[0].v.reason).toBe('acknowledgment_not_active');
    } finally {
      await db.close();
    }
  });

  it('after approval, deactivating the reviewer makes an exact repeat FAIL', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);
      const rid = (await createReview(db, pid)).request_id;

      await db.query(`select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}')`);
      await db.exec(`update public.qhub_quantex_staff set active=false where user_id='staff1'`);

      const rep = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.ok).toBe(false);
      expect(rep.rows[0].v.reason).toBe('staff_required');
    } finally {
      await db.close();
    }
  });

  it('after approval, a superseded Governance record makes an exact repeat FAIL', async () => {
    const db = await freshDb();

    try {
      const { pid, gid } = await seedAcknowledged(db);
      const rid = (await createReview(db, pid)).request_id;

      await db.query(`select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}')`);
      await db.exec(`update public.qhub_governance_essentials set record_version=9 where id='${gid}'`);

      const rep = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.ok).toBe(false);
      expect(rep.rows[0].v.reason).toBe('governance_changed');
    } finally {
      await db.close();
    }
  });
});

// ─── §3/§4 — review creation resolves authority in DB + binds classification ─────

describe('R11 §3/§4 — DB-authoritative review creation + classification binding', () => {
  it('creates a fully-bound review from ONLY org/project/requester/reason/key (no authority params)', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);
      const v = await createReview(db, pid);
      expect(v.ok).toBe(true);

      const row = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_manual_review_requests where id='${v.request_id}'
           and policy_version='${POL}' and required_acknowledgment_version='${ACK}'
           and declaration_identity_hash='${H64}' and requester_user_id='u1'
           and governance_record_id is not null and acknowledgment_record_id is not null`,
      );
      expect(row.rows[0].n).toBe(1);
    } finally {
      await db.close();
    }
  });

  it('binds the classification scheme/version into the request hash (config drift ⇒ different identity)', async () => {
    const dbA = await freshDb();
    const dbB = await freshDb();

    try {
      const a = await seedAcknowledged(dbA);
      const hashA = (await createReview(dbA, a.pid)).request_id;
      const hA = await dbA.query<{ h: string }>(
        `select request_hash h from public.qhub_manual_review_requests where id='${hashA}'`,
      );

      // Same inputs, but the DB-authoritative classification version differs ⇒ a different bound hash.
      await dbB.exec(
        `update public.qhub_commercial_authority set classification_scheme_version='2099-01-01.classification.vX' where id=1`,
      );

      const b = await seedAcknowledged(dbB);
      const hashB = (await createReview(dbB, b.pid)).request_id;
      const hB = await dbB.query<{ h: string }>(
        `select request_hash h from public.qhub_manual_review_requests where id='${hashB}'`,
      );

      expect(hA.rows[0].h).not.toBe(hB.rows[0].h);
    } finally {
      await dbA.close();
      await dbB.close();
    }
  });

  it('the canonical cell encoder is delimiter/null-collision safe', async () => {
    const db = await freshDb();

    try {
      const q = async (cells: string) =>
        (await db.query<{ c: string }>(`select public.qhub_canon_cells(${cells}) c`)).rows[0].c;

      // ['a|b'] must not collide with ['a','b'] (length prefix disambiguates the delimiter).
      expect(await q(`ARRAY['a|b']`)).not.toBe(await q(`ARRAY['a','b']`));

      // A NULL cell ('_') must not collide with the literal string '_'.
      expect(await q(`ARRAY[NULL]::text[]`)).not.toBe(await q(`ARRAY['_']`));

      // An empty string is length-0, distinct from NULL.
      expect(await q(`ARRAY['']`)).not.toBe(await q(`ARRAY[NULL]::text[]`));
    } finally {
      await db.close();
    }
  });
});

// ─── §6 — verifier R7 pins material authority semantics ──────────────────────────

describe('R11 §6 — verifier R7 fails closed on material authority drift', () => {
  it('is READY at r7 on a healthy schema; the second apply is idempotent', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql); // healthy second run

      const v = await verify(db);
      expect(v.expected_version).toBe('2026-07-30.commercial-launch-r7');
      expect(v.ready, v.failed.join('\n')).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('disabling the acknowledgment immutability trigger fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`ALTER TABLE public.qhub_acknowledgments DISABLE TRIGGER trg_qhub_acknowledgments_immutable`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_ack_immutable_trigger');
    } finally {
      await db.close();
    }
  });

  it('weakening the canonical cell encoder body fails READY', async () => {
    const db = await freshDb();

    try {
      // A weakened encoder that drops the length prefix (delimiter-ambiguous) has a different digest.
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_canon_cells(p_cells TEXT[])
        RETURNS TEXT LANGUAGE sql IMMUTABLE AS $f$
          SELECT string_agg(coalesce(c,'_'), '|' ORDER BY ord) FROM unnest(p_cells) WITH ORDINALITY AS t(c, ord);
        $f$;
      `);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_canon_cells_body_drift');
    } finally {
      await db.close();
    }
  });

  it('changing the review-create RPC owner fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`CREATE ROLE other_owner NOLOGIN`);
      await db.exec(`ALTER FUNCTION public.qhub_create_review_request(text,uuid,text,text,text) OWNER TO other_owner`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_create_review_owner_drift');
    } finally {
      await db.close();
    }
  });

  it('revoking service_role EXECUTE on the atomic ack RPC fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(
        `REVOKE EXECUTE ON FUNCTION public.qhub_record_acknowledgment(text,uuid,text,text) FROM service_role`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rpc_service_execute_missing:public.qhub_record_acknowledgment');
    } finally {
      await db.close();
    }
  });

  it('granting a browser role EXECUTE on the atomic ack RPC fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(
        `GRANT EXECUTE ON FUNCTION public.qhub_record_acknowledgment(text,uuid,text,text) TO authenticated`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rpc_execute_drift:public.qhub_record_acknowledgment');
    } finally {
      await db.close();
    }
  });

  it('adding a broad permissive policy to an authority table fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`CREATE POLICY p_broad ON public.qhub_acknowledgments FOR SELECT TO authenticated USING (true)`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('extra_policy:qhub_acknowledgments');
    } finally {
      await db.close();
    }
  });

  it('disabling FORCE ROW LEVEL SECURITY on an authority table fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`ALTER TABLE public.qhub_acknowledgments NO FORCE ROW LEVEL SECURITY`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rls_not_forced:qhub_acknowledgments');
    } finally {
      await db.close();
    }
  });

  it('a record_acknowledgment body drift fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_record_acknowledgment(
          p_org_id TEXT, p_project_id UUID, p_user_id TEXT, p_action TEXT
        ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN jsonb_build_object('ok', true); END; $f$;
      `);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_record_ack_body_drift');
    } finally {
      await db.close();
    }
  });

  it('dropping the DB-authoritative config row fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(`DELETE FROM public.qhub_commercial_authority WHERE id=1`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_authority_row_missing');
    } finally {
      await db.close();
    }
  });
});

// ─── config parity — TS constants match the DB-authoritative seed ────────────────

describe('R11 — TS ↔ DB authoritative config parity', () => {
  it('the seeded qhub_commercial_authority row equals the TS authority constants', async () => {
    const db = await freshDb();

    try {
      const row = await db.query<{
        review_policy_version: string;
        required_acknowledgment_version: string;
        policy_card_version: string;
        classification_scheme_id: string;
        classification_scheme_version: string;
      }>(
        `select review_policy_version, required_acknowledgment_version, policy_card_version,
                classification_scheme_id, classification_scheme_version
           from public.qhub_commercial_authority where id=1`,
      );

      expect(row.rows[0]).toEqual({
        review_policy_version: currentReviewPolicyVersion(),
        required_acknowledgment_version: currentRequiredAcknowledgmentVersion(),
        policy_card_version: currentGovernancePolicyCardVersion(),
        classification_scheme_id: GOVERNANCE_CLASSIFICATION_SCHEME_ID,
        classification_scheme_version: GOVERNANCE_CLASSIFICATION_SCHEME_VERSION,
      });
    } finally {
      await db.close();
    }
  });
});
