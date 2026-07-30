/**
 * QHUB Commercial Launch R12 — PERSISTED + REVALIDATED CLASSIFICATION AUTHORITY (PGlite)
 * app/test/commercial-r12-classification.test.ts
 *
 * Closes P1-A (stale-classification false approval): classification scheme id/version + risk tier are
 * persisted as independently revalidatable columns on the review request, bound into the request hash,
 * required for terminal rows, and reloaded + compared against current authority on EVERY decision —
 * including an exact terminal repeat — under a config-row lock. Any drift ⇒ classification_changed with
 * zero side effect. Verifier R8 pins the binding columns, terminal constraint, RPC bodies, and version.
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
const SCHEME = GOVERNANCE_CLASSIFICATION_SCHEME_ID;
const SVER = GOVERNANCE_CLASSIFICATION_SCHEME_VERSION;
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

/** REVIEW_REQUIRED project bound to an ACTIVE ack via the sole authority RPC, plus an active reviewer. */
async function seedAcknowledged(db: PGlite, riskTier = 'UNCLASSIFIED') {
  const pid = '5c000000-0000-0000-0000-000000000001';
  const gid = '6c000000-0000-0000-0000-000000000001';
  await db.exec(`
    insert into public.qhub_org_members (org_id, user_id, role, status) values ('o1','u1','builder','active');
    insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
    insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true);
    insert into public.qhub_governance_essentials
      (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash, policy_card_version, data_classes, declaration_complete, risk_tier)
      values ('${gid}','${pid}','o1','manual_review','requested', 4, '${H64}', '${CARD}', '["personal"]'::jsonb, true, '${riskTier}');
  `);

  const ack = await db.query<{ v: { ok: boolean; record_id: string } }>(
    `select public.qhub_record_acknowledgment('o1','${pid}','u1','ACKNOWLEDGE') v`,
  );
  expect(ack.rows[0].v.ok).toBe(true);

  return { pid, gid, aid: ack.rows[0].v.record_id };
}

async function createReview(db: PGlite, pid: string, key = 'k1') {
  const c = await db.query<{ v: { ok: boolean; request_id: string } }>(
    `select public.qhub_create_review_request('o1','${pid}','u1','sensitive data','${key}') v`,
  );
  expect(c.rows[0].v.ok).toBe(true);

  return c.rows[0].v.request_id;
}

async function noSideEffect(db: PGlite, gid: string) {
  const gov = await db.query<{ rs: string }>(
    `select review_state rs from public.qhub_governance_essentials where id='${gid}'`,
  );
  expect(gov.rows[0].rs).toBe('requested'); // Governance not mutated

  const aud = await db.query<{ n: number }>(
    `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
  );
  expect(aud.rows[0].n).toBe(0); // no audit evidence
}

// ─── §11 CLASSIFICATION BINDING ──────────────────────────────────────────────────

describe('R12 §1 — classification binding is persisted + revalidated', () => {
  it('a new review persists scheme id/version/risk tier (test 1)', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db, 'T1');
      const rid = await createReview(db, pid);

      const row = await db.query<{ sid: string; sver: string; rt: string }>(
        `select classification_scheme_id sid, classification_scheme_version sver, classification_risk_tier rt
           from public.qhub_manual_review_requests where id='${rid}'`,
      );
      expect(row.rows[0]).toEqual({ sid: SCHEME, sver: SVER, rt: 'T1' });
    } finally {
      await db.close();
    }
  });

  it('the request hash binds the persisted classification fields (test 2)', async () => {
    const dbA = await freshDb();
    const dbB = await freshDb();

    try {
      const a = await seedAcknowledged(dbA, 'T1');
      const ra = await createReview(dbA, a.pid);
      const ha = await dbA.query<{ h: string }>(
        `select request_hash h from public.qhub_manual_review_requests where id='${ra}'`,
      );

      // Same inputs but a different risk tier ⇒ a different bound hash (risk tier is in the canon cells).
      const b = await seedAcknowledged(dbB, 'T2');
      const rb = await createReview(dbB, b.pid);
      const hb = await dbB.query<{ h: string }>(
        `select request_hash h from public.qhub_manual_review_requests where id='${rb}'`,
      );

      expect(ha.rows[0].h).not.toBe(hb.rows[0].h);
    } finally {
      await dbA.close();
      await dbB.close();
    }
  });

  it('a changed classification scheme version rejects a pending approval (test 3) with zero side effect (test 8)', async () => {
    const db = await freshDb();

    try {
      const { pid, gid } = await seedAcknowledged(db);
      const rid = await createReview(db, pid);

      // The authoritative classification scheme advances after the review was created.
      await db.exec(
        `update public.qhub_commercial_authority set classification_scheme_version='2026-07-30.classification.v999' where id=1`,
      );

      const dec = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(dec.rows[0].v.ok).toBe(false);
      expect(dec.rows[0].v.reason).toBe('classification_changed');
      await noSideEffect(db, gid);
    } finally {
      await db.close();
    }
  });

  it('a changed risk tier rejects a pending approval (test 4) with zero side effect', async () => {
    const db = await freshDb();

    try {
      const { pid, gid } = await seedAcknowledged(db, 'T1');
      const rid = await createReview(db, pid);

      // The Governance risk tier is reclassified after the review was created.
      await db.exec(`update public.qhub_governance_essentials set risk_tier='T2' where id='${gid}'`);

      const dec = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(dec.rows[0].v.ok).toBe(false);
      expect(dec.rows[0].v.reason).toBe('classification_changed');
      await noSideEffect(db, gid);
    } finally {
      await db.close();
    }
  });

  it('a terminal exact repeat FAILS after classification drift (test 5)', async () => {
    const db = await freshDb();

    try {
      const { pid } = await seedAcknowledged(db);
      const rid = await createReview(db, pid);

      const ok = await db.query<{ v: { ok: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);

      // Classification authority drifts AFTER approval; the exact terminal repeat must not be idempotent.
      await db.exec(
        `update public.qhub_commercial_authority set classification_scheme_version='2026-07-30.classification.v999' where id=1`,
      );

      const rep = await db.query<{ v: { ok: boolean; idempotent?: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.ok).toBe(false);
      expect(rep.rows[0].v.idempotent).toBeUndefined();
      expect(rep.rows[0].v.reason).toBe('classification_changed');

      // Still exactly one audit row (the original approval) — the failed repeat added none.
      const aud = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(aud.rows[0].n).toBe(1);
    } finally {
      await db.close();
    }
  });

  it('a legacy review with NO classification binding is non-authorizing (test 6)', async () => {
    const db = await freshDb();

    try {
      const { pid, gid, aid } = await seedAcknowledged(db);
      const rid = '4d000000-0000-0000-0000-000000000001';

      // A legacy row fully bound EXCEPT classification (columns left NULL) — readable but never terminalizes.
      await db.exec(`
        insert into public.qhub_manual_review_requests
          (id, org_id, project_id, request_type, category, reason, request_hash, status,
           governance_record_id, governance_record_version, declaration_identity_hash, policy_version,
           required_acknowledgment_version, acknowledgment_record_id, acknowledgment_version, requester_user_id)
          values ('${rid}','o1','${pid}','data_review','personal','sensitive','h','pending',
           '${gid}', 4, '${H64}', '${POL}', '${ACK}', '${aid}', '${ACK}', 'u1');
      `);

      const dec = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(dec.rows[0].v.ok).toBe(false);
      expect(dec.rows[0].v.reason).toBe('non_authorizing_legacy_review');
      await noSideEffect(db, gid);
    } finally {
      await db.close();
    }
  });

  it('the decision RPC locks the authoritative config row FOR SHARE so classification cannot race (test 7)', async () => {
    const db = await freshDb();

    try {
      /*
       * TOCTOU protection is structural: the decision reloads + locks the config row that carries
       * classification authority within the same transaction, so a concurrent config mutation cannot
       * commit between revalidation and mutation. Pin that the RPC body takes the lock.
       */
      const body = await db.query<{ src: string }>(`select prosrc src from pg_proc where proname='qhub_decide_review'`);
      expect(body.rows[0].src).toMatch(/qhub_commercial_authority WHERE id = 1 FOR SHARE/);

      // And the classification revalidation precedes the terminal-repeat branch (validate-before-mutate).
      const idxClassif = body.rows[0].src.indexOf('classification_changed');
      const idxTerminal = body.rows[0].src.indexOf("r.status <> 'pending'");
      expect(idxClassif).toBeGreaterThan(0);
      expect(idxClassif).toBeLessThan(idxTerminal);
    } finally {
      await db.close();
    }
  });
});

// ─── §11 VERIFIER (tests 9-14) ───────────────────────────────────────────────────

describe('R12 §4 — verifier R8 fails closed on classification-binding drift', () => {
  it('is READY at r8 on a healthy schema; second apply idempotent', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const v = await verify(db);
      expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
      expect(v.ready, v.failed.join('\n')).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('a removed classification binding column fails READY (test 9)', async () => {
    const db = await freshDb();

    try {
      await db.exec(`ALTER TABLE public.qhub_manual_review_requests DROP COLUMN classification_risk_tier`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r8_review_classification_column:classification_risk_tier');
    } finally {
      await db.close();
    }
  });

  it('a weakened terminal classification constraint fails READY (test 11)', async () => {
    const db = await freshDb();

    try {
      await db.exec(
        `ALTER TABLE public.qhub_manual_review_requests DROP CONSTRAINT chk_qhub_review_classification_binding`,
      );
      await db.exec(
        `ALTER TABLE public.qhub_manual_review_requests ADD CONSTRAINT chk_qhub_review_classification_binding CHECK (true) NOT VALID`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r6_constraint_semantics:chk_qhub_review_classification_binding');
    } finally {
      await db.close();
    }
  });

  it('a create RPC that omits classification persistence fails READY (test 12)', async () => {
    const db = await freshDb();

    try {
      // Replace the create RPC body with one that does not persist classification columns.
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_create_review_request(
          p_org_id TEXT, p_project_id UUID, p_requester TEXT, p_reason TEXT, p_idempotency_key TEXT
        ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN jsonb_build_object('ok', true); END; $f$;
      `);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_create_review_body_drift');
    } finally {
      await db.close();
    }
  });

  it('a decision RPC that omits classification revalidation fails READY (test 13)', async () => {
    const db = await freshDb();

    try {
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_decide_review(
          p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
        ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN jsonb_build_object('ok', true); END; $f$;
      `);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('decide_review_body_drift');
    } finally {
      await db.close();
    }
  });

  it('classification config drift (missing authority column) fails READY (test 14)', async () => {
    const db = await freshDb();

    try {
      await db.exec(`ALTER TABLE public.qhub_commercial_authority DROP COLUMN classification_scheme_version`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r7_authority_column:classification_scheme_version');
    } finally {
      await db.close();
    }
  });
});
