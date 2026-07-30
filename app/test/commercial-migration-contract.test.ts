/**
 * QHUB Commercial Launch R3 — migration contract on real PostgreSQL (PGlite)
 * app/test/commercial-migration-contract.test.ts
 *
 * Transactional apply + idempotent rerun, the qhub_verify_commercial_schema()
 * readiness contract (ready + exact-semantics drift incl. fake-name index), the
 * project-derived atomic credit RPC (R3), the webhook LEASE claim + crash-recovery,
 * checkout-intent + project-ownership constraints, and append-only immutability.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const MIG = fileURLToPath(
  new URL('../../supabase/migrations/20260729_commercial_launch_foundation.sql', import.meta.url),
);
const sql = readFileSync(MIG, 'utf8');

// R11: the DB-authoritative current versions (seeded into qhub_commercial_authority).
const POL = '2026-07-30.governance-essentials.v1';
const ACK = '2026-07-30.acceptable-use.v1';
const CARD = '2026-07-30.policy-card.v1';

const TABLES = [
  'qhub_commercial_plans',
  'qhub_org_members',
  'qhub_quantex_staff',
  'qhub_org_invitations',
  'qhub_billing_customers',
  'qhub_subscriptions',
  'qhub_checkout_intents',
  'qhub_billing_webhook_events',
  'qhub_usage_credits',
  'qhub_usage_ledger',
  'qhub_project_entitlements',
  'qhub_onboarding_state',
  'qhub_acknowledgments',
  'qhub_governance_essentials',
  'qhub_manual_review_requests',
  'qhub_entitlement_audit',
];

async function freshDb(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  `);

  return db;
}

async function verify(db: PGlite): Promise<{ expected_version: string; ready: boolean; failed: string[] }> {
  const r = await db.query<{ v: { expected_version: string; ready: boolean; failed: string[] } }>(
    `select public.qhub_verify_commercial_schema() v`,
  );
  return r.rows[0].v;
}

/** Seed an active org with a project + active subscription so the credit RPC runs. */
async function seedProject(
  db: PGlite,
  org = 'org_x',
  project = '11111111-1111-1111-1111-111111111111',
  plan = 'builder_beta',
) {
  await db.exec(`
    insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
      values ('${project}','${org}','${plan}', true);
    insert into public.qhub_subscriptions (org_id, plan_id, status, provider)
      values ('${org}','${plan}','active','stripe');
  `);
}

describe('commercial-launch R3 migration', () => {
  it('applies transactionally and is idempotent (runs twice)', async () => {
    const db = await freshDb();

    try {
      await expect(db.exec(sql)).resolves.toBeDefined();
      await expect(db.exec(sql)).resolves.toBeDefined();
    } finally {
      await db.close();
    }
  });

  it('verifier is READY at the R3 version after a healthy run', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const v = await verify(db);
      expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
      expect(v.failed).toEqual([]);
      expect(v.ready).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('enables RLS + service-only policy on every table; denies browser roles', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      for (const t of TABLES) {
        const rls = await db.query<{ r: boolean }>(
          `select relrowsecurity r from pg_class where oid=('public.'||$1)::regclass`,
          [t],
        );
        expect(rls.rows[0].r, `${t} rls`).toBe(true);

        const anon = await db.query<{ ok: boolean }>(
          `select has_table_privilege('anon',('public.'||$1)::regclass,'SELECT') ok`,
          [t],
        );
        expect(anon.rows[0].ok, `anon ${t}`).toBe(false);
      }
    } finally {
      await db.close();
    }
  });

  it('verifier detects a FAKE-NAME index (right name, wrong definition)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`DROP INDEX public.uq_qhub_guided_one_active_project`);

      // Same name, wrong columns/predicate — a name-only check would pass; ours fails.
      await db.exec(
        `CREATE UNIQUE INDEX uq_qhub_guided_one_active_project ON public.qhub_project_entitlements (project_id)`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('index_semantics:guided_one_active');
    } finally {
      await db.close();
    }
  });

  it('verifier fails on weakened RLS and on a browser-granted credit RPC', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`ALTER TABLE public.qhub_subscriptions DISABLE ROW LEVEL SECURITY`);
      await db.exec(`GRANT EXECUTE ON FUNCTION public.qhub_consume_build_credit(uuid,text,text,integer) TO anon`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rls_disabled:qhub_subscriptions');
      expect(v.failed).toContain('credit_rpc_browser_exec');
    } finally {
      await db.close();
    }
  });

  it('credit RPC (R3): derives org, decrements atomically, idempotent, rejects changed request', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await seedProject(db);

      const period = new Date().toISOString().slice(0, 7);

      // Fix a small allotment for the current period to test exhaustion deterministically.
      await db.exec(`insert into public.qhub_usage_credits (org_id, period_key, period_start, period_end, allotted, used)
                     values ('org_x','${period}', now(), now()+interval '30 days', 2, 0)`);

      const c1 = await db.query<{ v: { ok: boolean; remaining: number } }>(
        `select public.qhub_consume_build_credit('11111111-1111-1111-1111-111111111111','k1','h1',1) v`,
      );
      expect(c1.rows[0].v.ok).toBe(true);
      expect(c1.rows[0].v.remaining).toBe(1);

      // exact idempotent retry
      const retry = await db.query<{ v: { ok: boolean; idempotent: boolean; remaining: number } }>(
        `select public.qhub_consume_build_credit('11111111-1111-1111-1111-111111111111','k1','h1',1) v`,
      );
      expect(retry.rows[0].v.idempotent).toBe(true);
      expect(retry.rows[0].v.remaining).toBe(1);

      // changed hash under same key → conflict
      const conflict = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_consume_build_credit('11111111-1111-1111-1111-111111111111','k1','DIFFERENT',1) v`,
      );
      expect(conflict.rows[0].v.ok).toBe(false);
      expect(conflict.rows[0].v.reason).toBe('idempotency_conflict');

      // exhaustion
      await db.query(`select public.qhub_consume_build_credit('11111111-1111-1111-1111-111111111111','k2','h2',1) v`);

      const empty = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_consume_build_credit('11111111-1111-1111-1111-111111111111','k3','h3',1) v`,
      );
      expect(empty.rows[0].v.ok).toBe(false);
      expect(empty.rows[0].v.reason).toBe('insufficient_credits');

      const led = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_usage_ledger where org_id='org_x'`,
      );
      expect(led.rows[0].n).toBe(2);
    } finally {
      await db.close();
    }
  });

  it('credit RPC rejects an ineligible (canceled) subscription and unknown project', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
                     values ('22222222-2222-2222-2222-222222222222','org_c','builder_beta', true)`);
      await db.exec(`insert into public.qhub_subscriptions (org_id, plan_id, status, provider)
                     values ('org_c','builder_beta','canceled','stripe')`);

      const r = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_consume_build_credit('22222222-2222-2222-2222-222222222222','k','h',1) v`,
      );
      expect(r.rows[0].v.reason).toBe('ineligible_subscription');

      const unknown = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_consume_build_credit('33333333-3333-3333-3333-333333333333','k','h',1) v`,
      );
      expect(unknown.rows[0].v.reason).toBe('unknown_project');
    } finally {
      await db.close();
    }
  });

  it('webhook LEASE: claim, active lease not stealable, reclaim after expiry', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const c1 = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct',100,'ph','worker_a',300) s`,
      );
      expect(c1.rows[0].s).toBe('CLAIMED');

      // A second worker cannot steal an active lease.
      const c2 = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct',100,'ph','worker_b',300) s`,
      );
      expect(c2.rows[0].s).toBe('IN_PROGRESS');

      // Expire the lease → the crashed PROCESSING event is reclaimable.
      await db.exec(
        `update public.qhub_billing_webhook_events set lease_expires_at = now() - interval '1 minute' where provider_event_id='evt_1'`,
      );

      const c3 = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct',100,'ph','worker_b',300) s`,
      );
      expect(c3.rows[0].s).toBe('CLAIMED');

      // Once PROCESSED, it is a DUPLICATE.
      await db.exec(`update public.qhub_billing_webhook_events set state='PROCESSED' where provider_event_id='evt_1'`);

      const c4 = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct',100,'ph','worker_c',300) s`,
      );
      expect(c4.rows[0].s).toBe('DUPLICATE');
    } finally {
      await db.close();
    }
  });

  it('enforces one active guided project + append-only ledger/acknowledgments', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
                     values (gen_random_uuid(),'org_g','guided_builder', true)`);
      await expect(
        db.exec(`insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
                 values (gen_random_uuid(),'org_g','guided_builder', true)`),
      ).rejects.toThrow(/uq_qhub_guided_one_active_project|duplicate key/);

      await db.exec(
        `insert into public.qhub_acknowledgments (org_id,user_id,ack_type,ack_version) values ('o','u','terms','1')`,
      );
      await expect(db.exec(`update public.qhub_acknowledgments set ack_version='2' where org_id='o'`)).rejects.toThrow(
        /immutable/,
      );
    } finally {
      await db.close();
    }
  });

  it('seat RPC accepts under the cap and rejects at the cap (transactional)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const i1 = '10000000-0000-0000-0000-000000000001';
      const i2 = '10000000-0000-0000-0000-000000000002';

      // Builder Beta subscription → the RPC derives seat cap = 1 (never caller-supplied).
      await db.exec(`
        insert into public.qhub_subscriptions (org_id, plan_id, status, provider)
          values ('o1','builder_beta','active','stripe');
        insert into public.qhub_org_invitations (id, org_id, email, role, token_hash, expires_at)
          values ('${i1}','o1','a@x.com','builder','tok1', now()+interval '1 day'),
                 ('${i2}','o1','b@x.com','builder','tok2', now()+interval '1 day');
      `);

      // Wrong email / wrong token are rejected.
      const em = await db.query<{ s: string }>(
        `select public.qhub_accept_invitation('${i1}','u1','WRONG@x.com','tok1') s`,
      );
      expect(em.rows[0].s).toBe('EMAIL_MISMATCH');

      const tk = await db.query<{ s: string }>(
        `select public.qhub_accept_invitation('${i1}','u1','a@x.com','WRONG') s`,
      );
      expect(tk.rows[0].s).toBe('TOKEN_MISMATCH');

      const a1 = await db.query<{ s: string }>(`select public.qhub_accept_invitation('${i1}','u1','a@x.com','tok1') s`);
      expect(a1.rows[0].s).toBe('ACCEPTED');

      // Plan-derived cap = 1 → the second acceptance is rejected (no caller cap).
      const a2 = await db.query<{ s: string }>(`select public.qhub_accept_invitation('${i2}','u2','b@x.com','tok2') s`);
      expect(a2.rows[0].s).toBe('SEAT_LIMIT');

      const n = await db.query<{ c: number }>(
        `select count(*)::int c from public.qhub_org_members where org_id='o1' and status='active'`,
      );
      expect(n.rows[0].c).toBe(1);
    } finally {
      await db.close();
    }
  });

  it('enforces one active invitation per org+email', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`insert into public.qhub_org_invitations (org_id,email,role,token_hash,expires_at)
                     values ('o1','dup@x.com','builder','t', now()+interval '1 day')`);
      await expect(
        db.exec(`insert into public.qhub_org_invitations (org_id,email,role,token_hash,expires_at)
                 values ('o1','DUP@x.com','builder','t', now()+interval '1 day')`),
      ).rejects.toThrow(/uq_qhub_invitation_active|duplicate key/);
    } finally {
      await db.close();
    }
  });

  it('checkout-intent consume: matching binds; wrong price / expired / replay handled', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const id = '20000000-0000-0000-0000-000000000001';
      await db.exec(`
        insert into public.qhub_checkout_intents
          (id, org_id, requested_by, plan_id, expected_recurring_price_id, expected_mode, expected_app_origin, idempotency_key, nonce, expires_at)
        values ('${id}','o1','u1','builder_beta','price_r','test','https://x','k','n', now()+interval '10 min');
      `);

      const c1 = await db.query<{ s: string }>(
        `select public.qhub_consume_checkout_intent('${id}','o1','price_r','test',null,'sess','cus','sub1') s`,
      );
      expect(c1.rows[0].s).toBe('CONSUMED');

      const c2 = await db.query<{ s: string }>(
        `select public.qhub_consume_checkout_intent('${id}','o1','price_r','test',null,'sess','cus','sub1') s`,
      );
      expect(c2.rows[0].s).toBe('ALREADY');

      const c3 = await db.query<{ s: string }>(
        `select public.qhub_consume_checkout_intent('${id}','o1','price_r','test',null,'sess','cus','sub_OTHER') s`,
      );
      expect(c3.rows[0].s).toBe('MISMATCH');

      const id2 = '20000000-0000-0000-0000-000000000002';
      await db.exec(`insert into public.qhub_checkout_intents
        (id, org_id, requested_by, plan_id, expected_recurring_price_id, expected_mode, expected_app_origin, idempotency_key, nonce, expires_at)
        values ('${id2}','o1','u1','builder_beta','price_r','test','https://x','k2','n2', now()+interval '10 min')`);

      const c4 = await db.query<{ s: string }>(
        `select public.qhub_consume_checkout_intent('${id2}','o1','price_WRONG','test',null,'sess','cus','subx') s`,
      );
      expect(c4.rows[0].s).toBe('MISMATCH');

      const id3 = '20000000-0000-0000-0000-000000000003';
      await db.exec(`insert into public.qhub_checkout_intents
        (id, org_id, requested_by, plan_id, expected_recurring_price_id, expected_mode, expected_app_origin, idempotency_key, nonce, expires_at)
        values ('${id3}','o1','u1','builder_beta','price_r','test','https://x','k3','n3', now()-interval '1 min')`);

      const c5 = await db.query<{ s: string }>(
        `select public.qhub_consume_checkout_intent('${id3}','o1','price_r','test',null,'sess','cus','suby') s`,
      );
      expect(c5.rows[0].s).toBe('EXPIRED');
    } finally {
      await db.close();
    }
  });

  it('verifier fails when the seat RPC is granted to a browser role', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`GRANT EXECUTE ON FUNCTION public.qhub_accept_invitation(uuid,text,text,text) TO anon`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('seat_rpc_browser_exec');
    } finally {
      await db.close();
    }
  });

  it('atomic checkout reconciliation: lease-bound, binds + consumes + PROCESSED in one txn', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const iid = '30000000-0000-0000-0000-000000000001';
      await db.exec(`
        insert into public.qhub_billing_webhook_events (provider, provider_event_id, event_type, state, processing_owner, claimed_at, lease_expires_at, attempt_count)
          values ('stripe','evt_r','checkout.session.completed','PROCESSING','worker_a', now(), now()+interval '5 min', 1);
        insert into public.qhub_checkout_intents (id, org_id, requested_by, plan_id, expected_recurring_price_id, expected_mode, expected_app_origin, idempotency_key, nonce, expires_at)
          values ('${iid}','o1','u1','builder_beta','price_r','test','https://x','k','n', now()+interval '10 min');
      `);

      // Wrong owner → lease_lost, nothing mutated.
      const bad = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_reconcile_checkout('stripe','evt_r','worker_B','${iid}','sess','cus','sub','price_r',false,'test',null,'active',123,100) v`,
      );
      expect(bad.rows[0].v.reason).toBe('lease_lost');

      // Correct owner → binds customer+subscription, consumes intent, marks PROCESSED.
      const ok = await db.query<{ v: { ok: boolean; org: string } }>(
        `select public.qhub_reconcile_checkout('stripe','evt_r','worker_a','${iid}','sess','cus','sub','price_r',false,'test',null,'active',123,100) v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);
      expect(ok.rows[0].v.org).toBe('o1');

      const sub = await db.query<{ status: string; sid: string }>(
        `select status, provider_subscription_id sid from public.qhub_subscriptions where org_id='o1'`,
      );
      expect(sub.rows[0].status).toBe('active');
      expect(sub.rows[0].sid).toBe('sub');

      const ev = await db.query<{ state: string }>(
        `select state from public.qhub_billing_webhook_events where provider_event_id='evt_r'`,
      );
      expect(ev.rows[0].state).toBe('PROCESSED');

      const it = await db.query<{ status: string }>(
        `select status from public.qhub_checkout_intents where id='${iid}'`,
      );
      expect(it.rows[0].status).toBe('consumed');

      // Exact replay is idempotent.
      const replay = await db.query<{ v: { ok: boolean; idempotent: boolean } }>(
        `select public.qhub_reconcile_checkout('stripe','evt_r','worker_a','${iid}','sess','cus','sub','price_r',false,'test',null,'active',123,100) v`,
      );
      expect(replay.rows[0].v.idempotent).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('atomic checkout reconciliation: Guided requires the setup line + rejects binding mismatch', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const iid = '30000000-0000-0000-0000-000000000002';
      await db.exec(`
        insert into public.qhub_billing_webhook_events (provider, provider_event_id, event_type, state, processing_owner, lease_expires_at)
          values ('stripe','evt_g','checkout.session.completed','PROCESSING','w', now()+interval '5 min');
        insert into public.qhub_checkout_intents (id, org_id, requested_by, plan_id, expected_recurring_price_id, expected_mode, expected_app_origin, idempotency_key, nonce, expires_at)
          values ('${iid}','o2','u1','guided_builder','price_g','test','https://x','k','n', now()+interval '10 min');
      `);

      // Guided with setup line missing → binding_mismatch.
      const miss = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_reconcile_checkout('stripe','evt_g','w','${iid}','sess','cus','sub','price_g',false,'test',null,'active',1,1) v`,
      );
      expect(miss.rows[0].v.reason).toBe('binding_mismatch');

      const it = await db.query<{ status: string }>(
        `select status from public.qhub_checkout_intents where id='${iid}'`,
      );
      expect(it.rows[0].status).toBe('failed');
    } finally {
      await db.close();
    }
  });

  it('atomic review decision: fully-bound request updates request + governance + immutable audit', async () => {
    const db = await freshDb();
    const HASH = 'a'.repeat(64);

    try {
      await db.exec(sql);

      const rid = '40000000-0000-0000-0000-000000000001';
      const pid = '50000000-0000-0000-0000-000000000001';
      const gid = '60000000-0000-0000-0000-000000000001';
      const aid = '70000000-0000-0000-0000-000000000001';
      await db.exec(`
        insert into public.qhub_org_members (org_id, user_id, role, status) values ('o1','u1','builder','active');
        insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
        insert into public.qhub_acknowledgments (id, org_id, user_id, ack_type, ack_version, project_id, required_version, status)
          values ('${aid}','o1','u1','acceptable_use','${ACK}','${pid}','${ACK}','ACTIVE');
        insert into public.qhub_governance_essentials
          (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash, policy_card_version, acknowledged, acknowledgment_version, acknowledgment_record_id)
          values ('${gid}','${pid}','o1','manual_review','requested', 4, '${HASH}', '${CARD}', true, '${ACK}', '${aid}');
        insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true), ('staff2','reviewer', true);
        insert into public.qhub_manual_review_requests
          (id, org_id, project_id, request_type, category, reason, request_hash, status,
           governance_record_id, governance_record_version, declaration_identity_hash, policy_version,
           required_acknowledgment_version, acknowledgment_record_id, acknowledgment_version, requester_user_id,
           classification_scheme_id, classification_scheme_version, classification_risk_tier)
          values ('${rid}','o1','${pid}','data_review','personal','sensitive','h','pending',
           '${gid}', 4, '${HASH}', '${POL}', '${ACK}', '${aid}', '${ACK}', 'u1',
           'qhub-governance-essentials', '2026-07-30.classification.v1', 'UNCLASSIFIED');
      `);

      // A caller-supplied is-staff flag is not enough — the actor must be an active staff row.
      const nonStaff = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','u1',true,'approved','ok','${POL}') v`,
      );
      expect(nonStaff.rows[0].v.reason).toBe('staff_required');

      const ok = await db.query<{ v: { ok: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);

      const req = await db.query<{ status: string }>(
        `select status from public.qhub_manual_review_requests where id='${rid}'`,
      );
      expect(req.rows[0].status).toBe('approved');

      const gov = await db.query<{ rs: string }>(
        `select review_state rs from public.qhub_governance_essentials where project_id='${pid}'`,
      );
      expect(gov.rows[0].rs).toBe('approved');

      const aud = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(aud.rows[0].n).toBe(1);

      // R11: EXACT repeat re-validates current authority FIRST, then returns idempotent (no 2nd audit).
      const rep = await db.query<{ v: { idempotent: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','${POL}') v`,
      );
      expect(rep.rows[0].v.idempotent).toBe(true);

      /*
       * MATERIALLY-changed repeats on a terminal request are deterministic conflicts, never
       * idempotent: changed reason / decision / reviewer each reject.
       */
      const changedReason = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','DIFFERENT reason','${POL}') v`,
      );
      expect(changedReason.rows[0].v.ok).toBe(false);
      expect(changedReason.rows[0].v.reason).toBe('decision_conflict');

      // R11: a wrong/stale policy version is rejected by revalidation BEFORE the terminal branch.
      const changedPolicy = await db.query<{ v: { reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','some-other-policy') v`,
      );
      expect(changedPolicy.rows[0].v.reason).toBe('policy_stale');

      const changedDecision = await db.query<{ v: { reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'rejected','looks fine','${POL}') v`,
      );
      expect(changedDecision.rows[0].v.reason).toBe('decision_conflict');

      const changedReviewer = await db.query<{ v: { reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff2',true,'approved','looks fine','${POL}') v`,
      );
      expect(changedReviewer.rows[0].v.reason).toBe('decision_conflict');

      // Still exactly ONE audit row after the idempotent repeat + all conflict attempts.
      const aud2 = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(aud2.rows[0].n).toBe(1);

      await expect(db.exec(`update public.qhub_entitlement_audit set reason='x'`)).rejects.toThrow(/immutable/);
    } finally {
      await db.close();
    }
  });

  it('R9: a legacy NULL-bound review can NEVER be terminalized (fail closed, zero side effect)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const rid = '41000000-0000-0000-0000-000000000001';
      const pid = '51000000-0000-0000-0000-000000000001';
      await db.exec(`
        insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
        insert into public.qhub_governance_essentials (project_id, org_id, disposition, review_state) values ('${pid}','o1','manual_review','requested');
        insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true);
        insert into public.qhub_manual_review_requests (id, org_id, project_id, request_type, category, reason, request_hash, status)
          values ('${rid}','o1','${pid}','data_review','personal','sensitive','h','pending');
      `);

      const legacy = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','pol1') v`,
      );
      expect(legacy.rows[0].v.ok).toBe(false);
      expect(legacy.rows[0].v.reason).toBe('non_authorizing_legacy_review');

      // ZERO side effect: request still pending, Governance not approved, no audit row.
      const req = await db.query<{ status: string }>(
        `select status from public.qhub_manual_review_requests where id='${rid}'`,
      );
      expect(req.rows[0].status).toBe('pending');

      const gov = await db.query<{ rs: string }>(
        `select review_state rs from public.qhub_governance_essentials where project_id='${pid}'`,
      );
      expect(gov.rows[0].rs).toBe('requested');

      const aud = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(aud.rows[0].n).toBe(0);
    } finally {
      await db.close();
    }
  });

  it('R9: verifier fails when authenticated (or PUBLIC) is granted EXECUTE on qhub_decide_review', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      await db.exec(
        `GRANT EXECUTE ON FUNCTION public.qhub_decide_review(uuid,text,boolean,text,text,text) TO authenticated`,
      );

      let v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rpc_execute_drift:public.qhub_decide_review');

      // Revoke, then a PUBLIC grant must also fail READY.
      await db.exec(
        `REVOKE EXECUTE ON FUNCTION public.qhub_decide_review(uuid,text,boolean,text,text,text) FROM authenticated`,
      );
      await db.exec(`GRANT EXECUTE ON FUNCTION public.qhub_decide_review(uuid,text,boolean,text,text,text) TO PUBLIC`);
      v = await verify(db);
      expect(v.ready).toBe(false);
    } finally {
      await db.close();
    }
  });

  it('R9: verifier fails on decide-review body drift, search_path drift, and a weaker overload', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      // Body drift — replace with a permissive body that drops the fail-closed guards.
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_decide_review(
          p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
        ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN RETURN jsonb_build_object('ok', true); END; $f$;
      `);

      let v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('decide_review_body_drift');

      // A weaker overload alongside the canonical function.
      await db.exec(sql);
      await db.exec(
        `CREATE FUNCTION public.qhub_decide_review(p_request_id uuid) RETURNS jsonb LANGUAGE sql AS $f$ SELECT jsonb_build_object('ok', true) $f$`,
      );
      v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('decide_review_overload');
    } finally {
      await db.close();
    }
  });

  it('atomic project creation: transactional cap + idempotency', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(
        `insert into public.qhub_subscriptions (org_id, plan_id, status, provider) values ('o1','guided_builder','active','stripe')`,
      );

      const p1 = await db.query<{ v: { ok: boolean; project_id: string } }>(
        `select public.qhub_create_project('o1','u1','k1','h1') v`,
      );
      expect(p1.rows[0].v.ok).toBe(true);

      // Guided cap = 1 → the second (different key) is rejected.
      const p2 = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_create_project('o1','u1','k2','h2') v`,
      );
      expect(p2.rows[0].v.reason).toBe('project_limit_reached');

      // Exact idempotent retry returns the same project.
      const retry = await db.query<{ v: { idempotent: boolean; project_id: string } }>(
        `select public.qhub_create_project('o1','u1','k1','h1') v`,
      );
      expect(retry.rows[0].v.idempotent).toBe(true);
      expect(retry.rows[0].v.project_id).toBe(p1.rows[0].v.project_id);

      // Changed hash under the same key fails.
      const conflict = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_create_project('o1','u1','k1','DIFFERENT') v`,
      );
      expect(conflict.rows[0].v.reason).toBe('idempotency_conflict');
    } finally {
      await db.close();
    }
  });

  it('verifier fails when a caller-supplied-cap seat RPC is reintroduced', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      // Reintroduce the old (caller-cap) overload alongside the R4 one.
      await db.exec(`CREATE FUNCTION public.qhub_accept_invitation(p_invitation_id uuid, p_user_id text, p_max_seats integer)
                     RETURNS text LANGUAGE sql AS $f$ SELECT 'X' $f$`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('seat_rpc_caller_cap');
    } finally {
      await db.close();
    }
  });
});

// ─── R10 §3/§6 — atomic review CREATION + exact-semantic verifier drift ──────────

const H64 = 'a'.repeat(64);

/** Seed a REVIEW_REQUIRED project with an ACTIVE acknowledgment, ready for qhub_create_review_request. */
async function seedReviewRequired(db: PGlite) {
  const pid = '52000000-0000-0000-0000-000000000001';
  const gid = '62000000-0000-0000-0000-000000000001';
  const aid = '72000000-0000-0000-0000-000000000001';
  await db.exec(`
    insert into public.qhub_org_members (org_id, user_id, role, status) values ('o1','u1','builder','active');
    insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
    insert into public.qhub_acknowledgments (id, org_id, user_id, ack_type, ack_version, project_id, required_version, status)
      values ('${aid}','o1','u1','acceptable_use','${ACK}','${pid}','${ACK}','ACTIVE');
    insert into public.qhub_governance_essentials
      (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash, policy_card_version, data_classes, declaration_complete, acknowledged, acknowledgment_version, acknowledgment_record_id)
      values ('${gid}','${pid}','o1','manual_review','requested', 4, '${H64}', '${CARD}', '["personal"]'::jsonb, true, true, '${ACK}', '${aid}');
  `);

  return { pid, gid, aid };
}

describe('commercial-launch R10 atomic review creation', () => {
  it('creates ONE fully-bound review; exact retry is idempotent; a changed key/identity conflicts', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const { pid } = await seedReviewRequired(db);

      const c1 = await db.query<{ v: { ok: boolean; idempotent: boolean; request_id: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','sensitive data','k1') v`,
      );
      expect(c1.rows[0].v.ok).toBe(true);
      expect(c1.rows[0].v.idempotent).toBe(false);

      const rid = c1.rows[0].v.request_id;

      // The inserted review is FULLY bound (no NULL binding fields) with DB-resolved versions + category.
      const row = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_manual_review_requests where id='${rid}'
           and governance_record_id is not null and governance_record_version is not null
           and declaration_identity_hash='${H64}' and policy_version='${POL}'
           and required_acknowledgment_version='${ACK}' and acknowledgment_record_id is not null
           and acknowledgment_version='${ACK}' and requester_user_id='u1' and category='personal'`,
      );
      expect(row.rows[0].n).toBe(1);

      // Exact identical retry → the SAME request (idempotent), no second row.
      const c2 = await db.query<{ v: { idempotent: boolean; request_id: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','sensitive data','k1') v`,
      );
      expect(c2.rows[0].v.idempotent).toBe(true);
      expect(c2.rows[0].v.request_id).toBe(rid);

      // Same idempotency key + a DIFFERENT (material) reason → deterministic conflict.
      const c3 = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','DIFFERENT reason','k1') v`,
      );
      expect(c3.rows[0].v.ok).toBe(false);
      expect(c3.rows[0].v.reason).toBe('idempotency_conflict');

      // A materially-different reason under a NEW key → a DISTINCT request identity (prior preserved).
      const c4 = await db.query<{ v: { ok: boolean; request_id: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','another distinct reason','k2') v`,
      );
      expect(c4.rows[0].v.ok).toBe(true);
      expect(c4.rows[0].v.request_id).not.toBe(rid);

      const total = await db.query<{ n: number }>(`select count(*)::int n from public.qhub_manual_review_requests`);
      expect(total.rows[0].n).toBe(2);
    } finally {
      await db.close();
    }
  });

  it('rejects creation when not REVIEW_REQUIRED, when not a member, and when the ack is not ACTIVE', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const { pid, gid, aid } = await seedReviewRequired(db);

      // Not a member (different requester).
      const nm = await db.query<{ v: { reason: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','other','r','k') v`,
      );
      expect(nm.rows[0].v.reason).toBe('not_a_member');

      // Ack revoked → not ACTIVE → rejected.
      await db.exec(`update public.qhub_acknowledgments set status='REVOKED', revoked_at=now() where id='${aid}'`);

      const rk = await db.query<{ v: { reason: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','r','k') v`,
      );
      expect(rk.rows[0].v.reason).toBe('acknowledgment_not_active');

      /*
       * Disposition not manual_review → review_not_required (checked before the ack, so the
       * still-REVOKED ack is not reached; and REVOKED→ACTIVE un-revoke is correctly forbidden).
       */
      await db.exec(`update public.qhub_governance_essentials set disposition='proceed' where id='${gid}'`);

      const nr = await db.query<{ v: { reason: string } }>(
        `select public.qhub_create_review_request('o1','${pid}','u1','r','k') v`,
      );
      expect(nr.rows[0].v.reason).toBe('review_not_required');
    } finally {
      await db.close();
    }
  });
});

describe('commercial-launch R10 verifier exact-semantic drift', () => {
  async function ready(db: PGlite) {
    await db.exec(sql);
    return verify(db);
  }

  it('is READY at r6 on a healthy schema', async () => {
    const db = await freshDb();

    try {
      const v = await ready(db);
      expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
      expect(v.ready).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('CHECK(true) substitution of the terminal-binding constraint fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`ALTER TABLE public.qhub_manual_review_requests DROP CONSTRAINT chk_qhub_review_terminal_binding`);
      await db.exec(
        `ALTER TABLE public.qhub_manual_review_requests ADD CONSTRAINT chk_qhub_review_terminal_binding CHECK (true) NOT VALID`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r6_constraint_semantics:chk_qhub_review_terminal_binding');
    } finally {
      await db.close();
    }
  });

  it('CHECK(true) substitution of the declaration-hash constraint fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`ALTER TABLE public.qhub_manual_review_requests DROP CONSTRAINT chk_qhub_review_decl_hash_hex`);
      await db.exec(
        `ALTER TABLE public.qhub_manual_review_requests ADD CONSTRAINT chk_qhub_review_decl_hash_hex CHECK (true)`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r6_constraint_semantics:chk_qhub_review_decl_hash_hex');
    } finally {
      await db.close();
    }
  });

  it('a same-name FK recreated against the WRONG relationship fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      // Recreate the review→governance FK to reference qhub_acknowledgments instead — wrong target.
      await db.exec(`ALTER TABLE public.qhub_manual_review_requests DROP CONSTRAINT fk_qhub_review_governance_record`);
      await db.exec(
        `ALTER TABLE public.qhub_manual_review_requests ADD CONSTRAINT fk_qhub_review_governance_record FOREIGN KEY (governance_record_id) REFERENCES public.qhub_acknowledgments(id)`,
      );

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('r6_constraint_semantics:fk_qhub_review_governance_record');
    } finally {
      await db.close();
    }
  });

  it('a comment/marker-spoofed decide body (weakened logic) fails READY (exact body pin)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      // Weakened body that RETAINS the old marker strings only in comments — the exact md5 differs.
      await db.exec(`
        CREATE OR REPLACE FUNCTION public.qhub_decide_review(
          p_request_id UUID, p_actor TEXT, p_is_staff BOOLEAN, p_decision TEXT, p_reason TEXT, p_policy_version TEXT
        ) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $f$
        BEGIN
          -- non_authorizing_legacy_review governance_changed acknowledgment_mismatch policy_stale
          RETURN jsonb_build_object('ok', true);
        END; $f$;
      `);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('decide_review_body_drift');
    } finally {
      await db.close();
    }
  });

  it('a direct authenticated UPDATE grant on an authority table fails READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`GRANT UPDATE ON TABLE public.qhub_manual_review_requests TO authenticated`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('browser_write_grant:qhub_manual_review_requests:UPDATE');
    } finally {
      await db.close();
    }
  });

  it('an anon INSERT grant, and a same-name wrong-table index, each fail READY', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`GRANT INSERT ON TABLE public.qhub_acknowledgments TO anon`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('browser_write_grant:qhub_acknowledgments:INSERT');
    } finally {
      await db.close();
    }
  });
});
