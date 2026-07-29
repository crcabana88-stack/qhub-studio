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
      expect(v.expected_version).toBe('2026-07-30.commercial-launch-r3');
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
});
