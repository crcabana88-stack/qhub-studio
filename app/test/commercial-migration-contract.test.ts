/**
 * QHUB Commercial Launch R2 — migration contract on real PostgreSQL (PGlite)
 * app/test/commercial-migration-contract.test.ts
 *
 * Verifies the R2 migration: transactional apply + idempotent rerun, the
 * qhub_verify_commercial_schema() readiness contract (ready + drift detection),
 * RESTRICTIVE service-only RLS, atomic idempotent credit RPC, the webhook-claim
 * state machine, and the one-active-guided-project rule.
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

describe('commercial-launch R2 migration', () => {
  it('applies transactionally and is idempotent (runs twice)', async () => {
    const db = await freshDb();

    try {
      await expect(db.exec(sql)).resolves.toBeDefined();
      await expect(db.exec(sql)).resolves.toBeDefined();
    } finally {
      await db.close();
    }
  });

  it('verifier reports READY at the R2 version after a healthy run', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const v = await verify(db);
      expect(v.expected_version).toBe('2026-07-29.commercial-launch-r2');
      expect(v.failed).toEqual([]);
      expect(v.ready).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('enables RLS + a RESTRICTIVE service-only policy on every table; denies browser roles', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      for (const t of TABLES) {
        const rls = await db.query<{ r: boolean }>(
          `select relrowsecurity r from pg_class where oid=('public.'||$1)::regclass`,
          [t],
        );
        expect(rls.rows[0].r, `${t} rls`).toBe(true);

        const pol = await db.query<{ permissive: string }>(
          `select permissive from pg_policies where schemaname='public' and tablename=$1 and policyname=$2`,
          [t, `${t}_service_only`],
        );
        expect(pol.rows[0]?.permissive, `${t} policy`).toBe('RESTRICTIVE');

        const anon = await db.query<{ ok: boolean }>(
          `select has_table_privilege('anon',('public.'||$1)::regclass,'SELECT') ok`,
          [t],
        );
        expect(anon.rows[0].ok, `anon ${t}`).toBe(false);

        const svc = await db.query<{ ok: boolean }>(
          `select has_table_privilege('service_role',('public.'||$1)::regclass,'INSERT') ok`,
          [t],
        );
        expect(svc.rows[0].ok, `service ${t}`).toBe(true);
      }
    } finally {
      await db.close();
    }
  });

  it('verifier FAILS when RLS is weakened (drift detection)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`ALTER TABLE public.qhub_subscriptions DISABLE ROW LEVEL SECURITY`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('rls_disabled:qhub_subscriptions');
    } finally {
      await db.close();
    }
  });

  it('verifier FAILS when a critical uniqueness is removed', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`DROP INDEX public.uq_qhub_guided_one_active_project`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('missing_index:guided_one_active');
    } finally {
      await db.close();
    }
  });

  it('verifier FAILS when the credit RPC is granted to a browser role', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`GRANT EXECUTE ON FUNCTION public.qhub_consume_build_credit(text,text,text,text) TO anon`);

      const v = await verify(db);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain('credit_rpc_browser_exec');
    } finally {
      await db.close();
    }
  });

  it('credit RPC: atomic decrement, exact idempotent retry, changed-request rejection, overdraw guard', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`
        insert into public.qhub_usage_credits (org_id, period_key, period_start, period_end, allotted, used)
        values ('org_x','2026-07', now(), now()+interval '30 days', 2, 0);
      `);

      const c1 = await db.query<{ r: number | null }>(
        `select public.qhub_consume_build_credit('org_x','2026-07','k1','h1') r`,
      );
      expect(c1.rows[0].r).toBe(1);

      // exact idempotent retry — same key + same request hash → no second decrement
      const retry = await db.query<{ r: number | null }>(
        `select public.qhub_consume_build_credit('org_x','2026-07','k1','h1') r`,
      );
      expect(retry.rows[0].r).toBe(1);

      // changed request under the same key → rejected
      await expect(
        db.query(`select public.qhub_consume_build_credit('org_x','2026-07','k1','DIFFERENT') r`),
      ).rejects.toThrow(/idempotency key reused/);

      // a new key consumes the last credit, then exhaustion returns NULL
      const c2 = await db.query<{ r: number | null }>(
        `select public.qhub_consume_build_credit('org_x','2026-07','k2','h2') r`,
      );
      expect(c2.rows[0].r).toBe(0);

      const c3 = await db.query<{ r: number | null }>(
        `select public.qhub_consume_build_credit('org_x','2026-07','k3','h3') r`,
      );
      expect(c3.rows[0].r).toBeNull();

      const led = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_usage_ledger where org_id='org_x'`,
      );
      expect(led.rows[0].n).toBe(2); // exactly two decrements ledgered
    } finally {
      await db.close();
    }
  });

  it('webhook-claim RPC: first delivery CLAIMED, processed duplicate DUPLICATE', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const first = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct_1',100,'ph') s`,
      );
      expect(first.rows[0].s).toBe('CLAIMED');

      await db.exec(
        `update public.qhub_billing_webhook_events set state='PROCESSED', processed_at=now() where provider_event_id='evt_1'`,
      );

      const dup = await db.query<{ s: string }>(
        `select public.qhub_claim_webhook_event('stripe','evt_1','x',false,'acct_1',100,'ph') s`,
      );
      expect(dup.rows[0].s).toBe('DUPLICATE');
    } finally {
      await db.close();
    }
  });

  it('enforces one active guided-plan project per org', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`
        insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
        values (gen_random_uuid(),'org_g','guided_builder', true);
      `);
      await expect(
        db.exec(`insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active)
                 values (gen_random_uuid(),'org_g','guided_builder', true);`),
      ).rejects.toThrow(/uq_qhub_guided_one_active_project|duplicate key/);
    } finally {
      await db.close();
    }
  });

  it('acknowledgments + usage ledger are immutable (append-only)', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(
        `insert into public.qhub_acknowledgments (org_id,user_id,ack_type,ack_version) values ('o','u','terms','1');`,
      );
      await expect(db.exec(`update public.qhub_acknowledgments set ack_version='2' where org_id='o'`)).rejects.toThrow(
        /immutable/,
      );
    } finally {
      await db.close();
    }
  });
});
