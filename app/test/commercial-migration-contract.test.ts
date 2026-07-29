/**
 * QHUB Commercial Launch — additive migration contract on real PostgreSQL (PGlite)
 * app/test/commercial-migration-contract.test.ts
 *
 * Verifies the commercial-launch migration: applies cleanly, is idempotent (runs
 * twice), enables RESTRICTIVE service-only RLS on every table, denies anon/
 * authenticated all table grants, grants the service role, and provides an atomic
 * build-credit consume RPC that decrements once per call and refuses to overdraw.
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
  'qhub_plan_entitlements',
  'qhub_billing_customers',
  'qhub_subscriptions',
  'qhub_billing_webhook_events',
  'qhub_usage_credits',
  'qhub_usage_ledger',
  'qhub_project_entitlements',
  'qhub_onboarding_state',
  'qhub_acknowledgments',
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

describe('commercial-launch migration', () => {
  it('applies and is idempotent (runs twice)', async () => {
    const db = await freshDb();

    try {
      await expect(db.exec(sql)).resolves.toBeDefined();
      await expect(db.exec(sql)).resolves.toBeDefined();
    } finally {
      await db.close();
    }
  });

  it('enables RLS on every commercial table', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      for (const t of TABLES) {
        const r = await db.query<{ relrowsecurity: boolean }>(
          `select relrowsecurity from pg_class where oid = ('public.' || $1)::regclass`,
          [t],
        );
        expect(r.rows[0]?.relrowsecurity, `${t} RLS`).toBe(true);
      }
    } finally {
      await db.close();
    }
  });

  it('has a RESTRICTIVE service-only policy on every table', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      for (const t of TABLES) {
        const r = await db.query<{ permissive: string; roles: string }>(
          `select permissive, roles::text from pg_policies where schemaname='public' and tablename=$1 and policyname=$2`,
          [t, `${t}_service_only`],
        );
        expect(r.rows.length, `${t} policy exists`).toBe(1);
        expect(r.rows[0].permissive, `${t} restrictive`).toBe('RESTRICTIVE');
      }
    } finally {
      await db.close();
    }
  });

  it('denies anon + authenticated all table privileges; grants service_role', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      for (const t of TABLES) {
        for (const role of ['anon', 'authenticated']) {
          for (const priv of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
            const r = await db.query<{ ok: boolean }>(
              `select has_table_privilege($1, ('public.' || $2)::regclass, $3) ok`,
              [role, t, priv],
            );
            expect(r.rows[0].ok, `${role} ${priv} ${t}`).toBe(false);
          }
        }

        const svc = await db.query<{ ok: boolean }>(
          `select has_table_privilege('service_role', ('public.' || $1)::regclass, 'INSERT') ok`,
          [t],
        );
        expect(svc.rows[0].ok, `service_role INSERT ${t}`).toBe(true);
      }
    } finally {
      await db.close();
    }
  });

  it('consume-credit RPC decrements atomically and refuses to overdraw', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(`
        insert into public.qhub_usage_credits (org_id, period_key, period_start, period_end, allotted, used)
        values ('org_x', '2026-07', now(), now() + interval '30 days', 2, 0);
      `);

      const c1 = await db.query<{ r: number | null }>(`select public.qhub_consume_build_credit('org_x','2026-07') r`);
      expect(c1.rows[0].r).toBe(1);

      const c2 = await db.query<{ r: number | null }>(`select public.qhub_consume_build_credit('org_x','2026-07') r`);
      expect(c2.rows[0].r).toBe(0);

      const c3 = await db.query<{ r: number | null }>(`select public.qhub_consume_build_credit('org_x','2026-07') r`);
      expect(c3.rows[0].r).toBeNull();

      const used = await db.query<{ used: number }>(`select used from public.qhub_usage_credits where org_id='org_x'`);
      expect(used.rows[0].used).toBe(2);
    } finally {
      await db.close();
    }
  });

  it('denies the consume-credit RPC to browser roles, grants service_role', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);

      const anon = await db.query<{ ok: boolean }>(
        `select has_function_privilege('anon','public.qhub_consume_build_credit(text,text)','EXECUTE') ok`,
      );
      expect(anon.rows[0].ok).toBe(false);

      const svc = await db.query<{ ok: boolean }>(
        `select has_function_privilege('service_role','public.qhub_consume_build_credit(text,text)','EXECUTE') ok`,
      );
      expect(svc.rows[0].ok).toBe(true);
    } finally {
      await db.close();
    }
  });

  it('seeds plan identity rows idempotently', async () => {
    const db = await freshDb();

    try {
      await db.exec(sql);
      await db.exec(sql);

      const r = await db.query<{ n: number }>(`select count(*)::int n from public.qhub_commercial_plans`);
      expect(r.rows[0].n).toBe(2);
    } finally {
      await db.close();
    }
  });
});
