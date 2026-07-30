/**
 * QHUB Commercial Launch R9 §1/§6-§8 — AUTHORITATIVE REVIEW BINDING
 * app/test/commercial-review-binding.test.ts
 *
 *   - buildDeclarationIdentityString binds the MATERIAL declaration (any change → distinct id).
 *   - upsertDeclaration persists the Governance identity but does NOT auto-open a review — a
 *     review is created only by the authoritative submitCustomerReview AFTER acknowledgment.
 *   - submitCustomerReview loads ALL binding fields server-side (Governance id/version + declaration
 *     hash + authoritative acknowledgment record/version + derived category) — the browser supplies
 *     only project/reason/idempotencyKey; a missing/stale acknowledgment or non-REVIEW_REQUIRED
 *     state is rejected; no NULL binding fields result.
 *   - the atomic decision RPC approves a fully-bound review and refuses one whose identity drifted.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  buildDeclarationIdentityString,
  currentRequiredAcknowledgmentVersion,
} from '~/lib/qhub/commercial/governance-essentials';
import { testReadyToken } from '~/test/helpers/commercial-ready-token';

// ─── buildDeclarationIdentityString: material-change sensitivity ─────────────────

describe('declaration identity binds the material declaration (R8 §6)', () => {
  const base = {
    orgId: 'o1',
    projectId: 'p1',
    purpose: 'summarize public docs',
    useCase: 'internal knowledge search',
    dataClasses: ['public', 'synthetic'] as never,
    riskTier: 'T1' as never,
    modelDeclaration: 'claude-sonnet',
    connectorDeclaration: ['github', 'slack'],
    policyCardVersion: '2026-07-30.policy-card.v1',
  };

  it('is stable under cosmetic reordering + whitespace (deterministic)', () => {
    const a = buildDeclarationIdentityString(base);
    const b = buildDeclarationIdentityString({
      ...base,
      dataClasses: ['synthetic', 'public'] as never,
      connectorDeclaration: ['slack', ' github '],
      purpose: '  summarize public docs  ',
    });
    expect(a).toBe(b);
  });

  it('changes when ANY material field changes', () => {
    const id = buildDeclarationIdentityString(base);

    const variants = [
      { ...base, purpose: 'something else' },
      { ...base, useCase: 'a different use case' },
      { ...base, dataClasses: ['public', 'personal'] as never },
      { ...base, modelDeclaration: 'gpt-4o' },
      { ...base, connectorDeclaration: ['github'] },
      { ...base, riskTier: 'T2' as never },
      { ...base, policyCardVersion: '2027-01-01.policy-card.v2' },
      { ...base, projectId: 'p2' },
    ];

    for (const v of variants) {
      expect(buildDeclarationIdentityString(v), JSON.stringify(v)).not.toBe(id);
    }
  });
});

// ─── mocked-DB flow: upsertDeclaration + submitCustomerReview ───────────────────

const HASH = 'a'.repeat(64);

const H = vi.hoisted(() => ({
  govUpserts: [] as Array<Record<string, unknown>>,
  reviewInserts: [] as Array<Record<string, unknown>>,

  // Configurable server state the mock returns.
  gov: null as Record<string, unknown> | null,
  ack: null as Record<string, unknown> | null,
  approvedReview: null as Record<string, unknown> | null,
}));

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    from(table: string) {
      const b: Record<string, unknown> = {};
      let cols = '';

      b.select = (c: string) => {
        cols = c;

        return b;
      };
      b.eq = () => b;
      b.order = () => b;
      b.limit = () => b;

      b.upsert = (row: Record<string, unknown>) => {
        if (table === 'qhub_governance_essentials') {
          H.govUpserts.push(row);
        }

        return b;
      };

      b.insert = (row: Record<string, unknown>) => {
        if (table === 'qhub_manual_review_requests') {
          H.reviewInserts.push(row);
        }

        if (table === 'qhub_acknowledgments') {
          // acknowledgeProject captures the inserted ack row id.
          b.__ack = { id: 'ack-rec-1' };
        }

        return b;
      };

      b.maybeSingle = async () => {
        if (table === 'qhub_acknowledgments') {
          if ((b as { __ack?: unknown }).__ack) {
            return { data: (b as { __ack?: unknown }).__ack, error: null };
          }

          return { data: H.ack, error: null };
        }

        if (table === 'qhub_manual_review_requests') {
          return { data: H.approvedReview, error: null }; // approved-review lookup (null = none)
        }

        if (table === 'qhub_governance_essentials') {
          // Prior-version read during upsert asks for the short column set.
          if (cols.includes('record_version') && !cols.includes('disposition')) {
            return { data: { id: 'gov-1', record_version: 3, declaration_identity_hash: 'old' }, error: null };
          }

          return { data: H.gov, error: null };
        }

        return { data: { id: 'rid' }, error: null };
      };

      return b;
    },
  }),
}));

const { upsertDeclaration, submitCustomerReview } = await import('~/lib/qhub/commercial/governance-essentials.server');

const CTX = { userId: 'u1', orgId: 'o1', isStaff: false } as never;
const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };

beforeEach(() => {
  H.govUpserts = [];
  H.reviewInserts = [];
  H.gov = null;
  H.ack = null;
  H.approvedReview = null;
});

describe('upsertDeclaration persists identity but does NOT auto-open a review (R9 §1)', () => {
  it('bumps record_version + persists the declaration hash, and opens NO review request', async () => {
    const rec = await upsertDeclaration(
      CTX,
      {
        projectId: 'p1',
        purpose: 'handle customer records',
        useCase: 'support triage',
        dataClasses: ['personal'] as never,
        riskTier: 'T1' as never,
        modelDeclaration: 'claude-sonnet',
        connectorDeclaration: [],
      },
      testReadyToken(ENV),
      ENV,
    );

    expect(H.govUpserts).toHaveLength(1);
    expect(H.govUpserts[0].record_version).toBe(4); // prior 3 → bumped (hash changed)
    expect(H.govUpserts[0].declaration_identity_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rec.recordVersion).toBe(4);

    // R9: the review request is NOT created at declaration time (must be fully bound at submit).
    expect(H.reviewInserts).toHaveLength(0);
  });
});

describe('submitCustomerReview binds the full authoritative identity (R9 §1)', () => {
  const govManualReview = {
    id: 'gov-1',
    project_id: 'p1',
    org_id: 'o1',
    disposition: 'manual_review',
    declaration_complete: true,
    acknowledged: true,
    review_state: 'requested',
    risk_tier: 'T1',
    review_policy_version: null,
    policy_card_version: '2026-07-30.policy-card.v1',
    acknowledgment_version: currentRequiredAcknowledgmentVersion(),
    record_version: 4,
    declaration_identity_hash: HASH,
    data_classes: ['personal'],
    acknowledgment_record_id: 'ack-rec-1',
  };

  const ackRow = {
    id: 'ack-rec-1',
    org_id: 'o1',
    user_id: 'u1',
    ack_version: currentRequiredAcknowledgmentVersion(),
  };

  it('persists governance + acknowledgment bindings derived entirely server-side', async () => {
    H.gov = govManualReview;
    H.ack = {
      acknowledged: true,
      acknowledgment_version: currentRequiredAcknowledgmentVersion(),
      acknowledgment_record_id: 'ack-rec-1',
    };

    /*
     * resolveCurrentAcknowledgment reads the ack ROW after the gov ack-state row; both come from
     * the same table stubs, so seed H.ack for the ack-row read path via the id lookup.
     */
    H.ack = ackRow;

    const r = await submitCustomerReview(
      CTX,
      { projectId: 'p1', reason: 'sensitive data', idempotencyKey: 'k1' },
      testReadyToken(ENV),
      ENV,
    );

    expect(r.ok).toBe(true);
    expect(H.reviewInserts).toHaveLength(1);

    const review = H.reviewInserts[0];
    expect(review.governance_record_id).toBe('gov-1');
    expect(review.governance_record_version).toBe(4);
    expect(review.declaration_identity_hash).toBe(HASH);
    expect(review.acknowledgment_record_id).toBe('ack-rec-1');
    expect(review.acknowledgment_version).toBe(currentRequiredAcknowledgmentVersion());
    expect(review.required_acknowledgment_version).toBe(currentRequiredAcknowledgmentVersion());
    expect(review.requester_user_id).toBe('u1');
    expect(review.category).toBe('personal'); // derived from the declared data class, not the browser
    expect(review.status).toBe('pending');
  });

  it('rejects when the project is not in a REVIEW_REQUIRED (manual_review) state', async () => {
    H.gov = { ...govManualReview, disposition: 'proceed' };

    const r = await submitCustomerReview(CTX, { projectId: 'p1', reason: 'x' }, testReadyToken(ENV), ENV);
    expect(r).toEqual({ ok: false, error: 'review_not_required' });
    expect(H.reviewInserts).toHaveLength(0);
  });

  it('rejects when there is no authoritative acknowledgment at the current required version', async () => {
    H.gov = { ...govManualReview, acknowledged: false, acknowledgment_record_id: null };
    H.ack = null;

    const r = await submitCustomerReview(CTX, { projectId: 'p1', reason: 'x' }, testReadyToken(ENV), ENV);
    expect(r.ok).toBe(false);
    expect(H.reviewInserts).toHaveLength(0);
  });
});

// ─── decision RPC: fully-bound approve + drift refusal (PGlite) ─────────────────

const MIG = fileURLToPath(
  new URL('../../supabase/migrations/20260729_commercial_launch_foundation.sql', import.meta.url),
);
const sql = readFileSync(MIG, 'utf8');

async function freshDb(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(
    `CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;`,
  );
  await db.exec(sql);

  return db;
}

const HASH_B = 'b'.repeat(64);

async function seedBoundReview(db: PGlite, ids: { pid: string; gid: string; aid: string; rid: string }) {
  await db.exec(`
    insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${ids.pid}','o1','builder_beta', true);
    insert into public.qhub_acknowledgments (id, org_id, user_id, ack_type, ack_version) values ('${ids.aid}','o1','u1','acceptable_use','ack1');
    insert into public.qhub_governance_essentials
      (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash, acknowledged, acknowledgment_version, acknowledgment_record_id)
      values ('${ids.gid}','${ids.pid}','o1','manual_review','requested', 4, '${HASH}', true, 'ack1', '${ids.aid}');
    insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true);
    insert into public.qhub_manual_review_requests
      (id, org_id, project_id, request_type, category, reason, request_hash, status,
       governance_record_id, governance_record_version, declaration_identity_hash, policy_version,
       required_acknowledgment_version, acknowledgment_record_id, acknowledgment_version, requester_user_id)
      values ('${ids.rid}','o1','${ids.pid}','data_review','personal','sensitive','h','pending',
       '${ids.gid}', 4, '${HASH}', 'pol1', 'ack1', '${ids.aid}', 'ack1', 'u1');
  `);
}

describe('atomic decision approves a fully-bound review and refuses a drifted one (R9 §3)', () => {
  it('approves when the bound identity matches, and rejects after a declaration change', async () => {
    const db = await freshDb();
    const ids = {
      pid: '50000000-0000-0000-0000-000000000009',
      gid: '60000000-0000-0000-0000-000000000009',
      aid: '70000000-0000-0000-0000-000000000009',
      rid: '40000000-0000-0000-0000-000000000009',
    };

    try {
      await seedBoundReview(db, ids);

      // Governance drift: the customer changed the declaration after the review was opened.
      await db.exec(
        `update public.qhub_governance_essentials set declaration_identity_hash='${HASH_B}', record_version=5 where id='${ids.gid}'`,
      );

      const drift = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${ids.rid}','staff1',true,'approved','looks fine','pol1') v`,
      );
      expect(drift.rows[0].v.ok).toBe(false);
      expect(drift.rows[0].v.reason).toBe('governance_changed');

      const req0 = await db.query<{ status: string }>(
        `select status from public.qhub_manual_review_requests where id='${ids.rid}'`,
      );
      expect(req0.rows[0].status).toBe('pending');

      // Restore the bound identity → the same decision approves and writes ONE audit row.
      await db.exec(
        `update public.qhub_governance_essentials set declaration_identity_hash='${HASH}', record_version=4 where id='${ids.gid}'`,
      );

      const ok = await db.query<{ v: { ok: boolean } }>(
        `select public.qhub_decide_review('${ids.rid}','staff1',true,'approved','looks fine','pol1') v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);

      const audit = await db.query<{ hash: string; requester: string }>(
        `select after_state->>'declaration_identity_hash' hash, after_state->>'requester_user_id' requester from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0].hash).toBe(HASH);
      expect(audit.rows[0].requester).toBe('u1');
    } finally {
      await db.close();
    }
  });

  it('refuses to approve when the acknowledgment binding no longer matches (R9 §3/§4)', async () => {
    const db = await freshDb();
    const ids = {
      pid: '51000000-0000-0000-0000-000000000009',
      gid: '61000000-0000-0000-0000-000000000009',
      aid: '71000000-0000-0000-0000-000000000009',
      rid: '41000000-0000-0000-0000-000000000009',
    };

    try {
      await seedBoundReview(db, ids);

      // The project's Governance acknowledgment is superseded (record no longer acknowledged).
      await db.exec(`update public.qhub_governance_essentials set acknowledged=false where id='${ids.gid}'`);

      const r = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${ids.rid}','staff1',true,'approved','looks fine','pol1') v`,
      );
      expect(r.rows[0].v.ok).toBe(false);
      expect(r.rows[0].v.reason).toBe('acknowledgment_stale');
    } finally {
      await db.close();
    }
  });
});
