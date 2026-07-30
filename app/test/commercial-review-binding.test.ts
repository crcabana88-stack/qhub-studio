/**
 * QHUB Commercial Launch R8 §6-§8 — PERSISTED GOVERNANCE / DECLARATION / ACK REVIEW BINDING
 * app/test/commercial-review-binding.test.ts
 *
 *   - buildDeclarationIdentityString binds the MATERIAL declaration: any change to purpose /
 *     use-case / data / model / connector / risk tier / policy-card / project yields a distinct
 *     identity, while cosmetic reordering/whitespace does not (deterministic).
 *   - upsertDeclaration persists the Governance record id/version + declaration_identity_hash and
 *     opens a review request BOUND to that exact identity (+ requester + required ack version).
 *   - the atomic decision RPC refuses to APPROVE a review whose bound declaration identity no
 *     longer matches the authoritative Governance record (governance drift → no side effect).
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

// ─── upsertDeclaration persists + binds the review identity ─────────────────────

const H = vi.hoisted(() => ({
  govUpserts: [] as Array<Record<string, unknown>>,
  reviewInserts: [] as Array<Record<string, unknown>>,
}));

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    from(table: string) {
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.eq = () => b;

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

        return b;
      };

      // Prior Governance record read (id + version + prior hash).
      b.maybeSingle = async () => {
        if (table === 'qhub_governance_essentials') {
          return { data: { id: 'gov-1', record_version: 3, declaration_identity_hash: 'old' }, error: null };
        }

        return { data: { id: 'rid' }, error: null };
      };

      return b;
    },
  }),
}));

const { upsertDeclaration } = await import('~/lib/qhub/commercial/governance-essentials.server');

const CTX = { userId: 'u1', orgId: 'o1', isStaff: false } as never;
const ENV = { SUPABASE_URL: 'https://ref.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' };

describe('upsertDeclaration persists + binds the authoritative review identity (R8 §6)', () => {
  beforeEach(() => {
    H.govUpserts = [];
    H.reviewInserts = [];
  });

  it('persists record_version + declaration_identity_hash and opens a BOUND review', async () => {
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

    // Governance record carries a bumped monotonic version + a hex-64 declaration identity.
    expect(H.govUpserts).toHaveLength(1);
    expect(H.govUpserts[0].record_version).toBe(4); // prior 3 → bumped (hash changed)
    expect(H.govUpserts[0].declaration_identity_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rec.recordVersion).toBe(4);
    expect(rec.governanceRecordId).toBe('gov-1');

    // A manual_review (personal data) opens exactly one review request, BOUND to the identity.
    expect(H.reviewInserts).toHaveLength(1);

    const review = H.reviewInserts[0];
    expect(review.governance_record_id).toBe('gov-1');
    expect(review.governance_record_version).toBe(4);
    expect(review.declaration_identity_hash).toBe(H.govUpserts[0].declaration_identity_hash);
    expect(review.required_acknowledgment_version).toBe(currentRequiredAcknowledgmentVersion());
    expect(review.requester_user_id).toBe('u1');
    expect(review.status).toBe('pending');
  });
});

// ─── decision RPC refuses to approve a drifted review (PGlite) ───────────────────

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

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

describe('atomic decision refuses a review whose Governance identity drifted (R8 §7)', () => {
  it('approves when the bound identity still matches, and rejects after a declaration change', async () => {
    const db = await freshDb();

    try {
      const pid = '50000000-0000-0000-0000-000000000009';
      const gid = '60000000-0000-0000-0000-000000000009';
      const rid = '40000000-0000-0000-0000-000000000009';
      await db.exec(`
        insert into public.qhub_project_entitlements (project_id, org_id, plan_id, active) values ('${pid}','o1','builder_beta', true);
        insert into public.qhub_governance_essentials (id, project_id, org_id, disposition, review_state, record_version, declaration_identity_hash)
          values ('${gid}','${pid}','o1','manual_review','requested', 4, '${HASH_A}');
        insert into public.qhub_quantex_staff (user_id, staff_role, active) values ('staff1','reviewer', true);
        insert into public.qhub_manual_review_requests
          (id, org_id, project_id, request_type, category, reason, request_hash, status,
           governance_record_id, governance_record_version, declaration_identity_hash, requester_user_id)
          values ('${rid}','o1','${pid}','data_review','personal','sensitive','h','pending',
           '${gid}', 4, '${HASH_A}', 'u1');
      `);

      // Governance drift: the customer changed the declaration after the review was opened.
      await db.exec(
        `update public.qhub_governance_essentials set declaration_identity_hash='${HASH_B}', record_version=5 where id='${gid}'`,
      );

      const drift = await db.query<{ v: { ok: boolean; reason: string } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','v1') v`,
      );
      expect(drift.rows[0].v.ok).toBe(false);
      expect(drift.rows[0].v.reason).toBe('governance_changed');

      // No side effect: the request is still pending and the Governance review_state unchanged.
      const req = await db.query<{ status: string }>(
        `select status from public.qhub_manual_review_requests where id='${rid}'`,
      );
      expect(req.rows[0].status).toBe('pending');

      const auditN = await db.query<{ n: number }>(
        `select count(*)::int n from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(auditN.rows[0].n).toBe(0);

      // Restore the bound identity → the same decision now approves and writes ONE audit row.
      await db.exec(
        `update public.qhub_governance_essentials set declaration_identity_hash='${HASH_A}', record_version=4 where id='${gid}'`,
      );

      const ok = await db.query<{ v: { ok: boolean } }>(
        `select public.qhub_decide_review('${rid}','staff1',true,'approved','looks fine','v1') v`,
      );
      expect(ok.rows[0].v.ok).toBe(true);

      const audit = await db.query<{ hash: string }>(
        `select after_state->>'declaration_identity_hash' hash from public.qhub_entitlement_audit where change_type='REVIEW_DECISION'`,
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0].hash).toBe(HASH_A);
    } finally {
      await db.close();
    }
  });
});
