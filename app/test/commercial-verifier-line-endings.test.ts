/**
 * QHUB R15.1 — VERIFIER LINE-ENDING PORTABILITY (PGlite)
 * app/test/commercial-verifier-line-endings.test.ts
 *
 * The five function-body pins in qhub_verify_commercial_schema() hash `prosrc`, the verbatim stored
 * body. Some application channels (a Windows clipboard paste into the Supabase SQL Editor) rewrite the
 * migration's LF line endings to CRLF; PostgreSQL stores that verbatim, so all five digests changed
 * uniformly even though the bodies were semantically identical. The pins now hash
 * `replace(prosrc, chr(13), '')`, so an LF-applied and a CRLF-applied database verify identically.
 *
 * These tests prove the normalization is exactly that narrow: CR is ignored, and EVERY other character
 * — including a single executable token — still changes the digest and is still reported as drift, even
 * when the drifted migration is applied through the CRLF channel.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const MIG = fileURLToPath(
  new URL('../../supabase/migrations/20260729_commercial_launch_foundation.sql', import.meta.url),
);
const LF = readFileSync(MIG, 'utf8');
const CRLF = LF.replace(/\n/g, '\r\n');

interface VerifierResult {
  expected_version: string;
  ready: boolean;
  failed: string[];
}

async function applyAndVerify(sql: string): Promise<VerifierResult> {
  const db = new PGlite();

  try {
    await db.exec(`
      CREATE ROLE anon NOLOGIN;
      CREATE ROLE authenticated NOLOGIN;
      CREATE ROLE service_role NOLOGIN BYPASSRLS;
    `);
    await db.exec(sql);

    const r = await db.query<{ v: VerifierResult }>(`select public.qhub_verify_commercial_schema() v`);

    return r.rows[0].v;
  } finally {
    await db.close();
  }
}

/** Apply `sql` and return the CR-presence + digest facts for one function. */
async function bodyFacts(sql: string, proname: string) {
  const db = new PGlite();

  try {
    await db.exec(`
      CREATE ROLE anon NOLOGIN;
      CREATE ROLE authenticated NOLOGIN;
      CREATE ROLE service_role NOLOGIN BYPASSRLS;
    `);
    await db.exec(sql);

    const r = await db.query<{ raw: string; normalized: string; has_cr: boolean }>(
      `select md5(p.prosrc) raw, md5(replace(p.prosrc, chr(13), '')) normalized,
              (position(chr(13) in p.prosrc) > 0) has_cr
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.proname = $1`,
      [proname],
    );

    return r.rows[0];
  } finally {
    await db.close();
  }
}

/*
 * One executable-token mutation per protected body, with the exact failure label the verifier must
 * report. Each replacement is asserted to actually change the source, so a stale pattern cannot make a
 * test silently vacuous.
 */
const BODY_MUTATIONS: Array<{ label: string; failure: string; mutate: (s: string) => string }> = [
  {
    label: 'qhub_decide_review',
    failure: 'decide_review_body_drift',
    mutate: (s) =>
      s.replace(
        "RETURN jsonb_build_object('ok', false, 'reason', 'staff_required');",
        "RETURN jsonb_build_object('ok', true, 'reason', 'staff_required');",
      ),
  },
  {
    label: 'qhub_create_review_request',
    failure: 'r7_create_review_body_drift',
    mutate: (s) => s.replace("'review_not_required'", "'review_not_requiredX'"),
  },
  {
    label: 'qhub_record_acknowledgment',
    failure: 'r7_record_ack_body_drift',
    mutate: (s) => s.replace("'not_acknowledgeable'", "'not_acknowledgeableX'"),
  },
  {
    label: 'qhub_canon_cells',
    failure: 'r7_canon_cells_body_drift',
    mutate: (s) => s.replace("length(convert_to(c, 'UTF8'))::text || ':' || c", 'c'),
  },
  {
    label: 'qhub_row_immutable',
    failure: 'r7_ack_immutable_body_drift',
    mutate: (s) =>
      s.replace(
        "RAISE EXCEPTION 'qhub_acknowledgments authority fields are immutable';",
        "RAISE NOTICE 'qhub_acknowledgments authority fields are immutable';",
      ),
  },
];

describe('R15.1 — verifier is portable across LF and CRLF application channels', () => {
  it('test 1 — the LF-applied migration verifies READY with no failures', async () => {
    const v = await applyAndVerify(LF);
    expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
    expect(v.failed).toEqual([]);
    expect(v.ready).toBe(true);
  }, 120_000);

  it('test 2 — the CRLF-applied migration verifies READY with no failures', async () => {
    const v = await applyAndVerify(CRLF);
    expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
    expect(v.failed).toEqual([]);
    expect(v.ready).toBe(true);
  }, 120_000);

  it('the CRLF channel really does store CR in prosrc (the condition being tolerated)', async () => {
    const lf = await bodyFacts(LF, 'qhub_decide_review');
    const crlf = await bodyFacts(CRLF, 'qhub_decide_review');

    expect(lf.has_cr).toBe(false);
    expect(crlf.has_cr).toBe(true);

    // Raw digests differ (that was the live failure); CR-normalized digests agree.
    expect(crlf.raw).not.toBe(lf.raw);
    expect(crlf.normalized).toBe(lf.normalized);
  }, 120_000);
});

describe('R15.1 — CR normalization does NOT mask real body drift', () => {
  for (const { label, failure, mutate } of BODY_MUTATIONS) {
    it(`test 3-8 — a single executable-token change in ${label} still reports ${failure}`, async () => {
      const mutated = mutate(LF);
      expect(mutated, `mutation pattern for ${label} did not match — test would be vacuous`).not.toBe(LF);

      const v = await applyAndVerify(mutated);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain(failure);
    }, 120_000);
  }

  it('test 3 — a mutated body applied through the CRLF channel is STILL detected', async () => {
    // The dangerous case: drift + CRLF must not cancel out.
    const mutatedCrlf = BODY_MUTATIONS[0].mutate(LF).replace(/\n/g, '\r\n');
    const v = await applyAndVerify(mutatedCrlf);
    expect(v.ready).toBe(false);
    expect(v.failed).toContain('decide_review_body_drift');
  }, 120_000);

  it('test 9 — whitespace that is NOT a carriage return still changes the digest', async () => {
    // Add one space inside an executable line of qhub_canon_cells: only CR is ignored, not spaces/LF.
    const spaced = LF.replace('string_agg(\n    CASE WHEN c IS NULL', 'string_agg(\n     CASE WHEN c IS NULL');
    expect(spaced, 'whitespace mutation pattern did not match').not.toBe(LF);

    const v = await applyAndVerify(spaced);
    expect(v.ready).toBe(false);
    expect(v.failed).toContain('r7_canon_cells_body_drift');
  }, 120_000);
});
