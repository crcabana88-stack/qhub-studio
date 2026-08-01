/**
 * QHUB R15.2 — VERIFIER EXACT DUAL-DIGEST BODY PINS (PGlite)
 * app/test/commercial-verifier-body-digests.test.ts
 *
 * The five function-body pins in qhub_verify_commercial_schema() hash RAW `prosrc` and accept exactly
 * two separately reviewed encodings of the same reviewed body: the LF digest and the CRLF digest.
 * (Some application channels — a Windows clipboard paste into the SQL Editor — rewrite LF to CRLF, and
 * PostgreSQL stores that verbatim.)
 *
 * This supersedes the WITHDRAWN R15.1 design, which hashed md5(replace(prosrc, chr(13), '')). Deleting
 * every CR also deletes a CR injected INSIDE executable text, so a body containing 'staff\r_required'
 * hashed identically to the reviewed body and produced a FALSE READY. That exact vector is now a
 * first-class regression test below.
 *
 * No normalization of any kind is used: any third byte sequence — an injected or removed CR or LF,
 * intra-body mixed endings, whitespace, a comment edit, or an executable token change — falls outside
 * the two-value allowlist and is reported as drift.
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

/** The exact reviewed raw digests, both encodings, per protected function. */
const APPROVED_DIGESTS: Record<string, { lf: string; crlf: string }> = {
  qhub_decide_review: { lf: '7e678f1e4bba0c540507cfe3743fbe54', crlf: 'dac8abcd56d7fc804baac660059c14bf' },
  qhub_create_review_request: { lf: '6b46c3d75636fd0c8b628b34a86f4084', crlf: '349b59554232ab7f3b9e4aa3a8cc2331' },
  qhub_record_acknowledgment: { lf: 'b6035e9a35f5ecc49369b68000c7b2a6', crlf: '09e053d93afb7aca96064b758d76213a' },
  qhub_canon_cells: { lf: '6151a5d4794e56fbc26fc891f8fefdb4', crlf: '2d569f42d1e95f2ffd38dc82e14d727c' },
  qhub_row_immutable: { lf: '41ae59dde9a471b580d28e2cb45984f5', crlf: '4936e3f58627dde5abc10d2b0ecf5b4f' },
};

/** Raw md5(prosrc) of one function on a database built from `sql`. */
async function rawDigest(sql: string, proname: string): Promise<string> {
  const db = new PGlite();

  try {
    await db.exec(`
      CREATE ROLE anon NOLOGIN;
      CREATE ROLE authenticated NOLOGIN;
      CREATE ROLE service_role NOLOGIN BYPASSRLS;
    `);
    await db.exec(sql);

    const r = await db.query<{ m: string }>(
      `select md5(p.prosrc) m from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.proname = $1`,
      [proname],
    );

    return r.rows[0].m;
  } finally {
    await db.close();
  }
}

/** Executable-token mutations, one per protected body, with the exact expected failure label. */
const TOKEN_MUTATIONS: Array<{ label: string; failure: string; mutate: (s: string) => string }> = [
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

describe('R15.2 — exactly two reviewed encodings are accepted', () => {
  it('test 1 — the exact LF body verifies READY', async () => {
    const v = await applyAndVerify(LF);
    expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
    expect(v.failed).toEqual([]);
    expect(v.ready).toBe(true);
  }, 120_000);

  it('test 2 — the exact CRLF body verifies READY', async () => {
    const v = await applyAndVerify(CRLF);
    expect(v.expected_version).toBe('2026-07-30.commercial-launch-r8');
    expect(v.failed).toEqual([]);
    expect(v.ready).toBe(true);
  }, 120_000);

  it('the reviewed LF and CRLF raw digests are exactly the approved constants', async () => {
    for (const [proname, { lf, crlf }] of Object.entries(APPROVED_DIGESTS)) {
      expect(await rawDigest(LF, proname), `${proname} LF`).toBe(lf);
      expect(await rawDigest(CRLF, proname), `${proname} CRLF`).toBe(crlf);
    }
  }, 240_000);

  it('test 17 — the verifier uses RAW prosrc with exactly two approved digests per pin', () => {
    // No normalization helper may appear against prosrc.
    expect(LF).not.toMatch(/replace\(p\.prosrc/);
    expect(LF).not.toMatch(/regexp_replace\(p\.prosrc/);
    expect(LF).not.toMatch(/translate\(p\.prosrc/);
    expect(LF).not.toMatch(/(btrim|ltrim|rtrim|trim)\(p\.prosrc/);

    /*
     * Six raw pins: the five R7-era per-function pins, plus R15.6's
     * row_immutable_body_digest check, which re-pins the SAME two approved
     * qhub_row_immutable digests under a row_immutable-scoped label.
     */
    expect((LF.match(/md5\(p\.prosrc\)/g) ?? []).length).toBe(6);
    expect((LF.match(/-- reviewed body, LF encoding/g) ?? []).length).toBe(5);
    expect((LF.match(/-- reviewed body, CRLF encoding/g) ?? []).length).toBe(5);

    /*
     * Every approved digest constant appears exactly at its pin sites — once per
     * function, except qhub_row_immutable whose two digests appear exactly twice
     * (the R7 pin and the R15.6 pin). No OTHER digest is ever added: the count
     * being exact both ways is what forbids quietly blessing a new encoding.
     */
    for (const [proname, { lf, crlf }] of Object.entries(APPROVED_DIGESTS)) {
      const expected = proname === 'qhub_row_immutable' ? 2 : 1;
      expect((LF.match(new RegExp(lf, 'g')) ?? []).length, `LF digest ${lf}`).toBe(expected);
      expect((LF.match(new RegExp(crlf, 'g')) ?? []).length, `CRLF digest ${crlf}`).toBe(expected);
    }
  });
});

describe('R15.2 — the withdrawn R15.1 false-READY vector is closed', () => {
  it('test 4 — a CR injected INSIDE executable text is drift, not a tolerated encoding (LF file)', async () => {
    const evil = LF.replace("'staff_required'", "'staff\r_required'");
    expect(evil, 'injection pattern did not match').not.toBe(LF);

    const v = await applyAndVerify(evil);
    expect(v.ready).toBe(false);
    expect(v.failed).toContain('decide_review_body_drift');
  }, 120_000);

  it('test 4b — the same injection inside a CRLF-applied file is also drift', async () => {
    const evil = CRLF.replace("'staff_required'", "'staff\r_required'");
    expect(evil).not.toBe(CRLF);

    const v = await applyAndVerify(evil);
    expect(v.ready).toBe(false);
    expect(v.failed).toContain('decide_review_body_drift');
  }, 120_000);
});

describe('R15.2 — every other byte sequence is rejected', () => {
  /** Convert only the first half of the qhub_decide_review body's lines to CRLF (intra-body mixing). */
  function intraBodyMixed(): string {
    const start = LF.indexOf('CREATE OR REPLACE FUNCTION public.qhub_decide_review');
    const end = LF.indexOf('$$;', start) + 3;
    const lines = LF.slice(start, end).split('\n');
    const half = Math.floor(lines.length / 2);

    return LF.slice(0, start) + lines.map((l, n) => (n < half ? `${l}\r` : l)).join('\n') + LF.slice(end);
  }

  const ENCODING_MUTATIONS: Array<{ name: string; build: () => string; failure: string }> = [
    { name: 'test 3/16 — intra-body mixed LF/CRLF', build: intraBodyMixed, failure: 'decide_review_body_drift' },
    {
      name: 'test 13 — one extra CR outside a CRLF pair',
      build: () => CRLF.replace('BEGIN\r\n  IF NOT p_is_staff', 'BEGIN\r\r\n  IF NOT p_is_staff'),
      failure: 'decide_review_body_drift',
    },
    {
      name: 'test 14 — one CR removed from an otherwise CRLF body',
      build: () => CRLF.replace('BEGIN\r\n  IF NOT p_is_staff', 'BEGIN\n  IF NOT p_is_staff'),
      failure: 'decide_review_body_drift',
    },
    {
      name: 'test 15a — one LF added',
      build: () => LF.replace('BEGIN\n  IF NOT p_is_staff', 'BEGIN\n\n  IF NOT p_is_staff'),
      failure: 'decide_review_body_drift',
    },
    {
      name: 'test 15b/5 — one LF removed (two lines joined)',
      build: () => LF.replace('BEGIN\n  IF NOT p_is_staff', 'BEGIN  IF NOT p_is_staff'),
      failure: 'decide_review_body_drift',
    },
    {
      name: 'test 6 — non-CR whitespace (one space)',
      build: () => LF.replace('string_agg(\n    CASE WHEN c IS NULL', 'string_agg(\n     CASE WHEN c IS NULL'),
      failure: 'r7_canon_cells_body_drift',
    },
    {
      name: 'test 7 — a comment character inside a protected body',
      build: () =>
        LF.replace(
          '-- ALL authority/identity/scope fields are immutable after insert.',
          '-- ALL authority/identity/scope fields are immutable after insert!',
        ),
      failure: 'r7_ack_immutable_body_drift',
    },
  ];

  for (const { name, build, failure } of ENCODING_MUTATIONS) {
    it(`${name} is reported as ${failure}`, async () => {
      const mutated = build();
      expect(mutated, 'mutation pattern did not match — test would be vacuous').not.toBe(LF);

      const v = await applyAndVerify(mutated);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain(failure);
    }, 120_000);
  }

  for (const { label, failure, mutate } of TOKEN_MUTATIONS) {
    it(`tests 8-12 — an executable-token change in ${label} is reported as ${failure}`, async () => {
      const mutated = mutate(LF);
      expect(mutated, `mutation pattern for ${label} did not match`).not.toBe(LF);

      const v = await applyAndVerify(mutated);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain(failure);
    }, 120_000);

    it(`tests 8-12 (CRLF channel) — the same change in ${label} is still ${failure}`, async () => {
      const mutated = mutate(LF).replace(/\n/g, '\r\n');
      const v = await applyAndVerify(mutated);
      expect(v.ready).toBe(false);
      expect(v.failed).toContain(failure);
    }, 120_000);
  }

  /*
   * By design, a per-BODY-consistent encoding is accepted: if one whole body is CRLF and the others are
   * LF, every body still hashes to one of its two separately reviewed encodings. Only mixing WITHIN a
   * body (above) creates an unreviewed third sequence. This documents that boundary explicitly.
   */
  it('a per-body-consistent encoding is accepted (each body is an exact reviewed encoding)', async () => {
    const start = LF.indexOf('CREATE OR REPLACE FUNCTION public.qhub_decide_review');
    const end = LF.indexOf('$$;', start) + 3;
    const perBody = LF.slice(0, start) + LF.slice(start, end).replace(/\n/g, '\r\n') + LF.slice(end);

    const v = await applyAndVerify(perBody);
    expect(v.ready).toBe(true);
    expect(v.failed).toEqual([]);
  }, 120_000);
});
