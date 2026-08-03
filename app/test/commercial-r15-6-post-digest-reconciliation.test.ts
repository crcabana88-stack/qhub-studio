/**
 * R15.6 POST body-digest reconciliation.
 *
 * Offline proof that the two digests observed by POST 23 are the preapproved
 * CRLF encodings of the exact reviewed LF function bodies committed in the
 * migration, R15.3 restoration source, and R15.6 PATCH 22.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const MIGRATION_PATH = 'supabase/migrations/20260729_commercial_launch_foundation.sql';
const R15_3_PATH = 'docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql';
const R15_6 = 'docs/release/r15-6-runtime-verifier/';
const PRE_PATH = R15_6 + '21_PRE_PROTECTED_FUNCTION_RESTORATION.sql';
const PATCH_PATH = R15_6 + '22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql';
const POST_PATH = R15_6 + '23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql';
const DIAGNOSTIC_19_PATH = R15_6 + '19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql';
const DIAGNOSTIC_20_PATH = R15_6 + '20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql';
const VERIFIER_PATCH_PATH = R15_6 + '17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql';

const read = (relative: string): string => readFileSync(REPO + relative, 'utf8');
const sha256 = (relative: string): string =>
  createHash('sha256')
    .update(readFileSync(REPO + relative))
    .digest('hex');
const md5 = (value: string): string => createHash('md5').update(value, 'utf8').digest('hex');

const MIGRATION = read(MIGRATION_PATH);
const R15_3 = read(R15_3_PATH);
const PRE = read(PRE_PATH);
const PATCH = read(PATCH_PATH);
const POST = read(POST_PATH);
const VERIFIER_PATCH = read(VERIFIER_PATCH_PATH);

const APPROVED_FILE_HASHES: Record<string, string> = {
  [MIGRATION_PATH]: '1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755',
  [DIAGNOSTIC_19_PATH]: 'dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa',
  [DIAGNOSTIC_20_PATH]: '0626edb61d9f5ed916be881eb48af0dddac972c852472c8d18f2a8832ffd9047',
  [PRE_PATH]: '9a4bbcae4bdba6e78355d89ae91e98b31d3b2192c66c88e7455a4a17a769cff1',
  [PATCH_PATH]: 'f0062b2dd1b59deb768c78f54155a69515a4e28bdf6f714aed8c1e9277d00303',
  [POST_PATH]: '9ff28bc78b4083064e5794925922866eba22b392c3c51daa05b6ca4ebead6f0f',
};

const DIGESTS = {
  qhub_decide_review: {
    lf: '7e678f1e4bba0c540507cfe3743fbe54',
    crlf: 'dac8abcd56d7fc804baac660059c14bf',
    lfWithoutLeading: '4d905767958a9112adfba1b9c07ffb1a',
    lfWithoutTrailing: 'fdcc1a9e9c69c0dfaf279cfc9750408c',
    lfWithoutBoth: '39970ff62ea12c111acca833c4fa25a8',
    crlfWithoutLeading: 'f751f1267b28949d92bfc733367a0c68',
    crlfWithoutTrailing: '92f5481591635dc9ead0e3ccb7618b43',
    crlfWithoutBoth: '1d763c81e100fe55e95902bd51c4c0c6',
    lfCount: 170,
    lfBytes: 8753,
  },
  qhub_row_immutable: {
    lf: '41ae59dde9a471b580d28e2cb45984f5',
    crlf: '4936e3f58627dde5abc10d2b0ecf5b4f',
    lfWithoutLeading: '00c7361cf761be01935c1b8505b07921',
    lfWithoutTrailing: '1efc944a05d5596cf638e4d596ea5b45',
    lfWithoutBoth: 'b28e3f82192d5d02f1a1f3fa02c24acc',
    crlfWithoutLeading: '51a31f57704393e024098587c8a19df3',
    crlfWithoutTrailing: '961edb146d6850aa41f23e2bc12672e8',
    crlfWithoutBoth: 'c7e5ad0cf15ba1111ee368cf088a3338',
    lfCount: 35,
    lfBytes: 1619,
  },
} as const;

type FunctionName = keyof typeof DIGESTS;

function definition(sql: string, name: FunctionName): string {
  const start = sql.indexOf('CREATE OR REPLACE FUNCTION public.' + name);
  const bodyMarker = sql.indexOf('AS $$', start);
  const end = sql.indexOf('$$;', bodyMarker);

  if (start < 0 || bodyMarker < 0 || end < 0) {
    throw new Error(name + ' definition missing or ambiguous');
  }

  return sql.slice(start, end + 3);
}

function body(sql: string, name: FunctionName): string {
  const fn = definition(sql, name);
  const start = fn.indexOf('AS $$') + 'AS $$'.length;
  const end = fn.lastIndexOf('$$;');

  return fn.slice(start, end);
}

const toCrlf = (value: string): string => value.replace(/\r?\n/g, '\r\n');

function variants(value: string) {
  const lf = value.replace(/\r\n/g, '\n');
  const crlf = toCrlf(lf);

  return {
    lf,
    crlf,
    lfWithoutLeading: lf.replace(/^\n/, ''),
    lfWithoutTrailing: lf.replace(/\n$/, ''),
    lfWithoutBoth: lf.replace(/^\n/, '').replace(/\n$/, ''),
    crlfWithoutLeading: crlf.replace(/^\r\n/, ''),
    crlfWithoutTrailing: crlf.replace(/\r\n$/, ''),
    crlfWithoutBoth: crlf.replace(/^\r\n/, '').replace(/\r\n$/, ''),
  };
}

async function pgProcDigests(definitions: string): Promise<Record<string, string>> {
  const db = new PGlite();

  try {
    await db.exec(definitions);

    const result = await db.query<{ proname: string; digest: string }>(
      'SELECT p.proname,md5(p.prosrc) digest FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace ' +
        "WHERE n.nspname='public' AND p.proname IN ('qhub_decide_review','qhub_row_immutable') ORDER BY p.proname",
    );

    return Object.fromEntries(result.rows.map((row) => [row.proname, row.digest]));
  } finally {
    await db.close();
  }
}

describe('R15.6 POST digest reconciliation — offline byte proof', () => {
  it('keeps all six approved artifacts byte-identical', () => {
    for (const [path, expected] of Object.entries(APPROVED_FILE_HASHES)) {
      expect(sha256(path), path).toBe(expected);
    }
  });

  it.each(Object.keys(DIGESTS) as FunctionName[])(
    '%s PATCH body is byte-identical to R15.3 and the migration',
    (name) => {
      expect(body(PATCH, name)).toBe(body(R15_3, name));
      expect(body(PATCH, name)).toBe(body(MIGRATION, name));
    },
  );

  it.each(Object.keys(DIGESTS) as FunctionName[])(
    '%s reproduces every relevant newline-boundary digest deterministically',
    (name) => {
      const expected = DIGESTS[name];
      const actual = variants(body(PATCH, name));

      expect(md5(actual.lf)).toBe(expected.lf);
      expect(md5(actual.crlf)).toBe(expected.crlf);
      expect(md5(actual.lfWithoutLeading)).toBe(expected.lfWithoutLeading);
      expect(md5(actual.lfWithoutTrailing)).toBe(expected.lfWithoutTrailing);
      expect(md5(actual.lfWithoutBoth)).toBe(expected.lfWithoutBoth);
      expect(md5(actual.crlfWithoutLeading)).toBe(expected.crlfWithoutLeading);
      expect(md5(actual.crlfWithoutTrailing)).toBe(expected.crlfWithoutTrailing);
      expect(md5(actual.crlfWithoutBoth)).toBe(expected.crlfWithoutBoth);
    },
  );

  it.each(Object.keys(DIGESTS) as FunctionName[])(
    '%s CRLF bytes differ only by one 0x0D before every reviewed 0x0A',
    (name) => {
      const expected = DIGESTS[name];
      const { lf, crlf } = variants(body(PATCH, name));
      const lfBytes = Buffer.from(lf, 'utf8');
      const crlfBytes = Buffer.from(crlf, 'utf8');
      const crPositions = [...crlfBytes.entries()].filter(([, byte]) => byte === 0x0d).map(([index]) => index);

      expect(lf.startsWith('\n')).toBe(true);
      expect(lf.endsWith('\n')).toBe(true);
      expect(lfBytes.length).toBe(expected.lfBytes);
      expect(crPositions).toHaveLength(expected.lfCount);
      expect(crlfBytes.length).toBe(lfBytes.length + expected.lfCount);
      expect(crPositions.every((index) => crlfBytes[index + 1] === 0x0a)).toBe(true);
      expect(Buffer.from(crlf.replace(/\r\n/g, '\n'), 'utf8')).toEqual(lfBytes);
      expect(crlf.replace(/\r\n/g, '\n')).toBe(lf);
      expect(crlf).not.toContain('\r\r\n');
    },
  );

  it('PostgreSQL-compatible pg_proc.prosrc hashing reproduces all four reviewed digests', async () => {
    const lfDefinitions = [definition(PATCH, 'qhub_decide_review'), definition(PATCH, 'qhub_row_immutable')].join('\n');
    const crlfDefinitions = toCrlf(lfDefinitions);

    await expect(pgProcDigests(lfDefinitions)).resolves.toEqual({
      qhub_decide_review: DIGESTS.qhub_decide_review.lf,
      qhub_row_immutable: DIGESTS.qhub_row_immutable.lf,
    });
    await expect(pgProcDigests(crlfDefinitions)).resolves.toEqual({
      qhub_decide_review: DIGESTS.qhub_decide_review.crlf,
      qhub_row_immutable: DIGESTS.qhub_row_immutable.crlf,
    });
  }, 120_000);

  it.each(Object.keys(DIGESTS) as FunctionName[])(
    '%s accepts only the two exact preapproved byte sequences',
    (name) => {
      const expected = DIGESTS[name];
      const actual = variants(body(PATCH, name));
      const approved = new Set<string>([expected.lf, expected.crlf]);
      const boundaryVariants = [
        actual.lfWithoutLeading,
        actual.lfWithoutTrailing,
        actual.lfWithoutBoth,
        actual.crlfWithoutLeading,
        actual.crlfWithoutTrailing,
        actual.crlfWithoutBoth,
      ];
      const mixedEnding = actual.lf.replace('\n', '\r\n');

      expect(approved).toEqual(new Set([md5(actual.lf), md5(actual.crlf)]));
      expect(boundaryVariants.every((variant) => !approved.has(md5(variant)))).toBe(true);
      expect(approved.has(md5(mixedEnding))).toBe(false);
      expect(approved.has(md5(actual.lf + ' '))).toBe(false);
    },
  );

  it('the actual CRLF digests were preapproved before PATCH execution', () => {
    for (const expected of Object.values(DIGESTS)) {
      for (const source of [MIGRATION, R15_3, PRE, PATCH, POST, VERIFIER_PATCH]) {
        expect(source).toContain(expected.lf);
        expect(source).toContain(expected.crlf);
      }
    }
  });

  it('PATCH commits on exact dual-digest membership, never semantic normalization', () => {
    expect(PATCH).toMatch(
      /md5\(p\.prosrc\) IN \('7e678f1e4bba0c540507cfe3743fbe54',\s*'dac8abcd56d7fc804baac660059c14bf'\)/,
    );
    expect(PATCH).toMatch(
      /md5\(p\.prosrc\) IN \('41ae59dde9a471b580d28e2cb45984f5',\s*'4936e3f58627dde5abc10d2b0ecf5b4f'\)/,
    );
    expect(POST).toContain(
      "THEN md5(p.prosrc) IN ('7e678f1e4bba0c540507cfe3743fbe54','dac8abcd56d7fc804baac660059c14bf')",
    );
    expect(POST).toContain(
      "ELSE md5(p.prosrc) IN ('41ae59dde9a471b580d28e2cb45984f5','4936e3f58627dde5abc10d2b0ecf5b4f')",
    );
    expect(PATCH).not.toMatch(/md5\s*\(\s*(?:replace|regexp_replace|translate)\s*\(\s*p\.prosrc/i);
    expect(POST).not.toMatch(/md5\s*\(\s*(?:replace|regexp_replace|translate)\s*\(\s*p\.prosrc/i);
  });
});
