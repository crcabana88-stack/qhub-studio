# R15.6 POST body-digest reconciliation

## Scope and conclusion

This is a strictly offline reconciliation of the two raw `pg_proc.prosrc` MD5 values reported by committed POST 23 after PATCH 22. It uses only committed repository content at `39f3ee077876fe94549e0c34eb073dba609e5559`; it does not query or change a live system.

The two POST values are the exact, preapproved CRLF encodings of the reviewed bodies. They differ from the LF source bodies only by one `0x0D` byte immediately before every existing `0x0A` line-feed byte. Removing those inserted CR bytes reconstructs the committed LF bodies byte-for-byte. No executable token, comment character, space, leading newline, trailing newline, or other byte differs.

Classification: **A — preapproved newline-only variants with identical SQL semantics**, caused operationally by **C — the browser editor's LF-to-CRLF transfer normalization**. This is not B, D, or E: the verifier does not normalize or broadly accept bodies; it accepts exactly two independently pinned raw byte sequences.

## Authoritative sources

The selected definitions are identical in all three sources:

- Migration: `supabase/migrations/20260729_commercial_launch_foundation.sql`
  - `qhub_row_immutable()`: lines 585–621
  - `qhub_decide_review(uuid,text,boolean,text,text,text)`: lines 1340–1513
- R15.3 restoration authority: `docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql`
  - decision function: lines 187–368
  - immutable-row function: lines 373–416
- R15.6 live PATCH: `docs/release/r15-6-runtime-verifier/22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql`
  - decision function: lines 295–476
  - immutable-row function: lines 481–524

For each function, the bytes between `AS $$` and the closing `$$;` in PATCH 22 are exactly equal to the corresponding R15.3 and migration bytes. Each body deliberately begins and ends with a newline because those newlines are inside the dollar-quoted value stored as `prosrc`.

## Exact byte transformations and reproduced digests

The committed files use LF line endings. The supported browser-editor variant is produced by this exact transformation:

```text
For every 0x0A in the reviewed body, insert one 0x0D immediately before it.
No other byte changes.
```

| Function | Variant | UTF-8 bytes | LF count | Raw `md5(prosrc)` |
|---|---:|---:|---:|---|
| `qhub_decide_review` | committed LF | 8,753 | 170 | `7e678f1e4bba0c540507cfe3743fbe54` |
| `qhub_decide_review` | exact CRLF | 8,923 | 170 | `dac8abcd56d7fc804baac660059c14bf` |
| `qhub_row_immutable` | committed LF | 1,619 | 35 | `41ae59dde9a471b580d28e2cb45984f5` |
| `qhub_row_immutable` | exact CRLF | 1,654 | 35 | `4936e3f58627dde5abc10d2b0ecf5b4f` |

The CRLF byte-length increase equals the LF count in each body: `8,923 − 8,753 = 170` and `1,654 − 1,619 = 35`. Every inserted `0x0D` is followed by `0x0A`; there are no lone CR bytes and no `CR CR LF` sequences. Replacing every `0x0D 0x0A` pair with `0x0A` yields a byte buffer exactly equal to the committed body.

Boundary-newline variants are different and are not approved:

| Function | Variant | Raw MD5 |
|---|---|---|
| decision | LF without leading newline | `4d905767958a9112adfba1b9c07ffb1a` |
| decision | LF without trailing newline | `fdcc1a9e9c69c0dfaf279cfc9750408c` |
| decision | LF without both boundary newlines | `39970ff62ea12c111acca833c4fa25a8` |
| decision | CRLF without leading newline | `f751f1267b28949d92bfc733367a0c68` |
| decision | CRLF without trailing newline | `92f5481591635dc9ead0e3ccb7618b43` |
| decision | CRLF without both boundary newlines | `1d763c81e100fe55e95902bd51c4c0c6` |
| immutable row | LF without leading newline | `00c7361cf761be01935c1b8505b07921` |
| immutable row | LF without trailing newline | `1efc944a05d5596cf638e4d596ea5b45` |
| immutable row | LF without both boundary newlines | `b28e3f82192d5d02f1a1f3fa02c24acc` |
| immutable row | CRLF without leading newline | `51a31f57704393e024098587c8a19df3` |
| immutable row | CRLF without trailing newline | `961edb146d6850aa41f23e2bc12672e8` |
| immutable row | CRLF without both boundary newlines | `c7e5ad0cf15ba1111ee368cf088a3338` |

The focused test also proves that a mixed-ending body, appended whitespace, or any boundary-newline removal falls outside the two-value sets.

## PostgreSQL `prosrc` reproduction

`app/test/commercial-r15-6-post-digest-reconciliation.test.ts` installs the exact extracted definitions in PGlite, queries `md5(pg_proc.prosrc)`, and reproduces all four values:

| Installed body | Decision digest | Immutable-row digest |
|---|---|---|
| exact committed LF definitions | `7e678f1e4bba0c540507cfe3743fbe54` | `41ae59dde9a471b580d28e2cb45984f5` |
| the same definitions with only LF→CRLF | `dac8abcd56d7fc804baac660059c14bf` | `4936e3f58627dde5abc10d2b0ecf5b4f` |

Direct UTF-8 hashing of the dollar-quoted body bytes returns the same values as the PostgreSQL-compatible `pg_proc.prosrc` query.

## Where the CRLF values were preapproved

Both CRLF values were committed before live PATCH execution:

- Migration verifier accepted sets:
  - decision: `supabase/migrations/20260729_commercial_launch_foundation.sql:2046–2047`
  - immutable row: `supabase/migrations/20260729_commercial_launch_foundation.sql:2158–2159`
- R15.2 exact dual-digest verifier: `docs/release/r15-2-verifier-patch/08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql:503–504,606–607`
- R15.3 restoration runbook labels them reviewed LF and reviewed CRLF: `docs/release/r15-3-body-restoration/R15_3_BODY_RESTORATION_RUNBOOK.md:47–52`
- R15.3 restoration final checks require membership in `(LF, CRLF)`: `docs/release/r15-3-body-restoration/11_RESTORE_REVIEWED_PROTECTED_BODIES.sql:556–557`
- R15.6 verifier PATCH accepted sets: `docs/release/r15-6-runtime-verifier/17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql:638–639,750–751`
- R15.6 PRE includes both expected variants: `docs/release/r15-6-runtime-verifier/21_PRE_PROTECTED_FUNCTION_RESTORATION.sql:181–188`
- R15.6 PATCH includes both variants in its preconditions and final assertions: `docs/release/r15-6-runtime-verifier/22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql:184–189,667–675`
- R15.6 POST reports and accepts both: `docs/release/r15-6-runtime-verifier/23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql:42–49,268–272`
- Regression coverage explicitly describes exactly two raw encodings and prohibits normalization: `app/test/commercial-verifier-body-digests.test.ts:1–17,126–149`

## Why PATCH committed

PATCH 22 did not assert only the LF digests. Its Gate 3 final assertions use exact membership in two-element raw-digest sets:

```sql
md5(p.prosrc) IN ('7e678f1e4bba0c540507cfe3743fbe54',
                  'dac8abcd56d7fc804baac660059c14bf')

md5(p.prosrc) IN ('41ae59dde9a471b580d28e2cb45984f5',
                  '4936e3f58627dde5abc10d2b0ecf5b4f')
```

The full script was transferred through a browser editor that represented the selected SQL with CRLF line endings. PostgreSQL stores the dollar-quoted function body text in `prosrc` with those line endings. The resulting digests were the second exact member of each already approved set, so Gate 3, the installed commercial verifier, and POST 23 all correctly passed. No semantic-equivalence heuristic was used.

## Reconciling the earlier exact-digest statement

The package statement that the committed definitions produce `7e678…` and `41ae…` is correct for the committed LF bytes and is reproduced offline. The later execution authorization was stricter: it required those LF values even though the committed package and established transfer model explicitly allowed the CRLF alternatives. Because the live transfer selected the CRLF representation, that authorization's single-variant condition was not satisfied. Stopping for reconciliation was therefore procedurally correct.

The database state reported by POST satisfies the committed verifier/PATCH/POST contract, but it did not satisfy the narrower LF-only wording in the execution authorization. This report resolves the discrepancy without changing any accepted digest or live object.

## Semantic and security assessment

PostgreSQL/PL/pgSQL treats LF and CRLF as line terminators. The CR bytes occur only as the first byte of every CRLF pair, at every original line boundary, including the intentionally retained leading and trailing body newlines. Normalizing CRLF to LF yields the authoritative body exactly; therefore the executable SQL, literals, identifiers, comments, control flow, and privileges are identical.

Security remains fail-closed:

- The verifier hashes raw `prosrc`; it performs no normalization.
- Exactly two reviewed byte sequences are accepted per function.
- Mixed endings, isolated CR insertion, whitespace edits, comment edits, boundary-newline edits, and executable changes produce third digests and fail.
- ACL, owner, metadata, identity, OID, trigger, and product-readiness checks remain independent of the body digest.
- No accepted set, verifier, migration, PRE, PATCH, POST, function, ACL, trigger, schema object, or live record is changed by this reconciliation.

## Findings

- **P0: 0**
- **P1: 0**
- **P2: 1 — procedural wording mismatch.** The execution authorization required only the LF member while the already approved package and documented browser-transfer model allowed both exact LF and CRLF members. The stop and this offline reconciliation close the evidence gap; no product or database remediation is indicated.

## Recommendation

**SAFE TO ACCEPT POST AS VERIFIED — PREAPPROVED NEWLINE-ONLY VARIANTS**
