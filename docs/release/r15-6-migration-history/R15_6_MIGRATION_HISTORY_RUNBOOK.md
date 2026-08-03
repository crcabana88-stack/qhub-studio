# QHUB R15.6 — Migration-History Reconciliation Runbook (corrected)

Human-operated. Records the complete, CLI-compatible history row for the already-applied,
already-verified commercial migration `20260729` — and does **nothing else**. This is the final
step before the founder-access preview. **Founder seed and Stripe configuration remain separate,
unauthorized follow-on gates and are NOT part of this package.**

## Purpose and scope

The commercial migration `20260729_commercial_launch_foundation.sql` was applied to the live
database and its resulting state has been fully verified (R15.6 closure: `product_ready=true`,
`product_version=2026-07-30.commercial-launch-r8`, `failed=[]`, protected bodies exact approved
CRLF variants, 0 P0/P1). Its history entry was never recorded. This package records exactly one
complete row:

```sql
INSERT INTO supabase_migrations.schema_migrations (version, name, statements)
VALUES ('20260729', 'commercial_launch_foundation', <the 89 CLI-parsed statements>);
```

Every field is derived, never guessed:

- `version` and `name` come from the pinned CLI's filename parser (`^([0-9]+)_(.*)\.sql$`,
  extracted verbatim from the installed binary) applied to the committed migration
  (SHA-256 `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755`, 125,186 bytes).
- `statements` is the **exact `text[]` the pinned CLI itself records** for this migration —
  derived offline by invoking the installed binary by explicit local path against an isolated
  localhost scratch database, byte-identical across three independent runs, round-trip-verified
  through the CLI's own `migration fetch`: **cardinality 89, total 124,959 bytes, canonical digest
  `7b28ccf3ba7cae3e29c17bc5c3be60b6`** (md5 over `octet_length(elem) || ':' || elem` in element
  order). The array is committed as the reviewable fixture
  `app/test/fixtures/r8-20260729-cli-statements.json` and embedded in `26` as single-line base64
  **INSERT data only** — decoded, integrity-checked, never interpreted, never executed; `26`
  contains no dynamic SQL and no `EXECUTE` of any kind.

`supabase migration repair` was evaluated and **rejected** as the mechanism: its applied-path
write is an unconditional `ON CONFLICT (version) DO UPDATE` upsert that silently overwrites
conflicting rows and cannot gate on verifier readiness (analysis §3).

## The pinned CLI (inspection and derivation only — never a live mutation tool here)

| Item | Value |
|---|---|
| Package | `supabase@2.110.0` (npm wrapper 2.110.0, platform binary 2.110.0) |
| Binary path | `%LOCALAPPDATA%\npm-cache\_npx\7960735060baecd3\node_modules\@supabase\cli-windows-x64\bin\supabase.exe` |
| Binary SHA-256 | `14814afa6fe59081eb9f24709fc077226bf89bc25cf77ee3bcb19565f3ef8899` |

The CLI is invoked **only** by that explicit local path, **only** against an isolated localhost
scratch database, and **only** for offline derivation/verification. **`npx --yes` and any command
capable of package-registry access are prohibited. `migration repair` against any live project is
prohibited. The commercial migration is never re-executed anywhere by this package.**

## Prerequisites (all mandatory, in order)

1. **Repository identity.** Local HEAD, origin tracking and the remote branch all equal the
   approved commit from the final review report; `git status` clean. Prior approved package
   commit: `5c36883eed44b877733768649c805ef2c64f0c7f`.
2. **Artifact integrity.** Recompute and match every hash in the table below. STOP on any
   mismatch — never run a mismatched artifact.
3. **Project confirmation.** The SQL Editor tab's URL must show project ref `jsjsanmaahvmynblmzkq`
   before every paste. (The in-transaction gates additionally fail closed on any database that
   does not carry this project's exact verifier digest and READY state.)
4. **Transfer safety.** Copy every file with exactly:
   `Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard`
   (The statements payload is additionally self-protecting: base64 lines are line-ending-inert
   and `26` refuses any payload whose decoded digest is not exact.)
5. **Fresh session per step.** Each separately authorized step (25, 26, 27) runs in a NEW SQL
   Editor session. `26` deliberately fails closed if re-run in a session that already ran it.

## Authoritative artifact hashes (SHA-256)

| Artifact | SHA-256 |
|---|---|
| `supabase/migrations/20260729_commercial_launch_foundation.sql` | `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755` |
| `docs/release/r15-6-runtime-verifier/19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql` | `dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa` |
| `docs/release/r15-6-runtime-verifier/20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql` | `0626edb61d9f5ed916be881eb48af0dddac972c852472c8d18f2a8832ffd9047` |
| `docs/release/r15-6-runtime-verifier/21_PRE_PROTECTED_FUNCTION_RESTORATION.sql` | `9a4bbcae4bdba6e78355d89ae91e98b31d3b2192c66c88e7455a4a17a769cff1` |
| `docs/release/r15-6-runtime-verifier/22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql` | `f0062b2dd1b59deb768c78f54155a69515a4e28bdf6f714aed8c1e9277d00303` |
| `docs/release/r15-6-runtime-verifier/23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql` | `9ff28bc78b4083064e5794925922866eba22b392c3c51daa05b6ca4ebead6f0f` |
| `docs/release/r15-6-migration-history/25_PRE_MIGRATION_HISTORY_VERIFY.sql` | `ecc21963ea44555132d87e89edffce45b40745b36c57a139f23d66a6d4f096a4` |
| `docs/release/r15-6-migration-history/26_MIGRATION_HISTORY_RECORD.sql` | `6d1605e7cb45195f8312098e1258e322648c6fbce10cb956c8ada82bab7274c8` |
| `docs/release/r15-6-migration-history/27_POST_MIGRATION_HISTORY_VERIFY.sql` | `e63e12ec60c4d84277aedbb855923b8fa0aed06309c554194820e2567db084bc` |
| `app/test/fixtures/r8-20260729-cli-statements.json` | `d2e85b8c5f68735ff9cf817a5cdcfb9751a980f913ebff1c5886bab56ef9999d` |

## Sequence

| # | step | require |
|---|---|---|
| 1 | `25_PRE_MIGRATION_HISTORY_VERIFY.sql` (read-only, fresh session, in full) | `SAFE_TO_RECORD_MIGRATION_HISTORY` — or `ALREADY_RECORDED_EXACTLY`, in which case skip step 3 |
| 2 | **HUMAN REVIEW** of both PRE result rows. Confirm the neighbor rows, the full table contract columns, and the exact expected version/name/statements identity. | explicit human go |
| 3 | `26_MIGRATION_HISTORY_RECORD.sql` (once, fresh session, in full) | the final SELECT shows `action = RECORDED_NOW` (or `ALREADY_RECORDED_EXACTLY`), `history_version = 20260729`, `history_name = commercial_launch_foundation`, `statements_cardinality = 89`, `statements_digest = 7b28ccf3ba7cae3e29c17bc5c3be60b6`, `statements_total_bytes = 124959`, `rows_for_version = 1`. Capture verbatim. |
| 4 | `27_POST_MIGRATION_HISTORY_VERIFY.sql` (read-only, fresh session, in full) | **`MIGRATION_20260729_HISTORY_RECONCILED`** |
| 5 | Founder-access preview (read-only) → **pause for human approval**. Founder seed and Stripe remain unauthorized. | — |

`27` — not `26`'s audit display — is the certification of durable state; reconciliation is
complete only when a separately authorized `27` returns its success verdict.

## Concurrency and isolation design (26)

One explicit transaction encompassing every temporary and durable operation:
`BEGIN` → `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` (declared before any authorization
state is read; post-lock reads must see the newest committed state) → `SET LOCAL search_path =
pg_catalog` (all non-catalog objects schema-qualified; pg_temp cannot shadow anything) →
`CREATE TEMP TABLE r15_6_migration_history_audit` (no `IF NOT EXISTS`) → one `DO` block:
payload integrity → resolve table → **`LOCK TABLE supabase_migrations.schema_migrations IN SHARE
ROW EXCLUSIVE MODE`** → re-resolve identity → complete verifier authority → product READY →
complete table contract → conflicts (malformed versions detected before any ordered comparison)
→ the single INSERT or a true no-op → exactly-one-row audit capture → `COMMIT`. The lock is held
through COMMIT. SHARE ROW EXCLUSIVE conflicts with every INSERT/UPDATE/DELETE writer (ROW
EXCLUSIVE) and with itself, so concurrent `26` runs and any concurrent CLI repair serialize —
proven by two-independent-session tests against a real PostgreSQL 16 server
(`app/test/commercial-r15-6-history-concurrency.test.ts`).

## Exact authorized mutation inventory

- **Durable:** at most ONE row inserted into `supabase_migrations.schema_migrations` —
  `('20260729', 'commercial_launch_foundation', <89-element statements array>)`. No UPDATE, no
  DELETE, no upsert path exists in the artifact; an existing row with a different name or
  NULL/incomplete/different statements is a STOP, never an update.
- **Temporary:** `pg_temp.r15_6_migration_history_audit`, created inside the transaction,
  mechanically guaranteed exactly one row (the DO block raises otherwise), removed by rollback on
  any failure, session-local after COMMIT until the session ends. A pre-existing object of that
  name (same-session rerun) fails the run closed before any gate. The post-COMMIT SELECT reads
  ONLY this captured evidence — it does not re-query durable state.
- Nothing else. No schema/table/function/trigger/ACL/policy/role/founder/entitlement/billing/
  Stripe change; the commercial migration is not re-executed; no stored statement text is ever
  interpreted or executed.

## Stop conditions

Treat **any** of the following as a STOP — capture everything, escalate, do not retry, do not run
supplemental SQL:

- any prerequisite fails (identity, hashes, project ref)
- `25` returns `UNEXPECTED_MIGRATION_HISTORY_STOP` — including: target under another name,
  NULL-name row, target with NULL/incomplete/different statements, name under another version,
  any malformed recorded version, any newer version, any table-contract drift (columns, PK,
  constraints, indexes, triggers, rules, policies, RLS, inheritance, owner, kind), verifier
  authority or readiness drift, missing history table
- `26` raises any exception (`migration_history_payload_integrity`,
  `unexpected_runtime_verifier_state`, `unexpected_runtime_verifier_authority`,
  `migration_history_product_not_ready`, `unexpected_migration_history_shape`,
  `migration_history_conflict`, or any SQL error)
- `26`'s final SELECT shows anything other than the exact expected values
- `27` is not exactly `MIGRATION_20260729_HISTORY_RECONCILED`
- **any notice, warning, unexpected result row, SQL error, timeout, cancellation, connection
  loss, or transaction ambiguity in any step**

## No-retry rules and recovery from ambiguity

- Automatic retries are prohibited. A deterministic gate that failed will fail identically
  without a state change; a retry after an unexplained state change must never happen silently.
- If a `26` run is cancelled, times out, loses its connection, or its outcome is otherwise
  unknown: the single-transaction design means the server either committed everything or rolled
  back everything (including the temp audit table). Open a FRESH session and run read-only `25`:
  `ALREADY_RECORDED_EXACTLY` means it committed — proceed to human review, then `27`.
  `SAFE_TO_RECORD_MIGRATION_HISTORY` means it rolled back — the database is unchanged; pause for
  human review before any new `26` run. Any other verdict: STOP and escalate.
- A `26` rerun in the SAME session fails closed by design (the audit table already exists);
  that failure changes nothing durable and is not an error to work around — use a fresh session
  only after the disambiguation above.

## Explicitly out of scope / unauthorized

Founder seed, founder entitlement creation, Stripe configuration, deployment, `db push`,
`--include-all`, `migration repair` against any live project, migration re-execution, the
duplicate-prefix version backlog for `20260725/20260726/20260727`, and any edit to previously
approved artifacts.
