# QHUB R15.6 — Migration-History Reconciliation Runbook

Human-operated. Records the migration-history entry for the already-applied, already-verified
commercial migration `20260729` — and does **nothing else**. This is the final step before the
founder-access preview. **Founder seed and Stripe configuration remain separate, unauthorized
follow-on gates and are NOT part of this package.**

## Purpose and scope

The commercial migration `20260729_commercial_launch_foundation.sql` was applied to the live
database and its resulting state has been fully verified (R15.6 closure: `product_ready=true`,
`product_version=2026-07-30.commercial-launch-r8`, `failed=[]`, protected bodies exact approved
CRLF variants, 0 P0/P1 findings). Its history entry was never recorded. This package records
exactly one row:

```sql
INSERT INTO supabase_migrations.schema_migrations (version, name)
VALUES ('20260729', 'commercial_launch_foundation');
```

`version` and `name` are derived from the committed filename through the pinned CLI's own parse
contract (`^([0-9]+)_(.*)\.sql$`, extracted verbatim from the installed `supabase@2.110.0`
binary). `statements` is deliberately NULL — see `MIGRATION_HISTORY_MECHANISM_ANALYSIS.md` §4.
The CLI's `migration repair --status applied` was evaluated and **rejected** as the mechanism: its
applied-path write is an unconditional `ON CONFLICT (version) DO UPDATE` upsert that silently
overwrites conflicting rows and cannot gate on verifier readiness (analysis §3).

## Prerequisites (all mandatory, in order)

1. **Repository identity.** Local HEAD, origin tracking and the remote branch all equal the
   approved commit from the final review report; `git status` clean.
   Approved starting commit for this package: `5a88cbf54b4c3cdf7ce17d57b46c495ff8861b44`.
2. **Artifact integrity.** Recompute and match every hash in the table below. STOP on any
   mismatch — never run a mismatched artifact.
3. **Project confirmation.** The SQL Editor tab's URL must show project ref `jsjsanmaahvmynblmzkq`
   before every paste. (The in-transaction gates additionally fail closed on any database that
   does not carry this project's exact verifier digest and READY state.)
4. **Transfer safety.** Copy every file with exactly:
   `Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard`
5. **R15.6 closure evidence** is accepted (commit `5a88cbf…`; live execution attributable to
   package commit `39f3ee077876fe94549e0c34eb073dba609e5559`). No product/database remediation is
   open.

## Authoritative artifact hashes (SHA-256)

| Artifact | SHA-256 |
|---|---|
| `supabase/migrations/20260729_commercial_launch_foundation.sql` | `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755` |
| `docs/release/r15-6-runtime-verifier/19_READ_ONLY_PRODUCT_FAILURE_DIAGNOSTIC.sql` | `dd2afaf16c5b927386dfeec50bc35676eaa6c10a06a93c15fb43c87f8ef6f8aa` |
| `docs/release/r15-6-runtime-verifier/20_READ_ONLY_PRODUCT_DRIFT_DIAGNOSTIC.sql` | `0626edb61d9f5ed916be881eb48af0dddac972c852472c8d18f2a8832ffd9047` |
| `docs/release/r15-6-runtime-verifier/21_PRE_PROTECTED_FUNCTION_RESTORATION.sql` | `9a4bbcae4bdba6e78355d89ae91e98b31d3b2192c66c88e7455a4a17a769cff1` |
| `docs/release/r15-6-runtime-verifier/22_PATCH_PROTECTED_FUNCTION_RESTORATION.sql` | `f0062b2dd1b59deb768c78f54155a69515a4e28bdf6f714aed8c1e9277d00303` |
| `docs/release/r15-6-runtime-verifier/23_POST_PROTECTED_FUNCTION_RESTORATION_VERIFY.sql` | `9ff28bc78b4083064e5794925922866eba22b392c3c51daa05b6ca4ebead6f0f` |
| `docs/release/r15-6-migration-history/25_PRE_MIGRATION_HISTORY_VERIFY.sql` | `54a0331fd073afae27a09351c26e3562dc1169e16637e6a95a2381f51ad77b77` |
| `docs/release/r15-6-migration-history/26_MIGRATION_HISTORY_RECORD.sql` | `4501545f37d89bfb709ab8a8a92873b151e2c787db6cee0d6734dc73dadf7af5` |
| `docs/release/r15-6-migration-history/27_POST_MIGRATION_HISTORY_VERIFY.sql` | `98e2518582d5b7540fbdd9f67bef474684f2ac49030ca74dfe5d3df02cf51bea` |

## Sequence

| # | step | require |
|---|---|---|
| 1 | `25_PRE_MIGRATION_HISTORY_VERIFY.sql` (read-only, in full) | `SAFE_TO_RECORD_MIGRATION_HISTORY` — or `ALREADY_RECORDED_EXACTLY`, in which case skip step 3 |
| 2 | **HUMAN REVIEW** of both PRE result rows (history detail + verdict). Confirm the neighbor rows look sane and the exact expected version/name are shown. | explicit human go |
| 3 | `26_MIGRATION_HISTORY_RECORD.sql` (once, in full) | final SELECT shows `action = RECORDED_NOW` (or `ALREADY_RECORDED_EXACTLY`), `history_version = 20260729`, `history_name = commercial_launch_foundation`, `rows_for_version = 1`. Capture this output verbatim. |
| 4 | `27_POST_MIGRATION_HISTORY_VERIFY.sql` (read-only, in full) | **`MIGRATION_20260729_HISTORY_RECONCILED`** |
| 5 | Optional CLI confirmation (read-only): `npx --yes supabase@2.110.0 migration list` | `20260729` shows a remote entry; prior versions unchanged. Duplicate-prefix second local rows may legitimately show blank remotes — the known repository versioning backlog, not a fault. |
| 6 | Founder-access preview (read-only) → **pause for human approval**. Founder seed and Stripe remain unauthorized. | — |

## Exact authorized mutation inventory

- At most ONE row inserted into `supabase_migrations.schema_migrations`:
  `('20260729', 'commercial_launch_foundation')`, `statements` NULL.
- One session-temporary audit row in `pg_temp` (drops with the session).
- Nothing else: no schema, table, row, function, trigger, ACL, policy, role, founder,
  entitlement, billing or Stripe change. The commercial migration is **not** re-executed.

## Expected output contracts

- **25 (PRE)** — two result rows. Row 1: history table identity, full column/PK inventory, all
  remote rows, target-version detail, name-under-other-version rows, versions newer than target.
  Row 2: the full verifier authority + product block and the single verdict
  `SAFE_TO_RECORD_MIGRATION_HISTORY` / `ALREADY_RECORDED_EXACTLY` /
  `UNEXPECTED_MIGRATION_HISTORY_STOP`. Read-only; a missing history table yields STOP, never a
  SQL error.
- **26 (REPAIR)** — either a deterministic exception naming its gate
  (`unexpected_runtime_verifier_state`, `unexpected_runtime_verifier_authority`,
  `migration_history_product_not_ready`, `unexpected_migration_history_shape`,
  `migration_history_conflict`) with the whole transaction rolled back and the live state left
  untouched as evidence — or COMMIT plus a final audit SELECT reporting the exact action
  (`RECORDED_NOW` / `ALREADY_RECORDED_EXACTLY`), the recorded row, and the row counts. Idempotent:
  re-running after success is a clean `ALREADY_RECORDED_EXACTLY` no-op.
- **27 (POST)** — one result row: full verifier authority + product block, history shape, target
  row detail, conflict counters, and the single verdict
  `MIGRATION_20260729_HISTORY_RECONCILED` / `MIGRATION_HISTORY_NOT_RECONCILED`. Read-only.

## Stop conditions

- any prerequisite fails (identity, hashes, project ref)
- `25` returns `UNEXPECTED_MIGRATION_HISTORY_STOP` — including: version recorded under another
  name, NULL-name partial/legacy row, the name recorded under another version, any version newer
  than `20260729`, history table missing or shape drift, verifier not READY
- `26` raises any exception — capture it, do **not** retry, do not run fragments, escalate
- `26`'s final SELECT shows anything other than the expected action/row
- `27` is not exactly `MIGRATION_20260729_HISTORY_RECONCILED`
- any SQL error in any file

## No-retry rules and ambiguous-transaction recovery

- Never re-run `26` after an exception without a new human review of a fresh `25` run: the gates
  are deterministic, so a retry without a state change will fail identically, and a retry after an
  unexplained state change is exactly what must not happen silently.
- If the SQL Editor connection drops mid-`26` and the outcome is unknown: run `25` again
  (read-only). `ALREADY_RECORDED_EXACTLY` means the transaction committed — proceed to `27`.
  `SAFE_TO_RECORD_MIGRATION_HISTORY` means it rolled back — the database is unchanged; pause for
  human review, then `26` may be run again from scratch. Any other verdict: STOP and escalate.
- `26` is a single transaction: there is no partially-recorded state to repair.

## Explicitly out of scope / unauthorized

Founder seed, founder entitlement creation, Stripe configuration, deployment, `db push`,
`--include-all`, the duplicate-prefix version backlog for `20260725/20260726/20260727`, and any
edit to previously approved artifacts.
