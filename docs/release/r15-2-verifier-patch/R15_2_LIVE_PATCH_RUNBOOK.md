# QHUB R15.2 — Live Verifier Exact Dual-Digest Patch Runbook

Human-operated. Fixes the five `*_body_drift` verifier failures on the live database by making the body
pins accept exactly the two separately reviewed encodings of each reviewed body.

**Supersedes R15.1, which is withdrawn.** R15.1 hashed `md5(replace(prosrc, chr(13), ''))`. Deleting every
carriage return also deletes a CR injected *inside* executable text, so a body containing
`'staff' || chr(13) || '_required'` hashed identically to the reviewed body and produced a **false READY**
(independently reproduced by Codex, and reproduced again here before the fix). R15.2 uses **no
normalization of any kind**.

| Item | Value |
|---|---|
| Schema version | `2026-07-30.commercial-launch-r8` (**unchanged**) |
| Branch | `commercial-launch-foundation` |
| Migration | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Reviewed commit / new migration SHA | see the R15.2 commit report — verify in Step 1 |
| Protected function bodies | **unchanged** |
| Approved LF digest constants | **unchanged** |
| Approved CRLF digest constants | added (second accepted encoding only) |

## The contract

Each of the five pins hashes **raw** `md5(p.prosrc)` — no `replace`, `regexp_replace`, `translate` or
`trim` — and accepts exactly two values: the reviewed **LF** digest and the reviewed **CRLF** digest.

Any third byte sequence is drift: an injected or removed CR, an injected or removed LF, mixed line
endings **within** a body, a whitespace change, a comment edit, or any executable token change.
`coalesce(..., FALSE)` keeps it fail-closed — a missing or renamed function reports drift rather than
silently passing.

> A per-**body**-consistent encoding is accepted by design: if one whole body is CRLF and another is LF,
> each body is still byte-identical to one of its two reviewed encodings. Only mixing *within* a single
> body produces an unreviewed sequence, and that is rejected.

## Step 1 — Verify the artifact

```bash
git -C C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation rev-parse HEAD
```
```bash
git -C C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation show HEAD:supabase/migrations/20260729_commercial_launch_foundation.sql | sha256sum
```
Both must match the R15.2 commit report. **STOP** on any mismatch.

## Step 2 — Pre-patch check (read-only)

SQL Editor → **New query** → paste `07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql` → Run.

Read **QUERY 2 `verdict`**:

| Verdict | Action |
|---|---|
| `SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH` | Continue to Step 3. |
| `UNEXPECTED_FUNCTION_BODY_STOP` | **STOP.** At least one live body is neither reviewed encoding. Capture QUERY 1 and escalate. Do not patch. |

The verdict uses the raw digest only. QUERY 3 (line-ending counts) is diagnostics — it must **not** be
used to authorize the patch. Record QUERY 1 and QUERY 4 for evidence; on the current live database expect
`matches_crlf = true` and `matches_lf = false` for all five.

## Step 3 — Apply the patch (one transaction, once)

SQL Editor → **New query** named `QHub R15.2 Verifier Exact Dual Digest` → paste the **entire**
`08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql` → confirm it begins with `BEGIN;` and ends with `COMMIT;`
→ **Run once**.

Do not split it, edit it, or re-run fragments on error. It is one transaction, so a failure rolls back
cleanly. The patch is idempotent — re-running it is safe. Line endings do not matter for this patch: the
verifier has no digest pinned against its own body.

Record start/finish timestamp, the success or full error text, and the query name.
**On any error: STOP**, preserve the error, do not repair manually.

## Step 4 — Post-patch verification (read-only)

SQL Editor → **New query** → paste `09_POST_PATCH_VERIFY.sql` → Run.

Require **QUERY 3 `final_status` = `R15_2_VERIFIER_READY`**, which requires all of:
- `ready = true`
- `expected_version = 2026-07-30.commercial-launch-r8`
- `failed_checks = []`
- verifier still SECURITY DEFINER with pinned `search_path`
- `service_role` holds EXECUTE; `anon`/`authenticated` do not
- exactly five raw `md5(p.prosrc)` pins and **no** normalization helper on `prosrc`

| Status | Action |
|---|---|
| `R15_2_VERIFIER_READY` | Continue to Step 5. |
| `R15_2_VERIFIER_NOT_READY` | **STOP.** Capture QUERY 1 + QUERY 2 and escalate. Do not mark history, do not seed. |

## Step 5 — Mark migration history (only after Step 4 passes)

```bash
npx --yes supabase@2.110.0 migration repair --status applied 20260729
```
```bash
npx --yes supabase@2.110.0 migration list
```
Confirm `20260729` now shows a remote entry and prior versions are unchanged. Duplicate-prefix second
rows may legitimately remain blank — that is the known repository versioning backlog, not a new fault.

**Do not run `db push`. Do not use `--include-all`.**

## Step 6 — Founder access

Only now proceed to the founder-access preview (read-only section first) and stop for explicit
confirmation of the founder UUID, email, org ID and roles before any seed.

## Stop conditions

- Repo HEAD or migration SHA does not match the commit report
- Pre-patch verdict is `UNEXPECTED_FUNCTION_BODY_STOP`
- Any error while applying the patch
- Post-patch status is `R15_2_VERIFIER_NOT_READY`, or `failed_checks` is non-empty
- Any prompt for `--include-all`, reset, force, or replay of prior migrations

## Out of scope

Stripe configuration, deployment, merging, tagging, and the duplicate migration-version cleanup
(post-launch maintenance task).
