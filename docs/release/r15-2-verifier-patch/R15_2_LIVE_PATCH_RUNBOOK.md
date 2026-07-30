# QHUB R15.2 — Live Verifier Exact Dual-Digest Patch Runbook

Human-operated. Fixes the five `*_body_drift` verifier failures on the live database by making the body
pins accept exactly the two separately reviewed encodings of each reviewed body.

**Supersedes R15.1, which is withdrawn.** R15.1 hashed `md5(replace(prosrc, chr(13), ''))`. Deleting every
carriage return also deletes a CR injected *inside* executable text, so a body containing
`'staff' || chr(13) || '_required'` hashed identically to the reviewed body and produced a **false READY**.
R15.2 uses **no normalization of any kind**.

## Stable identifiers

| Item | Value |
|---|---|
| Branch | `commercial-launch-foundation` |
| Base main | `6ab2c2bc82dc67a3073de1eb457583773cab0ac6` |
| Migration | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Migration SHA-256 | `b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf` |
| Schema version | `2026-07-30.commercial-launch-r8` |
| Live project reference | `jsjsanmaahvmynblmzkq` |
| Package | `docs/release/r15-2-verifier-patch/` |

The release commit hash is deliberately **not** printed here — a commit cannot contain its own hash. Take
it from the final review report and verify it in Step 1.

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

**Final READY requires all of:** product verifier `ready = true` · exact schema version · `failed = []` ·
exact verifier signature with no overload · exact owner · exact security mode (SECURITY DEFINER) · exact
fixed `search_path` · exact ACL (service_role EXECUTE present; PUBLIC/anon/authenticated denied; no
unexpected grantee) · exact verifier body identity.

## Step 1 — Verify branch, commit, origin and migration SHA

Run all four and compare against the final review report **immediately before executing anything**:

```bash
git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse --abbrev-ref HEAD && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse HEAD && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse origin/commercial-launch-foundation && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" show HEAD:supabase/migrations/20260729_commercial_launch_foundation.sql | sha256sum
```

Require, in order:
1. branch is `commercial-launch-foundation`
2. `rev-parse HEAD` **equals** `rev-parse origin/commercial-launch-foundation` — if local and origin
   differ, **STOP**; you are not holding the reviewed artifact
3. both equal the exact final commit printed in the final review report
4. the migration SHA-256 is exactly
   `b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf`

**STOP** on any mismatch. Do not "fix" a file to make a hash match.

## Step 2 — Pre-patch check (read-only)

Open the SQL Editor for project `jsjsanmaahvmynblmzkq` → **New query** → paste
`07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql` → Run.

Read **QUERY 2 `verdict`**:

| Verdict | Action |
|---|---|
| `SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH` | Continue to Step 3. |
| `UNEXPECTED_FUNCTION_BODY_STOP` | **STOP.** A protected function is missing, renamed, wrong-signature, overloaded, or carries an unapproved body. Capture QUERY 1 and escalate. |

The verdict binds **exact signature and exact raw digest together**. QUERY 3 (line-ending counts) is
non-authorizing diagnostics and must not be used to justify proceeding. Record QUERY 1 and QUERY 4 for
evidence; on the current live database expect `matches_crlf = true`, `matches_lf = false`,
`signature_matches = true`, `overload_count = 1` for all five.

## Step 3 — Apply the patch (one transaction, once)

SQL Editor → **New query** named `QHub R15.2 Verifier Exact Dual Digest` → paste the **entire**
`08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql` → confirm it begins with `BEGIN;` and ends with `COMMIT;`
→ **Run once**.

Do not split it, edit it, or re-run fragments on error. It is one transaction, so a failure rolls back
cleanly. The patch is idempotent. Line endings do not matter for the patch itself — the verifier's own
body is accepted in either reviewed encoding.

Record start/finish timestamp, the success or full error text, and the query name.
**On any error: STOP**, preserve the error, do not repair manually.

## Step 4 — Post-patch verification (read-only)

SQL Editor → **New query** → paste `09_POST_PATCH_VERIFY.sql` → Run the queries **in order** and stop at
the first that reports `R15_2_VERIFIER_NOT_READY` — that value is the final status.

| Query | Meaning |
|---|---|
| **QUERY 1** existence gate | Pure catalog, cannot raise. `verifier_present = false` ⇒ `R15_2_VERIFIER_NOT_READY`; **STOP** and do not run QUERY 2/3 (referencing a missing function raises PostgreSQL 42883). |
| **QUERY 2** catalog authority gate | Pure catalog, cannot raise. Checks owner, security mode, fixed `search_path`, ACL, body identity and overload **before** the verifier is invoked, because a drifted owner makes a SECURITY DEFINER function raise "permission denied" rather than return. `authority_status = R15_2_VERIFIER_NOT_READY` ⇒ **STOP**. |
| **QUERY 3** final status | Invokes the verifier and re-applies every catalog check. Require `final_status = R15_2_VERIFIER_READY`. |

Every column displayed in QUERY 2 and QUERY 3 is an input to its verdict — nothing shown there is
merely informational.

| Status | Action |
|---|---|
| `R15_2_VERIFIER_READY` | Continue to Step 5. |
| `R15_2_VERIFIER_NOT_READY` | **STOP.** Capture QUERY 1–3 and escalate. Do not mark history, do not seed. |

## Step 5 — Mark migration history (only after Step 4 returns READY)

```bash
npx --yes supabase@2.110.0 migration repair --status applied 20260729
```

## Step 6 — Verify migration history

```bash
npx --yes supabase@2.110.0 migration list
```
Confirm `20260729` now shows a remote entry and prior versions are unchanged. Duplicate-prefix second
rows may legitimately remain blank — that is the known repository versioning backlog, not a new fault.

**Do not run `db push`. Do not use `--include-all`.**

## Step 7 — Founder access

Only now proceed to the founder-access preview (read-only section first) and stop for explicit
confirmation of the founder UUID, email, org ID and roles before any seed.

## Stop conditions

- Branch is not `commercial-launch-foundation`, or local and origin HEAD differ
- HEAD does not equal the commit in the final review report
- Migration SHA-256 is not `b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf`
- Pre-patch verdict is `UNEXPECTED_FUNCTION_BODY_STOP`
- Any error while applying the patch
- QUERY 1 reports the verifier missing, QUERY 2 reports `R15_2_VERIFIER_NOT_READY`, or QUERY 3 is not
  `R15_2_VERIFIER_READY`
- Any prompt for `--include-all`, reset, force, or replay of prior migrations

## Out of scope

Stripe configuration, deployment, merging, tagging, and the duplicate migration-version cleanup
(post-launch maintenance task).
