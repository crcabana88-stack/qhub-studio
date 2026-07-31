# QHUB R15.3 — Encoding-Safe Protected-Body Restoration Runbook

Human-operated. Restores **two** live function bodies to their exact reviewed text so the R15.2C
verifier package can proceed. Nothing else on the database is touched.

## Why this exists

The 2026-07-30 manual apply moved the migration through a Windows PowerShell clipboard command that read
the BOM-less UTF-8 file **without `-Encoding UTF8`**. PowerShell 5.1 `Get-Content` then decodes using the
system ANSI code page (Windows-1252) and re-encodes mangled:

| reviewed | live (mojibake) |
|---|---|
| `§` | `Â§` |
| `—` | `â€"` |
| `→` | `â†'` |

Only two protected functions contain non-ASCII characters, and only inside **comments**. Forensics proved
the executable text is byte-identical (comments stripped: identical sha256 on both sides) and behavioral
parity passed 8/8 — but the **raw** digests differ, which is exactly why R15.2C's `07` correctly returned
`UNEXPECTED_FUNCTION_BODY_STOP`. That verdict was right, and the fix belongs on the live database: the
reviewed migration is correct and is **not** changed by this package.

> The three protected functions that already match are precisely the three that are pure ASCII. The two
> that drifted are the only protected functions containing non-ASCII. The byte arithmetic reconciles
> exactly: `qhub_decide_review` 3×`§` (+2 each) + 14 three-byte chars (+5 each) = **+76**;
> `qhub_row_immutable` 2×`→` = **+10**.

## Stable identifiers

| Item | Value |
|---|---|
| Branch | `commercial-launch-foundation` |
| Base main | `6ab2c2bc82dc67a3073de1eb457583773cab0ac6` |
| Migration | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Migration SHA-256 | `b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf` |
| Schema version | `2026-07-30.commercial-launch-r8` |
| Live project reference | `jsjsanmaahvmynblmzkq` |
| This package | `docs/release/r15-3-body-restoration/` |
| Verifier package (runs after) | `docs/release/r15-2-verifier-patch/` |

The release commit hash is deliberately **not** printed here — a commit cannot contain its own hash. Take
it from the final review report and verify it in Step 1.

## Digest contract

| function | reviewed LF | reviewed CRLF | known live mojibake |
|---|---|---|---|
| `qhub_decide_review(uuid,text,boolean,text,text,text)` | `7e678f1e4bba0c540507cfe3743fbe54` | `dac8abcd56d7fc804baac660059c14bf` | `9bc91d1671c5f65241ea22538c00d703` |
| `qhub_row_immutable()` | `41ae59dde9a471b580d28e2cb45984f5` | `4936e3f58627dde5abc10d2b0ecf5b4f` | `583882c1a9b203e278b27d1080065c9e` |

Authorization is by **exact raw `md5(prosrc)`** only — no `replace`, `regexp_replace`, `translate` or
`trim` participates in any verdict. Accepting a normalized match is precisely the withdrawn-R15.1 mistake.
**The mojibake digests are accepted only by `10` (as proof of the state being repaired) and are rejected
by `12`.** They must never be added to any accepted-body allowlist.

## ⚠ Encoding rules — the whole point of this package

- **Always** copy with:
  ```
  Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
  ```
- **Never** use PowerShell 5.1 `Get-Content` without `-Encoding UTF8`. That is the exact defect being
  repaired; using it here would silently reintroduce it.
- **Do not** copy from a rendered Markdown or HTML code block — renderers substitute quotes and dashes.
- **Do not** retype any SQL. **Do not** split a file. **Do not** proceed on any digest mismatch.
- `11` verifies the restored digests **before COMMIT**. If the transfer channel mangled `11` itself, it
  raises and the whole transaction rolls back, leaving the database exactly as it was.

## Step 1 — Verify branch, commit, origin and migration SHA

```bash
git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse --abbrev-ref HEAD && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse HEAD && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" rev-parse origin/commercial-launch-foundation && git -C "C:\Users\ccaba\qhub-studio\.claude\worktrees\commercial-launch-foundation" show HEAD:supabase/migrations/20260729_commercial_launch_foundation.sql | sha256sum
```

Require, in order: branch is `commercial-launch-foundation`; `HEAD` **equals** `origin/...`; both equal the
commit in the final review report; migration SHA-256 is exactly
`b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf`. **STOP** on any mismatch — and never
edit a file to make a hash match.

> **Run each file IN FULL, as one unit.** Each opens and closes its own transaction. On any SQL error,
> **STOP** — do not retry fragments.

## Step 2 — Pre-restore check (read-only)

Copy `10_PRE_RESTORE_LIVE_BODY_VERIFY.sql` with the encoding-safe command, paste the whole file into a new
SQL Editor query for project `jsjsanmaahvmynblmzkq`, Run. Suggested name: `QHub R15.3 Pre-Restore Verify`.

The **last** result is the verdict:

| Verdict | Action |
|---|---|
| `SAFE_TO_RESTORE_REVIEWED_BODIES` | Continue to Step 3. |
| `UNEXPECTED_LIVE_BODY_STOP` | **STOP.** Capture QUERY 1 and escalate. |

Two distinct STOP causes, and they are not interchangeable:
- `already_reviewed_count > 0` — the restoration has already run. Skip to Step 4 (`12`).
- a body is some **third** unknown value — unexplained drift that this package is not authorised to
  repair. Escalate; do **not** restore.

`10` reads `pg_catalog` only and never invokes a function, so running it in full is safe in any state and
cannot raise 42883.

## Step 3 — Restore (one transaction, once)

Copy `11_RESTORE_REVIEWED_PROTECTED_BODIES.sql` with the encoding-safe command → new query named
`QHub R15.3 Restore Reviewed Bodies` → confirm it begins with `BEGIN;` and ends with `COMMIT;` → **Run once**.

It replaces only the two function bodies using text extracted **verbatim** from the reviewed migration,
restates `qhub_decide_review`'s exact owner and ACL, and issues **no** grant, revoke or owner change for
`qhub_row_immutable` (whose reviewed contract is "no grants"). It creates no overload, alters no other
object, mutates no data, and never touches cluster role memberships. It is idempotent.

Record start/finish time, the success or full error text, and the query name. **On any error: STOP**,
preserve the error, do not repair by hand. A `R15.3 POST: ... STILL the mojibake body` error means the
clipboard channel mangled the file again — re-copy with `-Encoding UTF8` and re-run.

## Step 4 — Post-restore verification (read-only)

Copy `12_POST_RESTORE_BODY_VERIFY.sql` → new query → Run in full. It is one read-only REPEATABLE READ
transaction producing one authoritative statement (two rows, one per function).

Require **`final_status = R15_3_REVIEWED_BODIES_RESTORED`** and `function_ok = true` on both rows. Every
displayed column feeds that verdict: identity, no overload, owner, security mode, `search_path`,
volatility, reviewed body digest, mojibake cleared, ACL, and effective ACL.

The two ACL contracts differ **by design**: `qhub_decide_review` requires service_role EXECUTE without
grant option with PUBLIC/anon/authenticated denied and no unexpected direct or effective executor;
`qhub_row_immutable` is a trigger function the reviewed migration deliberately grants nothing, so its
exact reviewed state is `proacl IS NULL` (PUBLIC default) and the effective-executor test is reported
not-applicable rather than failed. Requiring a browser-denied ACL there would be a false failure — R15.2C's
own verifier does not pin it either.

| Status | Action |
|---|---|
| `R15_3_REVIEWED_BODIES_RESTORED` | Continue to Step 5. |
| `R15_3_BODY_RESTORE_NOT_READY` | **STOP.** Capture both rows and escalate. |

## Step 5 — Run the already-reviewed R15.2C verifier package

Now, and only now, proceed through `docs/release/r15-2-verifier-patch/` exactly as its own runbook
specifies — same encoding-safe copy command for every file:

1. `07_PRE_PATCH_EXACT_DIGEST_VERIFY.sql` → require `SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH`
2. `08_LIVE_VERIFIER_EXACT_DUAL_DIGEST_PATCH.sql` → run once
3. `09_POST_PATCH_VERIFY.sql` → require `R15_2_VERIFIER_READY`

`08` installs the verifier whose **own** body `09` digest-pins. If `08` is transferred through a mangling
channel the verifier body becomes mojibake and `09`'s `body_approved` fails — the same defect, one level
up. Use the encoding-safe command.

## Step 6 — Mark migration history (only after Step 5 returns READY)

```bash
npx --yes supabase@2.110.0 migration repair --status applied 20260729
```

Then verify:

```bash
npx --yes supabase@2.110.0 migration list
```

Confirm `20260729` now shows a remote entry and prior versions are unchanged. Duplicate-prefix second rows
may legitimately remain blank — that is the known repository versioning backlog, not a new fault.
**Do not run `db push`. Do not use `--include-all`.**

## Step 7 — Founder access

Only now proceed to the founder-access preview (read-only first) and stop for explicit confirmation of the
founder UUID, email, org ID and roles before any seed.

## Stop conditions

- Branch is not `commercial-launch-foundation`, or local and origin HEAD differ
- HEAD does not equal the commit in the final review report
- Migration SHA-256 is not `b5f0a466f293212812a8ea3d71d6c650ca7af30255275ef248cb420910a0d1cf`
- `10` returns `UNEXPECTED_LIVE_BODY_STOP` for any reason other than "already restored"
- `11` raises — especially `R15.3 POST: ... STILL the mojibake body` (bad transfer channel)
- `12` is not exactly `R15_3_REVIEWED_BODIES_RESTORED`
- `07` is not `SAFE_TO_APPLY_EXACT_DUAL_DIGEST_PATCH`, or `09` is not `R15_2_VERIFIER_READY`
- Any SQL error while running any file — do not retry fragments
- Any prompt for `--include-all`, reset, force, or replay of prior migrations

## Out of scope

`qhub_reconcile_checkout` and `qhub_claim_webhook_event` also carry mojibake in comments on live. They are
**not** digest-pinned, are cosmetic only, and are deliberately excluded from this pass — they belong to a
later maintenance task. Stripe configuration, deployment, merging, tagging and the duplicate
migration-version cleanup also remain out of scope.
