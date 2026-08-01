# QHUB R15.3 — Encoding-Safe Protected-Body Restoration Runbook

Human-operated. Restores **two** live function bodies to their exact reviewed text so the R15.6 runtime-
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
| Migration SHA-256 | `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755` |
| Schema version | `2026-07-30.commercial-launch-r8` |
| Live project reference | `jsjsanmaahvmynblmzkq` |
| This package | `docs/release/r15-3-body-restoration/` |
| Verifier package (runs after) | `docs/release/r15-6-runtime-verifier/` (supersedes R15.5 and `r15-2-verifier-patch/`) |

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

## Semantic attribute contract (R15.3A)

**`CREATE OR REPLACE FUNCTION` does not preserve omitted attribute clauses — it RESETS them to
defaults.** Independently verified: `IMMUTABLE STRICT PARALLEL SAFE COST 42` became
`VOLATILE / CALLED ON NULL INPUT / PARALLEL UNSAFE / COST 100`. Both targets' reviewed values *are*
those defaults, so a restoration that only fixed the body would silently normalise a tampered function
and erase the evidence. `10`, `11` and `12` therefore bind the **complete** contract:

| attribute | `qhub_decide_review` | `qhub_row_immutable` |
|---|---|---|
| language / prokind | `plpgsql` / `f` | `plpgsql` / `f` |
| return type | `jsonb` | `trigger` |
| volatility | `VOLATILE` | `VOLATILE` |
| strictness | `CALLED ON NULL INPUT` | `CALLED ON NULL INPUT` |
| parallel safety | `PARALLEL UNSAFE` | `PARALLEL UNSAFE` |
| leakproof | `NOT LEAKPROOF` | `NOT LEAKPROOF` |
| set-returning / rows | `false` / `0` | `false` / `0` |
| cost | `100` | `100` |
| variadic / support / transforms | none | none |
| security mode | `SECURITY DEFINER` | `SECURITY INVOKER` |
| `search_path` | `pg_catalog, public` | none |
| owner | owner of `qhub_manual_review_requests` | owner of `qhub_acknowledgments` |
| ACL | **exactly** the owner and service_role `EXECUTE` entries (see below) | **exactly the owner's `EXECUTE`** (R15.4 — see below) |

## The trigger-helper ACL, and why it changed (R15.4)

**PGlite and Supabase produced different ACLs from the same migration.** The migration
originally stated no ACL for `qhub_row_immutable()`, so the result was whatever the platform's
default privileges produced:

| environment | resulting `proacl` |
|---|---|
| plain PostgreSQL / PGlite | **`NULL`** (owner + PUBLIC by default) |
| Supabase (`ALTER DEFAULT PRIVILEGES … GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role`) | **five rows** — PUBLIC, `anon`, `authenticated`, owner, `service_role` |

Both were reproduced from this exact migration. R15.3C's precheck **correctly STOPPED** live on
the five-row set, because the reviewed contract had been derived under PGlite. That was an
**environment-contract defect, not tampering**.

**Supabase's defaults are not the desired contract.** `qhub_row_immutable()` is an internal
immutability trigger helper, never an application-facing RPC — PostgreSQL refuses to invoke a
trigger function directly regardless of privilege. R15.4 therefore states the contract
explicitly in the migration so both environments converge:

| | exact known live start | exact reviewed target |
|---|---|---|
| `qhub_row_immutable` | 5 rows: PUBLIC, `anon`, `authenticated`, owner, `service_role` | **1 row: the owner's EXECUTE only** |
| `qhub_decide_review` | 2 rows: owner + `service_role` | unchanged — 2 rows |

**Revoking is safe, and this was verified before the contract was adopted.** PostgreSQL checks
`EXECUTE` on a trigger function at `CREATE TRIGGER` time, **not at fire time**. With EXECUTE
revoked from PUBLIC, `anon`, `authenticated` and `service_role`, the triggers still fire: a
protected-field UPDATE is still rejected, the allowed `ACTIVE→REVOKED` transition still
succeeds, and direct invocation stays impossible for every role. **No `service_role` grant is
required. No browser-role grant is required.**

> `10` authorizes **only** this documented transition. A sixth row, a missing expected row, a
> grant option, a different grantor or a different owner all STOP. `11` normalizes **only**
> `qhub_row_immutable`, and only from that exact five-row set — it still never repairs unknown
> ACL drift on anything.

## Exact direct-ACL contract (R15.3C)

**`service_role` being present is not sufficient.** The reviewed ACL for `qhub_decide_review` is exactly
`{postgres=X/postgres,service_role=X/postgres}` — **two** rows. Revoking the *owner's own* entry leaves
`{service_role=X/postgres}`, which still has service_role present and still has no unexpected grantee, so
every weaker formulation accepts it. The package therefore compares the **normalized `aclexplode()` set**,
not the textual array:

| function | required direct ACL |
|---|---|
| `qhub_decide_review` | exactly 2 rows: `(owner, EXECUTE, granted-by owner, not grantable)` **and** `(service_role, EXECUTE, granted-by owner, not grantable)` — nothing else |
| `qhub_row_immutable` | **exactly 1 row** after restoration: `(owner, EXECUTE, granted-by owner, not grantable)`. Before restoration, exactly the documented 5-row Supabase-default set — see the R15.4 section above. |

Three flags are reported and all three feed the verdict: `acl_cardinality_exact`,
`acl_expected_rows_present`, `acl_no_unexpected_entry`. Comparison is set-based on
`(grantee, privilege, grantor, is_grantable)`, so re-issuing an identical grant (which rewrites
the array) is **not** drift.

> **Severity, stated precisely.** The owner keeps `EXECUTE` through *inherent ownership rights* even
> without the ACL row, so a missing owner entry is **contract-integrity drift, not an immediate privilege
> escalation**. It still means someone revoked from the owner, and it must be escalated rather than
> accepted or silently repaired.

### Who owns which privilege question

Five distinct things, deliberately not conflated:

| concern | owned by |
|---|---|
| exact **direct ACL** of the two restored functions | **R15.3** (this package) |
| the **verifier's own** direct ACL reset | R15.2C (`08`) |
| **inherited/effective** privilege via role membership on the verifier | R15.2C (`07`/`09`) |
| **owner inherent execution** (ownership rights, not an ACL row) | neither — a PostgreSQL property, documented above |
| **superuser inherent** privilege | R15.2C, reported separately as platform administrators |

`11` **never repairs ACL drift.** It raises `unexpected_function_acl_state` before touching anything, and
the drift survives as escalation evidence.

**Any** strictness, parallel-safety, volatility, leakproof, cost, rows, owner, security-mode,
`search_path`, ACL or signature drift is a **STOP** at `10` and a **NOT READY** at `12`.

## Callable-interface / default-argument contract (R15.3B)

**Identity arguments are not sufficient.** `pg_get_function_identity_arguments()` deliberately
**excludes** argument defaults, so adding `p_policy_version TEXT DEFAULT NULL` leaves *both* the
identity arguments *and* the raw `prosrc` digest completely unchanged — while creating a new callable
arity. Verified directly: with the reviewed body intact and one default added,
`SELECT public.qhub_decide_review(uuid, text, boolean, text, text)` **succeeded**, passing
`p_policy_version = NULL` into a SECURITY DEFINER decision RPC.

The reviewed contract for **both** functions is:

| property | reviewed value |
|---|---|
| `pronargs` | 6 (`qhub_decide_review`) / 0 (`qhub_row_immutable`) |
| `pronargdefaults` | **0** |
| `proargdefaults` | **NULL** |
| `pg_get_function_arguments()` | exactly the reviewed argument list, with **no** `DEFAULT` |
| `proargnames` | exact names / NULL |
| `proargmodes` | **NULL** (every argument plain `IN`) |
| `proallargtypes` | **NULL** (no OUT/TABLE arguments) |
| `proargtypes` | exact type OIDs |
| `provariadic` | 0 |
| `probin` / `prosqlbody` | **NULL** (the body lives in `prosrc`, where the digest can see it) |

**Any argument default is a STOP** — at `10`, inside `11`'s Gate 1 (raising
`unexpected_function_default_argument_state`), and at `12`.

> **`11` cannot and will not remove a default.** PostgreSQL itself refuses:
> *"cannot remove parameter defaults from existing function"*. Removing one requires `DROP FUNCTION`
> plus a recreate, which this package deliberately does **not** do. If `10` reports a default, STOP and
> escalate with a separately reviewed plan.

> **`11` refuses; it does not repair.** If `10` reports attribute drift, `11` raises before touching
> anything and the drift is left in place as escalation evidence. Do not "fix" it by running `11`
> anyway — that would destroy the only record that a `SECURITY DEFINER` decision function had been
> altered. Escalate instead.

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
`1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755`. **STOP** on any mismatch — and never
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

Three distinct STOP causes, and they are not interchangeable:
- `already_reviewed_count > 0` — the restoration has already run. Skip to Step 4 (`12`).
- `attributes_ok_count < 2` — an **attribute, authority or callable-interface drift** (strictness,
  parallel safety, volatility, leakproof, cost, rows, owner, security mode, `search_path`, ACL,
  signature, overload, **any argument default**, argument names/modes/types, `probin`/`prosqlbody`,
  **any direct-ACL difference including a missing owner EXECUTE entry**).
  **STOP and escalate. Do not run `11`** — it will refuse anyway, and running it is not a fix.
  QUERY 1 shows exactly which flag failed and the live value beside it; for a default, look at
  `no_arg_defaults`, `live_nargdefaults` and `live_full_arguments`.
- a body is some **third** unknown value — unexplained drift that this package is not authorised to
  repair. Escalate; do **not** restore.

`10` reads `pg_catalog` only and never invokes either target function, so running it in full is safe in
any state and cannot raise 42883 or a permission error.

## Step 3 — Restore (one transaction, once)

Copy `11_RESTORE_REVIEWED_PROTECTED_BODIES.sql` with the encoding-safe command → new query named
`QHub R15.3 Restore Reviewed Bodies` → confirm it begins with `BEGIN;` and ends with `COMMIT;` → **Run once**.

It replaces only the two function bodies using text extracted **verbatim** from the reviewed migration
(everything from `AS $$` onward is byte-for-byte; the headers additionally state the reviewed attribute
contract explicitly, which does not affect `prosrc` and so does not affect the digest). It restates
`qhub_decide_review`'s exact owner and ACL, and (R15.4) **normalizes `qhub_row_immutable`'s ACL** from
the documented five-row Supabase-default set to the reviewed owner-only contract, using the identical
statements the migration now contains. It creates no overload, alters no other object, mutates no
data, and never touches cluster role memberships. It is idempotent under the final reviewed state.

**Gate 1** re-asserts the complete identity + attribute + authority contract before any change and
raises on the first mismatch. **Gate 2** re-asserts all of it again *before* `COMMIT`, so a single
attribute mismatch rolls **both** functions back together.

Record start/finish time, the success or full error text, and the query name. **On any error: STOP**,
preserve the error, do not repair by hand. A `R15.3 POST: ... STILL the mojibake body` error means the
clipboard channel mangled the file again — re-copy with `-Encoding UTF8` and re-run.

## Step 4 — Post-restore verification (read-only)

Copy `12_POST_RESTORE_BODY_VERIFY.sql` → new query → Run in full. It is one read-only REPEATABLE READ
transaction producing one authoritative statement (two rows, one per function).

Require **`final_status = R15_3_REVIEWED_BODIES_RESTORED`** and `function_ok = true` on both rows. Every
displayed check feeds that verdict: identity, no overload, language, prokind, return type, the full
callable interface (`pg_get_function_arguments()`, `pronargs`, **no argument defaults**, argument
names/modes/types, no alternate arity), owner, security mode, `search_path`, ACL, effective ACL,
volatility, strictness, parallel safety, leakproof, set-returning flag, cost, rows estimate, variadic,
support function, transforms, `probin`/`prosqlbody`, the reviewed body digest, and mojibake cleared.

A **correct body with a drifted attribute or an added argument default is NOT READY** — that is the
R15.3A/R15.3B closure. `body_reviewed` will read `true` beside the failing flag so the cause is
unambiguous.

The two final ACL contracts differ **by design** (R15.4): `qhub_decide_review` requires exactly its
two reviewed rows — the owner's and service_role's EXECUTE, neither grantable — with
PUBLIC/anon/authenticated denied and no unexpected direct or effective executor; `qhub_row_immutable`
requires **exactly one row, the owner's own EXECUTE**. Trigger execution does not require browser or
service_role direct EXECUTE at fire time — PostgreSQL checks EXECUTE at `CREATE TRIGGER` time, which
was verified before the contract was adopted — so no other grant exists or is needed.

| Status | Action |
|---|---|
| `R15_3_REVIEWED_BODIES_RESTORED` | Continue to Step 5. |
| `R15_3_BODY_RESTORE_NOT_READY` | **STOP.** Capture both rows and escalate. |

## Step 5 — Run the R15.6 runtime-verifier package

**R15.6 supersedes R15.5 (`13/14/15`) and R15.2C (`07/08/09`) as the operational verifier
patch.** Both earlier packages remain reviewed history, but their verifier bodies predate the
complete R15.6 contract and must not be installed after this one.

Now, and only now, proceed through `docs/release/r15-6-runtime-verifier/` exactly as its own runbook
specifies — same encoding-safe copy command for every file:

1. `16_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql` → require `SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH`
2. `17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql` → run once
3. `18_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql` → require **`R15_6_VERIFIER_READY`**

`17` installs the verifier whose **own** body `18` digest-pins, and additionally verifies its own
installed digest before COMMIT — if the transfer channel mangles it, the whole transaction rolls
back. Use the encoding-safe command anyway.

## Step 6 — Mark migration history (only after Step 5 returns `R15_6_VERIFIER_READY`)

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
- Migration SHA-256 is not `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755`
- `10` returns `UNEXPECTED_LIVE_BODY_STOP` for any reason other than "already restored"
- `10` reports any attribute/authority drift (`attributes_ok = false`) — escalate; **do not run `11`**
- `11` raises — `unexpected_function_acl_state` (direct-ACL drift, including a missing **owner** EXECUTE
  entry; escalate, the package never repairs ACLs), `unexpected_function_default_argument_state` (an
  argument default or callable-interface drift; escalate, the package will never remove a default),
  `R15.3 PRE: ... drifted` (attribute drift; escalate) or `R15.3 POST: ... STILL the mojibake body`
  (bad transfer channel; re-copy with `-Encoding UTF8`)
- `12` is not exactly `R15_3_REVIEWED_BODIES_RESTORED`
- `16` is not `SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH`, or `18` is not `R15_6_VERIFIER_READY`
- Any SQL error while running any file — do not retry fragments
- Any prompt for `--include-all`, reset, force, or replay of prior migrations

## Out of scope

`qhub_reconcile_checkout` and `qhub_claim_webhook_event` also carry mojibake in comments on live. They are
**not** digest-pinned, are cosmetic only, and are deliberately excluded from this pass — they belong to a
later maintenance task. Stripe configuration, deployment, merging, tagging and the duplicate
migration-version cleanup also remain out of scope.
