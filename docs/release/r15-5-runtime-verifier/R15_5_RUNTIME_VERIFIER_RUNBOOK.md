# QHUB R15.5 — Runtime Verifier Trigger-ACL Patch Runbook

Human-operated. Replaces **one** function — `public.qhub_verify_commercial_schema()` — with the
R15.5 body, which makes the runtime verifier enforce the R15.4 trigger-helper authority contract.

**Supersedes `docs/release/r15-2-verifier-patch/` (07/08/09) as the operational verifier patch.**
That package remains reviewed history and its discipline is carried forward verbatim, but its
verifier body predates the R15.4 contract and must not be installed after this one.

## Why this exists

Codex reproduced a P1 against a clean R15.4 install: after `GRANT EXECUTE ON
public.qhub_row_immutable() TO anon`, the runtime verifier still returned `ready=true, failed=[]`.
The verifier had no checks for the trigger helper's ACL or its trigger attachments, so live drift
against the newly reviewed owner-only contract was invisible — a false READY.

The R15.5 verifier adds, with stable and specific failure labels:

| concern | labels |
|---|---|
| helper identity (SECURITY INVOKER, no search_path, trigger rettype, no defaults, exact owner) | `row_immutable_identity` |
| exact one-row owner-only ACL | `row_immutable_acl_cardinality`, `row_immutable_acl_owner_entry`, `row_immutable_acl_unexpected_grantee`, `row_immutable_acl_grant_option` |
| the three immutability triggers attached, enabled, bound to exactly this function | `row_immutable_trigger_missing:<table>`, `row_immutable_trigger_binding:<table>`, `row_immutable_trigger_disabled:<table>` for `qhub_acknowledgments`, `qhub_usage_ledger`, `qhub_entitlement_audit` |

Bindings are checked by exact name + table + function OID + timing/event bits, so a renamed,
rebound or replacement trigger cannot satisfy a count, and an unrelated extra trigger satisfies
nothing. Every pre-existing verifier check is preserved — the R15.5 label inventory is a strict
superset of the previous one (72 → 80 labels).

## Stable identifiers

| Item | Value |
|---|---|
| Branch | `commercial-launch-foundation` |
| Base main | `6ab2c2bc82dc67a3073de1eb457583773cab0ac6` |
| Migration | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Migration SHA-256 | `f893fb9883835b5212a0aa823f8b3b33c5c28b116d0ab6922795fd48fe6a860a` |
| Schema version | `2026-07-30.commercial-launch-r8` |
| Live project reference | `jsjsanmaahvmynblmzkq` |
| This package | `docs/release/r15-5-runtime-verifier/` |

## Verifier body digest contract

| state | md5(prosrc) |
|---|---|
| documented live start (commit `644b5c6`'s verifier through the 2026-07-30 CRLF+cp1252 mojibake channel) | `a35d8320d4a9804725a95f76534fe5a2` |
| reviewed R15.5 body, LF | `83c8cd60a96e44e6cb8d66db93daf403` |
| reviewed R15.5 body, CRLF | `f3c181abf13b54087eaf802ce11a29a4` |

The start digest is **derived, not measured** — computed from the exact commit the live database
was applied from, through the exact channel proven by the R15.3 forensics. If the live digest
differs, `13` STOPs. That is the correct outcome, not a calibration problem: it means the live
verifier is in a state nobody has explained.

## The full live sequence (after Codex GO)

Every file copied with **exactly**:

```
Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard
```

pasted whole into the SQL Editor for `jsjsanmaahvmynblmzkq`, and run **in full, as one unit**:

| # | file | require |
|---|---|---|
| 1 | R15.3 `10_PRE_RESTORE_LIVE_BODY_VERIFY.sql` | `SAFE_TO_RESTORE_REVIEWED_BODIES` |
| 2 | R15.3 `11_RESTORE_REVIEWED_PROTECTED_BODIES.sql` (once) | success, no exception |
| 3 | R15.3 `12_POST_RESTORE_BODY_VERIFY.sql` | `R15_3_REVIEWED_BODIES_RESTORED` |
| 4 | R15.5 `13_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql` | `SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH` |
| 5 | R15.5 `14_LIVE_RUNTIME_VERIFIER_TRIGGER_ACL_PATCH.sql` (once) | success, no exception |
| 6 | R15.5 `15_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql` | **`R15_5_VERIFIER_READY`** |
| 7 | `npx --yes supabase@2.110.0 migration repair --status applied 20260729` | 20260729 recorded |
| 8 | `npx --yes supabase@2.110.0 migration list` | prior versions unchanged |
| 9 | founder-access preview (read-only) → **pause for human approval** | — |

**Do not run `db push`. Do not use `--include-all`.** `R15_5_VERIFIER_READY` — with
`product_ready = true`, exact version and `failed = 0` — is required **before** history alignment.

## What 13 / 14 / 15 do

**13 (read-only)** verifies the live verifier's exact identity (zero-argument, no overload),
SECURITY DEFINER, exact `search_path`, exact owner, exact direct ACL, the effective-executor
contract (role membership included; superusers reported separately), and that its body digest is a
**fully explained** state — the documented live start or already R15.5. It never invokes a
user-defined function and cannot raise 42883.

**14 (one transaction, once)** replaces only the verifier, preserving the whole R15.2C patch
discipline verbatim: the membership-derived effective-executor precondition (never repairs cluster
role memberships), the exact owner/direct-ACL reset (owner derived from the migration-created
authority tables; `REVOKE ALL` from PUBLIC/anon/authenticated/service_role — which strips any stale
grant option — then `GRANT EXECUTE` to service_role alone), and the authoritative post-patch
effective-ACL recheck before COMMIT. New in R15.5: a start-state gate (only the documented live
digest or the reviewed body may be replaced) and a **body-digest gate before COMMIT** — if the
transfer channel mangled the file, the installed body is not a reviewed encoding and the whole
transaction rolls back. Idempotent under the final state.

**15 (read-only)** is the Codex-approved R15.2C `09` architecture unchanged — one REPEATABLE READ
snapshot, one authoritative statement, catalog authority and the guarded `query_to_xml` invocation
in the same statement — with the verifier's own approved digests updated to the R15.5 body. Because
the R15.5 body enforces the trigger-helper contract, `product_ready = true` now *requires* the
one-row owner-only helper ACL and all three immutability triggers attached, enabled and correctly
bound.

## Stop conditions

- local/origin HEAD differs from the final review report, or migration SHA-256 differs
- `13` returns `UNEXPECTED_RUNTIME_VERIFIER_STOP` — especially an unexplained body digest
- `14` raises — `unexpected_effective_verifier_executor*` (role-graph problem; never revoke
  memberships), `unexpected_runtime_verifier_state` (unexplained live verifier), or the
  `R15.5 POST` body-digest failure (bad transfer channel; re-copy with `-Encoding UTF8`)
- `15` is not exactly `R15_5_VERIFIER_READY`
- any SQL error in any file — do not retry fragments

## Out of scope

Founder seed execution (human approval required), Stripe configuration, deployment, merging,
tagging, role-membership changes, and the duplicate migration-version cleanup.
