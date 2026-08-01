# QHUB R15.6 — Runtime Verifier Patch Runbook

Human-operated. Replaces **one** function — `public.qhub_verify_commercial_schema()` — with the
reviewed R15.6 body, which makes the runtime verifier enforce the **complete** trigger-helper
contract: the R15.4 owner-only ACL, the full reviewed pg_proc semantic/callable contract, the
exact reviewed body digests, and exact trigger timing/event bits.

**Supersedes `docs/release/r15-5-runtime-verifier/` (13/14/15) as the operational verifier
patch.** R15.5 and the earlier R15.2C package remain immutable reviewed history; neither verifier
body contains the complete R15.6 semantic and authority contract and neither may be installed
after this package.

## Why this exists

Codex reproduced a P1 against a clean R15.4 install: after `GRANT EXECUTE ON
public.qhub_row_immutable() TO anon`, the runtime verifier still returned `ready=true, failed=[]`.
The verifier had no checks for the trigger helper's ACL or its trigger attachments, so live drift
against the newly reviewed owner-only contract was invisible — a false READY.

R15.6 closes four additional Codex-reproduced P1s left by R15.5: (1) `ALTER FUNCTION … IMMUTABLE STRICT
PARALLEL SAFE LEAKPROOF COST 42` on the helper still reported READY; (2) a trigger broadened to
`BEFORE INSERT OR UPDATE OR DELETE` still reported READY (bit containment); (3) PRE `13` accepted a
verifier missing its own owner ACL row; (4) PATCH `14` silently repaired a SECURITY INVOKER start.

The verifier now enforces, with stable and specific failure labels:

| concern | labels |
|---|---|
| helper identity (SECURITY INVOKER, no search_path, exact owner) | `row_immutable_identity` |
| callable interface (zero-arg trigger fn, no overload, no defaults/variadic/arg metadata, plpgsql) | `row_immutable_callable_interface` |
| semantic attributes (VOLATILE, CALLED ON NULL INPUT, PARALLEL UNSAFE, NOT LEAKPROOF, COST 100, ROWS 0) | `row_immutable_semantic_attributes` |
| execution metadata (no support fn, no transforms, no probin, no prosqlbody) | `row_immutable_execution_metadata` |
| exact reviewed body (raw LF/CRLF digests only — mojibake never accepted) | `row_immutable_body_digest` |
| exact one-row owner-only ACL (owner-granted, non-grantable) | `row_immutable_acl_cardinality`, `row_immutable_acl_owner_entry`, `row_immutable_acl_unexpected_grantee`, `row_immutable_acl_grant_option` |
| the three immutability triggers attached, enabled, bound to exactly this function | `row_immutable_trigger_missing:<table>`, `row_immutable_trigger_binding:<table>`, `row_immutable_trigger_disabled:<table>` for `qhub_acknowledgments`, `qhub_usage_ledger`, `qhub_entitlement_audit` |

Every contract value was **derived from the reviewed migration in a disposable database**
(identical under plain PostgreSQL and Supabase default privileges), never guessed. The
`row_immutable_acl_owner_entry` predicate binds the **grantor** — a one-row ACL whose only defect
is a non-owner grantor is NOT READY (proven by catalog-fixture test).

Bindings are checked by exact name + table + function OID + **exact `tgtype = 27`**
(FOR EACH ROW + BEFORE + DELETE + UPDATE, equality not containment), so a renamed, rebound or
replacement trigger cannot satisfy a count, an unrelated extra trigger satisfies nothing, and an
extra INSERT or TRUNCATE event, AFTER timing, or statement-level scope is NOT READY. Every
pre-existing verifier check is preserved — the label inventory is a strict superset across rounds
(72 → 80 → 84 labels, zero removed or renamed, mechanically proven against the committed
predecessor).

## Stable identifiers

| Item | Value |
|---|---|
| Branch | `commercial-launch-foundation` |
| Base main | `6ab2c2bc82dc67a3073de1eb457583773cab0ac6` |
| Migration | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Migration SHA-256 | `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755` |
| Schema version | `2026-07-30.commercial-launch-r8` |
| Live project reference | `jsjsanmaahvmynblmzkq` |
| This package | `docs/release/r15-6-runtime-verifier/` |

## Verifier body digest contract

| state | md5(prosrc) |
|---|---|
| documented live start (commit `644b5c6`'s verifier through the 2026-07-30 CRLF+cp1252 mojibake channel) | `a35d8320d4a9804725a95f76534fe5a2` |
| reviewed final (R15.6) body, LF | `1c6f85b4cb410dc4ca307ed22ee1de47` |
| reviewed final (R15.6) body, CRLF | `42b43aaa01a770dc7d4a2a0d2f7f33b6` |

The start digest is **derived, not measured** — computed from the exact commit the live database
was applied from, through the exact channel proven by the R15.3 forensics. If the live digest
differs, `16` STOPs. That is the correct outcome, not a calibration problem: it means the live
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
| 4 | R15.6 `16_PRE_PATCH_RUNTIME_VERIFIER_VERIFY.sql` | `SAFE_TO_APPLY_RUNTIME_VERIFIER_PATCH` |
| 5 | R15.6 `17_LIVE_RUNTIME_VERIFIER_SEMANTIC_AUTHORITY_PATCH.sql` (once) | success, no exception |
| 6 | R15.6 `18_POST_PATCH_RUNTIME_VERIFIER_VERIFY.sql` | **`R15_6_VERIFIER_READY`** |
| 7 | `npx --yes supabase@2.110.0 migration repair --status applied 20260729` | 20260729 recorded |
| 8 | `npx --yes supabase@2.110.0 migration list` | prior versions unchanged |
| 9 | founder-access preview (read-only) → **pause for human approval** | — |

**Do not run `db push`. Do not use `--include-all`.** `R15_6_VERIFIER_READY` — with
`product_ready = true`, exact version and `failed = 0` — is required **before** history alignment.

## The exact verifier start-state authority contract

`16` and `17` authorize exactly **two** explained states — the documented live-era state or the
reviewed final state — and **both** must satisfy the complete contract in every respect:

- SECURITY DEFINER with `search_path=pg_catalog, public`, owned by the contract owner
- the **exact normalized two-row direct ACL**: the owner's own EXECUTE row **and** service_role's
  EXECUTE row, both granted **by the owner**, neither grantable, cardinality exactly 2, no other
  grantee, **no grant option anywhere**. The explicit owner ACL row is **mandatory** — its absence
  is not a benign default, it is evidence someone rewrote the verifier's ACL, and it is a STOP.
- the exact semantic/callable attributes (jsonb-returning zero-argument plpgsql STABLE non-strict
  PARALLEL UNSAFE non-leakproof, COST 100, no defaults/variadic/transforms/support/probin/
  prosqlbody), no overload
- a body digest that is fully explained (documented live start, or the reviewed final body)
- no unexplained effective executor (role membership included; superusers reported separately)

A SECURITY INVOKER verifier, a missing owner ACL row, a wrong grantor, a wrong owner, a wrong
`search_path`, a semantic/callable drift, an unknown body, or any third state is **unexplained
authority drift: STOP**. **The PATCH never silently repairs unexplained verifier authority drift**
— it raises before `CREATE OR REPLACE`, leaves the evidence intact, and rolls back.

## What 16 / 17 / 18 do

**16 (read-only)** verifies the complete start-state contract above and reports every check
individually; every displayed check feeds the single verdict. It never invokes a user-defined
function and cannot raise 42883.

**17 (one transaction, once)** replaces only the verifier. Gate 1 — **before** `CREATE OR
REPLACE` — verifies the identical complete start-state contract and raises deterministically on
any unexplained state: `unexpected_runtime_verifier_authority` (SECURITY INVOKER, ACL, owner,
search_path), `unexpected_runtime_verifier_interface` (semantic/callable),
`unexpected_runtime_verifier_state` (unknown body), or the verbatim R15.2C
`unexpected_effective_verifier_executor` (role-graph; never repairs cluster memberships). Only
after Gate 1 proves the authority state is already an explained one does the R15.2C
owner/direct-ACL reassertion run — it re-asserts a verified state and is forbidden from repairing
an unexplained one. Gate 2 — before COMMIT — re-asserts the **complete final contract**: exact
new body digest, exact schema version, owner, SECURITY DEFINER, search_path, the exact two-row
ACL, no overload, and the exact semantic/callable attributes; the authoritative R15.2C
effective-ACL recheck then runs. A mangling transfer channel or any residual drift rolls the whole
transaction back. Idempotent under the final state.

**18 (read-only)** carries forward the Codex-approved R15.2C `09` architecture — one REPEATABLE READ
snapshot, one authoritative statement, catalog authority and the guarded `query_to_xml` invocation
in the same statement — extended with the exact-ACL (owner row mandatory, grantors bound, zero
grant options, cardinality 2) and semantic/callable checks, all feeding `final_status`. Because
the R15.6 body enforces the complete helper contract, `product_ready = true` now *requires* the
one-row owner-only helper ACL, the complete reviewed pg_proc contract for the helper (an
`IMMUTABLE`/`STRICT`/`COST` drift is NOT READY), the exact reviewed helper body, and all three
immutability triggers attached, enabled and bound with `tgtype` exactly 27 (an extra INSERT event
is NOT READY).

## Stop conditions

- local/origin HEAD differs from the final review report, or migration SHA-256 differs
- `16` returns `UNEXPECTED_RUNTIME_VERIFIER_STOP` — an unexplained body digest, a missing owner
  ACL row, SECURITY INVOKER, wrong owner/search_path/grantor, semantic/callable drift, overload,
  or any unexpected effective executor
- `17` raises — `unexpected_effective_verifier_executor*` (role-graph problem; never revoke
  memberships), `unexpected_runtime_verifier_authority` / `unexpected_runtime_verifier_interface` /
  `unexpected_runtime_verifier_state` (unexplained start; never patch over it), or the
  `R15.6 POST` final-contract failure (bad transfer channel or residual drift; for encoding,
  re-copy with `-Encoding UTF8`)
- `18` is not exactly `R15_6_VERIFIER_READY`
- any SQL error in any file — do not retry fragments

## Out of scope

Founder seed execution (human approval required), Stripe configuration, deployment, merging,
tagging, role-membership changes, and the duplicate migration-version cleanup.
