# QHUB R15.6 — Managed-Role Evidence Gate Runbook (additive)

Offline documentation. **This document authorizes nothing.** It does not authorize Diagnostic 28,
PRE 25, RECORD 26, POST 27, a founder-access preview, a founder seed, Stripe configuration, a
deployment, or a merge. It records the gate that is currently open, pins the artifacts that a
future authorization would have to name, and prescribes the fail-closed order in which the gate
may be resolved.

This is **not** a new runtime release and is **not** R15.7. The committed evidence supports an
R15.6 Managed-Role Evidence Gate only.

## 1. Authority boundary

`R15_6_MIGRATION_HISTORY_RUNBOOK.md` remains the authoritative operator procedure for
PRE 25 / RECORD 26 / POST 27. This document **supplements** it and **modifies nothing**: that
runbook's bytes are unchanged, its hashes are unchanged, and its Sequence remains valid — but only
**from the point at which the evidence gate described here has been resolved**.

The reason a supplement is needed is narrow and factual. That runbook was last changed at
`fe0558dfe194525089159aaa9ce8b6fe9eb1922d`. Diagnostic 28 was introduced afterwards at
`dc08f4e7e8bcaadb3f415f9547cbda525e963376`. Consequently the migration-history runbook:

- does not name Diagnostic 28 anywhere;
- does not pin Diagnostic 28 in its authoritative artifact-hash table;
- has no step for collecting managed-role evidence and no step for classifying a role;
- begins its Sequence at "run 25 → expect `SAFE_TO_RECORD_MIGRATION_HISTORY`", which the
  last recorded live observation contradicts.

Nothing in that runbook is wrong. It is incomplete with respect to a gate discovered after it was
written. This document closes that documentation gap and nothing else.

## 2. What is already closed and must not be reopened

- R15.6 protected-function restoration (package `21`/`22`/`23`).
- The offline POST body-digest reconciliation (`24_POST_DIGEST_RECONCILIATION.md`).
- The Managed-Role Diagnostic 28 implementation.
- The five-commit hermetic-matcher correction cycle ending at
  `23533a624ca2f71a772cc1213a7792c02cddb6bb`, which changed only
  `app/test/commercial-r15-6-managed-role-diagnostic.test.ts`.
- The controlled fast-forward push that synchronized the branch at that commit.

## 3. What remains open

Migration-history reconciliation; classification of `cli_login_postgres`, `supabase_etl_admin` and
`supabase_read_only_user`; any live Diagnostic 28 execution; any rerun of PRE 25; RECORD 26;
POST 27; the founder-access preview; the founder seed; Stripe configuration; deployment; merge.

## 4. Pinned artifacts

Every value below was computed mechanically from the committed bytes at
`23533a624ca2f71a772cc1213a7792c02cddb6bb`. Complete hashes only — never an abbreviation.

| Artifact | Git blob | Bytes | CR | SHA-256 |
|---|---|---|---|---|
| `docs/release/r15-6-migration-history/25_PRE_MIGRATION_HISTORY_VERIFY.sql` | `063003a77b6021fe978ffbce7dafb2f83a40d3f6` | 31,031 | 0 | `bf7b9c1331ffb6b845fd8fcebd159786b62b9d28d0bf0b6787967f055632f627` |
| `docs/release/r15-6-migration-history/26_MIGRATION_HISTORY_RECORD.sql` | `a11877994ebfa5dae46ccdf0c5a25d37e29d7678` | 204,358 | 0 | `2be2a0abf5537c8333c11836e1f509ee329af011de660078512b7af927cf1064` |
| `docs/release/r15-6-migration-history/27_POST_MIGRATION_HISTORY_VERIFY.sql` | `03d2983d44a7e738b613870e49a9c8a628b0a928` | 23,202 | 0 | `c6a8ff99c9da4dcc2fe517bdfe4a2fe979ece82ff92fb093e365c8897ef2e0b2` |
| `docs/release/r15-6-migration-history/28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql` | `5bde8d0116b5dc73892a47ff82ea93a356a485bd` | 47,588 | 0 | `52acf699ed170ec4ded25301190676491e984e94ad963e13c3d33c6ae037ee60` |
| `docs/release/r15-6-migration-history/R15_6_MIGRATION_HISTORY_RUNBOOK.md` | `2d59db229fbf9710e0bde5a8891d226cff980806` | 14,485 | 0 | `43960dbd4c9ddbbf34ad2ce81441d5a0990eafd9d88438fc46a2af8d9da1fc2c` |
| `docs/release/r15-6-migration-history/MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md` | `1c1d7900abf2e21b830b0111b2ac79ee70a7d4b1` | 31,866 | 0 | `95cd95fa79d837564681920eab8b5c49f3067e300a3f8abdfb00a63800fcceab` |

Diagnostic 28 is the **only** artifact this gate would ever execute, and only read-only, and only
under a separate authorization naming that exact SHA-256.

### 4.1 Provenance

| Fact | Commit |
|---|---|
| Introduced Diagnostic 28 and its analysis | `dc08f4e7e8bcaadb3f415f9547cbda525e963376` |
| Authoritative current analysis content | `873669f1a51bc16cd9b6a2689467b249641d9173` |
| Last change to the migration-history runbook; also the commit at which PRE 25 was executed live | `fe0558dfe194525089159aaa9ce8b6fe9eb1922d` |
| Synchronized baseline for this document | `23533a624ca2f71a772cc1213a7792c02cddb6bb` |

### 4.2 PRE-25 byte continuity

`MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md` §1 records that the live PRE 25 run used artifact SHA-256
`bf7b9c1331ffb6b845fd8fcebd159786b62b9d28d0bf0b6787967f055632f627`. The committed
`25_PRE_MIGRATION_HISTORY_VERIFY.sql` at the baseline hashes to exactly that value. The gate that
produced the recorded stop is therefore **byte-identical** to the gate a rerun would execute. No
rerun may assume a different outcome without a change in the database, not in the artifact.

## 5. The blocking condition

### 5.1 What committed evidence records

`MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md` §1 records the result of a single, separately authorized,
read-only PRE 25 execution against the project reference named in that section:

- `verdict = UNEXPECTED_MIGRATION_HISTORY_STOP`
- `no_unauthorized_access_path = false`
- `unauthorized_access_paths = {cli_login_postgres, supabase_etl_admin, supabase_read_only_user}`

Exactly one condition failed. Everything else verified:

- `product_ready = true`
- `product_version = 2026-07-30.commercial-launch-r8`
- `product_failed_count = 0`
- the history table matched the pinned CLI contract in every dimension
- `nspacl` and `relacl` were empty
- `anon`, `authenticated` and `service_role` held nothing
- no malformed, newer or conflicting rows, and `target_rows = 0` — **the `20260729` history row
  remains absent**

Diagnostic 28 was created to collect bounded evidence about those three roles. **It has never been
executed live.**

### 5.2 Evidence classification

Nothing below is asserted because an artifact or a passing test exists.

| Fact | Classification |
|---|---|
| `product_version = 2026-07-30.commercial-launch-r8` | Live fact recorded in committed evidence (analysis §1) |
| `product_ready = true`, `product_failed_count = 0` | Live fact recorded in committed evidence (analysis §1) |
| PRE 25 stopped on `no_unauthorized_access_path = false` with the three named roles | Live fact recorded in committed evidence (analysis §1) |
| The `20260729` history row is absent (`target_rows = 0`) | Live fact recorded in committed evidence (analysis §1) |
| Protected-function restoration POST outcome | Prior execution report; the committed reconciliation (`24`) is explicitly offline |
| `qhub_decide_review` / `qhub_row_immutable` definitions and digests | Locally reproducible offline (`commercial-r15-6-post-digest-reconciliation`) |
| Diagnostic 28 behaviour, bounds and ordering | Locally reproducible offline on disposable PostgreSQL 16; never run live |
| What the three roles actually are | **Unresolved.** Future live work, currently unauthorized |

### 5.3 Rules that hold during this documentation task

- A role name is not evidence. Any role may be created with any non-`pg_`-prefixed name, and the
  observed names are documented nowhere in this repository.
- No role may be accepted, rejected, altered, disabled, granted, revoked, or otherwise classified
  by this document or by the task that produced it.
- The mandatory PRE-25 predicate is unchanged. This document adds no name whitelist, no prefix
  exemption, and no relaxation of any gate.

## 6. Future fail-closed sequence

Each numbered transition is a separate, separately authorized step.

| # | Step | Requirement to proceed |
|---|---|---|
| 1 | Verify the synchronized source baseline and every pinned artifact identity in §4 | exact match on all values |
| 2 | Obtain separate authorization for a **read-only** live Diagnostic 28 execution | explicit human authorization naming SHA-256 `52acf699ed170ec4ded25301190676491e984e94ad963e13c3d33c6ae037ee60` |
| 3 | Execute only that exact pinned artifact, complete, in a fresh session | no substitution, no excerpt, no supplemental SQL |
| 4 | Preserve the complete output and execution metadata (§8) | evidence stored in the approved location designated under §8.1 |
| 5 | **Stop.** Do not proceed automatically | explicit human go |
| 6 | Classify each of the three roles through documented human review (§7) | one completed record per role |
| 7 | Independent review of the evidence package and the classifications | explicit independent-reviewer result |
| 8 | If evidence is incomplete, contradictory, undocumented, or cannot establish every access path | **remain fail-closed; stop** |
| 9 | Only after a successful classification **and** independent review may a separate prompt authorize a PRE-25 rerun | separate authorization |
| 10 | PRE 25 must independently return its required safe verdict | `SAFE_TO_RECORD_MIGRATION_HISTORY` or `ALREADY_RECORDED_EXACTLY` |
| 11 | RECORD 26 and POST 27 each keep their existing sequencing, stop conditions, evidence capture and separate authorization from `R15_6_MIGRATION_HISTORY_RUNBOOK.md` | as written there |
| 12 | Founder preview, founder seed, Stripe, deployment, merge and all other downstream work | outside this runbook |

**No single future prompt may combine** live Diagnostic 28, human classification, PRE 25,
RECORD 26, POST 27, deployment, or merge. Every consequential transition requires its own reviewed
evidence and its own authorization.

### 6.1 Operator notes for an eventual authorized Diagnostic 28 run

- Fresh session; the complete script; never a fragment.
- Copy the artifact without transformation:
  `Get-Content -Raw -Encoding UTF8 <file> | Set-Clipboard`.
- `statement_timeout` in 28 is transaction-local and applies **per statement**. The script is not
  capped in total, a later statement can fail after earlier result sets have already rendered, and
  **partial output authorizes nothing**. Only a complete fresh run counts.
- Diagnostic 28 emits **evidence, not a verdict**. It contains no verdict, approves nothing, and
  clears no role.

## 7. Role-classification record

One record per role. **Do not fill in verdicts as part of the documentation task that created this
file.** Every field below is `UNRESOLVED` until completed under a separate authorization, and an
`UNRESOLVED` field must never be presented or summarized as a completed fact.

### 7.1 Field definitions

| Field | Meaning |
|---|---|
| Role name | Exact role name as reported by the catalog |
| Role existence | Whether the role exists at evidence-capture time |
| Login capability | Whether the role can authenticate |
| Direct memberships | Memberships granted directly, with `INHERIT` / `SET` / `ADMIN` options |
| Inherited memberships | Memberships reachable transitively, with the option that makes each usable |
| Ownership / administrative relationship | Whether the role owns, or can assume an owner or a superuser |
| Grants and effective access paths | Per-privilege reach on the protected objects, separated into usable-without-`SET ROLE` and reachable-via-`SET ROLE` |
| Credential / authentication observations | Only what Diagnostic 28 reports; never a secret value |
| Managed / customer / human / service / unresolved | The classification category |
| Authoritative documentation title | Title of the platform document relied upon |
| Authoritative documentation publisher | Who publishes it |
| Documentation URL or durable reference | Where it can be retrieved |
| Access / retrieval date | When it was read |
| Relevant statement | The applicable statement, summarized without extended quotation |
| Supporting diagnostic evidence | Which Diagnostic 28 result sets and rows support the classification |
| Contradictory evidence | Anything that argues against it |
| Reviewer | Identity of the human classifier |
| Reviewer date | Date of that classification |
| Final classification | The concluded category |
| Classification rationale | Why the evidence establishes it |
| Independent reviewer | Identity of the independent reviewer |
| Independent-review result | Accepted, rejected, or returned for more evidence |

### 7.2 `cli_login_postgres`

| Field | Value |
|---|---|
| Role name | `cli_login_postgres` |
| Role existence | UNRESOLVED |
| Login capability | UNRESOLVED |
| Direct memberships | UNRESOLVED |
| Inherited memberships | UNRESOLVED |
| Ownership / administrative relationship | UNRESOLVED |
| Grants and effective access paths | UNRESOLVED |
| Credential / authentication observations | UNRESOLVED |
| Managed / customer / human / service / unresolved | UNRESOLVED |
| Authoritative documentation title | UNRESOLVED |
| Authoritative documentation publisher | UNRESOLVED |
| Documentation URL or durable reference | UNRESOLVED |
| Access / retrieval date | UNRESOLVED |
| Relevant statement | UNRESOLVED |
| Supporting diagnostic evidence | UNRESOLVED |
| Contradictory evidence | UNRESOLVED |
| Reviewer | UNRESOLVED |
| Reviewer date | UNRESOLVED |
| Final classification | UNRESOLVED |
| Classification rationale | UNRESOLVED |
| Independent reviewer | UNRESOLVED |
| Independent-review result | UNRESOLVED |

### 7.3 `supabase_etl_admin`

| Field | Value |
|---|---|
| Role name | `supabase_etl_admin` |
| Role existence | UNRESOLVED |
| Login capability | UNRESOLVED |
| Direct memberships | UNRESOLVED |
| Inherited memberships | UNRESOLVED |
| Ownership / administrative relationship | UNRESOLVED |
| Grants and effective access paths | UNRESOLVED |
| Credential / authentication observations | UNRESOLVED |
| Managed / customer / human / service / unresolved | UNRESOLVED |
| Authoritative documentation title | UNRESOLVED |
| Authoritative documentation publisher | UNRESOLVED |
| Documentation URL or durable reference | UNRESOLVED |
| Access / retrieval date | UNRESOLVED |
| Relevant statement | UNRESOLVED |
| Supporting diagnostic evidence | UNRESOLVED |
| Contradictory evidence | UNRESOLVED |
| Reviewer | UNRESOLVED |
| Reviewer date | UNRESOLVED |
| Final classification | UNRESOLVED |
| Classification rationale | UNRESOLVED |
| Independent reviewer | UNRESOLVED |
| Independent-review result | UNRESOLVED |

### 7.4 `supabase_read_only_user`

| Field | Value |
|---|---|
| Role name | `supabase_read_only_user` |
| Role existence | UNRESOLVED |
| Login capability | UNRESOLVED |
| Direct memberships | UNRESOLVED |
| Inherited memberships | UNRESOLVED |
| Ownership / administrative relationship | UNRESOLVED |
| Grants and effective access paths | UNRESOLVED |
| Credential / authentication observations | UNRESOLVED |
| Managed / customer / human / service / unresolved | UNRESOLVED |
| Authoritative documentation title | UNRESOLVED |
| Authoritative documentation publisher | UNRESOLVED |
| Documentation URL or durable reference | UNRESOLVED |
| Access / retrieval date | UNRESOLVED |
| Relevant statement | UNRESOLVED |
| Supporting diagnostic evidence | UNRESOLVED |
| Contradictory evidence | UNRESOLVED |
| Reviewer | UNRESOLVED |
| Reviewer date | UNRESOLVED |
| Final classification | UNRESOLVED |
| Classification rationale | UNRESOLVED |
| Independent reviewer | UNRESOLVED |
| Independent-review result | UNRESOLVED |

### 7.5 Rules binding every record

- Role names are **not** classification evidence.
- Apparent read-only naming is **not** proof of least privilege.
- Platform ownership must be **proven**, not inferred.
- An undocumented access path **fails closed**.
- The absence of a known exploit is **not** proof of authorization.
- All three roles must be resolved **individually**. No majority, aggregate, or
  by-analogy verdict is permitted; two resolved roles do not carry the third.

### 7.6 Outcomes that keep the gate shut

Restated from `MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md` §9 as binding gate conditions. Any of these
keeps the gate closed regardless of classification effort:

- any candidate with **write** reach (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`), whether usable
  directly or reachable via `SET ROLE`;
- any candidate that can `SET ROLE` to the pinned owner, an actual object owner, or a superuser,
  or that inherits from any of them;
- any candidate reaching the objects through an explicit ACL entry it can actually use — the
  pinned contract is `nspacl IS NULL` and `relacl IS NULL`, so any entry is drift;
- any `PUBLIC` grant;
- any candidate whose identity cannot be tied to a documented platform mechanism, including a role
  that merely looks managed;
- any `SET ROLE`-only path a reviewer cannot attribute to a controlled operator workflow;
- an expired role is not thereby safe: expiry bounds password authentication, not authority.

### 7.7 Prohibited forms of exception

Restated from `MANAGED_ROLE_DIAGNOSTIC_ANALYSIS.md` §10. An exception, if ever granted, must be a
precisely verified capability and identity — narrow, per-role, per-privilege, and re-verified at
execution time. Specifically prohibited:

- a broad `pg_`-prefix or `supabase_`-prefix exemption;
- an unconditional role-name whitelist;
- any change that lets a role with write access, owner assumption, or a usable explicit ACL entry
  pass;
- editing the gate to make the current live state green without first explaining it.

## 8. Evidence handling

### 8.1 Storage location

This repository defines **no** location for live execution evidence, and this document does not
invent one. Before any live Diagnostic 28 execution, an **approved secure evidence location must be
designated** by the authorizing human, and the authorization must name it. Until then there is no
approved destination and no live run may occur.

### 8.2 Never commit

Credentials; access tokens; passwords; connection strings; private keys; session cookies;
unredacted secrets; and any live output more sensitive than the gate requires. Diagnostic 28 is
designed to report catalog facts, not secret values; if any captured output contains a secret, it
must be redacted before it leaves the approved location, and the redaction must be recorded.

### 8.3 Metadata to preserve with the output

Artifact SHA-256 actually executed; the source commit; the session start and end; the operator
identity; the complete text of every result set; and any notice, warning, error, timeout,
cancellation, or connection loss. Anything anomalous is a stop, not a footnote.

## 9. Future outcomes

These are outcomes of **future, separately authorized** work. None of them is produced by the
documentation task that created this file.

| Outcome | Meaning |
|---|---|
| `R15_6_MANAGED_ROLE_DIAGNOSTIC_EVIDENCE_CAPTURED — HUMAN CLASSIFICATION REQUIRED` | A complete Diagnostic 28 run was captured. Nothing is classified and nothing is authorized. |
| `R15_6_MANAGED_ROLE_EVIDENCE_INCOMPLETE_STOP` | The run or the documentation could not establish every access path. Fail closed. |
| `R15_6_MANAGED_ROLE_EVIDENCE_REJECTED_STOP` | Evidence or classification was reviewed and rejected — including any §7.6 outcome. Fail closed. |
| `R15_6_MANAGED_ROLE_EVIDENCE_CLASSIFIED — PRE25 RERUN MAY BE SEPARATELY AUTHORIZED` | All three roles are individually classified and independently reviewed. This authorizes **only the preparation of a separate PRE-25 prompt**. It does not execute PRE 25 and does not authorize it. |

The outcome of the present documentation package is separate from all four and is reported by the
task that created this file.

## 10. Explicitly out of scope

Live execution of Diagnostic 28, PRE 25, RECORD 26 or POST 27; any SQL execution; any change to
`R15_6_MIGRATION_HISTORY_RUNBOOK.md`, the analyses, the diagnostics, the migration, the statements
fixture, or any source, test, configuration, package, lockfile, hook or workflow file; the
founder-access preview; the founder seed; Stripe configuration; deployment; merge; the
duplicate-prefix version backlog for `20260725`, `20260726` and `20260727`; and any edit to a
previously approved artifact.
