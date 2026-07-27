# QHUB Governance — Lifecycle & Milestone Map

The single authoritative index of the QHUB governance milestones, their verified
tags, and their documentation. It also reconciles a naming quirk worth knowing up
front.

## Numbering reconciliation (read this first)

Two numbering schemes coexist and are **off by one**:

- **Lifecycle step numbers** describe the product flow:
  `01 CLASSIFY → 02 POLICY → 03 GOVERNED BUILD → 04 CONTROL ENFORCEMENT →
  05 EXACT-VERSION ATTESTATION → DEPLOYMENT APPROVAL`.
- **Gate tag numbers** are the git milestone tags: CLASSIFY was tagged `GATE-02`,
  POLICY `GATE-03`, ENFORCE `GATE-04`, ATTEST `GATE-05`.

So **lifecycle step _N_ is tagged `GATE-0(N+1)`**, and the `GATE-01` slot is filled
by **P0 — the governance spine** (the ledger/chain/HMAC/WORM foundation). There was
never a separately-built "Gate 01"; P0 is the foundation, and CLASSIFY is the first
functional gate (tagged `GATE-02`). Tags are immutable audit history and are **not
renamed** — this note is the reconciliation of record.

## Milestones

| # | Milestone | Verified tag → commit | Architecture doc | Milestone doc |
|---|---|---|---|---|
| P0 | Governance spine (evidence + identity) | `P0-GOVERNANCE-SPINE-VERIFIED` → `069ea23` (`p0-live-closure` → `3285dd1`) | [p0-governance-spine-architecture.md](p0-governance-spine-architecture.md) | — |
| 01 CLASSIFY | Hybrid classifier, tier floors, classification event | `GATE-02-CLASSIFICATION-VERIFIED` → `902ffeb` | [gate-02-classification-architecture.md](gate-02-classification-architecture.md) | — |
| 02 POLICY | Policy profile assignment + schema-readiness hardening | `GATE-03-POLICY-VERIFIED` → `5bdf8d9` | [gate-03-policy-architecture.md](gate-03-policy-architecture.md), [gate-03-schema-readiness-hardening.md](gate-03-schema-readiness-hardening.md) | — |
| 03/04 ENFORCE | Central governed-action enforcement, control decisions, approvals | `GATE-04-ENFORCEMENT-VERIFIED` → `8ecbab6`; `GATE-04-ENFORCEMENT-VERIFIED-R2` → `bf35f12` | [gate-04-control-enforcement-architecture.md](gate-04-control-enforcement-architecture.md) | — |
| 05 ATTEST | Exact-version attestation + deployment authorization | `GATE-05-ATTESTATION-VERIFIED` → `19e25ab` | [gate-05-attestation-architecture.md](gate-05-attestation-architecture.md) | [gate-05-attestation-milestone.md](gate-05-attestation-milestone.md) |
| — | Agent Framework Foundation | (live-closure passed; **untagged, unmerged**) `agent-framework-foundation` | [agent-framework-foundation-architecture.md](agent-framework-foundation-architecture.md) | [agent-framework-foundation-milestone.md](agent-framework-foundation-milestone.md) |

## Invariants that hold across every milestone

- **Server-authoritative identity** — tenant/owner/policy/plan/decision/hashes are
  never browser-supplied.
- **Append-only evidence** — HMAC-signed, hash-chained events (wire `spec_version
  2.6`) in DynamoDB + S3 WORM (GOVERNANCE Object-Lock + KMS); `qhub-verifier-staging`
  requires zero failed chains.
- **Fail-closed** — missing/misconfigured schema, absent attestation, stale
  policy/plan, or unverifiable evidence blocks the action; nothing partial persists.
- **Exact-version binding** — decisions bind the exact content hash (policy, plan,
  release, and, for agents, the manifest); any material change invalidates the
  prior authorization.
- **No fabricated execution** — `DEPLOYMENT_EXECUTED` is emitted only for a real
  governed deployment.

## Documentation conventions

New markdown under `docs/` is `*.md`-gitignored; commit milestone/architecture docs
with `git add -f`. Persistent working state also lives in the assistant memory
index (`qhub-gate-progress.md`), which is the day-to-day source of truth between
sessions.
