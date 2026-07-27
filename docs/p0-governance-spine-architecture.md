# QHUB P0 — Governance Spine: Architecture

**Status:** VERIFIED — tags `P0-GOVERNANCE-SPINE-VERIFIED` @ `069ea23` and `p0-live-closure` @ `3285dd1`.

> **Numbering note.** P0 is the **foundation** that every lifecycle gate sits on.
> There is no separately-built "Gate 01": the lifecycle step numbers are one lower
> than the gate tags (CLASSIFY is lifecycle step 01 but is tagged `GATE-02`). See
> [qhub-governance-lifecycle.md](qhub-governance-lifecycle.md) for the authoritative map.

P0 establishes the **append-only, tamper-evident evidence spine** for QHUB
governance. Every later gate (CLASSIFY, POLICY, ENFORCE, ATTEST) and the Agent
Framework records its decisions onto this spine; nothing downstream is trusted
unless it is on-chain here.

## Trust boundary

Governance identity is **always server-authoritative**. userId, orgId,
qhub_app_id, chain_id, tier, policy/plan hashes, and decisions are set server-side
from the authenticated session and durable state — never from the browser. The
browser can request an action; it can never assert who it is, what it is allowed
to do, or what was decided.

## Event envelope (wire contract)

Events are HMAC-signed, hash-chained records with a **frozen wire
`spec_version = 2.6`**. The verifier is version- and event-type-agnostic, so new
event types can be added by later gates without changing the envelope contract.
Signing is HMAC-SHA256, performed only inside `GovernanceService` (Node `crypto`,
secret from env) — never in the browser. Each event carries `chain_id` + `seq`
(ordering), `prev_hash` + `event_hash` (linkage), `actor` (id + type +
identity_provider, no PII beyond the id), `risk_tier`, and a compact `payload` of
hashes/ids/references — never raw prompts, credentials, or customer data.

A chain begins with a `CHAIN_GENESIS` event; later gates append their canonical
events (e.g. `CLASSIFICATION_ASSIGNED`, `POLICY_PROFILE_ASSIGNED`,
`AI_MODEL_INVOKED`, `CONTROL_DECISION_RECORDED`, `GOVERNED_ACTION_RECEIPT_RECORDED`,
`ATTESTATION_SIGNED`, `DEPLOYMENT_APPROVED`/`REJECTED`). No `DEPLOYMENT_EXECUTED`
is fabricated without a real governed deployment.

## Pipeline (staging)

```
Studio (Fly, GovernanceService HMAC-signs)
  → API Gateway → ingest Lambda
     → DynamoDB  qhub-ledger-staging  (events, PK chain_id / SK seq)
     → DynamoDB  qhub-chains-staging   (chain heads)
     → S3 WORM   qhub-worm-client-smoke (Object-Lock GOVERNANCE + aws:kms + retention)
  → qhub-verifier-staging (Lambda) recomputes hashes + ordering across all chains
```

- **DynamoDB** holds the ordered, hash-chained event log.
- **S3 WORM** stores each event under `Object-Lock: GOVERNANCE` with `aws:kms`
  encryption and a retention window — immutable evidence independent of the
  primary store.
- **`qhub-verifier-staging`** re-derives every chain's hash linkage and ordering
  and reports `chains_failed` / invalid events; the acceptance bar is **zero
  failed chains and zero invalid events**.

## Persistence identity

Supabase (project `jsjsanmaahvmynblmzkq`) holds the mutable application/governance
state (apps, classifications, policy profiles, enforcement plans, approvals,
release candidates, attestations, agents). The `service_role` key is used only
server-side; browser roles (`anon`, `authenticated`) are denied by restrictive
RLS. Schema readiness is fail-closed from Gate 03 onward (see the gate docs).

## Durability & recovery

State is reconstructable from Supabase after a Fly restart, and the immutable
evidence (DynamoDB + S3 WORM) is external to the app runtime. A restart never
invents authorization: consumed approvals stay consumed, and re-derived
enforcement plans reproduce the same deterministic hashes.

## What P0 is NOT

P0 is the evidence + identity spine only. Classification logic, policy
compilation, runtime enforcement, exact-version attestation, and agents are the
subsequent gates — each additive, each recording onto this spine.
