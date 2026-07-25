# QHUB Gate 03 — POLICY Stage: Architecture

**Status:** Implemented · unit-verified (tsc 0 errors, 56 tests) · staging Lambda live · **Env:** staging (qhub-studio.fly.dev)
**Preceded by:** `GATE-02-CLASSIFICATION-VERIFIED` @ `902ffeb`

Gate 03 implements the **POLICY** stage of the QHUB compliance lifecycle
(`01 CLASSIFY → 02 POLICY → 03 BUILD → 04 ATTEST`), built on the frozen P0 spine
and the Gate 02 classifier. It answers one question deterministically: **given the
confirmed classification, what controls must be present before build / preview /
deploy / operate?** It adds one ledger event type (`POLICY_PROFILE_ASSIGNED`) and
one decision point (policy acknowledgement before generation). No P0 architecture
was modified.

- **In scope:** versioned control catalog, deterministic policy engine, policy
  profile + hash, `POLICY_PROFILE_ASSIGNED` event, profile persistence, policy
  card, policy→build constraint handoff, and a Phase-0 hardening of Gate 02
  (server-persisted classification proposals).
- **Out of scope (later):** full Governance Console, exception/waiver workflow, a
  legal-mapping engine, MCP/A2A enforcement, billing. The ATTEST stage (Gate 04)
  is untouched.

## The Phase-0 hardening (why classification changed)

Gate 02 confirmed a classification by trusting the signals the browser sent back.
A hostile client could rewrite them to lower the deterministic floor. Gate 03
closes this: `/api/classify` now persists the **provisional** classification
server-side (`qhub_classification_proposals`) and returns only an opaque
`proposal_id`. Confirmation binds to that id — the server reloads the authoritative
signals, re-derives the floor, and clamps the final tier to `max(floor, confirmedTier)`.
Proposals are single-use, tenant-scoped, and time-limited. The browser's only
classification input is a *raise* of the tier; it can never lower it.

## Component inventory & module boundary

| Module | Boundary | Responsibility |
|---|---|---|
| `app/lib/qhub/policy.ts` | browser-safe | Policy type surface: `EnforcementLevel`, `LifecycleStage`, 12 `ControlCategory`s, `PolicyControl`/`AppliedControl`, `Constraint`, `PolicyProfile`, `PolicyStatus`, gate states. No secrets. |
| `app/lib/qhub/policy-catalog.ts` | browser-safe | **Versioned catalog** (`gate03-catalog-1.0.0`): ~35 controls, cumulative `TIER_BASELINE` (T0⊂T1⊂T2⊂T3), `SIGNAL_OVERLAYS`, `REGULATORY_OVERLAYS`. Framework references are applicability tags in data, not logic. |
| `app/lib/qhub/policy-engine.ts` | pure/shared | Deterministic `buildPolicyProfile()`; `canonicalPolicyString()` (hash preimage); `formatBuildConstraintsForPrompt()` (governed-build handoff text). No I/O, no AI, independently unit-testable. |
| `app/lib/qhub/governance-service.server.ts` | server-only | `recordPolicyProfile()` signs & emits `POLICY_PROFILE_ASSIGNED`; `acknowledgePolicy()`; proposal-based `recordClassification()`. HMAC signing lives only here. |
| `app/lib/qhub/qhub-app.server.ts` | server-only | Proposal store (`persistProposal`/`getProposal`/`markProposalConsumed`) and policy snapshot (`persistPolicyProfile`/`getPolicyProfile`/`getPolicyProfileByConversation`/`updatePolicyStatus`). |
| `app/routes/api.classify.ts` | route (server) | Auth-gated analysis; persists a proposal, returns `{classification, proposalId}`. Writes nothing to the ledger. |
| `app/routes/api.governance.ts` | route (server) | Adds `POLICY_ASSIGN` / `POLICY_ACKNOWLEDGE` intents (server-authoritative identity). |
| `app/lib/qhub/governance-client.ts` | browser-safe | `requestClassification` (returns `proposalId`), `confirmClassification` (proposal-bound), `assignPolicy`, `acknowledgePolicy`. No signing, no AWS. |
| `app/lib/.server/llm/stream-text.ts` | server-only | **Appends** the policy constraints to the full builder prompt (never replaces it) so generation is bound to the assigned controls. |
| `app/components/chat/PolicyCard.tsx` | client | Business-readable `02 · Policy` card: required/conditional/advisory controls, build constraints, required attestations, profile hash. |
| `supabase/migrations/20260725_gate03_policy.sql` | DB | `qhub_classification_proposals` table + policy snapshot columns on `qhub_applications`. |

## The deterministic engine

`buildPolicyProfile(input)` is a pure function of the **catalog version** and the
**confirmed classification** (tier + signals + regulatory domains):

1. **Collect** control ids: tier baseline → signal overlays → regulatory overlays,
   into a `Map<control_id, Set<reason>>` (a control triggered many ways appears
   once with all its reasons).
2. **Resolve** to `AppliedControl[]`, sorted by id.
3. **Partition** by `enforcement_level` → required (MANDATORY) / conditional / advisory.
4. **Derive** stage constraints (build / preview / deploy / runtime), required
   attestations, and required evidence.

Mandatory controls come **only** from the catalog. No actor — human or AI — may
remove a mandatory control, weaken an enforcement level, or override a requirement.
`canonicalPolicyString()` serializes only the policy-determining content (never ids,
timestamps, or actor), so identical classifications always yield an identical
`policy_profile_hash`.

## Runtime data flow

```
Classification confirmed (Gate 02, proposal-bound)
  → Chat.client: assignPolicy()
     → POST /api/governance {action: POLICY_ASSIGN}
         → GovernanceService.recordPolicyProfile():
             1. load the SERVER-persisted confirmed classification (authoritative)
             2. buildPolicyProfile() from catalog + classification  (deterministic)
             3. stamp policy_profile_id (uuid), generated_at, and
                policy_profile_hash = sha256(canonicalPolicyString(profile))
             4. sign + POST a COMPACT POLICY_PROFILE_ASSIGNED to the AWS Lambda
                (ids / hash / counts / attestations — NOT the whole document)
             5. persistPolicyProfile() snapshot to qhub_applications
     → render <PolicyCard>; BUILD IS PAUSED
  → User acknowledges → acknowledgePolicy()
     → POST /api/governance {action: POLICY_ACKNOWLEDGE}
         → status ASSIGNED → ACKNOWLEDGED
  → build proceeds (reload)
     → stream-text.ts appends formatBuildConstraintsForPrompt(profile)
        to the full builder system prompt (never replaces it)
```

## Trust model

- **Server-authoritative, never from the browser:** `user_id`, `org_id`,
  `qhub_app_id`, `chain_id`, classification signals/floor, mandatory controls,
  policy version, and `policy_profile_hash`.
- **HMAC signing** happens exclusively inside `GovernanceService` (Node crypto,
  secret from server env). The browser posts intents only.
- **On-chain vs. operational:** the immutable ledger holds the authoritative
  `POLICY_PROFILE_ASSIGNED` (identity + hash). The full profile lives in the
  operational store; the on-chain hash lets any examiner confirm it was not altered.
- **The AI may not** remove a mandatory control, weaken enforcement, override a
  deterministic requirement, approve an exception, or authorize deployment.

## Ledger event: `POLICY_PROFILE_ASSIGNED`

Emitted after `CLASSIFICATION_ASSIGNED`, before build. Compact payload:
`policy_profile_id`, `policy_profile_version`, `policy_catalog_version`,
`policy_profile_hash`, `classification_version`, `risk_tier`, `required_control_ids[]`,
conditional/advisory counts, `regulatory_domains[]`, `required_attestations[]`.
`SPEC_VERSION` stays `2.6` on the wire — the canonical hash is version- and
event-type-agnostic, so all v2.5/v2.6 conformance vectors still pass. Spec:
`qhub-specs/event-schema-v2.8.md`. Ingest change: one entry added to
`VALID_EVENT_TYPES`; Rule 11 already permits a post-classification event with a
real `T0–T3` tier.

## Reference cases (unit-verified)

| Case | Classification | Policy outcome |
|---|---|---|
| **A** — public marketing microsite | T0, public data | Baseline only (`SD-NO-CLIENT-SECRETS`, `AE-BASELINE-EVENTS`, …). No owner attestation, no preview-only. |
| **B** — commission reconciliation | T2, client PII + system-of-record | Adds RBAC, strict tenant isolation, encryption, integration allowlist, books-and-records + **owner attestation**. Not preview-only. |
| **C** — autonomous trading agent | T3, trading + autonomous | Adds **preview-only**, kill switch, action limits, no-unrestricted-autonomy, dual control + **authorized governance approval**. |

## Verification status & remaining steps

- **Independently verified:** full project typecheck (0 errors); 56 tests
  (11 engine/reference-case + 6 policy-governance + 39 P0/Gate-02) pass; ingest
  conformance gate PASSED; `qhub-ingest-staging` Lambda updated (Active).
- **Pending (one human step):** apply `supabase/migrations/20260725_gate03_policy.sql`
  in the Supabase SQL editor. Then: deploy the Studio to Fly, drive live cases
  A/B/C, confirm `POLICY_PROFILE_ASSIGNED` in DynamoDB + S3 WORM + the AWS
  verifier (0 failures), run the isolate-restart durability check, and tag
  `GATE-03-POLICY-VERIFIED`.
