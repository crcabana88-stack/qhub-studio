# QHUB Gate 05 — Exact-Version Attestation & Deployment Authorization: Architecture

**Status:** In development on branch `gate05-attestation`
**Base:** `8ecbab6` (Gate 04 main baseline, staging-validated)
**Preceded by:** `GATE-04-ENFORCEMENT-VERIFIED`

Gate 05 implements exact-version human attestation and production authorization:

> "Who is accepting responsibility for **this exact** application/agent version —
> under this exact classification, policy, enforcement plan, deployment target,
> and approval scope?"

It cryptographically binds authorized human attestations to a frozen release
candidate and prevents an old approval from authorizing changed code, policy,
tools, models, data access, or a different environment.

Lifecycle: `01 CLASSIFY → 02 POLICY → 03 BUILD → 04 ENFORCE → 05 ATTEST → DEPLOY`.

## Honest capability boundary (inspected)

- Generated-app files live client-side (`FilesStore`/WebContainer); the server
  receives them as context. Gate 05 computes the **release hash server-side** from
  a submitted canonical file manifest (`{path, sha256, size}` per file). The browser
  supplies file data; the **server** computes every hash and the release-candidate
  hash — the browser never supplies an authoritative hash, role, or status.
- Real deploy adapters exist (`api.netlify-deploy.ts`, `api.vercel-deploy.ts`) but
  are ungoverned. Gate 05 wires the deployment gate as a **precondition** to them
  (no valid `DEPLOYMENT_APPROVED` → deploy blocked) and defines the
  `DEPLOYMENT_EXECUTED` emission path for after a real deploy. A live provider
  deploy is **not exercised** this sprint (requires provider tokens + external side
  effect); `DEPLOYMENT_EXECUTED` is emitted only after an actual deploy — never faked.

## Event vocabulary (no new event types)

Reuses existing canonical events: `APP_SUBMITTED` (freeze a release candidate),
`ATTESTATION_SIGNED`, `DEPLOYMENT_APPROVED`, `DEPLOYMENT_REJECTED`,
`DEPLOYMENT_EXECUTED` (only after a real deploy). Wire `spec_version` stays 2.6.

## Layers

```
Working app version → freeze exact source+config → canonical file manifest (server-hashed)
  → release_candidate_hash (server) → APP_SUBMITTED (FROZEN)
  → required attestations (derived from policy profile + enforcement plan)
  → collect ATTESTATION_SIGNED (each scoped to the exact release_candidate_hash + role)
  → evaluateReleaseForDeployment() → DEPLOYMENT_APPROVED | DEPLOYMENT_REJECTED
  → (real deploy adapter, gated) → DEPLOYMENT_EXECUTED (only after actual deploy)
```

Any material change after freeze → new release candidate + new hash; prior
attestations remain historical but inapplicable; new attestations + new decision.

## File-level plan

Browser-safe (pure, unit-tested):
- `app/lib/qhub/release-candidate.ts` — types: `ReleaseCandidate`, `ReleaseStatus`,
  `FileManifestEntry`, `AttestationRequirement`, `AttestationPurpose`, `Attestation`,
  `AttestationStatus`, `DeploymentDecision`, `ReleaseAssuranceReceipt`.
- `app/lib/qhub/release-manifest.ts` — pure `canonicalFileManifestString`,
  `canonicalReleaseCandidateString` (release_candidate_hash preimage),
  `deriveAttestationRequirements(profile, plan)`, `canonicalStatementString`,
  `canonicalReceiptString`. Deterministic; identical inputs → identical hash.

Server-only:
- `app/lib/qhub/release-hash.server.ts` — sha256 of the canonical strings.
- `app/lib/qhub/attestation-store.server.ts` — release candidates, attestations,
  deployment decisions; TOCTOU-safe conditional writes; supersession.
- `app/lib/qhub/attestation.server.ts` — freeze(), signAttestation(),
  evaluateReleaseForDeployment(); records events; server-authoritative.
- `app/lib/qhub/governance-service.server.ts` (MODIFY) — emit helpers for
  APP_SUBMITTED / ATTESTATION_SIGNED / DEPLOYMENT_APPROVED / DEPLOYMENT_REJECTED /
  DEPLOYMENT_EXECUTED (existing event types).
- `app/routes/api.release.ts` — freeze RC, list readiness, submit attestation,
  evaluate deployment (auth-gated, server-authoritative).
- `app/routes/api.netlify-deploy.ts` / `api.vercel-deploy.ts` (MODIFY) — require a
  valid DEPLOYMENT_APPROVED for the exact release before deploying; emit
  DEPLOYMENT_EXECUTED after a real deploy only.

Persistence: `supabase/migrations/20260727_gate05_attestation.sql` — additive,
idempotent: `qhub_release_candidates`, `qhub_attestations`, `qhub_deployment_decisions`
with DB-enforced invariants (unique release_candidate_id / attestation_id, one active
RC per app-version, one valid attestation per (rc,purpose,signer), immutable frozen
hash, no duplicate deployment execution).

UX: release-readiness card, signer experience (plain-language statement + scope +
changes + Confirm/Sign/Reject/Request-Changes), role-scoped approval inbox, release
assurance receipt (human + JSON + stable hash).

## Signer authority & separation of duties

Signer role + tenant are server-authoritative (from session). Required attestations
derive from the policy profile + enforcement plan (not tier alone). Enforced: signer
authorized for the purpose; no self-approval where independence required; distinct
signers for distinct mandatory roles; release still FROZEN + hashes match; recent
session (re-confirm for T2/T3). Stronger step-up (WebAuthn/IdP) left as an adapter
boundary — no cryptographic non-repudiation is claimed beyond authenticated-account
+ server-bound release hash.

## Change invalidation & deployment gate

`evaluateReleaseForDeployment()` (server-only) recomputes the release hash, confirms
FROZEN + current classification/policy/plan, loads required attestations from policy,
validates each signer's authority/role/scope/expiry/revocation, enforces distinct
signers + no self-approval, verifies every attestation binds the exact same
release_candidate_hash + target environment, then returns APPROVE/REJECT and durably
records DEPLOYMENT_APPROVED/REJECTED. A production deploy is never approved merely
because the app is T0/T1 — the assigned policy is authoritative.
