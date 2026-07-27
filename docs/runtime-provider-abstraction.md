# QHUB — Replaceable Runtime Providers & Build Integrity

Generic platform infrastructure that lets QHub host **any** agent reasoning engine
behind one governed boundary, prove that engine obeys the governance contract, and
verify exactly which source built the running image. No specific third-party
runtime is required, default, or endorsed by this document.

## Replaceable runtime providers

A runtime provider implements `AgentRuntimeProvider`
(`app/lib/qhub/agent/runtime/provider.ts`): it only **proposes** governed actions
and receives governed **results**. It is handed a safe `RuntimeManifestView` (no
hashes, no secrets) — never a credential, database client, connector, or execution
path — so it is structurally incapable of bypassing Gate 04.

QHub remains solely authoritative for identity, Agent Manifest, tenant/ownership,
classification, policy profile, enforcement plan, lifecycle, release approval,
signer authority, Gate 04 decisions, tool/model/connector permissions, execution
adapters, receipts, immutable evidence, kill switch, and supervision limits.
Providers are selected **server-side** by the registry
(`provider-registry.server.ts`); an unknown or version-mismatched provider **fails
closed**. The **local deterministic simulation provider is the default and
verified baseline.**

## Provider-neutral conformance suite

`runtime-provider-conformance.ts` is a reusable, dependency-free harness that
simulates the run orchestrator with an in-memory Gate 04 that **counts
executions**, so restart/replay guarantees are provable without a database. It
asserts 30 numbered governance properties against any `providerFactory` — provider
selection and fail-closed behaviour, manifest-only inputs, no credentials, every
model/tool/connector action routed through Gate 04, DENY stops, REQUIRE_APPROVAL
pauses, exact-E2 resume, replay produces no duplicate receipt, restart restores
state, limits and kill switch enforced, Gate 05 binding and manifest-change
invalidation (orchestrator-owned), no auto-retry of consequential actions,
evidence-failure fail-closed, and no chain-of-thought/credentials persisted. The
suite is reusable for any future provider.

### No-replay recovery

`run-reconstruction.ts` guarantees that on start / resume / restart, position is
recovered by **reconstructing state from the authoritative QHub run-step records —
never by re-executing completed nodes**. It verifies steps are contiguous
(missing ⇒ fail closed) and each executed step's `input_hash` matches a faithful
re-derivation (tamper ⇒ fail closed), then resumes only at the next permitted
node so a paused consequential action runs exactly once.

## Build-identity diagnostic & integrity

Non-secret build identity (`QHUB_BUILD_SOURCE_COMMIT`, `QHUB_BUILD_ARTIFACT_HASH`,
`QHUB_BUILD_AT`) is injected at deploy time. These names are declared in
`worker-configuration.d.ts` so `bindings.sh` forwards them to `wrangler pages dev`
as `--binding` flags, making them visible to `context.cloudflare.env`.

Authenticated `/api/system/build-info` reports the identity; unauthenticated
access is 401; `/api/health` stays generic; and when the bindings are absent the
route returns a **safe unavailable** result (nulls, `build_identity_present:false`)
— never an error, never a secret. `compareBuildIdentity` (`build-identity.ts`)
fails the release-integrity check on any mismatch against the on-image
`build/qhub-build-identity.json`, so a running image that does not match its
recorded source/artifact identity is caught.

## Scope

This infrastructure is generic. It introduces no migration and no new canonical
ledger event, and it makes no claim about any particular external runtime being
production-supported or default.
