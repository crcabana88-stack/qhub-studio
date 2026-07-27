# QHUB Agent Framework Foundation — Architecture

**Status:** VERIFIED (live closure passed) — branch `agent-framework-foundation`, base `19e25ab` (Gate 05). Not yet merged/tagged.

The Agent Framework Foundation is the minimum durable substrate for **governed
agents** on top of Gates 01–05. A QHUB agent is never an unbounded chatbot: it is
identified, versioned, classified, policy-bound, release-bound, permissioned,
supervised, observable, suspendable, governed by Gate 04, and approved through
Gate 05. Additive over the verified base — **zero changes to Gate 01–05 code**.

## Lifecycle

```
CLASSIFY → POLICY → GOVERNED BUILD → CONTROL ENFORCEMENT → EXACT-VERSION ATTESTATION
        → DEPLOYMENT APPROVAL → [ AGENT: DRAFT → SIMULATION → SUPERVISED → ACTIVE ]
```

Agent lifecycle states (fail-closed, server-controlled): `DRAFT` (manifest not
frozen) → `SIMULATION` (synthetic data + simulation adapters only) → `SUPERVISED`
(human approval + Gate 04) → `ACTIVE` (only where Gate 05 approval + policy
permit). `SUSPENDED` and `RETIRED` are reachable from any state (kill-switch /
owner action). Every transition is guarded by `evaluateTransition`
(`agent-lifecycle.ts`) and applied server-side (`agent-lifecycle.server.ts`).

## Components

| Concern | Module |
|---|---|
| Canonical manifest + hashing (pure) | `agent-manifest.ts` |
| Server-authoritative manifest build | `agent-manifest.server.ts` |
| Lifecycle guards (pure) + service | `agent-lifecycle.ts`, `agent-lifecycle.server.ts` |
| Tenant registry (immutable versions vs mutable state) | `agent-registry.server.ts` |
| Runtime provider interface + local sim + registry | `runtime/provider.ts`, `runtime/local-simulation-provider.ts`, `runtime/provider-registry.server.ts` |
| Run model (pure) + orchestrator | `agent-run.ts`, `agent-run.server.ts` |
| Gate 05 exact-version binding | `agent-release-binding.server.ts` |
| Schema readiness (fail-closed) + verifier | `agent-schema-check.server.ts`, RPC `qhub_verify_agent_schema()` |
| Reference agent (synthetic) | `reference/commission-reconciliation.ts` |
| API + UI | `routes/api.agent.ts`, `routes/agents.tsx`, `components/agent/*` |

## Server-authoritative manifest

The manifest is built and hashed server-side. The browser supplies only
descriptive intent (name, purpose, requested models/tools/limits). QHUB sets
every trusted field (tenant, owner, classification, policy, plan, tier, hashes)
from durable governance state. `canonicalAgentManifestString` excludes
ids/timestamps, so identical material content is a stable hash and any material
change yields a new hash → a new immutable agent version.

## Every action routes through Gate 04

The runtime provider only **proposes** actions and receives **governed results**
— it holds no credentials and no execution path, so it structurally cannot bypass
Gate 04. The run orchestrator routes each proposed model/tool/connector action
through the central `enforceGovernedAction` path:

```
provider.step() → propose → enforceGovernedAction → ALLOW/DENY/REQUIRE_APPROVAL
  → DENY: no execution, run FAILED
  → REQUIRE_APPROVAL: pause (AWAITING_APPROVAL, pending_evaluation_id)
      → owner grants scoped single-use approval (Gate 04 /api/enforcement)
      → resume re-enforces the EXACT action as a distinct E2 (':e2' idempotency
        key + parentEvaluationId) → consumes the approval → adapter executes
      → one SIMULATED receipt → COMPLETED
```

Limits (max actions / model-calls / runtime), kill-switch, replay-safe
idempotency, and fail-closed evidence are enforced in the orchestrator. Evidence
(`qhub_agent_run_steps`) stores hashes/summaries only — never raw parameters,
prompts, chain-of-thought, or secrets. No `DEPLOYMENT_EXECUTED` is fabricated.

## Exact-version Gate 05 binding

An app-level release approval does **not** authorize an agent. The agent's release
is frozen (`freeze_release`) with a dedicated file-manifest entry
`qhub://agent-manifest/<agent_version_id>` whose sha256 **is** the manifest hash,
so the `release_candidate_hash` cryptographically binds the exact manifest (no
Gate 05 semantics change). `bind_release` and `checkReleaseBinding` verify the
approved release's `canonical_file_manifest_hash` equals the server-computed agent
file-manifest hash, else `AGENT_MANIFEST_NOT_IN_RELEASE`. Therefore a wrong
release, a changed manifest, or a superseded release cannot bind, and
SUPERVISED/ACTIVE require a current, exact, APPROVED release.

## Schema readiness (fail-closed)

`assertAgentSchemaReady` gates every agent operation before any create/run/state
change. It probes the four tables via PostgREST **and** calls the service-role
metadata verifier `qhub_verify_agent_schema()` (RLS, policies, validated FKs,
privileges, version `2026-07-27.agent-foundation`). This is separate from Gate
04's `qhub_verify_governance_schema()`, which is unchanged. A predeploy smoke
check (`scripts/schema-smoke-check.mjs`) and authed `/api/system/schema-check`
report readiness; `/api/health` stays generic.

## Deployment integrity

Fly's Dockerfile copies a prebuilt `build/`, so a stale build could ship code that
does not match source. `scripts/build-with-identity.mjs` (`pnpm build:verified`)
refuses a dirty tracked tree, clean-builds, fails if current code markers are
absent (stale build), and records a non-secret build identity (source commit,
artifact hash, lockfile hash) → `build/qhub-build-identity.json`. The deploy
injects `-e QHUB_BUILD_*`; the authed `/api/system/build-info` reports the source
commit and artifact hash; a post-deploy check confirms the running image matches
the intended Git commit.

## Persistence (migration `20260727_agent_framework_foundation.sql`)

Four additive tables — `qhub_agents` (mutable identity + lifecycle),
`qhub_agent_versions` (immutable content), `qhub_agent_runs`, `qhub_agent_run_steps`
— with 13 validated foreign keys (tenant/app, release-candidate, agent/version/run),
CHECK constraints, unique content/idempotency/step indexes, service-only RLS, and
the metadata verifier. No new canonical ledger event is introduced; agent/run
lifecycle is authoritative persistence referenced by existing events.

## Reference agent

Commission Reconciliation (synthetic only): analyze two synthetic datasets →
identify a discrepancy → propose an adjustment → REQUIRE_APPROVAL → owner approval
→ exact E2 resume → the existing staging EXTERNAL_DATA_TRANSMISSION simulation
adapter executes to a `.invalid` synthetic sink (`STAGING_SYNTHETIC_SINK`,
`payload_hash` only) → COMPLETED. No real transmission or accounting write, no
customer data.

## Not in this phase

MCP, A2A, FIX, real order routing, real external connectors, production autonomous
execution, marketplace, and billing are explicitly out of scope.
`BOUNDED_AUTONOMOUS_AGENT` exists as a manifest option only (disabled /
simulation-only).
