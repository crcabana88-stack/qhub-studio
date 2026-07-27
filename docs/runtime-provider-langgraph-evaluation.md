# QHUB — Runtime-Provider Evaluation: LangGraph Prototype

**Status:** EVALUATION (prototype) · base `6ab2c2b` (`AGENT-FRAMEWORK-FOUNDATION-VERIFIED`).
Not a decision to make LangGraph the default runtime or any part of the QHub
control plane.

## Purpose

Evaluate LangGraph as a **replaceable orchestration provider** behind QHub's
existing `AgentRuntimeProvider` interface — for stateful workflow coordination,
branching, durable pause/resume, human-in-the-loop approval waits, and restart
recovery — **without ceding any governance authority**.

QHub remains solely authoritative for: agent identity, Agent Manifest, tenant /
ownership, classification, policy profile, enforcement plan, lifecycle, release
approval, signer authority, Gate 04 decisions, tool/model/connector permissions,
execution adapters, receipts, immutable evidence, kill switch, and supervision
limits. **LangGraph may coordinate workflow steps; it may never authorize or
directly execute a consequential action.**

## Architecture

The provider contract (`app/lib/qhub/agent/runtime/provider.ts`) is unchanged: a
provider only `PROPOSE`s governed actions and receives governed **results**. It
receives a safe `RuntimeManifestView` (no hashes, no secrets), never a credential,
DB client, or execution path — so it is structurally incapable of bypassing
Gate 04.

- **Graph** (`app/lib/qhub/agent/reference/commission-reconciliation-graph.ts`) —
  a real LangGraph `StateGraph` running only the **pure planning pipeline**:
  `START → VALIDATE_SYNTHETIC_INPUT → COMPARE_RECORDS → ANALYZE_DISCREPANCY →
  PROPOSE_RECONCILIATION → END`. These nodes have no external effect; they emit a
  deterministic `governed_plan` of `ProposedAction`s. The consequential Phase-5
  nodes (`SUBMIT_TO_GATE_04 / EXECUTE_QHUB_ADAPTER / RECORD_RECEIPT`) are **not**
  executed inside the graph — they are surfaced to QHub and driven one node at a
  time through Gate 04.
- **Provider** (`langgraph-runtime-provider.ts`) — derives the plan at `init`
  (one pure graph run) and proposes exactly one planned action per `step_index`.
  Selected server-side by the registry; the LangGraph id is
  `qhub.runtime.langgraph`. The **local simulation provider remains the default.**

### No-replay recovery (mandatory rule)

On start / resume / restart, position is recovered by **reconstructing state from
the authoritative QHub run-step records — never by re-executing completed nodes**.
`run-reconstruction.ts` folds stored steps into ordered governed results and:

- verifies steps are contiguous from 0 (a gap ⇒ `MISSING_PRIOR_STEP`, fail closed);
- verifies each executed step's `input_hash` against the value a faithful,
  deterministic re-derivation of the plan would produce (mismatch ⇒
  `PRIOR_RESULT_TAMPERED`, fail closed);
- resumes only at the next permitted node; the paused consequential action runs
  exactly once (as the distinct Gate 04 E2 evaluation).

Re-running the **pure** planning graph on restart is the sanctioned recomputation
path: it has no external effect, creates no evidence, invokes no model/tool, and
its output is checked against stored evidence.

## Conformance suite

`runtime-provider-conformance.ts` is a provider-neutral harness that simulates the
run orchestrator with an in-memory Gate 04 that **counts executions**, so
restart/replay guarantees are provable without a database. It asserts all 30
governance properties and is reusable for future providers (Google ADK, other
LangGraph versions, internal or customer-approved runtimes). Both the **local**
and **LangGraph** providers pass the identical suite, plus explicit tests that:
restart repeats no model call, Gate 04 submission, approval request, adapter
execution, or receipt; reconstructed state matches stored state; and a tampered or
missing prior result fails closed instead of replaying.

## Dependencies & licenses

| Package | Version | License | Notes |
|---|---|---|---|
| `@langchain/langgraph` | `1.4.8` (exact) | MIT | graph authoring + routing |
| `@langchain/core` (peer) | `1.2.3` (exact) | MIT | node ≥ 20 |

All transitive deps are MIT (`@langchain/langgraph-checkpoint`, `-sdk`,
`@langchain/protocol`, `langsmith`, `js-tiktoken`, `mustache`, `p-queue`,
`p-retry`, `@cfworker/json-schema`, `@standard-schema/spec`). No `zod` bump
(installed `3.25.76` satisfies the peer). The `langchain` umbrella is **not**
added.

**LangSmith / tracing:** `langsmith` is an unavoidable transitive dependency of
`@langchain/core`, but tracing is disabled by default (activates only if
`LANGCHAIN_TRACING_V2` / `LANGSMITH_*` env is set — none are). We never construct
its client. A `no-network` test spies on `fetch`/`http`/`https` and proves zero
network activity across a full governed run; a tracing test asserts no tracing env
is enabled. No LangGraph Cloud, hosted deployment, managed checkpointer, or
external account is used.

## Persistence

QHub's `qhub_agent_runs` / `qhub_agent_run_steps` remain the source of truth.
LangGraph's internal checkpointer is **not** used for cross-request state — its
stateful checkpoint model is impedance-mismatched with QHub's authoritative-run
model, which is precisely why the provider drives one node per request from
durable state. **No migration and no new canonical event are introduced.**

## Local vs LangGraph comparison

| Dimension | Local | LangGraph | Verdict |
|---|---|---|---|
| Business result | reconcile 1 discrepancy | identical | = |
| Manifest / release binding | orchestrator-owned | identical | = |
| Gate 04 decisions | ALLOW / REQUIRE_APPROVAL / DENY | identical | = |
| Approval pause / exact-E2 resume | yes | identical | = |
| Run state / step count | 2 steps | 2 steps | = |
| Receipt count | 1 connector receipt | 1 | = |
| Replay / restart durability | no dup / no replay | identical | = |
| Kill switch | blocks/suspends | identical | = |
| Evidence output | hashes + safe metadata | identical | = |
| Full-run latency (in-proc, 200×) | ~0.08 ms | ~6.9 ms | Local faster; both negligible for HITL |
| Dependency footprint | zero | +LangChain core tree (incl. `langsmith`) | Local lighter |
| Debugging clarity | flat plan | explicit graph topology + node trace | LangGraph clearer for complex flows |
| Operational risk | minimal | workerd bundle + tracing-off discipline | Local lower |

**Decision matrix:** `CONTINUE_PROTOTYPE`. LangGraph cleanly fits behind the
provider interface with full governance parity and adds real value for complex,
branching, multi-node workflows (explicit topology, routing, trace). Its costs —
a larger dependency tree (incl. `langsmith`), workerd bundle/cold-start impact,
and the added latency — do not justify making it the default for the current
single-branch reference workflow. It is **not** adopted as a supported production
provider and is **not** the default; the local deterministic provider remains the
verified baseline.

## Build-info diagnostic fix

Root cause (previously confirmed): `bindings.sh` forwards to `wrangler pages dev`
only the env-var names declared in `worker-configuration.d.ts`. The three
non-secret build-identity names are now declared there, so authenticated
`/api/system/build-info` reports `source_commit` / `artifact_hash` / `built_at`.
Unauthenticated access stays 401; `/api/health` stays generic; absent bindings
return a safe unavailable result; and `compareBuildIdentity` fails the
release-integrity check on any mismatch against `build/qhub-build-identity.json`.

## Explicitly NOT included

MCP, A2A, FIX, real connectors, real order routing, real accounting writes,
production autonomy, Google ADK, LangSmith hosted tracing, billing, marketplace,
and the Node 22 upgrade. No claim of production support for LangGraph is made.
