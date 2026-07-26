# QHUB Gate 04 — Control Enforcement: Architecture

**Status:** In development on branch `gate04-enforcement`
**Base:** `b0aa2cc93275de3cb071b88f2e3024fff15e5c43` (staging-validated)
**Preceded by:** `GATE-03-POLICY-VERIFIED` (policy profiles) + schema-readiness hardening

Gate 04 converts the Gate 03 **policy snapshot** (descriptive metadata) into
**deterministic, fail-closed, independently verifiable runtime enforcement**. It
answers, for one exact operation:

> "May this exact action execute now under the application's current
> classification, policy profile, approvals, limits, and governance state?"

Authoritative decision values (closed enum): **ALLOW · DENY · REQUIRE_APPROVAL**.
A protected side effect never executes without a valid, durable, exact-action
ALLOW decision recorded **before** the side effect.

## Authoritative event model (final)

Exactly **one** new canonical ledger event: **`CONTROL_DECISION_RECORDED`**.

- A `decision=DENY` event is itself the affirmative, authoritative **block record**
  — blocking is never inferred merely from the absence of an action event.
- The corresponding governed-action event (canonical **`AI_MODEL_INVOKED`**, and
  future real side-effect events) gains **enforcement reference fields** and may be
  emitted only after a matching prior `CONTROL_DECISION_RECORDED(ALLOW)`.
- **Superseded and NOT implemented:** the earlier `CONTROL_EVALUATION_REQUESTED`,
  `CONTROL_ENFORCEMENT_APPLIED`, `GOVERNED_ACTION_BLOCKED` proposal is dropped.

`AI_MODEL_INVOKED` is the canonical governed-action event. `AI_MODEL_USED` is only
the existing browser *intent* verb that maps to it server-side — not a ledger event
and not an alias. No new alias is introduced.

Wire envelope/hash `spec_version` stays **2.6** (the canonical hash is version- and
event-type-agnostic; historical chains remain byte-for-byte valid and verifiable).

## Layered architecture

```
Confirmed classification + assigned policy profile   (Gate 02/03, server-authoritative)
        ↓  compile (pure, versioned)
Enforcement plan  (control_rules, approval_requirements, limits, allowlists, restrictions)
        ↓  enforcement_plan_hash = sha256(canonical(plan))
Canonical action request  (server-constructed; server-issued ids/nonce)
        ↓  action_digest = sha256(canonical(request))
Deterministic decision engine  (pure: state + plan + request → decision)
        ↓
ALLOW | DENY | REQUIRE_APPROVAL   (+ reason_codes, control_results, required_attestations)
        ↓  durable, BEFORE any side effect
CONTROL_DECISION_RECORDED (ledger) + qhub_control_evaluations (authoritative record)
        ↓  atomic claim (TOCTOU/replay-safe)
Protected side effect  (only on valid, single-use ALLOW)
        ↓
Governed-action event (AI_MODEL_INVOKED) referencing the exact evaluation
```

Mandatory controls come only from deterministic policy + enforcement rules. The AI
may explain a decision but may never weaken a mandatory control, alter the action
digest, grant approval, override a DENY, authorize execution, or modify the plan.

## File-level implementation plan (all new files unless noted)

Browser-safe (pure, no secrets, unit-testable):
- `app/lib/qhub/enforcement.ts` — types: `GovernedActionType`, `EnforcementPhase`,
  `Decision`, `ReasonCode`, `ControlStatus`, `ControlResult`, `EnforcementPlanEntry`,
  `EnforcementPlan`, `CanonicalActionRequest`, `EnforcementResult`, `EnforcementMode`.
- `app/lib/qhub/enforcement-catalog.ts` — control_id → {phase, adapter, guards[],
  mandatory-from-profile}; protected action types; per-control rule params.
- `app/lib/qhub/enforcement-plan.ts` — pure `compileEnforcementPlan(profile,
  classification)` → `EnforcementPlan` (no hash); `canonicalEnforcementPlanString(plan)`;
  `canonicalActionRequestString(req)`. Deterministic + independently reproducible.
- `app/lib/qhub/enforcement-decision.ts` — pure `evaluate(input)` → `EnforcementResult`
  (decision + reason_codes + control_results + required_attestations). Adapters are
  pure predicates over authoritative inputs (approvals/kill-switch/limits passed IN).

Server-only:
- `app/lib/qhub/enforcement-hash.server.ts` — `computeEnforcementPlanHash`,
  `computeActionDigest` (sha256 of the canonical strings via node:crypto).
- `app/lib/qhub/enforcement-store.server.ts` — persistence + TOCTOU-safe conditional
  writes (plans, evaluations, approvals, kill-switch, idempotency/replay claims).
- `app/lib/qhub/enforcement.server.ts` — the central `enforceGovernedAction(...)`
  entry point (reconstructs all state server-side; emits `CONTROL_DECISION_RECORDED`;
  atomic claim; returns browser-safe result).
- `app/lib/qhub/governance-service.server.ts` (MODIFY) — add `CONTROL_DECISION_RECORDED`
  to `LambdaEventType` + a `recordControlDecision()` emitter; extend `AI_MODEL_INVOKED`
  payload with enforcement references; require a prior exact ALLOW before emitting it.
- `app/routes/api.enforcement.ts` (NEW) — approval grant/revoke + kill-switch toggle
  (server-authoritative, role-gated).
- `app/routes/api.governance.ts` (MODIFY) — route the `AI_MODEL_USED` intent through
  `enforceGovernedAction` first; DENY → no side effect.

Backend + spec:
- `supabase/migrations/20260726_gate04_enforcement.sql` — additive, idempotent:
  `qhub_enforcement_plans`, `qhub_control_evaluations`, `qhub_control_approvals`,
  `qhub_action_claims` (idempotency), `qhub_applications.kill_switch_active`. DB
  unique/constraint invariants for single-use + scope + one-claim-per-evaluation.
- `lambda/ingest/index.mjs` (quantex-qhub) — add `CONTROL_DECISION_RECORDED` to
  `VALID_EVENT_TYPES`. Verifier is event-type-agnostic (no change).
- `qhub-specs/event-schema-v2.9.md` + CHANGELOG — additive `CONTROL_DECISION_RECORDED`.

UX:
- Minimal decision surface (component) — action, decision, plain-English reason,
  controls involved, approval needed, plan/profile version, evidence-recorded status.
  No sensitive params, internal rules, secrets, or raw model reasoning.

## Canonical action request & action digest

The server constructs a `CanonicalActionRequest` and computes `action_digest =
sha256(canonicalActionRequestString(req))`, binding (as applicable): authenticated
tenant (client_id), `qhub_app_id`, `action_request_id` (server nonce), `action_type`,
`target_resource`, `operation`, `material_parameters_hash`, `model/provider/tool`
identity, environment, application/version reference, `policy_profile_id/version/hash`,
`enforcement_plan_hash`. An ALLOW for action A never authorizes a changed action B
(any material change → different digest → no match). No raw secrets/prompts/PII/MNPI
in the request or ledger — only hashes/references.

Server-issued and never trusted from the browser: `evaluation_id` (globally unique,
single-use), `action_request_id`, `action_digest`, `enforcement_plan_hash`.

## REQUIRE_APPROVAL flow (immutable)

E1 `CONTROL_DECISION_RECORDED(REQUIRE_APPROVAL)` → `ATTESTATION_SIGNED` (existing
canonical approval evidence, scope-bound to the exact `action_digest` + policy version)
→ E2 `CONTROL_DECISION_RECORDED(ALLOW|DENY, parent_evaluation_id=E1)`. Only E2=ALLOW
authorizes. A REQUIRE_APPROVAL decision is never mutated into ALLOW. Dual/four-eyes:
the same approver cannot satisfy two distinct required roles; self-approval is barred
where policy requires independent approval. (Full Gate 05 attestation UX is out of scope.)

## TOCTOU / replay (atomic)

One transactional unit (Postgres conditional writes / unique constraints): validate
approval ownership/role/scope/expiry/digest + policy&plan-version match → consume
single-use approvals → **claim** the ALLOW evaluation (unique claim per evaluation) →
authorize at most one side effect. Authorization is invalidated by any change to
action_digest, material params, app version, classification version, policy version/hash,
enforcement-plan version/hash, target resource, model/tool identity, environment,
approval expiry/revocation, or kill-switch state.

## Fail-closed & evidence reliability

If `CONTROL_DECISION_RECORDED` cannot be durably committed **before** execution →
do not execute; return browser-safe BLOCKED; raise a visible governance signal. After
a side effect executes, its action evidence must not vanish silently — if the ingest
write fails it is recorded to a durable local outbox (`qhub_action_claims` carries the
pending-evidence state) and surfaced as a governance incident. Failure semantics
(decision-write / side-effect / action-evidence / retry / idempotency) documented here
and in code.

## Protected surfaces (real, existing)

Primary enforced side effect: **AI model invocation** (`AI_MODEL_INVOKED`). Other
action types (`DEPLOYMENT_EXECUTION`, `EXTERNAL_DATA_TRANSMISSION`, `TRADING_OR_ORDER_ROUTING`)
are defined in the catalog and fully evaluated by the decision engine (so their DENY/
REQUIRE_APPROVAL is authoritative), but are marked **not-operationally-wired** until a
real executing route exists — no invented side-effect adapters.

## Tier consequences (from the plan, not tier alone)

T0 baseline (low-consequence ALLOW automatically) · T1 identity/model/integration
controls · T2 consequential actions may REQUIRE_APPROVAL, owner attestation where
assigned, tightly-scoped writes · T3 preview/simulation by default, production
consequential actions require authorized approval, dual control where required, limits
+ kill-switch enforced, allowlists enforced, unrestricted autonomous action denied.

## Persistence invariants (DB-enforced)

Unique `evaluation_id`; unique `action_request_id`; one successful claim per evaluation;
one consumption per single-use approval; tenant/app ownership (RLS + server checks);
version consistency. Additive idempotent migration; one consolidated human SQL step.
