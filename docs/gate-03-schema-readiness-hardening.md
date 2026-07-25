# QHUB Post-Gate-03 — Schema Readiness Hardening: Architecture

**Status:** Implemented · unit-verified (tsc 0 errors, 116 tests) · fail-closed on schema drift
**Preceded by:** Gate 03 POLICY stage @ `5bdf8d9`

## Why this exists (the missed signal)

During Gate 03 **live closure** the deployed Studio was pointed at a Supabase
project that had **never received the Gate-02 classification migration** — yet
nothing surfaced it. `persistClassification()` caught the Postgres
"column does not exist" error, logged *"run the classification migration"*, and
**continued**. The governance record silently degraded and a project/schema
mismatch went unnoticed.

The fix makes schema drift a **loud, fail-closed** condition at every layer that
could have caught it: the persistence call, the governance path, the running
server, a diagnostic endpoint, and the deploy pipeline. No governance logic or P0
architecture was modified.

## The single source of truth

`app/lib/qhub/schema-contract.ts` (browser-safe, no secrets) declares:

- `EXPECTED_SCHEMA_VERSION` — the pinned version tag the running code expects
  (`2026-07-25.gate03`). Bump on every schema change.
- `REQUIRED_SCHEMA_OBJECTS` — one representative `(table, column)` per migration
  the governance path depends on:
  `qhub_applications.qhub_app_id` (identity),
  `qhub_applications.classification` (Gate 02),
  `qhub_applications.policy_profile` (Gate 03),
  `qhub_classification_proposals.proposal_id` (Gate 03).
- `isSchemaMissingError()` — classifies a driver/REST error as a **missing
  object** (drift) vs a transient/auth failure. Matches PostgREST/Postgres codes
  `PGRST205`, `PGRST204`, `42P01`, `42703` and the message signatures
  (`does not exist`, `could not find`, `schema cache`).
- `projectRefFromUrl()` — extracts the **non-secret** project ref (subdomain)
  from `SUPABASE_URL`, so diagnostics can name *which* project without ever
  touching a key.

## Component inventory & module boundary

| Module | Boundary | Responsibility |
|---|---|---|
| `app/lib/qhub/schema-contract.ts` | browser-safe | Expected schema version, `REQUIRED_SCHEMA_OBJECTS`, `isSchemaMissingError()`, `projectRefFromUrl()`. No secrets, no I/O. |
| `app/lib/qhub/schema-check.server.ts` | server-only | REST probe of each required object (`GET /rest/v1/<table>?select=<col>&limit=1`); cached `getSchemaReadiness()`; `assertGovernanceSchemaReady()` guard + `SchemaNotReadyError`. Reads the service key to authenticate the probe; **never returns/logs it**. |
| `app/lib/qhub/qhub-app.server.ts` | server-only | `persistClassification` / `getClassification` now **fail closed** (throw `SchemaMissingError`) when the `classification` column is absent, instead of logging and continuing. |
| `app/lib/qhub/governance-service.server.ts` | server-only | `recordClassification` and `recordPolicyProfile` call the schema guard first; drift → browser-safe `{ ok:false, gateState:'BLOCKED' }`. |
| `app/routes/api.health.ts` | route (server) | **Public, generic** liveness + readiness: `200 {status:'healthy'}` / `503 {status:'degraded'}`. Leaks **no** schema internals. |
| `app/routes/api.system.schema-check.ts` | route (server) | **Authenticated** non-secret expected-vs-current diagnostic (`401` if unauthenticated; `?force=1` bypasses cache). 200 ready / 503 behind. |
| `scripts/schema-smoke-check.mjs` | build/deploy | Probes the **target** project before deploy; exits non-zero if any object is missing/unverifiable. Wired into `npm run deploy`. Bypass is **staging-only** (`isDeployBypassAuthorized`). |

## Fail-closed layers (defense in depth)

1. **Persistence** — `persistClassification`/`getClassification` throw
   `SchemaMissingError` on a missing column. A missing `classification` column can
   no longer read as "not yet classified" and let policy assignment proceed.
2. **Governance path** — `assertGovernanceSchemaReady()` runs before classification
   confirm and policy assign. Drift returns `gateState: 'BLOCKED'` with a
   builder-readable message — no ledger event is emitted against an unmigrated DB.
3. **Running server (public, generic)** — `GET /api/health` returns **503
   `degraded`** when the connected project is behind the code, so
   orchestrators/smoke checks refuse to treat a drifted deployment as healthy.
   The public body is **generic** (`{status, timestamp}`) — it never leaks project
   ref, host, expected version, or missing-object names. A one-time `console.error`
   still logs the full drift server-side per isolate.
4. **Diagnostic (authenticated)** — `GET /api/system/schema-check` requires an
   authenticated QHUB session (`401` otherwise) and returns the full
   expected-vs-current diff (project ref + host only, never keys). This is the
   operator check that would have caught the Gate 03 mismatch in seconds.
5. **Deploy gate** — `npm run deploy` runs `schema:check` first; a target project
   missing any required object **fails the deploy**. The bypass
   (`QHUB_SKIP_SCHEMA_CHECK=1`) is **staging-only**: it is honored solely with a
   staging marker (`QHUB_DEPLOY_ENV=staging|preview` or a `FLY_APP_NAME` containing
   "staging") and is **always refused in production**
   (`isDeployBypassAuthorized`). It governs only the predeploy convenience skip —
   runtime enforcement (layers 1–3) is independent and never bypassable.

## Trust & secret discipline

Every diagnostic surface is **non-secret**: it reports the project ref (already
public in every API URL) and the Supabase host — never
`SUPABASE_SERVICE_ROLE_KEY`, the anon key, or `QHUB_HMAC_SECRET`. The probe uses
the service key only as a request header and discards it.

## Caching

`getSchemaReadiness()` caches per project ref within the isolate: a **ready**
result for 60s, a **not-ready/erroring** result for 5s (so a freshly-migrated
project recovers quickly). `{ force: true }` bypasses the cache for the diagnostic
route.

## Verification

- `tsc --noEmit` — 0 errors.
- `vitest --run` — 127 passing, including:
  - `app/test/schema-contract.test.ts` — classifier codes, the exact Gate-03
    closure messages, transient-error exclusion, required-object coverage.
  - `app/test/schema-routes.test.ts` — **route-level fail-closed**: `/api/health`
    generic (200/503, no leak), `/api/system/schema-check` authorization
    (401 unauthenticated / 200 authenticated / 503 behind), governance
    classification-confirm & policy-assign **BLOCKED** with no ledger event when
    the schema is behind, and the **staging-only** deploy-bypass matrix.
  - the existing governance/policy suites (Gate 03 regression — unchanged
    behaviour; the schema guard is mocked ready there).
- `scripts/schema-smoke-check.mjs` — verified fail-closed on missing creds and
  unreachable project; the bypass is refused without a staging marker and in
  production, honoured only for an authorized staging context; prints no secrets.
