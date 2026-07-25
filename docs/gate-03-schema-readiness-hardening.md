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
| `app/routes/api.health.ts` | route (server) | Liveness **+** schema readiness. Returns **503** when the project is behind the code. |
| `app/routes/api.system.schema-check.ts` | route (server) | Non-secret **expected-vs-current** diagnostic (`?force=1` bypasses cache). 200 ready / 503 behind. |
| `scripts/schema-smoke-check.mjs` | build/deploy | Probes the **target** project before deploy; exits non-zero if any object is missing/unverifiable. Wired into `npm run deploy`. |

## Fail-closed layers (defense in depth)

1. **Persistence** — `persistClassification`/`getClassification` throw
   `SchemaMissingError` on a missing column. A missing `classification` column can
   no longer read as "not yet classified" and let policy assignment proceed.
2. **Governance path** — `assertGovernanceSchemaReady()` runs before classification
   confirm and policy assign. Drift returns `gateState: 'BLOCKED'` with a
   builder-readable message — no ledger event is emitted against an unmigrated DB.
3. **Running server** — `GET /api/health` returns **503 `degraded`** when the
   connected project is behind the code, so orchestrators/smoke checks refuse to
   treat a drifted deployment as healthy. A one-time `console.error` logs the drift
   (project ref, expected version, missing objects) per isolate.
4. **Diagnostic** — `GET /api/system/schema-check` returns the full
   expected-vs-current diff (project ref + host only). This is the check that would
   have caught the Gate 03 mismatch in seconds.
5. **Deploy gate** — `npm run deploy` runs `schema:check` first; a target project
   missing any required object **fails the deploy**. Escape hatch:
   `QHUB_SKIP_SCHEMA_CHECK=1` (logged, not recommended).

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
- `vitest --run` — 116 passing, including `app/test/schema-contract.test.ts`
  (classifier codes, the exact Gate-03 closure messages, transient-error
  exclusion, required-object coverage) and the existing governance/policy suites
  (unchanged behaviour; the schema guard is mocked ready there — drift is covered
  by the contract test).
- `scripts/schema-smoke-check.mjs` — verified fail-closed on missing creds,
  unreachable project, and honoured the skip override; prints no secrets.
