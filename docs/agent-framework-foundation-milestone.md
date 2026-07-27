# QHUB — Agent Framework Foundation — Milestone Record

**Status:** VERIFIED · LIVE-CLOSURE PASSED — 2026-07-27. **Not merged, not tagged** (awaiting Carlos approval).

| Field | Value |
|---|---|
| Branch / commit | `agent-framework-foundation` @ `6ab2c2b` |
| Base | `19e25ab` (`GATE-05-ATTESTATION-VERIFIED`); `main` untouched |
| Migration | `supabase/migrations/20260727_agent_framework_foundation.sql` |
| Migration SHA-256 | `e729f8cf2b1b5e3e35120887de7dec63d01c806497076ba08d6b7529d8bf5f9f` |
| Agent schema version | `2026-07-27.agent-foundation` (verifier `qhub_verify_agent_schema()`) |
| Gate 04 verifier | `2026-07-26.gate04` — unchanged |
| Fly release | v43 (machine `080d26dad12248`) |
| Build identity | source_commit `6ab2c2b…`, artifact_hash `3f22857c…`, lockfile_hash `77612648…` (deployed image verified == commit) |
| Supabase project | `jsjsanmaahvmynblmzkq` |
| Tests | 325/325 (tsc 0, lint clean, production build OK) |

## Scope delivered
Server-hashed Agent Manifest; closed operating modes (ASSISTANT / WORKFLOW_AGENT /
SUPERVISED_ACTION_AGENT; BOUNDED_AUTONOMOUS disabled); fail-closed lifecycle;
tenant registry (immutable versions vs mutable state); replaceable runtime-provider
interface + local deterministic simulation provider; run orchestrator routing
**every** action through Gate 04; exact-version Gate 05 binding; fail-closed schema
assurance (verifier + `assertAgentSchemaReady` on every op); deployment-integrity
guard; commission-reconciliation reference agent. No new canonical ledger event.

## Live closure (Fly v43 / project jsjsanmaahvmynblmzkq)
- Full lifecycle DRAFT→SIMULATION→`freeze_release`→attest→**APPROVE**→bind→SUPERVISED.
- Run → REQUIRE_APPROVAL → owner grant → exact-E2 resume → **one SIMULATED
  transmission receipt** (`STAGING_SYNTHETIC_SINK`, `payload_hash` only) → COMPLETED.
- Agent-exact binding: wrong / changed / superseded release all rejected
  (`AGENT_MANIFEST_NOT_IN_RELEASE` / `RELEASE_NOT_APPROVED`).
- Wrong-action approval cannot resume; replay creates no duplicate; kill-switch
  blocks; cross-tenant rejected.
- Restart durability: agent identity + lifecycle + kill-switch, version + manifest
  hash, run + steps + receipt persist; approval `CONSUMED` (non-replayable);
  agent + Gate 04 schemas READY.
- Evidence: `qhub-verifier-staging` OK — 48 chains, 0 failed, 368 events; **0**
  `DEPLOYMENT_EXECUTED`; S3 WORM GOVERNANCE Object-Lock + `aws:kms` + retention;
  no raw params/prompts/secrets/customer data.

## Live-discovered fixes (all committed + deployed)
| Fix | Commit |
|---|---|
| `bind_release` route + approved-release lookup | `e589a99` |
| real conversation_id + app_version_ref threading; `.invalid` sink | `63386b0` |
| `qhub_agent_versions.created_by` persistence + create rollback | `7d7494e` |
| verified-build `npx` invocation | `601263e` |
| run-step explicit update-or-insert (resume) | `1bee397` |
| agent-exact Gate 05 binding + deployment-integrity guard | `82ccc4d` |
| resume distinct E2 idempotency key + re-pause fail-closed | `6ab2c2b` |

## Non-blocking follow-ups
- Prefer building inside the Docker image (or keep `pnpm build:verified` as the
  mandatory predeploy gate) so `build/` can never be stale.
- Node 20 → 22 staging runtime upgrade in a separate controlled task.
- Retain/clean staging test agents + records only via a separately authorized
  staging-data process.
