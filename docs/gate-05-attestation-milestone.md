# QHUB — Gate 05 Exact-Version Attestation — Milestone Record

**Status:** VERIFIED · MERGED · DEPLOYED · TAGGED — 2026-07-27

| Field | Value |
|---|---|
| Studio commit | `19e25ab` (fast-forwarded to `main`) |
| Gate 04 R2 baseline | `bf35f1208d58e881cf2a201a8f143c4589bb5239` (tag `GATE-04-ENFORCEMENT-VERIFIED-R2`) |
| Migration | `supabase/migrations/20260727_gate05_attestation.sql` |
| Migration SHA-256 | `ae90105c6a1bbb50b5d6a2be52e5d8fc1404a28c7c8aeb228967e4f46cd9aace` |
| Fly release | v33 (machine `080d26dad12248`, `qhub-studio.fly.dev`) |
| AWS verifier | 48 chains · 290 events · 0 failed chains |
| Release tag | `GATE-05-ATTESTATION-VERIFIED` → `19e25ab` |
| Supabase project | `jsjsanmaahvmynblmzkq` |

## Scope delivered
Canonical release-candidate manifests + server-computed release hashes; policy+plan-derived
attestation requirements (not tier-derived); server-authoritative signer roles; separation of
duties (distinct governance signers); exact-version `DEPLOYMENT_APPROVED`/`DEPLOYMENT_REJECTED`;
release-assurance receipts; reuse of existing canonical events; **no fabricated
`DEPLOYMENT_EXECUTED`** (0 across all ledger events). 3 additive tables
(`qhub_release_candidates`, `qhub_attestations`, `qhub_deployment_decisions`), 10 validated FKs,
service-only RLS. Zero Gate 04 enforcement files changed.

## Live closure (Fly v33 / project jsjsanmaahvmynblmzkq)
T0/T2/T3 flows passed; hash stability + invalidation; signer authority; cross-tenant rejection;
self-approval/SoD; expired/revoked/superseded fail-closed; APPROVE bound to exact release+env;
receipt hash-verified; 29/29 adversarial live checks; restart durability; DynamoDB + S3 WORM
(GOVERNANCE Object-Lock + KMS) evidence verified; Gate 04 regression clean; no secrets in evidence.

## Non-blocking follow-ups
- Add `qhub_verify_attestation_schema()` for live Gate 05 metadata parity with Gate 04.
- Upgrade staging runtime Node 20 → 22 in a separate controlled task.
- Retain/clean staging test users & records only via a separately authorized staging-data process.
- Keep the unrelated snapshot (untracked `.claude/`, `.pnpm-store/`) excluded.
