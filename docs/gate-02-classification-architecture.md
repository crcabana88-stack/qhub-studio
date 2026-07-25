# QHUB Gate 02 — CLASSIFY Stage: Architecture

**Status:** Complete & verified · **Tag:** `GATE-02-CLASSIFICATION-VERIFIED` @ `902ffeb` · **Env:** staging (qhub-studio.fly.dev)

Gate 02 implements the **CLASSIFY** stage of the QHUB compliance lifecycle
(`01 CLASSIFY → 02 POLICY → 03 BUILD → 04 ATTEST`), built on top of the frozen
P0 governance spine. It adds one new ledger event type (`CLASSIFICATION_ASSIGNED`)
and one new decision point (inline classification before generation). No P0
architecture was modified.

- **In scope:** deterministic risk-floor engine, AI classifier, `CLASSIFICATION_ASSIGNED`
  event, current-classification persistence, inline Studio classification UX,
  minimal tier-driven gate consequences.
- **Out of scope (Gate 03):** full Policy Engine, exception/downgrade workflow,
  Governance Console.

## Component inventory & module boundary

| Module | Boundary | Responsibility |
|---|---|---|
| `app/lib/qhub/classification.ts` | browser-safe | Canonical `T0–T3` taxonomy (single source of truth), regulatory-domain tags, signal + result schemas, tier helpers (`tierRank`, `maxTier`). No separate Low/Med/High enum. |
| `app/lib/qhub/classification-rules.ts` | pure/shared | Deterministic **risk-floor** engine — no I/O, no secrets, independently unit-testable. |
| `app/lib/qhub/classifier.server.ts` | server-only | AI classifier (Anthropic structured output) + deterministic keyword fallback; combines with the floor. |
| `app/routes/api.classify.ts` | route (server) | Auth-gated analysis endpoint; returns a **provisional** classification. Writes nothing to the ledger. |
| `app/lib/qhub/governance-service.server.ts` | server-only | `recordClassification()` signs & emits `CLASSIFICATION_ASSIGNED`; stamps the real tier on `AI_MODEL_INVOKED` and the gate. |
| `app/lib/qhub/qhub-app.server.ts` | server-only | `persistClassification` / `getClassification` / `getPersistedRiskTier`. |
| `app/lib/qhub/governance-client.ts` | browser-safe | `requestClassification`, `confirmClassification`. No signing, no AWS. |
| `app/components/chat/ClassificationCard.tsx` | client | Business-readable card; enforces the downgrade block in the UI. |
| `app/components/chat/{Chat.client,BaseChat}.tsx` | client | First-message interception + `classificationSlot` render point. |
| `supabase/migrations/20260725_qhub_classification.sql` | DB | Adds `classification JSONB` to `qhub_applications`. |

## Runtime data flow

```
User submits app description (first message)
  → Chat.client sendMessage() intercepts (authed + not-yet-classified)
     • creates the first user message (stable conversationId)
     • POST /api/classify {description, conversationId}
         → classifier.server: AI structured extract + rules floor
         → returns ClassificationResult (provisional, confirmed_by=null)
     • renders <ClassificationCard>; BUILD IS PAUSED
  → User confirms/raises tier → confirmClassification()
     → POST /api/governance {action: CLASSIFICATION_CONFIRMED, ...}
         → GovernanceService.recordClassification():
             1. getOrCreateQhubApp (server-authoritative org/user)
             2. if no chain → recordGenesis() first  (CLASSIFY opens the chain)
             3. re-derive floor server-side from submitted signals
             4. finalTier = max(floor, confirmedTier)  (never below floor)
             5. sign + POST CLASSIFICATION_ASSIGNED to the AWS ingest Lambda
             6. persistClassification() to qhub_applications
  → Chat.client reload() → BUILD proceeds (api.chat → AI_MODEL_INVOKED @ real tier)
```

**Event ordering on the chain:** `seq1 CHAIN_GENESIS (UNCLASSIFIED)` →
`seq2 CLASSIFICATION_ASSIGNED (tier)` → `seq3+ AI_MODEL_INVOKED (tier)`. Genesis
is intentionally pre-classification; because a chain must exist to attach the
classification, `recordClassification` guarantees genesis first (idempotent).

## Classification model

- **Tiers (persisted, authoritative):** `T0 Minimal`, `T1 Low`, `T2 Elevated`, `T3 High/Consequential`.
- **Signals:** `data_classes[]`, `integration_types[]`, `ai_behavior`, `autonomy_level`,
  `deployment_surface`, `regulatory_domains[]` (an array of applicability **tags** —
  SEC/FINRA/CFTC/NFA/MSRB/BANKING/PRIVACY/CYBERSECURITY/BOOKS_AND_RECORDS/SUPERVISION/
  INTERNAL_POLICY/NONE_IDENTIFIED — never a single field, not legal conclusions).

## Deterministic floor (non-bypassable minimum)

`computeRiskFloor(signals) → {floor, reasons[]}`, evaluated most-consequential-first;
a single high-risk characteristic can set the tier:

- **T3** if: trading/orders · payments/transfers · outbound external comms ·
  `CONSEQUENTIAL_DECISION` · autonomous-in-production · MNPI/credentials.
- **T2** if: client/transaction/financial data · regulated records · supervision or
  books-and-records · external system of record · business-system write · AI financial recommendation.
- **T0** only if public-data-only + no integrations + no AI consequence; else **T1** baseline.

## AI classifier

`classifyApplication(description, env)` calls Anthropic (`claude-sonnet-4-6`) via a
direct Messages API fetch (bypasses the pinned `@ai-sdk/anthropic@0.0.39`) with a
strict JSON schema; every field is validated against the enums. If the AI is
unavailable/invalid, a deterministic keyword fallback extracts signals so
classification is never skipped. **Final tier = `max(ruleFloor, AI_proposed)`.**

## Event & persistence model

`CLASSIFICATION_ASSIGNED` payload: `classification_version, risk_tier, risk_floor,
ai_proposed_tier, classification_method, regulatory_domains[], data_classes[],
integration_types[], ai_behavior, autonomy_level, deployment_surface, rationale,
floor_reasons[], confidence, confirmed_by, confirmed_at, classifier_version,
downgrade_below_floor_blocked`.

- **Authoritative history:** immutable WORM ledger (one S3 object per event, Object-Lock GOVERNANCE).
- **Fast-read snapshot:** `qhub_applications.classification` (JSONB) + `risk_tier`.
  The tier write is split from the JSONB write so tier inheritance works even if the
  JSONB column isn't migrated.
- **Versioning:** any correction/reclassification is a new immutable event with
  `classification_version = prev+1`; history is never overwritten.

## Security / trust model

- **Identity is server-only** — `user_id/org_id/app_id/chain_id` come from the
  authenticated Supabase session and the server-owned record, never the browser.
- **Floor is re-derived server-side** in `recordClassification`; a browser-supplied
  floor is ignored. `finalTier = max(floor, confirmedTier)` ⇒ a human cannot lower
  below the floor (blocked; formal exception workflow deferred).
- **HMAC signing** only in `GovernanceService` (Node crypto, secret from server env).
- **Auth gates:** `/api/classify` and `/api/governance` both 401 unauthenticated.

## Tier-driven gate consequences (minimal, §8)

Computed in `checkDeploymentGate` from the persisted tier:
`UNCLASSIFIED → BLOCKED` (must classify first) · `T0/T1 → permitted` (baseline) ·
`T2 → prod requires owner attestation` · `T3 → prod requires authorized
governance/compliance approval, builds preview-only`.

## Verification

- **Unit:** 17 rules tests (reference cases A/B/C, single-high-risk→T3, downgrade
  clamp, floor triggers) + governance suite = 39 passing; `tsc` clean; prod build OK.
- **Live (real Studio UI, `client_id=client-smoke`):** A→T0 (`2b04c35b`),
  B→T2 (`c54a5ee5`), C→T3 (`421d8d4e`); tier inheritance on `AI_MODEL_INVOKED`;
  survives a real Fly machine restart (post-restart T3 event resolved from Supabase).
- **AWS:** 3 events + 3 WORM objects (Object-Lock GOVERNANCE) per chain;
  `qhub-verifier-staging` → 0 failures (13 chains / 25 events).

## Known limitations / follow-ups

- **Signal-tampering:** the floor is re-derived from submitted signals, not from an
  independent server-side re-classification — hardening (server re-run on confirm,
  or a signed provisional token) is a noted follow-up.
- **Exception workflow** (authorized below-floor downgrade) is intentionally unbuilt.
- **Model list:** static `claude-3-5-sonnet-20241022` errors under the pinned AI SDK;
  only `claude-sonnet-4-6` builds — recommend pruning the fallback.
