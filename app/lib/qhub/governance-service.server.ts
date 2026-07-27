/**
 * QHUB GovernanceService — SERVER ONLY
 * app/lib/qhub/governance-service.server.ts
 *
 * The single authoritative path for writing governance events to the
 * QHUB evidence ledger (AWS API Gateway → Ingest Lambda → DynamoDB + S3 WORM).
 *
 * TRUST MODEL:
 *   - All authority claims (actor, org, timestamp, gate state) come from
 *     trusted server-side state — never from browser-supplied values.
 *   - HMAC signing happens entirely here using Node.js crypto.
 *   - The HMAC secret is read from server environment at call time.
 *   - This module MUST NOT be imported by any client-side code.
 *     The .server.ts suffix enforces this in Remix (Vite will error if a
 *     client bundle tries to import it).
 *
 * APPLICATION IDENTITY:
 *   Every event is identified by qhub_app_id — a stable Quantex-owned UUID
 *   that is independent of Bolt's chatId, urlId, and conversationId.
 *   qhub_app_id is persisted in Supabase (qhub_applications table).
 *   chain_id is also persisted in Supabase after CHAIN_GENESIS is accepted,
 *   replacing the previous in-memory chainIdCache.
 *
 * LAMBDA v2.6 SCHEMA:
 *   Caller sends exactly 7 fields:
 *     chain_id? (omit for genesis), event_type (from closed enum), app_id,
 *     client_id, actor (object), payload (object), risk_tier
 *   Lambda computes all other fields. Do not send: spec_version, event_id,
 *   seq, prev_event_hash, event_hash, timestamp.
 *   Rule 10: no additional top-level fields permitted.
 *
 * REQUIRED ENV VARS (server-side only):
 *   QHUB_LEDGER_INGEST_URL      Direct execute-api URL (server→server only)
 *   QHUB_API_BASE               Reader API base URL (GET /chains)
 *   QHUB_HMAC_SECRET            HMAC-SHA256 signing key — NEVER commit or log
 *   SUPABASE_URL                Quantex Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY   Service role key (bypasses RLS) — server only
 */

import { createHmac, createHash, randomUUID } from 'node:crypto';
import {
  getOrCreateQhubApp,
  persistChainId,
  getChainId,
  persistClassification,
  getClassification,
  getPersistedRiskTier,
  getProposal,
  markProposalConsumed,
  persistPolicyProfile,
  getPolicyProfile,
  updatePolicyStatus,
} from './qhub-app.server';
import {
  maxTier,
  tierRank,
  type ClassificationResult,
  type ClassificationSignals,
  type RiskTier,
} from './classification';
import { computeRiskFloor } from './classification-rules';
import { buildPolicyProfile, canonicalPolicyString, type PolicyEngineInput } from './policy-engine';
import type { PolicyProfile } from './policy';
import { assertGovernanceSchemaReady, SchemaNotReadyError } from './schema-check.server';
import { SchemaMissingError } from './qhub-app.server';

// ─── Gate state machine ───────────────────────────────────────────────────────

/**
 * Explicit gate states. ONLY 'APPROVED' authorizes production deployment.
 * Never treat UNKNOWN, ERROR, or BLOCKED as APPROVED.
 */
export type GateState = 'APPROVED' | 'BLOCKED' | 'UNKNOWN' | 'ERROR';

// ─── Event intent types (browser-supplied, untrusted) ────────────────────────

/** Intents the browser may request. Does not include any authority claims. */
export type GovernanceIntent =
  | { action: 'PROJECT_CREATED'; conversationId: string; projectTitle: string; builderProjectId?: string }
  | { action: 'AI_MODEL_USED'; conversationId: string; provider: string; model: string; builderProjectId?: string }
  | { action: 'DEPLOYMENT_GATE_CHECK'; conversationId: string; builderProjectId?: string }
  | {
      action: 'CLASSIFICATION_CONFIRMED';
      conversationId: string;
      projectTitle?: string;

      /**
       * Opaque id of a server-persisted classification proposal. The server
       * reloads the authoritative signals from this id — the browser cannot
       * rewrite them. `confirmedTier` is the only classification input the
       * browser supplies, and it can only RAISE the tier above the floor.
       */
      proposalId: string;
      confirmedTier: RiskTier;
      builderProjectId?: string;
    }
  | { action: 'POLICY_ASSIGN'; conversationId: string; builderProjectId?: string }
  | { action: 'POLICY_ACKNOWLEDGE'; conversationId: string; builderProjectId?: string };

/*
 * ─── Lambda v2.6 caller event body ───────────────────────────────────────────
 * These are exactly the 7 fields the caller sends. No more, no less.
 * Lambda computes: spec_version, event_id, seq, prev_event_hash, event_hash, timestamp.
 */

type LambdaEventType =
  | 'CHAIN_GENESIS'
  | 'APP_SUBMITTED'
  | 'AI_MODEL_INVOKED' // v2.6 — AI/LLM model invoked during development
  | 'CLASSIFICATION_ASSIGNED'
  | 'POLICY_PROFILE_ASSIGNED' // Gate 03 — deterministic policy profile bound to the app
  | 'CONTROL_DECISION_RECORDED' // Gate 04 — authoritative enforcement decision for one action
  | 'GOVERNED_ACTION_RECEIPT_RECORDED'
  | 'GATE_PASSED'
  | 'GATE_FAILED'
  | 'ATTESTATION_SIGNED'
  | 'DEPLOYMENT_APPROVED'
  | 'DEPLOYMENT_REJECTED'
  | 'DEPLOYMENT_EXECUTED'
  | 'EXCEPTION_RAISED'
  | 'EXCEPTION_APPROVED'
  | 'EXCEPTION_DENIED'
  | 'AUDIT_EXPORTED';

/** Ledger risk_tier field allows UNCLASSIFIED; the classification RiskTier does not. */
type LedgerRiskTier = 'UNCLASSIFIED' | RiskTier;

interface LambdaEventBody {
  chain_id?: string;
  event_type: LambdaEventType;
  app_id: string; // qhub_app_id (Quantex-owned UUID)
  client_id: string; // orgId (tenant)
  actor: {
    id: string;
    type: 'human' | 'system';
    identity_provider: string;

    // display_name omitted when absent (v2.4 Option A: null ≡ absent)
  };
  payload: Record<string, unknown>;
  risk_tier: LedgerRiskTier;
}

interface LambdaIngestResponse {
  chain_id?: string;
  event_id?: string;
  seq?: number;
  event_hash?: string;
  [key: string]: unknown;
}

// ─── GovernanceService ────────────────────────────────────────────────────────

export interface GovernanceContext {
  userId: string;
  orgId: string;
  sessionId: string;
  env: Record<string, string | undefined>;
}

export interface GovernanceResult {
  ok: boolean;
  gateState?: GateState;
  chainId?: string;
  qhubAppId?: string;
  riskTier?: RiskTier;
  riskFloor?: RiskTier;

  /** Present for POLICY_ASSIGN / POLICY_ACKNOWLEDGE — browser-safe, no secrets. */
  policyProfile?: PolicyProfile;
  policyStatus?: string;
  error?: string;
}

export class GovernanceService {
  private ingestUrl: string;
  private apiBase: string;
  private hmacSecret: string;
  private ctx: GovernanceContext;

  constructor(ctx: GovernanceContext) {
    this.ctx = ctx;

    this.ingestUrl =
      ctx.env.QHUB_LEDGER_INGEST_URL ??
      process.env.QHUB_LEDGER_INGEST_URL ??
      ctx.env.QHUB_API_BASE ??
      process.env.QHUB_API_BASE ??
      'https://api.quantex-tech.com';

    this.apiBase = ctx.env.QHUB_API_BASE ?? process.env.QHUB_API_BASE ?? this.ingestUrl;

    // DO NOT log this value.
    this.hmacSecret = ctx.env.QHUB_HMAC_SECRET ?? process.env.QHUB_HMAC_SECRET ?? '';
  }

  async handleIntent(intent: GovernanceIntent): Promise<GovernanceResult> {
    if (!this.hmacSecret) {
      console.warn('[GovernanceService] No HMAC secret configured — governance events skipped');
      return { ok: true, gateState: 'UNKNOWN' };
    }

    switch (intent.action) {
      case 'PROJECT_CREATED':
        return this.recordGenesis(intent);
      case 'AI_MODEL_USED':
        return this.recordAiModelInvoked(intent);
      case 'DEPLOYMENT_GATE_CHECK':
        return this.checkDeploymentGate(intent);
      case 'CLASSIFICATION_CONFIRMED':
        return this.recordClassification(intent);
      case 'POLICY_ASSIGN':
        return this.recordPolicyProfile(intent);
      case 'POLICY_ACKNOWLEDGE':
        return this.acknowledgePolicy(intent);
      default:
        return { ok: false, error: 'Unknown governance intent' };
    }
  }

  /*
   * ── Schema readiness guard ─────────────────────────────────────────────────
   * Returns a fail-closed GovernanceResult when the connected Supabase project
   * is behind the code (missing required tables/columns), or null when the
   * schema is verified ready. Used to gate classification confirm & policy
   * assign so governance never proceeds against an unmigrated database.
   */
  private async guardSchemaReady(): Promise<GovernanceResult | null> {
    try {
      await assertGovernanceSchemaReady(this.ctx.env);
      return null;
    } catch (err) {
      return this.schemaFailClosedResult(err);
    }
  }

  /** Map a schema-drift error to a browser-safe fail-closed result (no secrets). */
  private schemaFailClosedResult(err: unknown): GovernanceResult {
    if (err instanceof SchemaNotReadyError) {
      const missing = err.report.missing.map((m) => `${m.table}.${m.column}`).join(', ');
      console.error(
        `[GovernanceService] BLOCKED — schema not ready (project=${err.report.projectRef ?? 'unknown'}, ` +
          `expected=${err.report.expectedSchemaVersion}, missing=[${missing || 'unverified'}])`,
      );

      return {
        ok: false,
        gateState: 'BLOCKED',
        error:
          'Governance is unavailable: the connected database is behind this deployment. ' +
          'Required schema objects are missing — apply the pending migrations and retry.',
      };
    }

    if (err instanceof SchemaMissingError) {
      console.error(`[GovernanceService] BLOCKED — ${err.message}`);
      return {
        ok: false,
        gateState: 'BLOCKED',
        error:
          'Governance is unavailable: a required database object is missing. Apply the pending migrations and retry.',
      };
    }

    // Unknown failure while checking readiness — fail closed.
    console.error('[GovernanceService] schema readiness check errored:', err);

    return { ok: false, gateState: 'BLOCKED', error: 'Governance is temporarily unavailable (schema check failed).' };
  }

  /*
   * ── CHAIN_GENESIS ──────────────────────────────────────────────────────────
   * Creates permanent QHUB app identity, fires genesis, persists chain_id.
   */

  private async recordGenesis(
    intent: Extract<GovernanceIntent, { action: 'PROJECT_CREATED' }>,
  ): Promise<GovernanceResult> {
    // Step 1: Get or create permanent QHUB app identity
    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: intent.conversationId,
          builderProjectId: intent.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] Failed to get/create app record:', err);

      /*
       * If Supabase is unavailable, we cannot safely fire genesis without
       * a stable qhub_app_id. Return error — do not use a transient ID.
       */
      return { ok: false, error: 'Could not establish QHUB app identity' };
    }

    /*
     * If genesis was already committed for this app, return the existing chain_id.
     * This makes recordGenesis idempotent on replay/retry.
     */
    if (appRecord.chain_id) {
      console.log(`[GovernanceService] Genesis already committed for qhub_app_id=${appRecord.qhub_app_id}`);
      return { ok: true, chainId: appRecord.chain_id, qhubAppId: appRecord.qhub_app_id };
    }

    // Step 2: POST CHAIN_GENESIS to Lambda (no chain_id — Lambda creates UUID)
    const body: LambdaEventBody = {
      // chain_id intentionally omitted — Lambda generates UUID, seq=1
      event_type: 'CHAIN_GENESIS',
      app_id: appRecord.qhub_app_id, // Quantex-owned stable UUID
      client_id: this.ctx.orgId,
      actor: {
        id: this.ctx.userId,
        type: 'human',
        identity_provider: 'supabase',
      },
      payload: {
        project_title: (intent as { projectTitle: string }).projectTitle,
        conversation_id: intent.conversationId,
        builder_project_id: intent.builderProjectId ?? null,
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
      },
      risk_tier: 'UNCLASSIFIED',
    };

    const result = await this.postEvent(body);

    if (!result.ok || !result.data) {
      return { ok: false, error: 'Lambda rejected CHAIN_GENESIS', qhubAppId: appRecord.qhub_app_id };
    }

    const chainId = result.data.chain_id;

    if (!chainId) {
      console.error('[GovernanceService] Lambda response missing chain_id');
      return { ok: false, error: 'Lambda did not return chain_id', qhubAppId: appRecord.qhub_app_id };
    }

    // Step 3: Persist chain_id durably to Supabase
    await persistChainId(appRecord.qhub_app_id, chainId, this.ctx.env);

    console.log(
      `[GovernanceService] CHAIN_GENESIS committed — qhub_app_id=${appRecord.qhub_app_id} chain_id=${chainId} seq=1`,
    );

    return { ok: true, chainId, qhubAppId: appRecord.qhub_app_id };
  }

  /*
   * ── CLASSIFICATION_ASSIGNED (Gate 02) ──────────────────────────────────────
   * Emits the classification onto the app chain. The deterministic floor is
   * ALWAYS re-computed server-side from the signals — the confirmed tier can
   * raise it but never lower it below the floor (downgrade blocked, spec §8).
   * Genesis is guaranteed first: CLASSIFY is lifecycle stage 01, so it also
   * opens the chain if the build hasn't already.
   */

  private async recordClassification(
    intent: Extract<GovernanceIntent, { action: 'CLASSIFICATION_CONFIRMED' }>,
  ): Promise<GovernanceResult> {
    /*
     * Fail closed if the connected project is behind the code. Confirming a
     * classification against an unmigrated database silently degraded the
     * governance record during Gate 03 live closure — never again.
     */
    const schemaGuard = await this.guardSchemaReady();

    if (schemaGuard) {
      return schemaGuard;
    }

    /*
     * Gate 03 Phase 0: authoritative signals come from the server-persisted
     * proposal, never from the browser. Confirming without a valid, live,
     * single-use proposal fails closed.
     */
    if (!intent.proposalId) {
      return { ok: false, error: 'Missing classification proposal reference' };
    }

    const proposal = await getProposal(intent.proposalId, this.ctx.env);

    if (!proposal) {
      return { ok: false, error: 'Classification proposal not found or expired' };
    }

    if (proposal.org_id !== this.ctx.orgId) {
      // Proposal belongs to another tenant — refuse.
      console.error('[GovernanceService] classification: proposal org mismatch');
      return { ok: false, error: 'Classification proposal not valid for this tenant' };
    }

    if (proposal.status !== 'PENDING') {
      return { ok: false, error: 'Classification proposal already consumed' };
    }

    if (new Date(proposal.expires_at).getTime() < Date.now()) {
      return { ok: false, error: 'Classification proposal expired — please re-run classification' };
    }

    const provisional = proposal.provisional; // authoritative ClassificationResult

    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: intent.conversationId,
          builderProjectId: intent.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] classification: app lookup failed:', err);
      return { ok: false, error: 'Could not establish QHUB app identity' };
    }

    // Ensure the chain exists (genesis is seq=1; classification attaches after).
    let chainId = appRecord.chain_id ?? (await getChainId(intent.conversationId, this.ctx.orgId, this.ctx.env));

    if (!chainId) {
      const genesis = await this.recordGenesis({
        action: 'PROJECT_CREATED',
        conversationId: intent.conversationId,
        projectTitle: intent.projectTitle ?? 'Untitled project',
        builderProjectId: intent.builderProjectId,
      });

      if (!genesis.ok || !genesis.chainId) {
        return { ok: false, error: 'Genesis failed before classification' };
      }

      chainId = genesis.chainId;
    }

    /*
     * Re-derive the deterministic floor from the AUTHORITATIVE proposal signals.
     * Never trust a browser-supplied floor or signals. Final tier can only be >= floor.
     */
    const signals: ClassificationSignals = {
      data_classes: provisional.data_classes,
      integration_types: provisional.integration_types,
      ai_behavior: provisional.ai_behavior,
      autonomy_level: provisional.autonomy_level,
      deployment_surface: provisional.deployment_surface,
      regulatory_domains: provisional.regulatory_domains,
    };
    const { floor } = computeRiskFloor(signals);
    const confirmedTier = intent.confirmedTier ?? provisional.risk_tier;
    const downgradeBlocked = tierRank(confirmedTier) < tierRank(floor);
    const finalTier = maxTier(floor, confirmedTier); // >= floor, always

    // Versioning: a correction/reclassification is a new immutable version.
    const existing = await getClassification(appRecord.qhub_app_id, this.ctx.env);
    const version = (existing?.classification_version ?? 0) + 1;

    const method: ClassificationResult['classification_method'] =
      finalTier === provisional.ai_proposed_tier ? 'HUMAN_CONFIRMED' : 'HUMAN_CORRECTED';

    const finalClassification: ClassificationResult = {
      ...provisional,
      classification_version: version,
      risk_tier: finalTier,
      risk_floor: floor,
      classification_method: method,
      confirmed_by: this.ctx.userId, // server-authoritative
      confirmed_at: new Date().toISOString(),
    };

    const body: LambdaEventBody = {
      chain_id: chainId,
      event_type: 'CLASSIFICATION_ASSIGNED',
      app_id: appRecord.qhub_app_id,
      client_id: this.ctx.orgId,
      actor: {
        id: this.ctx.userId,
        type: 'human',
        identity_provider: 'supabase',
      },
      payload: {
        classification_version: version,
        risk_tier: finalTier,
        risk_floor: floor,
        ai_proposed_tier: provisional.ai_proposed_tier,
        classification_method: method,
        regulatory_domains: finalClassification.regulatory_domains,
        data_classes: finalClassification.data_classes,
        integration_types: finalClassification.integration_types,
        ai_behavior: finalClassification.ai_behavior,
        autonomy_level: finalClassification.autonomy_level,
        deployment_surface: finalClassification.deployment_surface,
        rationale: finalClassification.rationale,
        floor_reasons: finalClassification.floor_reasons,
        confidence: finalClassification.confidence,
        confirmed_by: this.ctx.userId,
        confirmed_at: finalClassification.confirmed_at,
        classifier_version: finalClassification.classifier_version,
        downgrade_below_floor_blocked: downgradeBlocked,
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
      },
      risk_tier: finalTier,
    };

    const result = await this.postEvent(body);

    if (!result.ok) {
      return { ok: false, error: 'Lambda rejected CLASSIFICATION_ASSIGNED', qhubAppId: appRecord.qhub_app_id };
    }

    try {
      await persistClassification(appRecord.qhub_app_id, finalClassification, this.ctx.env);
    } catch (err) {
      /*
       * The ledger event committed, but the snapshot write failed closed
       * (e.g. schema drift racing the readiness cache). Surface it, don't mask it.
       */
      return this.schemaFailClosedResult(err);
    }

    await markProposalConsumed(intent.proposalId, this.ctx.env); // single-use

    console.log(
      `[GovernanceService] CLASSIFICATION_ASSIGNED committed — qhub_app_id=${appRecord.qhub_app_id} risk_tier=${finalTier} floor=${floor} v=${version}${downgradeBlocked ? ' (below-floor downgrade blocked)' : ''}`,
    );

    return { ok: true, qhubAppId: appRecord.qhub_app_id, riskTier: finalTier, riskFloor: floor };
  }

  /*
   * ── POLICY_PROFILE_ASSIGNED (Gate 03) ──────────────────────────────────────
   * Given the CONFIRMED classification (loaded server-side — never from the
   * browser), the deterministic engine produces the policy profile from the
   * versioned catalog. The full profile is persisted as the operational
   * snapshot; a COMPACT event (ids/hash/counts, not the whole document) is
   * written to the immutable chain.
   */

  private async recordPolicyProfile(
    intent: Extract<GovernanceIntent, { action: 'POLICY_ASSIGN' }>,
  ): Promise<GovernanceResult> {
    // Fail closed if the connected project is behind the code (missing policy_* / classification columns).
    const schemaGuard = await this.guardSchemaReady();

    if (schemaGuard) {
      return schemaGuard;
    }

    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: intent.conversationId,
          builderProjectId: intent.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] policy: app lookup failed:', err);
      return { ok: false, error: 'Could not establish QHUB app identity' };
    }

    // Policy REQUIRES a confirmed classification. Load it server-side.
    const classification = await getClassification(appRecord.qhub_app_id, this.ctx.env);

    if (!classification || classification.risk_tier == null) {
      return { ok: false, error: 'Classification required before policy assignment (Gate 02 not complete).' };
    }

    const chainId = appRecord.chain_id ?? (await getChainId(intent.conversationId, this.ctx.orgId, this.ctx.env));

    if (!chainId) {
      return { ok: false, error: 'No governance chain — classification must be committed first.' };
    }

    // Idempotency: if a profile is already bound to this classification version, return it.
    const existingProfile = await getPolicyProfile(appRecord.qhub_app_id, this.ctx.env);

    if (
      existingProfile &&
      existingProfile.classification_version === classification.classification_version &&
      existingProfile.policy_catalog_version // sanity
    ) {
      return {
        ok: true,
        qhubAppId: appRecord.qhub_app_id,
        policyProfile: existingProfile,
        policyStatus: existingProfile.status,
        riskTier: classification.risk_tier,
      };
    }

    // Determine the next profile version (a reclassification supersedes prior policy).
    const nextVersion = (existingProfile?.policy_profile_version ?? 0) + 1;

    const engineInput: PolicyEngineInput = {
      qhub_app_id: appRecord.qhub_app_id,
      classification_version: classification.classification_version,
      classification_reference: chainId,
      risk_tier: classification.risk_tier,
      regulatory_domains: classification.regulatory_domains,
      signals: {
        data_classes: classification.data_classes,
        integration_types: classification.integration_types,
        ai_behavior: classification.ai_behavior,
        autonomy_level: classification.autonomy_level,
        deployment_surface: classification.deployment_surface,
        regulatory_domains: classification.regulatory_domains,
      },
      policy_profile_version: nextVersion,
      generated_by: this.ctx.userId,
    };

    const profile = buildPolicyProfile(engineInput);

    // Server-only stamping: id, hash, timestamp, status.
    profile.policy_profile_id = randomUUID();
    profile.generated_at = new Date().toISOString();
    profile.policy_profile_hash = createHash('sha256').update(canonicalPolicyString(profile)).digest('hex');
    profile.status = 'ASSIGNED';

    // COMPACT ledger payload — ids, hash, counts, and mandatory summary only.
    const body: LambdaEventBody = {
      chain_id: chainId,
      event_type: 'POLICY_PROFILE_ASSIGNED',
      app_id: appRecord.qhub_app_id,
      client_id: this.ctx.orgId,
      actor: { id: this.ctx.userId, type: 'human', identity_provider: 'supabase' },
      payload: {
        policy_profile_id: profile.policy_profile_id,
        policy_profile_version: profile.policy_profile_version,
        policy_catalog_version: profile.policy_catalog_version,
        policy_profile_hash: profile.policy_profile_hash,
        classification_version: profile.classification_version,
        risk_tier: profile.risk_tier,
        regulatory_domains: profile.regulatory_domains,
        required_control_ids: profile.required_controls.map((c) => c.control_id),
        conditional_control_count: profile.conditional_controls.length,
        advisory_control_count: profile.advisory_controls.length,
        required_attestations: profile.required_attestations,
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
      },
      risk_tier: profile.risk_tier,
    };

    const result = await this.postEvent(body);

    if (!result.ok) {
      return { ok: false, error: 'Lambda rejected POLICY_PROFILE_ASSIGNED', qhubAppId: appRecord.qhub_app_id };
    }

    await persistPolicyProfile(appRecord.qhub_app_id, profile, this.ctx.env);

    console.log(
      `[GovernanceService] POLICY_PROFILE_ASSIGNED committed — qhub_app_id=${appRecord.qhub_app_id} tier=${profile.risk_tier} v=${profile.policy_profile_version} required=${profile.required_controls.length} hash=${profile.policy_profile_hash.slice(0, 12)}…`,
    );

    return {
      ok: true,
      qhubAppId: appRecord.qhub_app_id,
      policyProfile: profile,
      policyStatus: profile.status,
      riskTier: profile.risk_tier,
    };
  }

  /*
   * ── POLICY ACKNOWLEDGE ─────────────────────────────────────────────────────
   * The builder acknowledges the assigned controls. This flips the operational
   * status ASSIGNED → ACKNOWLEDGED, which the build gate requires before code
   * generation. No new chain event type is minted (the assignment is already
   * on-chain); acknowledgement is an operational state transition.
   */

  private async acknowledgePolicy(
    intent: Extract<GovernanceIntent, { action: 'POLICY_ACKNOWLEDGE' }>,
  ): Promise<GovernanceResult> {
    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: intent.conversationId,
          builderProjectId: intent.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] policy ack: app lookup failed:', err);
      return { ok: false, error: 'Could not establish QHUB app identity' };
    }

    const profile = await getPolicyProfile(appRecord.qhub_app_id, this.ctx.env);

    if (!profile) {
      return { ok: false, error: 'No policy profile to acknowledge.' };
    }

    if (profile.status === 'ACKNOWLEDGED') {
      return { ok: true, qhubAppId: appRecord.qhub_app_id, policyProfile: profile, policyStatus: 'ACKNOWLEDGED' };
    }

    await updatePolicyStatus(appRecord.qhub_app_id, 'ACKNOWLEDGED', this.ctx.env);
    profile.status = 'ACKNOWLEDGED';

    console.log(
      `[GovernanceService] policy ACKNOWLEDGED — qhub_app_id=${appRecord.qhub_app_id} v=${profile.policy_profile_version}`,
    );

    return { ok: true, qhubAppId: appRecord.qhub_app_id, policyProfile: profile, policyStatus: 'ACKNOWLEDGED' };
  }

  /*
   * ── AI_MODEL_INVOKED ───────────────────────────────────────────────────────
   * v2.6 canonical event type for AI/LLM invocations during code generation.
   * NOT APP_SUBMITTED. See event-schema-v2.6.md.
   */

  async recordAiModelInvokedDirect(params: {
    conversationId: string;
    builderProjectId?: string;
    provider: string;
    model: string;
    /**
     * Gate 04 enforcement references. When present, this AI invocation is bound
     * to a prior exact ALLOW decision — the action event references that evaluation.
     */
    enforcement?: {
      evaluation_id: string;
      action_request_id: string;
      action_digest: string;
      enforcement_plan_id: string;
      enforcement_plan_version: number;
      enforcement_plan_hash: string;
    };
  }): Promise<GovernanceResult> {
    if (!this.hmacSecret) {
      console.warn('[GovernanceService] No HMAC secret — AI_MODEL_INVOKED skipped');
      return { ok: false, error: 'Ledger signing unavailable' };
    }

    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: params.conversationId,
          builderProjectId: params.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] AI_MODEL_INVOKED: app lookup failed:', err);
      return { ok: false, error: 'App identity lookup failed' };
    }

    // chain_id may be null if genesis hasn't fired yet (e.g. AI call before project save)
    const chainId = appRecord.chain_id ?? (await getChainId(params.conversationId, this.ctx.orgId, this.ctx.env));

    // Gate 02: stamp the REAL persisted tier (UNCLASSIFIED until classification confirmed).
    const riskTier = await getPersistedRiskTier(params.conversationId, this.ctx.orgId, this.ctx.env);

    // Gate 03: reference the assigned policy profile so every AI invocation is
    // provably bound to the controls in force at the time. Null before policy
    // assignment; present (with hash) once POLICY_PROFILE_ASSIGNED has committed.
    const policy = await getPolicyProfile(appRecord.qhub_app_id, this.ctx.env);

    const body: LambdaEventBody = {
      ...(chainId ? { chain_id: chainId } : {}),
      event_type: 'AI_MODEL_INVOKED',
      app_id: appRecord.qhub_app_id,
      client_id: this.ctx.orgId,
      actor: {
        id: this.ctx.userId,
        type: 'human',
        identity_provider: 'supabase',
      },
      payload: {
        provider: params.provider,
        model: params.model,
        conversation_id: params.conversationId,
        builder_project_id: params.builderProjectId ?? null,
        ...(policy
          ? {
              policy_profile_id: policy.policy_profile_id,
              policy_profile_version: policy.policy_profile_version,
              policy_profile_hash: policy.policy_profile_hash,
              policy_catalog_version: policy.policy_catalog_version,
            }
          : {}),
        ...(params.enforcement
          ? {
              evaluation_id: params.enforcement.evaluation_id,
              action_request_id: params.enforcement.action_request_id,
              action_digest: params.enforcement.action_digest,
              enforcement_plan_id: params.enforcement.enforcement_plan_id,
              enforcement_plan_version: params.enforcement.enforcement_plan_version,
              enforcement_plan_hash: params.enforcement.enforcement_plan_hash,
              enforcement_decision: 'ALLOW',
            }
          : {}),
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
      },
      risk_tier: riskTier,
    };

    const result = await this.postEvent(body);

    return { ok: result.ok, qhubAppId: appRecord.qhub_app_id };
  }

  /**
   * Gate 04 — emit the authoritative CONTROL_DECISION_RECORDED event. This is the
   * durable enforcement evidence written BEFORE any protected side effect. A
   * decision=DENY event is itself the affirmative block record. Compact payload:
   * ids/hashes/decision/reason_codes/control-result summary — never raw params.
   */
  async recordControlDecision(params: {
    conversationId: string;
    chainId: string | null;
    riskTier: LedgerRiskTier;
    qhubAppId: string;
    payload: Record<string, unknown>;
  }): Promise<{ ok: boolean }> {
    if (!this.hmacSecret) {
      console.warn('[GovernanceService] No HMAC secret — CONTROL_DECISION_RECORDED skipped');
      return { ok: false };
    }

    const chainId = params.chainId ?? (await getChainId(params.conversationId, this.ctx.orgId, this.ctx.env));

    const body: LambdaEventBody = {
      ...(chainId ? { chain_id: chainId } : {}),
      event_type: 'CONTROL_DECISION_RECORDED',
      app_id: params.qhubAppId,
      client_id: this.ctx.orgId,
      actor: { id: this.ctx.userId, type: 'human', identity_provider: 'supabase' },
      payload: { ...params.payload, session_id: this.ctx.sessionId, source: 'qhub-studio' },
      risk_tier: params.riskTier,
    };

    const result = await this.postEvent(body);

    return { ok: result.ok };
  }

  /**
   * Gate 04 / event catalog v2.10 — durable terminal governed-adapter receipt.
   * The payload is already compact and allowlisted by the server-only adapter;
   * do not append session data or raw action material.
   */
  async recordGovernedActionReceipt(params: {
    conversationId: string;
    chainId: string | null;
    riskTier: LedgerRiskTier;
    qhubAppId: string;
    payload: Record<string, unknown>;
  }): Promise<{ ok: boolean; eventId?: string; eventHash?: string; seq?: number }> {
    if (!this.hmacSecret) {
      console.warn('[GovernanceService] No HMAC secret — GOVERNED_ACTION_RECEIPT_RECORDED skipped');

      return { ok: false };
    }

    const chainId = params.chainId ?? (await getChainId(params.conversationId, this.ctx.orgId, this.ctx.env));

    if (!chainId) {
      return { ok: false };
    }

    const body: LambdaEventBody = {
      chain_id: chainId,
      event_type: 'GOVERNED_ACTION_RECEIPT_RECORDED',
      app_id: params.qhubAppId,
      client_id: this.ctx.orgId,
      actor: { id: this.ctx.userId, type: 'human', identity_provider: 'supabase' },
      payload: params.payload,
      risk_tier: params.riskTier,
    };
    const result = await this.postEvent(body);

    return {
      ok: result.ok,
      eventId: result.data?.event_id,
      eventHash: result.data?.event_hash,
      seq: result.data?.seq,
    };
  }

  /**
   * Gate 05 — emit a release/attestation/deployment event using an EXISTING
   * canonical event type (APP_SUBMITTED, ATTESTATION_SIGNED, DEPLOYMENT_APPROVED,
   * DEPLOYMENT_REJECTED, DEPLOYMENT_EXECUTED). Compact payload only — never raw
   * source, secrets, or signer PII beyond the authenticated id.
   */
  async recordReleaseEvent(params: {
    conversationId: string;
    chainId: string | null;
    eventType:
      | 'APP_SUBMITTED'
      | 'ATTESTATION_SIGNED'
      | 'DEPLOYMENT_APPROVED'
      | 'DEPLOYMENT_REJECTED'
      | 'DEPLOYMENT_EXECUTED';
    riskTier: LedgerRiskTier;
    qhubAppId: string;
    payload: Record<string, unknown>;
  }): Promise<{ ok: boolean }> {
    if (!this.hmacSecret) {
      console.warn(`[GovernanceService] No HMAC secret — ${params.eventType} skipped`);
      return { ok: false };
    }

    const chainId = params.chainId ?? (await getChainId(params.conversationId, this.ctx.orgId, this.ctx.env));

    const body: LambdaEventBody = {
      ...(chainId ? { chain_id: chainId } : {}),
      event_type: params.eventType,
      app_id: params.qhubAppId,
      client_id: this.ctx.orgId,
      actor: { id: this.ctx.userId, type: 'human', identity_provider: 'supabase' },
      payload: { ...params.payload, session_id: this.ctx.sessionId, source: 'qhub-studio' },
      risk_tier: params.riskTier,
    };

    const result = await this.postEvent(body);

    return { ok: result.ok };
  }

  private async recordAiModelInvoked(
    _intent: Extract<GovernanceIntent, { action: 'AI_MODEL_USED' }>,
  ): Promise<GovernanceResult> {
    /*
     * Gate 04: the AI_MODEL_USED browser notification no longer emits AI_MODEL_INVOKED
     * directly — that would bypass enforcement. The real model call is enforced and
     * emitted server-side in stream-text.ts via enforceGovernedAction (which records
     * CONTROL_DECISION_RECORDED first and emits AI_MODEL_INVOKED only on ALLOW). This
     * intent is now a no-op acknowledgement.
     */
    return { ok: true };
  }

  // ── DEPLOYMENT GATE CHECK ──────────────────────────────────────────────────

  private async checkDeploymentGate(
    intent: Extract<GovernanceIntent, { action: 'DEPLOYMENT_GATE_CHECK' }>,
  ): Promise<GovernanceResult> {
    let appRecord;

    try {
      appRecord = await getOrCreateQhubApp(
        {
          orgId: this.ctx.orgId,
          userId: this.ctx.userId,
          conversationId: intent.conversationId,
          builderProjectId: intent.builderProjectId,
        },
        this.ctx.env,
      );
    } catch (err) {
      console.error('[GovernanceService] gate check: app lookup failed:', err);
      return { ok: false, gateState: 'UNKNOWN' };
    }

    const attestationState = await this.queryGateState(appRecord.qhub_app_id);
    const chainId = appRecord.chain_id ?? (await getChainId(intent.conversationId, this.ctx.orgId, this.ctx.env));
    const riskTier = await getPersistedRiskTier(intent.conversationId, this.ctx.orgId, this.ctx.env);

    /*
     * Gate 02 tier consequences (§8 — minimal; the full Policy Engine is Gate 03):
     *   UNCLASSIFIED → blocked (must classify first)
     *   T0/T1        → permitted under baseline controls once classified
     *   T2           → production requires owner attestation
     *   T3           → production requires authorized governance/compliance approval
     */
    let gateState: GateState;
    let reason: string | undefined;

    if (riskTier === 'UNCLASSIFIED') {
      gateState = 'BLOCKED';
      reason = 'Classification required before deployment (Gate 02 CLASSIFY not completed).';
    } else if (riskTier === 'T0' || riskTier === 'T1') {
      gateState = 'APPROVED';
    } else if (riskTier === 'T2') {
      gateState = attestationState === 'APPROVED' ? 'APPROVED' : 'BLOCKED';

      if (gateState !== 'APPROVED') {
        reason = 'T2 Elevated: production deployment requires owner attestation.';
      }
    } else {
      gateState = attestationState === 'APPROVED' ? 'APPROVED' : 'BLOCKED';

      if (gateState !== 'APPROVED') {
        reason =
          'T3 High: production deployment requires authorized governance/compliance/security approval; builds are limited to isolated preview.';
      }
    }

    const eventType: LambdaEventType = gateState === 'APPROVED' ? 'GATE_PASSED' : 'GATE_FAILED';

    const body: LambdaEventBody = {
      ...(chainId ? { chain_id: chainId } : {}),
      event_type: eventType,
      app_id: appRecord.qhub_app_id,
      client_id: this.ctx.orgId,
      actor: {
        id: this.ctx.userId,
        type: 'human',
        identity_provider: 'supabase',
      },
      payload: {
        gate_id: 'studio-deploy-gate',
        gate_name: 'QHUB Studio Deployment Gate',
        gate_state: gateState,
        risk_tier: riskTier,
        attestation_state: attestationState,
        conversation_id: intent.conversationId,
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
        ...(reason ? { reason } : {}),
      },
      risk_tier: riskTier,
    };

    const result = await this.postEvent(body);

    return {
      ok: result.ok,
      gateState,
      qhubAppId: appRecord.qhub_app_id,
      riskTier: riskTier === 'UNCLASSIFIED' ? undefined : riskTier,
    };
  }

  // ── Gate state query ───────────────────────────────────────────────────────

  private async queryGateState(qhubAppId: string): Promise<GateState> {
    try {
      const url = `${this.apiBase}/chains?app_id=${encodeURIComponent(qhubAppId)}&client_id=${encodeURIComponent(this.ctx.orgId)}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: { 'X-QHUB-OrgId': this.ctx.orgId },
        signal: AbortSignal.timeout(8000),
      });

      if (!res.ok) {
        console.error('[GovernanceService] gate query returned', res.status);
        return 'ERROR';
      }

      const data = (await res.json()) as { gate_passed?: boolean; attestation_status?: string };

      if (data.gate_passed === true || data.attestation_status === 'ATTESTED') {
        return 'APPROVED';
      }

      return 'BLOCKED';
    } catch (err) {
      console.error('[GovernanceService] gate query failed:', err);
      return 'UNKNOWN';
    }
  }

  // ── Signing + transport ────────────────────────────────────────────────────

  /**
   * Sign the raw request body with HMAC-SHA256.
   * Lambda verifies: HMAC-SHA256(secret, rawBody) in constant time.
   * DO NOT print this value or the secret.
   */
  private sign(rawBody: string): string {
    return createHmac('sha256', this.hmacSecret).update(rawBody).digest('hex');
  }

  /**
   * POST a v2.6-compliant event to the AWS ingest Lambda.
   * Uses QHUB_LEDGER_INGEST_URL (server-to-server only).
   * Returns { ok, data } — data contains chain_id, event_id, seq, event_hash.
   */
  private async postEvent(body: LambdaEventBody): Promise<{ ok: boolean; data?: LambdaIngestResponse }> {
    const payload = JSON.stringify(body);
    const signature = this.sign(payload);

    try {
      const res = await fetch(`${this.ingestUrl}/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-QHUB-Signature': signature,
        },
        body: payload,
        signal: AbortSignal.timeout(10000),
      });

      if (!res.ok) {
        const text = await res.text();
        console.error(`[GovernanceService] POST /events → ${res.status}: ${text}`);

        return { ok: false };
      }

      const data = (await res.json()) as LambdaIngestResponse;

      return { ok: true, data };
    } catch (err) {
      console.error('[GovernanceService] POST /events network error:', err);
      return { ok: false };
    }
  }
}

export function createGovernanceService(ctx: GovernanceContext): GovernanceService {
  return new GovernanceService(ctx);
}
