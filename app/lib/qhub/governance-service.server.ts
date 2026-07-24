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

import { createHmac } from 'node:crypto';
import {
  getOrCreateQhubApp,
  persistChainId,
  getChainId,
} from './qhub-app.server';

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
  | { action: 'DEPLOYMENT_GATE_CHECK'; conversationId: string; builderProjectId?: string };

// ─── Lambda v2.6 caller event body ───────────────────────────────────────────
// These are exactly the 7 fields the caller sends. No more, no less.
// Lambda computes: spec_version, event_id, seq, prev_event_hash, event_hash, timestamp.

type LambdaEventType =
  | 'CHAIN_GENESIS'
  | 'APP_SUBMITTED'
  | 'AI_MODEL_INVOKED'         // v2.6 — AI/LLM model invoked during development
  | 'CLASSIFICATION_ASSIGNED'
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

type RiskTier = 'UNCLASSIFIED' | 'T0' | 'T1' | 'T2' | 'T3';

interface LambdaEventBody {
  chain_id?: string;
  event_type: LambdaEventType;
  app_id: string;        // qhub_app_id (Quantex-owned UUID)
  client_id: string;     // orgId (tenant)
  actor: {
    id: string;
    type: 'human' | 'system';
    identity_provider: string;
    // display_name omitted when absent (v2.4 Option A: null ≡ absent)
  };
  payload: Record<string, unknown>;
  risk_tier: RiskTier;
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

    this.apiBase =
      ctx.env.QHUB_API_BASE ??
      process.env.QHUB_API_BASE ??
      this.ingestUrl;

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
      default:
        return { ok: false, error: 'Unknown governance intent' };
    }
  }

  // ── CHAIN_GENESIS ──────────────────────────────────────────────────────────
  // Creates permanent QHUB app identity, fires genesis, persists chain_id.

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
      // If Supabase is unavailable, we cannot safely fire genesis without
      // a stable qhub_app_id. Return error — do not use a transient ID.
      return { ok: false, error: 'Could not establish QHUB app identity' };
    }

    // If genesis was already committed for this app, return the existing chain_id.
    // This makes recordGenesis idempotent on replay/retry.
    if (appRecord.chain_id) {
      console.log(
        `[GovernanceService] Genesis already committed for qhub_app_id=${appRecord.qhub_app_id}`,
      );
      return { ok: true, chainId: appRecord.chain_id, qhubAppId: appRecord.qhub_app_id };
    }

    // Step 2: POST CHAIN_GENESIS to Lambda (no chain_id — Lambda creates UUID)
    const body: LambdaEventBody = {
      // chain_id intentionally omitted — Lambda generates UUID, seq=1
      event_type: 'CHAIN_GENESIS',
      app_id: appRecord.qhub_app_id,   // Quantex-owned stable UUID
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

  // ── AI_MODEL_INVOKED ───────────────────────────────────────────────────────
  // v2.6 canonical event type for AI/LLM invocations during code generation.
  // NOT APP_SUBMITTED. See event-schema-v2.6.md.

  async recordAiModelInvokedDirect(params: {
    conversationId: string;
    builderProjectId?: string;
    provider: string;
    model: string;
  }): Promise<GovernanceResult> {
    if (!this.hmacSecret) {
      console.warn('[GovernanceService] No HMAC secret — AI_MODEL_INVOKED skipped');
      return { ok: true };
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
    const chainId = appRecord.chain_id ??
      await getChainId(params.conversationId, this.ctx.orgId, this.ctx.env);

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
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
      },
      risk_tier: 'UNCLASSIFIED',
    };

    const result = await this.postEvent(body);
    return { ok: result.ok, qhubAppId: appRecord.qhub_app_id };
  }

  private async recordAiModelInvoked(
    intent: Extract<GovernanceIntent, { action: 'AI_MODEL_USED' }>,
  ): Promise<GovernanceResult> {
    return this.recordAiModelInvokedDirect({
      conversationId: intent.conversationId,
      builderProjectId: intent.builderProjectId,
      provider: intent.provider,
      model: intent.model,
    });
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

    const gateState = await this.queryGateState(appRecord.qhub_app_id);
    const chainId = appRecord.chain_id ??
      await getChainId(intent.conversationId, this.ctx.orgId, this.ctx.env);

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
        conversation_id: intent.conversationId,
        session_id: this.ctx.sessionId,
        source: 'qhub-studio',
        ...(gateState !== 'APPROVED' ? { reason: 'Governance attestation not yet confirmed' } : {}),
      },
      risk_tier: 'UNCLASSIFIED',
    };

    const result = await this.postEvent(body);
    return { ok: result.ok, gateState, qhubAppId: appRecord.qhub_app_id };
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
  private async postEvent(
    body: LambdaEventBody,
  ): Promise<{ ok: boolean; data?: LambdaIngestResponse }> {
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
