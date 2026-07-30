/**
 * QHUB Commercial Launch R2 — GOVERNANCE ESSENTIALS (PERSISTED SERVER WORKFLOW)
 * app/lib/qhub/commercial/governance-essentials.server.ts
 *
 * Turns Governance Essentials from pure helpers into an enforced, persisted server
 * workflow. The SERVER computes the disposition from declared signals — the browser
 * can never downgrade prohibited/manual-review to proceed. Model invocation cannot
 * occur until the declaration + acknowledgment are complete and the disposition is
 * proceed; publication cannot occur until required review is approved. Evidence is
 * exported from the authoritative persisted record (no secrets/prompt content).
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { CommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import type { RiskTier } from '~/lib/qhub/classification';
import { assertReadyToken, type CommercialReadyToken } from '~/lib/qhub/commercial/commercial-schema-check.server';
import {
  buildDeclarationIdentityString,
  currentGovernancePolicyCardVersion,
  currentRequiredAcknowledgmentVersion,
  currentReviewPolicyVersion,
  evaluateGovernanceEssentials,
  type DataClass,
  type Disposition,
} from '~/lib/qhub/commercial/governance-essentials';
import { createReviewRequest } from '~/lib/qhub/commercial/review.server';

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[GovernanceEssentials] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

/** Privileged MUTATION client — re-validates the readiness token before any write. */
function mutator(token: CommercialReadyToken, env: Record<string, string | undefined>): SupabaseClient {
  assertReadyToken(token, env);

  return admin(env);
}

export interface DeclarationInput {
  projectId: string;
  purpose: string;
  useCase: string;
  dataClasses: DataClass[];
  riskTier: RiskTier;
  modelDeclaration: string;
  connectorDeclaration: string[];

  // Prohibited-signal declarations (used for the server disposition).
  handlesSecretsOrCredentials?: boolean;
  involvesMnpi?: boolean;
  involvesRegulatedRecords?: boolean;
  requestsConsequentialAction?: boolean;
  requestsExternalWrite?: boolean;
  requestsAutonomousAgent?: boolean;
}

export interface GovernanceRecord {
  projectId: string;
  orgId: string;
  disposition: Disposition;
  declarationComplete: boolean;
  acknowledged: boolean;
  reviewState: 'none' | 'requested' | 'approved' | 'rejected';
  riskTier: RiskTier;

  /** The SERVER policy version the current approval was decided under (R6 currency check). */
  reviewPolicyVersion: string | null;

  /** The Governance policy-card version the project was evaluated under (R7 currency check). */
  policyCardVersion: string | null;

  /** The acknowledgment version the human accepted (R7 currency check). */
  acknowledgmentVersion: string | null;

  /** R8 §6: the authoritative Governance record id (for review binding). */
  governanceRecordId?: string | null;

  /** R8 §6: the monotonic Governance record version (bumped on material declaration change). */
  recordVersion?: number | null;

  /** R8 §6: the canonical declaration_identity_hash of the current material declaration. */
  declarationIdentityHash?: string | null;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Persist/refresh a project's Governance Essentials declaration. The server
 * recomputes the disposition from the declared signals (a client-provided
 * disposition is never trusted). A manual_review disposition also opens a
 * staff review request.
 */
export async function upsertDeclaration(
  ctx: CommercialContext,
  input: DeclarationInput,
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<GovernanceRecord> {
  if (!ctx.orgId) {
    throw new Error('no_org_context');
  }

  // SERVER-computed disposition — never taken from the browser.
  const evalResult = evaluateGovernanceEssentials({
    dataClasses: input.dataClasses,
    riskTier: input.riskTier,
    handlesSecretsOrCredentials: input.handlesSecretsOrCredentials,
    involvesMnpi: input.involvesMnpi,
    involvesRegulatedRecords: input.involvesRegulatedRecords,
    requestsConsequentialAction: input.requestsConsequentialAction,
    requestsExternalWrite: input.requestsExternalWrite,
    requestsAutonomousAgent: input.requestsAutonomousAgent,
  });

  const declarationComplete =
    !!input.purpose.trim() && !!input.useCase.trim() && input.dataClasses.length > 0 && !!input.modelDeclaration.trim();

  const reviewState = evalResult.disposition === 'manual_review' ? 'requested' : 'none';
  const policyCardVersion = currentGovernancePolicyCardVersion();

  // R8 §6: the canonical identity of THIS material declaration (server-derived).
  const declarationIdentityHash = await sha256Hex(
    buildDeclarationIdentityString({
      orgId: ctx.orgId,
      projectId: input.projectId,
      purpose: input.purpose,
      useCase: input.useCase,
      dataClasses: input.dataClasses,
      riskTier: input.riskTier,
      modelDeclaration: input.modelDeclaration,
      connectorDeclaration: input.connectorDeclaration,
      policyCardVersion,
    }),
  );

  const sb = mutator(token, env);

  /*
   * Read the prior record to compute a MONOTONIC record_version — it bumps whenever the
   * material declaration identity changes (a same-content re-write keeps the version).
   */
  const { data: prior } = await sb
    .from('qhub_governance_essentials')
    .select('id,record_version,declaration_identity_hash')
    .eq('project_id', input.projectId)
    .eq('org_id', ctx.orgId)
    .maybeSingle();

  const priorVersion = (prior?.record_version as number) ?? 0;
  const priorHash = (prior?.declaration_identity_hash as string | undefined) ?? undefined;
  const recordVersion = priorHash === declarationIdentityHash ? priorVersion || 1 : priorVersion + 1;

  await sb.from('qhub_governance_essentials').upsert(
    {
      project_id: input.projectId,
      org_id: ctx.orgId,
      purpose: input.purpose,
      use_case: input.useCase,
      data_classes: input.dataClasses,
      risk_tier: input.riskTier,
      model_declaration: input.modelDeclaration,
      connector_declaration: input.connectorDeclaration,
      disposition: evalResult.disposition,
      declaration_complete: declarationComplete,

      // Bind the CURRENT Governance policy-card version to this declaration (R7 currency).
      policy_card_version: policyCardVersion,

      // R8 §6: persist the monotonic version + canonical declaration identity.
      record_version: recordVersion,
      declaration_identity_hash: declarationIdentityHash,

      // A new declaration invalidates a prior acknowledgment AND any prior review approval.
      acknowledged: false,
      acknowledgment_version: null,
      review_state: reviewState,
      review_policy_version: null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'project_id' },
  );

  // Resolve the authoritative Governance record id for the review binding.
  let governanceRecordId = (prior?.id as string) ?? null;

  if (!governanceRecordId) {
    const { data: fresh } = await sb
      .from('qhub_governance_essentials')
      .select('id')
      .eq('project_id', input.projectId)
      .eq('org_id', ctx.orgId)
      .maybeSingle();
    governanceRecordId = (fresh?.id as string) ?? null;
  }

  // Open a staff review request for sensitive data — BOUND to this Governance identity.
  if (evalResult.disposition === 'manual_review') {
    const sensitive = input.dataClasses.find((c) => ['personal', 'financial', 'restricted'].includes(c));

    if (sensitive) {
      await createReviewRequest(
        ctx,
        { projectId: input.projectId, category: sensitive, reason: 'Sensitive data declared in Governance Essentials' },
        token,
        env,
        { governanceRecordId, governanceRecordVersion: recordVersion, declarationIdentityHash },
      );
    }
  }

  return {
    projectId: input.projectId,
    orgId: ctx.orgId,
    disposition: evalResult.disposition,
    declarationComplete,
    acknowledged: false,
    reviewState,
    riskTier: input.riskTier,

    // A fresh declaration has no decided review yet (any prior approval was invalidated).
    reviewPolicyVersion: null,
    policyCardVersion,
    acknowledgmentVersion: null,
    governanceRecordId,
    recordVersion,
    declarationIdentityHash,
  };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * Record the human acknowledgment for a project. Only valid once declaration-complete.
 */
export async function acknowledgeProject(
  ctx: CommercialContext,
  input: { projectId: string; acknowledgmentVersion: string },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!ctx.orgId) {
    return { ok: false, error: 'no_org_context' };
  }

  const sb = mutator(token, env);
  const { data: rec } = await sb
    .from('qhub_governance_essentials')
    .select('declaration_complete,disposition')
    .eq('project_id', input.projectId)
    .eq('org_id', ctx.orgId)
    .maybeSingle();

  if (!rec) {
    return { ok: false, error: 'not_found' };
  }

  if (!rec.declaration_complete) {
    return { ok: false, error: 'declaration_incomplete' };
  }

  if (rec.disposition === 'prohibited' || rec.disposition === 'blocked') {
    return { ok: false, error: 'not_acknowledgeable' };
  }

  await sb
    .from('qhub_governance_essentials')
    .update({
      acknowledged: true,
      acknowledgment_version: input.acknowledgmentVersion,
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', input.projectId)
    .eq('org_id', ctx.orgId);

  await sb.from('qhub_acknowledgments').insert({
    org_id: ctx.orgId,
    user_id: ctx.userId,
    ack_type: 'acceptable_use',
    ack_version: input.acknowledgmentVersion,
  });

  return { ok: true };
}

/** @qhub-service: INTERNAL_SERVER_ONLY */
export async function getGovernanceRecord(
  orgId: string,
  projectId: string,
  env: Record<string, string | undefined>,
): Promise<GovernanceRecord | null> {
  const sb = admin(env);
  const { data } = await sb
    .from('qhub_governance_essentials')
    .select(
      'id,project_id,org_id,disposition,declaration_complete,acknowledged,review_state,risk_tier,review_policy_version,policy_card_version,acknowledgment_version,record_version,declaration_identity_hash',
    )
    .eq('project_id', projectId)
    .eq('org_id', orgId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  return {
    projectId: data.project_id as string,
    orgId: data.org_id as string,
    disposition: data.disposition as Disposition,
    declarationComplete: !!data.declaration_complete,
    acknowledged: !!data.acknowledged,
    reviewState: (data.review_state as GovernanceRecord['reviewState']) ?? 'none',
    riskTier: (data.risk_tier as RiskTier) ?? 'UNCLASSIFIED',
    reviewPolicyVersion: (data.review_policy_version as string) ?? null,
    policyCardVersion: (data.policy_card_version as string) ?? null,
    acknowledgmentVersion: (data.acknowledgment_version as string) ?? null,
    governanceRecordId: (data.id as string) ?? null,
    recordVersion: (data.record_version as number) ?? null,
    declarationIdentityHash: (data.declaration_identity_hash as string) ?? null,
  };
}

/**
 * @qhub-service: PURE_NO_IO
 * R7: the SINGLE current-authorization check every protected reviewed operation (model/build,
 * publication, evidence export) must call. It requires the FULL current version set to match
 * exactly — a stale policy, Governance policy-card, OR human-acknowledgment version blocks the
 * operation BEFORE any credit/model/publication/export/audit side effect. All versions are
 * server-derived; the browser has no authority over any of them. A clean 'proceed' disposition
 * still requires a current acknowledgment; a 'manual_review' disposition additionally requires
 * an APPROVED review whose policy version is current.
 */
export function assertCurrentReviewAuthorization(rec: GovernanceRecord | null): { ok: boolean; reason: string } {
  if (!rec) {
    return { ok: false, reason: 'no_governance_record' };
  }

  if (!rec.declarationComplete) {
    return { ok: false, reason: 'declaration_incomplete' };
  }

  if (!rec.acknowledged) {
    return { ok: false, reason: 'acknowledgment_required' };
  }

  // The human acknowledgment must be for the CURRENT required version (stale ack → re-ack).
  if (rec.acknowledgmentVersion !== currentRequiredAcknowledgmentVersion()) {
    return { ok: false, reason: 'acknowledgment_stale_version' };
  }

  // The Governance record must be for the CURRENT policy-card (stale Governance → re-declare).
  if (rec.policyCardVersion !== currentGovernancePolicyCardVersion()) {
    return { ok: false, reason: 'governance_stale_version' };
  }

  if (rec.disposition === 'prohibited' || rec.disposition === 'blocked') {
    return { ok: false, reason: 'disposition_blocked' };
  }

  // A clean proceed disposition needs no manual review (ack + Governance currency already met).
  if (rec.disposition === 'proceed') {
    return { ok: true, reason: 'proceed' };
  }

  // manual_review: an APPROVED review is required, AND it must be for the CURRENT policy.
  if (rec.reviewState !== 'approved') {
    return { ok: false, reason: 'review_required' };
  }

  if (rec.reviewPolicyVersion !== currentReviewPolicyVersion()) {
    // Stale approval: the applicable policy changed since the review was decided.
    return { ok: false, reason: 'review_stale_policy' };
  }

  return { ok: true, reason: 'approved_current_policy' };
}

/**
 * @qhub-service: PURE_NO_IO
 * Model invocation requires a complete + acknowledged declaration that may proceed under
 * the CURRENT policy (a stale approval cannot authorize).
 */
export function isModelInvocationAllowed(rec: GovernanceRecord | null): boolean {
  return assertCurrentReviewAuthorization(rec).ok;
}

/**
 * @qhub-service: PURE_NO_IO
 * Publication requires an approved review valid for the CURRENT policy (or a clean proceed
 * disposition).
 */
export function isPublicationAllowed(rec: GovernanceRecord | null): boolean {
  return assertCurrentReviewAuthorization(rec).ok;
}

/**
 * @qhub-service: PURE_NO_IO
 * Evidence export built ONLY from authoritative persisted fields (no secrets). Its
 * readiness-gated wrapper is exportCommercialProject (REQUIRES_COMMERCIAL_READY_TOKEN).
 */
export function buildEvidenceExport(rec: GovernanceRecord): Record<string, unknown> {
  return {
    project_id: rec.projectId,
    org_id: rec.orgId,
    risk_tier: rec.riskTier,
    disposition: rec.disposition,
    declaration_complete: rec.declarationComplete,
    acknowledged: rec.acknowledged,
    review_state: rec.reviewState,
    schema: 'qhub-governance-essentials-1.0.0',
  };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' as const;
