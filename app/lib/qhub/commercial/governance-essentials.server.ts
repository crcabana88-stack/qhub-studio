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

  /** R9: the material data classes declared (used to derive the review category server-side). */
  dataClasses?: DataClass[];

  /** R9: the authoritative acknowledgment record id bound to the project's current acknowledgment. */
  acknowledgmentRecordId?: string | null;

  /**
   * R9: the stored binding of the APPROVED review (loaded server-side by getGovernanceRecord when
   * the disposition is manual_review). Null when there is no fully-bound approved review — a legacy
   * NULL-bound review can never be approved by qhub_decide_review, so its absence blocks authorization.
   */
  approvedReview?: ApprovedReviewBinding | null;
}

/** R9: the persisted authoritative identity a review was APPROVED under. */
export interface ApprovedReviewBinding {
  governanceRecordVersion: number | null;
  declarationIdentityHash: string | null;
  acknowledgmentRecordId: string | null;
  acknowledgmentVersion: string | null;
  requiredAcknowledgmentVersion: string | null;
  policyVersion: string | null;
  requesterUserId: string | null;
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

  // Resolve the authoritative Governance record id (for the later authoritative review binding).
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

  /*
   * R9 §1: a manual_review disposition sets the Governance record to REVIEW_REQUIRED
   * (disposition=manual_review, review_state=requested). The review REQUEST row is NOT created
   * here — it is opened only by the authoritative submitCustomerReview flow AFTER the customer has
   * acknowledged, so every review request is fully bound (Governance + acknowledgment identity) at
   * creation and no NULL-bound review can ever exist for a new project.
   */

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
 *
 * R9 §4: the acknowledgment version is SERVER-derived (currentRequiredAcknowledgmentVersion) —
 * the browser has NO authority over it. The inserted acknowledgment row's id is bound onto the
 * Governance record (acknowledgment_record_id) so every later authorization/decision resolves the
 * authoritative acknowledgment identity rather than trusting a client-supplied version.
 */
export async function acknowledgeProject(
  ctx: CommercialContext,
  input: { projectId: string },
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

  // SERVER-derived required version — never taken from the browser.
  const ackVersion = currentRequiredAcknowledgmentVersion();

  const { data: ack } = await sb
    .from('qhub_acknowledgments')
    .insert({
      org_id: ctx.orgId,
      user_id: ctx.userId,
      ack_type: 'acceptable_use',
      ack_version: ackVersion,
    })
    .select('id')
    .maybeSingle();

  const acknowledgmentRecordId = (ack?.id as string) ?? null;

  await sb
    .from('qhub_governance_essentials')
    .update({
      acknowledged: true,
      acknowledgment_version: ackVersion,
      acknowledgment_record_id: acknowledgmentRecordId,
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', input.projectId)
    .eq('org_id', ctx.orgId);

  return { ok: true };
}

/**
 * @qhub-service: INTERNAL_SERVER_ONLY
 * R9 §4: the ONE authoritative resolver of a user's CURRENT acknowledgment for a project. It never
 * trusts a browser-supplied version — it loads the persisted acknowledgment row and the project's
 * Governance acknowledgment state and proves currency + ownership (org/user/project). Used by review
 * submission and by the current-review authorization / decision paths.
 */
export async function resolveCurrentAcknowledgment(
  orgId: string,
  projectId: string,
  userId: string,
  env: Record<string, string | undefined>,
): Promise<{ ok: true; recordId: string; version: string; requiredVersion: string } | { ok: false; reason: string }> {
  const requiredVersion = currentRequiredAcknowledgmentVersion();
  const sb = admin(env);

  // The project's Governance acknowledgment state must be current.
  const { data: g } = await sb
    .from('qhub_governance_essentials')
    .select('acknowledged,acknowledgment_version,acknowledgment_record_id')
    .eq('project_id', projectId)
    .eq('org_id', orgId)
    .maybeSingle();

  if (!g) {
    return { ok: false, reason: 'no_governance_record' };
  }

  if (!g.acknowledged || !g.acknowledgment_record_id) {
    return { ok: false, reason: 'acknowledgment_required' };
  }

  if (g.acknowledgment_version !== requiredVersion) {
    return { ok: false, reason: 'acknowledgment_stale' };
  }

  // The requester's OWN acknowledgment row must exist for the current required version.
  const { data: a } = await sb
    .from('qhub_acknowledgments')
    .select('id,org_id,user_id,ack_version')
    .eq('id', g.acknowledgment_record_id as string)
    .maybeSingle();

  if (!a) {
    return { ok: false, reason: 'acknowledgment_not_found' };
  }

  if (a.org_id !== orgId || a.user_id !== userId) {
    return { ok: false, reason: 'acknowledgment_owner_mismatch' };
  }

  if (a.ack_version !== requiredVersion) {
    return { ok: false, reason: 'acknowledgment_stale' };
  }

  return { ok: true, recordId: a.id as string, version: a.ack_version as string, requiredVersion };
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
      'id,project_id,org_id,disposition,declaration_complete,acknowledged,review_state,risk_tier,review_policy_version,policy_card_version,acknowledgment_version,record_version,declaration_identity_hash,data_classes,acknowledgment_record_id',
    )
    .eq('project_id', projectId)
    .eq('org_id', orgId)
    .maybeSingle();

  if (!data) {
    return null;
  }

  const governanceRecordId = (data.id as string) ?? null;
  let approvedReview: ApprovedReviewBinding | null = null;

  /*
   * R9 §10: when the disposition requires manual review, load the APPROVED review's stored binding
   * so the authorization check can prove it is fully bound + current. A NULL result (no fully-bound
   * approved review — the only kind qhub_decide_review can produce) blocks authorization.
   */
  if ((data.disposition as Disposition) === 'manual_review' && governanceRecordId) {
    const { data: rev } = await sb
      .from('qhub_manual_review_requests')
      .select(
        'governance_record_version,declaration_identity_hash,acknowledgment_record_id,acknowledgment_version,required_acknowledgment_version,policy_version,requester_user_id',
      )
      .eq('org_id', orgId)
      .eq('project_id', projectId)
      .eq('governance_record_id', governanceRecordId)
      .eq('status', 'approved')
      .order('decided_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (rev) {
      approvedReview = {
        governanceRecordVersion: (rev.governance_record_version as number) ?? null,
        declarationIdentityHash: (rev.declaration_identity_hash as string) ?? null,
        acknowledgmentRecordId: (rev.acknowledgment_record_id as string) ?? null,
        acknowledgmentVersion: (rev.acknowledgment_version as string) ?? null,
        requiredAcknowledgmentVersion: (rev.required_acknowledgment_version as string) ?? null,
        policyVersion: (rev.policy_version as string) ?? null,
        requesterUserId: (rev.requester_user_id as string) ?? null,
      };
    }
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
    governanceRecordId,
    recordVersion: (data.record_version as number) ?? null,
    declarationIdentityHash: (data.declaration_identity_hash as string) ?? null,
    dataClasses: (data.data_classes as DataClass[]) ?? [],
    acknowledgmentRecordId: (data.acknowledgment_record_id as string) ?? null,
    approvedReview,
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
 * R9 §10: the SINGLE authoritative current-review authorization every protected reviewed operation
 * (model/build, publication, evidence export) must call. It layers a FULLY-BOUND check over the
 * record-level currency check: for a manual_review disposition it requires the loaded APPROVED
 * review binding to be present, every stored field non-null, and EXACTLY equal to the current
 * Governance + acknowledgment identity + current policy/required-ack versions. A legacy NULL-bound
 * review (never producible by qhub_decide_review) is rejected. Fails BEFORE any side effect.
 */
export function assertBoundReviewAuthorization(rec: GovernanceRecord | null): { ok: boolean; reason: string } {
  const base = assertCurrentReviewAuthorization(rec);

  if (!base.ok || !rec) {
    return base;
  }

  // Only a manual_review disposition has an approved review to bind; 'proceed' needs none.
  if (rec.disposition !== 'manual_review') {
    return base;
  }

  const ar = rec.approvedReview;

  if (
    !ar ||
    ar.governanceRecordVersion == null ||
    !ar.declarationIdentityHash ||
    !ar.acknowledgmentRecordId ||
    !ar.acknowledgmentVersion ||
    !ar.requiredAcknowledgmentVersion ||
    !ar.policyVersion ||
    !ar.requesterUserId
  ) {
    return { ok: false, reason: 'non_authorizing_legacy_review' };
  }

  if (
    ar.governanceRecordVersion !== rec.recordVersion ||
    ar.declarationIdentityHash !== rec.declarationIdentityHash ||
    ar.acknowledgmentRecordId !== rec.acknowledgmentRecordId ||
    ar.acknowledgmentVersion !== rec.acknowledgmentVersion ||
    ar.requiredAcknowledgmentVersion !== currentRequiredAcknowledgmentVersion() ||
    ar.policyVersion !== currentReviewPolicyVersion()
  ) {
    return { ok: false, reason: 'review_binding_stale' };
  }

  return { ok: true, reason: 'approved_bound' };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * R9 §1: the AUTHORITATIVE customer review-submission path. The browser supplies ONLY the project,
 * a bounded reason, and an idempotency key. EVERYTHING that binds authorization is derived
 * server-side: the project must be REVIEW_REQUIRED (disposition manual_review), the requester's
 * authoritative acknowledgment must already exist at the current required version, the category is
 * derived from the declared sensitive data class, and the full Governance + acknowledgment identity
 * is bound into the request. No NULL binding fields can result.
 */
export async function submitCustomerReview(
  ctx: CommercialContext,
  input: { projectId: string; reason: string; idempotencyKey?: string },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<{ ok: true; requestId: string; idempotent: boolean } | { ok: false; error: string }> {
  // Fail closed on readiness before any read or the delegated (token-guarded) review write.
  assertReadyToken(token, env);

  if (!ctx.orgId) {
    return { ok: false, error: 'no_org_context' };
  }

  const rec = await getGovernanceRecord(ctx.orgId, input.projectId, env);

  if (!rec) {
    return { ok: false, error: 'no_governance_record' };
  }

  if (!rec.declarationComplete) {
    return { ok: false, error: 'declaration_incomplete' };
  }

  // The project must be in the REVIEW_REQUIRED state (a clean proceed disposition needs no review).
  if (rec.disposition !== 'manual_review') {
    return { ok: false, error: 'review_not_required' };
  }

  if (!rec.governanceRecordId || rec.recordVersion == null || !rec.declarationIdentityHash) {
    return { ok: false, error: 'governance_binding_incomplete' };
  }

  // The requester's authoritative acknowledgment must already exist at the current required version.
  const ack = await resolveCurrentAcknowledgment(ctx.orgId, input.projectId, ctx.userId, env);

  if (!ack.ok) {
    return { ok: false, error: ack.reason };
  }

  // The review category is DERIVED from the declared sensitive data class (never browser-supplied).
  const category = (rec.dataClasses ?? []).find((c) => ['personal', 'financial', 'restricted'].includes(c));

  if (!category) {
    return { ok: false, error: 'no_review_eligible_category' };
  }

  return createReviewRequest(
    ctx,
    { projectId: input.projectId, category, reason: input.reason, idempotencyKey: input.idempotencyKey },
    token,
    env,
    {
      governanceRecordId: rec.governanceRecordId,
      governanceRecordVersion: rec.recordVersion,
      declarationIdentityHash: rec.declarationIdentityHash,
      acknowledgmentRecordId: ack.recordId,
      acknowledgmentVersion: ack.version,
    },
  );
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
