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
  evaluateGovernanceEssentials,
  type DataClass,
  type Disposition,
} from '~/lib/qhub/commercial/governance-essentials';
import { createReviewRequest } from '~/lib/qhub/commercial/review.server';

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

  const sb = mutator(token, env);
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

      // A new declaration invalidates a prior acknowledgment.
      acknowledged: false,
      review_state: reviewState,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'project_id' },
  );

  // Open a staff review request for sensitive data.
  if (evalResult.disposition === 'manual_review') {
    const sensitive = input.dataClasses.find((c) => ['personal', 'financial', 'restricted'].includes(c));

    if (sensitive) {
      await createReviewRequest(
        ctx,
        { projectId: input.projectId, category: sensitive, reason: 'Sensitive data declared in Governance Essentials' },
        token,
        env,
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
    .select('project_id,org_id,disposition,declaration_complete,acknowledged,review_state,risk_tier')
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
  };
}

/**
 * @qhub-service: PURE_NO_IO
 * Model invocation requires a complete + acknowledged declaration that may proceed.
 */
export function isModelInvocationAllowed(rec: GovernanceRecord | null): boolean {
  if (!rec) {
    return false;
  }

  const dispositionOk =
    rec.disposition === 'proceed' || (rec.disposition === 'manual_review' && rec.reviewState === 'approved');

  return rec.declarationComplete && rec.acknowledged && dispositionOk;
}

/**
 * @qhub-service: PURE_NO_IO
 * Publication requires an approved review (or a clean proceed disposition).
 */
export function isPublicationAllowed(rec: GovernanceRecord | null): boolean {
  if (!rec) {
    return false;
  }

  if (rec.disposition === 'prohibited' || rec.disposition === 'blocked') {
    return false;
  }

  return rec.reviewState === 'approved' || rec.disposition === 'proceed';
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
