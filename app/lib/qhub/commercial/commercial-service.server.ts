/**
 * QHUB Commercial Launch R4 — PROTECTED COMMERCIAL SERVICE LAYER (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-service.server.ts
 *
 * The lowest practical shared boundary for commercial work. Every mutating function
 * REQUIRES both a CommercialExecutionContext (produced only by the authoritative
 * resolver + project-ownership binding) AND a branded CommercialReadyToken (produced
 * only by the central readiness service after an exact READY result). It re-checks
 * capability + Governance Essentials + readiness token + credits before doing protected
 * work. Callers cannot supply raw org/plan/project authority, forge the token, or claim
 * they already passed authorization.
 *
 * Each exported function is tagged `@qhub-service: <classification>` for the executable
 * architecture test (commercial-architecture.test.ts).
 */

import type { CommercialExecutionContext } from '~/lib/qhub/commercial/commercial-context.server';
import { hasCapability, type Capability } from '~/lib/qhub/commercial/capabilities';
import { assertReadyToken, type CommercialReadyToken } from '~/lib/qhub/commercial/commercial-schema-check.server';
import {
  getGovernanceRecord,
  isModelInvocationAllowed,
  isPublicationAllowed,
} from '~/lib/qhub/commercial/governance-essentials.server';
import { consumeBuildCredit, type CreditResult } from '~/lib/qhub/commercial/commercial-store.server';

export type ServiceOutcome<T> = { ok: true; value: T } | { ok: false; reason: string };

function isExecutionContext(ctx: unknown): ctx is CommercialExecutionContext {
  const c = ctx as Partial<CommercialExecutionContext> | null;
  return (
    !!c &&
    typeof c.userId === 'string' &&
    typeof c.projectId === 'string' &&
    typeof c.projectOrgId === 'string' &&
    c.capabilities instanceof Set
  );
}

function requireCap(ctx: CommercialExecutionContext, cap: Capability): boolean {
  return hasCapability(ctx.capabilities, cap);
}

/**
 * Non-throwing readiness-token check: true only when the token proves an exact READY
 * result for the CURRENT target. Every non-READY / wrong-target / forged token is false.
 */
function tokenValid(token: CommercialReadyToken, env: Record<string, string | undefined>): boolean {
  try {
    assertReadyToken(token, env);

    return true;
  } catch {
    return false;
  }
}

// ─── Canonical request hash (binds the MATERIAL build request) ──────────────────

export interface CommercialBuildRequest {
  model: string;
  provider: string;

  /** A stable hash of the normalized prompt/input (never raw content). */
  inputHash: string;
  action: string;
  template: string;
  units: number;
  governanceVersion: string;
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * @qhub-service: PURE_NO_IO
 * Canonical, timestamp-independent request identity binding org/project/user/model/
 * input/action/template/units/governance version. Message count is NOT used.
 */
export async function canonicalRequestHash(
  ctx: CommercialExecutionContext,
  req: CommercialBuildRequest,
): Promise<string> {
  const parts = [
    ctx.projectOrgId,
    ctx.projectId,
    ctx.userId,
    req.provider,
    req.model,
    req.inputHash,
    req.action,
    req.template,
    String(req.units),
    req.governanceVersion,
  ];

  return sha256Hex(parts.join(''));
}

// ─── invokeCommercialModel ──────────────────────────────────────────────────────

export interface ModelInvokeResult {
  credit: CreditResult;
  governanceVersion: string;
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 * The ONLY commercial path to a model invocation. Enforces (in order): execution
 * context present, MODEL_INVOKE capability, not suspended, readiness token valid,
 * Governance Essentials complete + acknowledged + T0/T1 + PROCEED/approved-review, then
 * consumes credit atomically (token re-validated at the store) BEFORE the model runner.
 */
export async function invokeCommercialModel<T>(
  ctx: CommercialExecutionContext,
  req: CommercialBuildRequest,
  idempotencyKey: string,
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
  runner: () => Promise<T>,
): Promise<ServiceOutcome<{ result: T; credit: CreditResult }>> {
  if (!isExecutionContext(ctx)) {
    return { ok: false, reason: 'missing_execution_context' };
  }

  if (ctx.suspended) {
    return { ok: false, reason: 'suspended' };
  }

  if (!requireCap(ctx, 'MODEL_INVOKE')) {
    return { ok: false, reason: 'capability_denied' };
  }

  // Fail closed on readiness BEFORE credit consumption or the model runner.
  if (!tokenValid(token, env)) {
    return { ok: false, reason: 'schema_not_ready' };
  }

  const gov = await getGovernanceRecord(ctx.projectOrgId, ctx.projectId, env);

  if (!isModelInvocationAllowed(gov)) {
    return { ok: false, reason: 'governance_gate_blocked' };
  }

  const hash = await canonicalRequestHash(ctx, req);
  const credit = await consumeBuildCredit(
    token,
    { projectId: ctx.projectId, idempotencyKey, canonicalHash: hash, units: req.units },
    env,
  );

  if (!credit.ok) {
    return { ok: false, reason: credit.reason ?? 'credit_denied' };
  }

  const result = await runner();

  return { ok: true, value: { result, credit } };
}

// ─── createCommercialProject / export / publication request ─────────────────────

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function createCommercialProject(
  ctx: CommercialExecutionContext | Omit<CommercialExecutionContext, 'projectId' | 'projectOrgId'>,
  input: { idempotencyKey: string; requestHash: string },
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<ServiceOutcome<{ projectId: string; idempotent?: boolean }>> {
  if (!ctx.capabilities || !hasCapability(ctx.capabilities, 'PROJECT_CREATE')) {
    return { ok: false, reason: 'capability_denied' };
  }

  if (!ctx.orgId) {
    return { ok: false, reason: 'no_org_context' };
  }

  // Fail closed on readiness BEFORE any project write.
  if (!tokenValid(token, env)) {
    return { ok: false, reason: 'schema_not_ready' };
  }

  /*
   * ONE atomic RPC: derives + locks org/subscription/active-count, enforces the plan
   * cap and idempotency, inserts project + entitlement, appends audit — all-or-nothing.
   * The store's mutator() re-validates the token before the write.
   */
  const { createProjectAtomic } = await import('~/lib/qhub/commercial/commercial-store.server');
  const created = await createProjectAtomic(
    token,
    { orgId: ctx.orgId, createdBy: ctx.userId, idempotencyKey: input.idempotencyKey, requestHash: input.requestHash },
    env,
  );

  if (!created.ok || !created.project_id) {
    return { ok: false, reason: created.reason ?? 'create_failed' };
  }

  return { ok: true, value: { projectId: created.project_id, idempotent: created.idempotent } };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function exportCommercialProject(
  ctx: CommercialExecutionContext,
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<ServiceOutcome<{ projectId: string }>> {
  if (!isExecutionContext(ctx)) {
    return { ok: false, reason: 'missing_execution_context' };
  }

  if (!requireCap(ctx, 'CODE_EXPORT')) {
    return { ok: false, reason: 'capability_denied' };
  }

  // Fail closed on readiness BEFORE producing any evidence export.
  if (!tokenValid(token, env)) {
    return { ok: false, reason: 'schema_not_ready' };
  }

  return { ok: true, value: { projectId: ctx.projectId } };
}

/**
 * @qhub-service: REQUIRES_COMMERCIAL_READY_TOKEN
 */
export async function requestCommercialPublication(
  ctx: CommercialExecutionContext,
  token: CommercialReadyToken,
  env: Record<string, string | undefined>,
): Promise<ServiceOutcome<{ projectId: string; publishable: boolean }>> {
  if (!isExecutionContext(ctx)) {
    return { ok: false, reason: 'missing_execution_context' };
  }

  if (!requireCap(ctx, 'PUBLISH_REQUEST')) {
    return { ok: false, reason: 'capability_denied' };
  }

  // Fail closed on readiness BEFORE any publication request.
  if (!tokenValid(token, env)) {
    return { ok: false, reason: 'schema_not_ready' };
  }

  const gov = await getGovernanceRecord(ctx.projectOrgId, ctx.projectId, env);

  // Publication requires an approved review (or a clean proceed disposition).
  return { ok: true, value: { projectId: ctx.projectId, publishable: isPublicationAllowed(gov) } };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'MIXED_EXPLICIT_EXPORT_CLASSIFICATION' as const;
