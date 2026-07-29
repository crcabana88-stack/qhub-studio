/**
 * QHUB — EVIDENCE AUTHORITY client (SERVER ONLY)
 * app/lib/qhub/evidence-authority.server.ts
 *
 * TRUST BOUNDARY (R4): the general QHub runtime uses the `service_role` credential
 * and CANNOT manufacture durable evidence — it cannot mark evidence COMMITTED,
 * create receipt bindings, or finalize EXECUTED/SIMULATED without an authority-
 * created binding. The SEPARATE evidence authority (Trust Spine) is the ONLY holder
 * of the dedicated `qhub_evidence_writer` credential and the ONLY caller permitted
 * to execute the authority commit RPCs (qhub_commit_evaluation_evidence,
 * qhub_commit_governed_action_receipt).
 *
 * This module is the runtime-side interface to that authority. It authenticates
 * with a DISTINCT credential (`SUPABASE_EVIDENCE_WRITER_KEY`, mapped to
 * qhub_evidence_writer) — never the general `service_role` key. If that credential
 * is absent it FAILS CLOSED (returns false): no COMMITTED transition, no binding,
 * so no terminal finalization can follow.
 *
 * PRODUCTION DEPLOYMENT (later human checkpoint — see the migration header + report):
 * the general Studio/runtime process must NOT be provisioned this credential; only
 * the separate Trust Spine / evidence-writer service receives it.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

/** Resolve the DISTINCT evidence-authority connection (never service_role). */
export function evidenceAuthorityClient(env: Record<string, string | undefined>): SupabaseClient | null {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_EVIDENCE_WRITER_KEY ?? process.env.SUPABASE_EVIDENCE_WRITER_KEY ?? '';

  if (!url || !key) {
    return null; // fail closed — the general runtime must not commit evidence itself
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

/** True when the evidence-authority credential is configured (production readiness). */
export function evidenceAuthorityConfigured(env: Record<string, string | undefined>): boolean {
  return !!(env.SUPABASE_EVIDENCE_WRITER_KEY ?? process.env.SUPABASE_EVIDENCE_WRITER_KEY);
}

/**
 * Authority-only: mark the exact evaluation's evidence COMMITTED. Used by the
 * general Gate 04 evidence flow (replacing a direct service_role update, which the
 * database now rejects). Fails closed when the authority credential is absent.
 */
export async function commitEvaluationEvidence(
  evaluationId: string,
  orgId: string,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = evidenceAuthorityClient(env);

  if (!sb) {
    return false;
  }

  const { error } = await sb.rpc('qhub_commit_evaluation_evidence', {
    p_evaluation_id: evaluationId,
    p_org_id: orgId,
  });

  return !error;
}

/** The receipt + durable ledger commitment the authority binds atomically. */
export interface GovernedActionCommitInput {
  run_id: string;
  org_id: string;
  evaluation_id: string;
  decision: 'EXECUTED' | 'SIMULATED';
  action_type: string;
  action_request_id: string;
  action_digest: string;
  receipt_id: string;
  receipt_type: string;
  receipt_schema_version: string;
  receipt_hash: string;
  evidence_chain_id: string | null;
  evidence_event_id: string;
  evidence_event_hash: string;
  evidence_seq: number | null;
  committed_at: string;
}

/**
 * Authority-only: atomically mark evidence COMMITTED and insert the immutable
 * receipt binding for an agent governed action. Fails closed when the authority
 * credential is absent. Idempotent on exact retry (the database enforces it).
 */
export async function commitGovernedActionReceipt(
  input: GovernedActionCommitInput,
  env: Record<string, string | undefined>,
): Promise<boolean> {
  const sb = evidenceAuthorityClient(env);

  if (!sb) {
    return false;
  }

  const { error } = await sb.rpc('qhub_commit_governed_action_receipt', {
    p_run_id: input.run_id,
    p_org_id: input.org_id,
    p_evaluation_id: input.evaluation_id,
    p_decision: input.decision,
    p_action_type: input.action_type,
    p_action_request_id: input.action_request_id,
    p_action_digest: input.action_digest,
    p_receipt_id: input.receipt_id,
    p_receipt_type: input.receipt_type,
    p_receipt_schema_version: input.receipt_schema_version,
    p_receipt_hash: input.receipt_hash,
    p_evidence_chain_id: input.evidence_chain_id,
    p_evidence_event_id: input.evidence_event_id,
    p_evidence_event_hash: input.evidence_event_hash,
    p_evidence_seq: input.evidence_seq,
    p_committed_at: input.committed_at,
  });

  return !error;
}
