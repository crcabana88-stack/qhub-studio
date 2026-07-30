/**
 * QHUB Gate 05 — Attestation & deployment authorization service — SERVER ONLY
 * app/lib/qhub/attestation.server.ts
 *
 * Three server-authoritative operations:
 *   freezeReleaseCandidate() — snapshot the exact version + compute release hash + APP_SUBMITTED
 *   signAttestation()        — bind an authorized human attestation to the exact release hash
 *   evaluateReleaseForDeployment() — APPROVE/REJECT against required attestations
 *
 * The browser never supplies release hash, signer role/authority, policy/plan
 * references, or decision — all are reconstructed and verified here.
 */

import { createHash, randomUUID } from 'node:crypto';
import { getOrCreateQhubApp, getChainId, getClassification, getPolicyProfile } from './qhub-app.server';
import { canonicalPolicyString } from './policy-engine';
import { canonicalEnforcementPlanString } from './enforcement-plan';
import { getActivePlan } from './enforcement-store.server';
import { assertGovernanceSchemaReady } from './schema-check.server';
import { createGovernanceService } from './governance-service.server';
import * as store from './attestation-store.server';
import {
  canonicalFileManifestString,
  canonicalReleaseCandidateString,
  canonicalStatementString,
  attestationStatementText,
  deriveAttestationRequirements,
} from './release-manifest';
import {
  ATTESTATION_STATEMENT_VERSION,
  RELEASE_MANIFEST_VERSION,
  type Attestation,
  type AttestationPurpose,
  type FileManifestEntry,
  type ReleaseCandidate,
  type ReleaseReasonCode,
  type TargetEnvironment,
} from './release-candidate';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const stable = (v: unknown): string => {
  if (v === null || typeof v !== 'object') {
    return JSON.stringify(v);
  }

  if (Array.isArray(v)) {
    return `[${v.map(stable).join(',')}]`;
  }

  const k = Object.keys(v as Record<string, unknown>).sort();

  return `{${k.map((x) => `${JSON.stringify(x)}:${stable((v as Record<string, unknown>)[x])}`).join(',')}}`;
};

interface Session {
  userId: string;
  orgId: string;
  role: string;
}

// ─── FREEZE ───────────────────────────────────────────────────────────────────

export interface FreezeInput {
  session: Session;
  conversationId: string;
  files: FileManifestEntry[];
  declared_models: string[];
  declared_connectors: string[];
  declared_data_access: string[];
  dependency_lockfile_hash?: string | null;
  source_commit?: string | null;
  target_environment: TargetEnvironment;
  deployment_target: string;
  release_scope: string;
  sessionId: string;
  env: Record<string, string | undefined>;
}

export interface FreezeResult {
  ok: boolean;
  reason?: ReleaseReasonCode;
  release_candidate_id?: string;
  release_candidate_hash?: string;
  qhub_app_version?: number;
  required_attestations?: {
    purpose: AttestationPurpose;
    roles: string[];
    min_signers: number;
    distinct_signers: boolean;
  }[];
  status?: string;
}

export async function freezeReleaseCandidate(input: FreezeInput): Promise<FreezeResult> {
  const { session, conversationId, env } = input;

  try {
    await assertGovernanceSchemaReady(env);
  } catch {
    return { ok: false, reason: 'SCHEMA_NOT_READY' };
  }

  const app = await getOrCreateQhubApp({ orgId: session.orgId, userId: session.userId, conversationId }, env).catch(
    () => null,
  );

  if (!app) {
    return { ok: false, reason: 'RELEASE_NOT_FOUND' };
  }

  if (app.org_id !== session.orgId) {
    return { ok: false, reason: 'TENANT_MISMATCH' };
  }

  const classification = await getClassification(app.qhub_app_id, env);

  if (!classification) {
    return { ok: false, reason: 'CLASSIFICATION_STALE' };
  }

  const profile = await getPolicyProfile(app.qhub_app_id, env);

  if (!profile || sha256(canonicalPolicyString(profile)) !== profile.policy_profile_hash) {
    return { ok: false, reason: 'POLICY_STALE' };
  }

  const stored = await getActivePlan(app.qhub_app_id, session.orgId, env);

  if (!stored || sha256(canonicalEnforcementPlanString(stored.plan)) !== stored.plan.enforcement_plan_hash) {
    return { ok: false, reason: 'PLAN_STALE' };
  }

  const plan = stored.plan;
  const version = (await store.getReleaseCandidateCount(app.qhub_app_id, session.orgId, env)) + 1;

  const partial = {
    qhub_app_id: app.qhub_app_id,
    qhub_app_version: version,
    conversation_id: conversationId,
    source_commit: input.source_commit ?? null,
    canonical_file_manifest_hash: sha256(canonicalFileManifestString(input.files)),
    file_count: input.files.length,
    build_artifact_digest: null,
    dependency_lockfile_hash: input.dependency_lockfile_hash ?? null,
    classification_version: classification.classification_version,
    classification_reference: app.chain_id,
    risk_tier: profile.risk_tier,
    policy_profile_id: profile.policy_profile_id,
    policy_profile_version: profile.policy_profile_version,
    policy_profile_hash: profile.policy_profile_hash,
    enforcement_plan_id: plan.enforcement_plan_id,
    enforcement_plan_version: plan.enforcement_plan_version,
    enforcement_plan_hash: plan.enforcement_plan_hash,
    model_manifest_hash: sha256(stable([...input.declared_models].sort())),
    connector_manifest_hash: sha256(stable([...input.declared_connectors].sort())),
    data_access_manifest_hash: sha256(stable([...input.declared_data_access].sort())),
    target_environment: input.target_environment,
    deployment_target: input.deployment_target,
    release_scope: input.release_scope,
    manifest_version: RELEASE_MANIFEST_VERSION,
  };
  const releaseCandidateHash = sha256(canonicalReleaseCandidateString(partial));

  const rc: ReleaseCandidate = {
    ...partial,
    release_candidate_id: randomUUID(),
    created_by: session.userId,
    created_at: new Date().toISOString(),
    release_candidate_hash: releaseCandidateHash,
    status: 'FROZEN',
    supersedes_release_candidate_id: null,
  };

  const up = await store.upsertReleaseCandidate(rc, session.orgId, env);

  if (!up.ok || !up.rc) {
    return { ok: false, reason: 'RELEASE_NOT_FOUND' };
  }

  const rcId = up.rc.release_candidate_id as string;
  await store.freezeReleaseCandidate(rcId, session.orgId, env);
  await store.supersedeOtherReleases(app.qhub_app_id, session.orgId, rcId, env);

  const requirements = deriveAttestationRequirements(profile, plan);

  // APP_SUBMITTED = the exact release candidate has been frozen and submitted.
  const gov = createGovernanceService({
    userId: session.userId,
    orgId: session.orgId,
    sessionId: input.sessionId,
    env,
  });
  await gov.recordReleaseEvent({
    conversationId,
    chainId: app.chain_id ?? (await getChainId(conversationId, session.orgId, env)),
    eventType: 'APP_SUBMITTED',
    riskTier: profile.risk_tier,
    qhubAppId: app.qhub_app_id,
    payload: {
      release_candidate_id: rcId,
      release_candidate_hash: releaseCandidateHash,
      qhub_app_version: up.rc.qhub_app_version,
      canonical_file_manifest_hash: partial.canonical_file_manifest_hash,
      file_count: partial.file_count,
      policy_profile_hash: profile.policy_profile_hash,
      enforcement_plan_hash: plan.enforcement_plan_hash,
      target_environment: partial.target_environment,
      required_attestation_purposes: requirements.map((r) => r.purpose),
      status: 'FROZEN',
    },
  });

  return {
    ok: true,
    release_candidate_id: rcId,
    release_candidate_hash: releaseCandidateHash,
    qhub_app_version: up.rc.qhub_app_version,
    required_attestations: requirements.map((r) => ({
      purpose: r.purpose,
      roles: r.roles,
      min_signers: r.min_signers,
      distinct_signers: r.distinct_signers,
    })),
    status: 'FROZEN',
  };
}

// ─── SIGN ATTESTATION ─────────────────────────────────────────────────────────

export interface SignInput {
  session: Session;
  conversationId: string;
  release_candidate_id: string;
  attestation_purpose: AttestationPurpose;
  sessionId: string;
  env: Record<string, string | undefined>;
}

export interface SignResult {
  ok: boolean;
  reason?: ReleaseReasonCode | 'DUPLICATE' | 'NOT_FROZEN';
  attestation_id?: string;
}

export async function signAttestation(input: SignInput): Promise<SignResult> {
  const { session, conversationId, env } = input;

  try {
    await assertGovernanceSchemaReady(env);
  } catch {
    return { ok: false, reason: 'SCHEMA_NOT_READY' };
  }

  const rc = await store.getReleaseCandidate(input.release_candidate_id, session.orgId, env);

  if (!rc) {
    return { ok: false, reason: 'RELEASE_NOT_FOUND' };
  }

  if (rc.org_id !== session.orgId) {
    return { ok: false, reason: 'TENANT_MISMATCH' };
  }

  if (!['FROZEN', 'AWAITING_ATTESTATION', 'APPROVED'].includes(rc.status)) {
    return { ok: false, reason: 'NOT_FROZEN' };
  }

  const profile = await getPolicyProfile(rc.qhub_app_id, env);
  const stored = await getActivePlan(rc.qhub_app_id, session.orgId, env);

  if (!profile || !stored) {
    return { ok: false, reason: 'POLICY_STALE' };
  }

  const requirements = deriveAttestationRequirements(profile, stored.plan);
  const req = requirements.find((r) => r.purpose === input.attestation_purpose);

  if (!req) {
    return { ok: false, reason: 'SIGNER_NOT_AUTHORIZED' };
  }

  // Server-authoritative signer authority: the session role must be permitted.
  if (!req.roles.includes(session.role)) {
    return { ok: false, reason: 'SIGNER_NOT_AUTHORIZED' };
  }

  const scope = rc.release_scope as string;
  const statement = attestationStatementText(input.attestation_purpose, rc.target_environment);
  const statementHash = sha256(
    canonicalStatementString({
      version: ATTESTATION_STATEMENT_VERSION,
      purpose: input.attestation_purpose,
      statement,
      release_candidate_hash: rc.release_candidate_hash,
      target_environment: rc.target_environment,
      scope,
    }),
  );

  const att: Attestation = {
    attestation_id: randomUUID(),
    release_candidate_id: rc.release_candidate_id,
    release_candidate_hash: rc.release_candidate_hash,
    qhub_app_id: rc.qhub_app_id,
    qhub_app_version: rc.qhub_app_version,
    signer_user_id: session.userId,
    signer_org_id: session.orgId,
    signer_role: session.role,
    authority_source: 'qhub-session',
    attestation_purpose: input.attestation_purpose,
    attestation_scope: scope,
    target_environment: rc.target_environment,
    policy_profile_id: rc.policy_profile_id,
    policy_profile_version: rc.policy_profile_version,
    policy_profile_hash: rc.policy_profile_hash,
    enforcement_plan_id: rc.enforcement_plan_id,
    enforcement_plan_version: rc.enforcement_plan_version,
    enforcement_plan_hash: rc.enforcement_plan_hash,
    attestation_statement_version: ATTESTATION_STATEMENT_VERSION,
    attestation_statement_hash: statementHash,
    signed_at: new Date().toISOString(),
    expires_at: null,
    status: 'VALID',
    supersedes_attestation_id: null,
    evidence_reference: null,
  };

  const ins = await store.insertAttestation(att, session.orgId, env);

  if (!ins.ok) {
    return { ok: false, reason: 'DUPLICATE' };
  }

  await store.setReleaseStatus(rc.release_candidate_id, session.orgId, 'AWAITING_ATTESTATION', env);

  const gov = createGovernanceService({
    userId: session.userId,
    orgId: session.orgId,
    sessionId: input.sessionId,
    env,
  });
  await gov.recordReleaseEvent({
    conversationId,
    chainId: null,
    eventType: 'ATTESTATION_SIGNED',
    riskTier: rc.risk_tier,
    qhubAppId: rc.qhub_app_id,
    payload: {
      attestation_id: att.attestation_id,
      release_candidate_id: rc.release_candidate_id,
      release_candidate_hash: rc.release_candidate_hash,
      qhub_app_version: rc.qhub_app_version,
      attestation_purpose: att.attestation_purpose,
      attestation_scope: scope,
      signer_role: att.signer_role,
      authority_reference: att.authority_source,
      target_environment: att.target_environment,
      policy_profile_hash: att.policy_profile_hash,
      enforcement_plan_hash: att.enforcement_plan_hash,
      attestation_statement_version: att.attestation_statement_version,
      attestation_statement_hash: att.attestation_statement_hash,
      signed_at: att.signed_at,
    },
  });

  return { ok: true, attestation_id: att.attestation_id };
}

// ─── EVALUATE FOR DEPLOYMENT ──────────────────────────────────────────────────

export interface EvalInput {
  session: Session;
  conversationId: string;
  release_candidate_id: string;
  target_environment: TargetEnvironment;
  sessionId: string;
  env: Record<string, string | undefined>;
}

export interface EvalResult {
  ok: boolean;
  decision: 'APPROVE' | 'REJECT';
  reason_codes: ReleaseReasonCode[];
  satisfied_requirements: string[];
  missing_requirements: string[];
  decision_id: string | null;
  release_candidate_hash: string | null;
}

export async function evaluateReleaseForDeployment(input: EvalInput): Promise<EvalResult> {
  const { session, conversationId, env } = input;
  const reject = (codes: ReleaseReasonCode[], hash: string | null = null): EvalResult => ({
    ok: true,
    decision: 'REJECT',
    reason_codes: codes,
    satisfied_requirements: [],
    missing_requirements: [],
    decision_id: null,
    release_candidate_hash: hash,
  });

  try {
    await assertGovernanceSchemaReady(env);
  } catch {
    return reject(['SCHEMA_NOT_READY']);
  }

  const rc = await store.getReleaseCandidate(input.release_candidate_id, session.orgId, env);

  if (!rc) {
    return reject(['RELEASE_NOT_FOUND']);
  }

  if (rc.org_id !== session.orgId) {
    return reject(['TENANT_MISMATCH']);
  }

  if (rc.status === 'SUPERSEDED' || rc.status === 'REJECTED') {
    return reject(['NOT_FROZEN'], rc.release_candidate_hash);
  }

  if (!['FROZEN', 'AWAITING_ATTESTATION', 'APPROVED'].includes(rc.status)) {
    return reject(['NOT_FROZEN'], rc.release_candidate_hash);
  }

  if (rc.target_environment !== input.target_environment) {
    return reject(['ENVIRONMENT_MISMATCH'], rc.release_candidate_hash);
  }

  // Current classification / policy / plan must match the frozen release.
  const classification = await getClassification(rc.qhub_app_id, env);
  const profile = await getPolicyProfile(rc.qhub_app_id, env);
  const stored = await getActivePlan(rc.qhub_app_id, session.orgId, env);

  if (!classification || classification.classification_version !== rc.classification_version) {
    return reject(['CLASSIFICATION_STALE'], rc.release_candidate_hash);
  }

  if (!profile || profile.policy_profile_hash !== rc.policy_profile_hash) {
    return reject(['POLICY_STALE'], rc.release_candidate_hash);
  }

  if (!stored || stored.plan.enforcement_plan_hash !== rc.enforcement_plan_hash) {
    return reject(['PLAN_STALE'], rc.release_candidate_hash);
  }

  const requirements = deriveAttestationRequirements(profile, stored.plan);
  const attestations = (await store.getAttestationsForRelease(rc.release_candidate_id, session.orgId, env)).filter(
    (a) =>
      a.status === 'VALID' &&
      a.release_candidate_hash === rc.release_candidate_hash &&
      a.target_environment === rc.target_environment,
  );

  const reasons = new Set<ReleaseReasonCode>();
  const satisfied: string[] = [];
  const missing: string[] = [];

  for (const req of requirements) {
    let pool = attestations.filter((a) => a.attestation_purpose === req.purpose && req.roles.includes(a.signer_role));

    if (req.distinct_signers) {
      pool = pool.filter((a, i, arr) => arr.findIndex((x) => x.signer_user_id === a.signer_user_id) === i);
    }

    if (new Set(pool.map((a) => a.signer_user_id)).size >= req.min_signers) {
      satisfied.push(req.requirement_id);
    } else {
      missing.push(req.requirement_id);
      reasons.add('MISSING_ATTESTATION');
    }
  }

  const decisionValue: 'APPROVE' | 'REJECT' = missing.length === 0 ? 'APPROVE' : 'REJECT';

  if (decisionValue === 'APPROVE') {
    reasons.clear();
    reasons.add('APPROVED_ALL_ATTESTATIONS' as ReleaseReasonCode);
  }

  const decisionId = randomUUID();

  /*
   * Emit the decision to the immutable ledger FIRST. Fail-closed: if an APPROVE
   * cannot be durably recorded on-chain, it must not authorize deployment.
   */
  const gov = createGovernanceService({
    userId: session.userId,
    orgId: session.orgId,
    sessionId: input.sessionId,
    env,
  });
  const evt = await gov.recordReleaseEvent({
    conversationId,
    chainId: null,
    eventType: decisionValue === 'APPROVE' ? 'DEPLOYMENT_APPROVED' : 'DEPLOYMENT_REJECTED',
    riskTier: rc.risk_tier,
    qhubAppId: rc.qhub_app_id,
    payload: {
      decision_id: decisionId,
      release_candidate_id: rc.release_candidate_id,
      release_candidate_hash: rc.release_candidate_hash,
      qhub_app_version: rc.qhub_app_version,
      decision: decisionValue,
      reason_codes: Array.from(reasons),
      satisfied_requirements: satisfied,
      missing_requirements: missing,
      target_environment: rc.target_environment,
      policy_profile_hash: rc.policy_profile_hash,
      enforcement_plan_hash: rc.enforcement_plan_hash,
    },
  });

  if (decisionValue === 'APPROVE' && !evt.ok) {
    // Ledger write failed → do not authorize. Record a REJECT decision instead.
    await store.recordDeploymentDecision(
      {
        decision_id: decisionId,
        org_id: session.orgId,
        qhub_app_id: rc.qhub_app_id,
        release_candidate_id: rc.release_candidate_id,
        release_candidate_hash: rc.release_candidate_hash,
        decision: 'REJECT',
        reason_codes: ['DECISION_RECORD_FAILED'],
        satisfied_requirements: satisfied,
        missing_requirements: missing,
        target_environment: rc.target_environment,
        decided_by: session.userId,
      },
      env,
    );

    return {
      ok: true,
      decision: 'REJECT',
      reason_codes: ['DECISION_RECORD_FAILED'],
      satisfied_requirements: satisfied,
      missing_requirements: missing,
      decision_id: null,
      release_candidate_hash: rc.release_candidate_hash,
    };
  }

  await store.recordDeploymentDecision(
    {
      decision_id: decisionId,
      org_id: session.orgId,
      qhub_app_id: rc.qhub_app_id,
      release_candidate_id: rc.release_candidate_id,
      release_candidate_hash: rc.release_candidate_hash,
      decision: decisionValue,
      reason_codes: Array.from(reasons),
      satisfied_requirements: satisfied,
      missing_requirements: missing,
      target_environment: rc.target_environment,
      decided_by: session.userId,
    },
    env,
  );
  await store.setReleaseStatus(
    rc.release_candidate_id,
    session.orgId,
    decisionValue === 'APPROVE' ? 'APPROVED' : 'REJECTED',
    env,
  );

  return {
    ok: true,
    decision: decisionValue,
    reason_codes: Array.from(reasons),
    satisfied_requirements: satisfied,
    missing_requirements: missing,
    decision_id: decisionId,
    release_candidate_hash: rc.release_candidate_hash,
  };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
