#!/usr/bin/env node

/**
 * Gate 04 authenticated staging live-test matrix.
 *
 * This is a trusted-operator CLI, never an application route. Authentication
 * material stays in memory. Governance state is changed only through the real
 * deployed routes; the service client is used for synthetic auth provisioning
 * and read-only postcondition checks.
 */

import { createHash, randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { createServerClient } from '@supabase/ssr';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

const APPROVED_TARGET = 'https://qhub-studio.fly.dev';
const APPROVED_PROJECT_REF = 'jsjsanmaahvmynblmzkq';
const PRIMARY_TENANT = 'client-smoke';
const OTHER_TENANT = 'other-org-live';
const EXPECTED_SCHEMA_VERSION = '2026-07-26.gate04';
const SAFE_TARGET_SUFFIX = '.invalid';

const PRINCIPALS = Object.freeze({
  requester: { label: 'gate04-requester', orgId: PRIMARY_TENANT, role: 'admin' },
  owner: { label: 'gate04-owner', orgId: PRIMARY_TENANT, role: 'owner' },
  governance: { label: 'gate04-governance-1', orgId: PRIMARY_TENANT, role: 'governance' },
  security: { label: 'gate04-governance-2', orgId: PRIMARY_TENANT, role: 'security' },
  otherTenant: { label: 'gate04-other-tenant', orgId: OTHER_TENANT, role: 'owner' },
});

const SECRET_KEY =
  /(authorization|cookie|password|secret|service.?role|access.?token|refresh.?token|token.?hash|magic.?link|otp|email)/i;
const JWT_LIKE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const EMAIL_LIKE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const SQL_LIKE =
  /\b(create|alter|drop|select|insert|update|delete|grant|revoke)\s+(table|policy|function|from|into|public\.)/i;
const RLS_PREDICATE_LIKE = /\b(using|with\s+check)\s*\(/i;

/*
 * The harness never uses Supabase Realtime. Supplying an inert transport keeps
 * trusted Node 20 one-off containers from requiring a native WebSocket while
 * ensuring an accidental realtime call still fails closed.
 */
class DisabledRealtimeTransport {
  constructor() {
    throw new Error('Realtime is disabled in the Gate 04 staging harness');
  }
}

const REALTIME_DISABLED = Object.freeze({ transport: DisabledRealtimeTransport });

/** @param {Record<string, string | undefined>} env */
export function validateStagingGuards(env = process.env) {
  const problems = [];
  const target = safeUrl(env.QHUB_STAGING_BASE_URL);
  const supabase = safeUrl(env.SUPABASE_URL);
  const targetRef = supabase?.hostname.split('.')[0] ?? '';
  const deploymentMarkers = [env.NODE_ENV, env.QHUB_DEPLOY_ENV, env.FLY_APP_NAME, env.ENVIRONMENT].filter(Boolean);

  if (env.QHUB_ALLOW_STAGING_LIVE_TESTS !== '1') {
    problems.push('live-test flag is not enabled');
  }

  if (env.QHUB_LIVE_TEST_ENV !== 'staging') {
    problems.push('environment is not explicitly staging');
  }

  if (!target || target.origin !== APPROVED_TARGET) {
    problems.push('target is not the approved staging origin');
  }

  if (target?.protocol !== 'https:') {
    problems.push('target is not HTTPS');
  }

  if (!supabase || supabase.protocol !== 'https:') {
    problems.push('Supabase URL is not HTTPS');
  }

  if (targetRef !== APPROVED_PROJECT_REF) {
    problems.push('Supabase project ref does not match the approved staging project');
  }

  if (!env.SUPABASE_ANON_KEY) {
    problems.push('Supabase anon key is unavailable');
  }

  if (!env.SUPABASE_SERVICE_ROLE_KEY) {
    problems.push('Supabase service role key is unavailable');
  }

  if (env.QHUB_TEST_TENANT && env.QHUB_TEST_TENANT !== PRIMARY_TENANT) {
    problems.push('customer tenant override refused');
  }

  if (env.QHUB_TEST_OTHER_TENANT && env.QHUB_TEST_OTHER_TENANT !== OTHER_TENANT) {
    problems.push('other-tenant override refused');
  }

  if (deploymentMarkers.some((value) => /(^|[-_])prod(uction)?($|[-_])/i.test(String(value)))) {
    problems.push('production environment marker detected');
  }

  if (problems.length) {
    throw new Error(`Staging live-test guard refused to run: ${problems.join('; ')}`);
  }

  return {
    target: target.origin,
    projectRef: targetRef,
    primaryTenant: PRIMARY_TENANT,
    otherTenant: OTHER_TENANT,
  };
}

export function redactForReport(value, key = '') {
  if (SECRET_KEY.test(key)) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactForReport(item));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([childKey]) => !SECRET_KEY.test(childKey))
        .map(([childKey, child]) => [childKey, redactForReport(child, childKey)]),
    );
  }

  if (typeof value === 'string') {
    return value.replace(JWT_LIKE, '[REDACTED]').replace(EMAIL_LIKE, '[REDACTED]');
  }

  return value;
}

export function assertRedactedReportSafe(report) {
  const serialized = JSON.stringify(report);

  if (JWT_LIKE.test(serialized) || EMAIL_LIKE.test(serialized)) {
    throw new Error('Report contains authentication material');
  }

  if (SECRET_KEY.test(serialized)) {
    throw new Error('Report contains a secret-bearing field name');
  }

  return true;
}

function safeUrl(value) {
  try {
    return value ? new URL(value) : null;
  } catch {
    return null;
  }
}

function assert(condition, message, report) {
  if (condition) {
    return;
  }

  report.failures.push(message);
  throw new Error(message);
}

function stableEmail(label) {
  return `qhub-${label}@example.com`;
}

async function listAllUsers(admin) {
  const users = [];

  for (let page = 1; page <= 20; page += 1) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });

    if (error) {
      throw new Error('Synthetic principal inventory failed');
    }

    users.push(...data.users);

    if (data.users.length < 100) {
      break;
    }
  }

  return users;
}

async function resolveSyntheticPrincipals(admin, allowProvisioning) {
  let users = await listAllUsers(admin);
  const resolved = {};

  for (const [name, specification] of Object.entries(PRINCIPALS)) {
    let candidates = users.filter((user) => user.user_metadata?.test_principal === specification.label);

    if (candidates.length > 1) {
      throw new Error(`Synthetic principal label is not unique: ${specification.label}`);
    }

    if (!candidates.length) {
      if (!allowProvisioning) {
        throw new Error(
          `Missing synthetic principal ${specification.label}; enable the separately approved provisioning guard`,
        );
      }

      const { data, error } = await admin.auth.admin.createUser({
        email: stableEmail(specification.label),
        email_confirm: true,
        user_metadata: {
          test_principal: specification.label,
          staging_only: true,
          org_id: specification.orgId,
          role: specification.role,
        },
      });

      if (error || !data.user) {
        throw new Error(`Synthetic principal provisioning failed: ${specification.label}`);
      }

      users = [...users, data.user];
      candidates = [data.user];
    }

    const user = candidates[0];

    if (
      user.user_metadata?.staging_only !== true ||
      user.user_metadata?.org_id !== specification.orgId ||
      user.user_metadata?.role !== specification.role ||
      !user.email_confirmed_at ||
      user.banned_until
    ) {
      throw new Error(`Synthetic principal metadata is invalid: ${specification.label}`);
    }

    resolved[name] = { ...specification, userId: user.id, email: user.email };
  }

  const ids = Object.values(resolved).map((principal) => principal.userId);

  if (new Set(ids).size !== ids.length) {
    throw new Error('Distinct-role test principals are not distinct identities');
  }

  return resolved;
}

async function mintCookieSession({ admin, supabaseUrl, anonKey, principal }) {
  const { data: linkData, error: linkError } = await admin.auth.admin.generateLink({
    type: 'magiclink',
    email: principal.email,
  });
  const tokenHash = linkData?.properties?.hashed_token;

  if (linkError || !tokenHash) {
    throw new Error(`Session mint failed for ${principal.label}`);
  }

  const authClient = createClient(supabaseUrl, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    realtime: REALTIME_DISABLED,
  });
  const { data: verified, error: verifyError } = await authClient.auth.verifyOtp({
    token_hash: tokenHash,
    type: 'email',
  });

  if (verifyError || !verified.session || !verified.user) {
    throw new Error(`Session exchange failed for ${principal.label}`);
  }

  const cookieValues = new Map();
  const serverClient = createServerClient(supabaseUrl, anonKey, {
    realtime: REALTIME_DISABLED,
    cookies: {
      getAll: () => [],
      setAll: (cookies) => cookies.forEach(({ name, value }) => cookieValues.set(name, value)),
    },
  });
  const { error: sessionError } = await serverClient.auth.setSession({
    access_token: verified.session.access_token,
    refresh_token: verified.session.refresh_token,
  });

  if (sessionError || !cookieValues.size) {
    throw new Error(`SSR session creation failed for ${principal.label}`);
  }

  const metadata = verified.user.user_metadata ?? {};

  if (
    verified.user.id !== principal.userId ||
    metadata.org_id !== principal.orgId ||
    metadata.role !== principal.role
  ) {
    throw new Error(`Minted session authority mismatch for ${principal.label}`);
  }

  return [...cookieValues.entries()]
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join('; ');
}

function createRouteClient(baseUrl, cookieHeader = '') {
  return async function requestRoute(path, options = {}) {
    const headers = { Accept: 'application/json' };

    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }

    const response = await fetch(`${baseUrl}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      redirect: 'manual',
    });
    const text = await response.text();
    let body = null;

    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = { nonJson: true };
    }

    return { status: response.status, body };
  };
}

async function setupGovernedApp(client, conversationId, tier, description, report, requiredSignals = {}) {
  const classification = await client('/api/classify', {
    method: 'POST',
    body: { description, conversationId },
  });
  assert(
    classification.status === 200 && classification.body?.ok && classification.body?.proposalId,
    `${tier} classification failed`,
    report,
  );

  if (requiredSignals.integrationType) {
    assert(
      classification.body.classification?.integration_types?.includes(requiredSignals.integrationType),
      `${tier} classification omitted required synthetic integration signal`,
      report,
    );
  }

  if (requiredSignals.autonomyLevel) {
    assert(
      classification.body.classification?.autonomy_level === requiredSignals.autonomyLevel,
      `${tier} classification omitted required synthetic autonomy signal`,
      report,
    );
  }

  const confirmed = await client('/api/governance', {
    method: 'POST',
    body: {
      action: 'CLASSIFICATION_CONFIRMED',
      conversationId,
      proposalId: classification.body.proposalId,
      confirmedTier: tier,
      projectTitle: `Gate 04 ${tier} synthetic staging test`,
    },
  });
  assert(
    confirmed.status === 200 && confirmed.body?.ok && confirmed.body?.riskTier === tier,
    `${tier} confirmation failed`,
    report,
  );

  const assigned = await client('/api/governance', {
    method: 'POST',
    body: { action: 'POLICY_ASSIGN', conversationId },
  });
  assert(
    assigned.status === 200 && assigned.body?.ok && assigned.body?.riskTier === tier,
    `${tier} policy assignment failed`,
    report,
  );

  const acknowledged = await client('/api/governance', {
    method: 'POST',
    body: { action: 'POLICY_ACKNOWLEDGE', conversationId },
  });
  assert(
    acknowledged.status === 200 && acknowledged.body?.ok && acknowledged.body?.policyStatus === 'ACKNOWLEDGED',
    `${tier} policy acknowledgement failed`,
    report,
  );

  return {
    qhubAppId: confirmed.body.qhubAppId,
    riskTier: tier,
    classificationSignals: {
      integrationTypes: classification.body.classification?.integration_types ?? [],
      autonomyLevel: classification.body.classification?.autonomy_level ?? null,
      deploymentSurface: classification.body.classification?.deployment_surface ?? null,
    },
  };
}

function assertSafeAction(action) {
  const target = safeUrl(action.target_resource);

  if (!target || !target.hostname.endsWith(SAFE_TARGET_SUFFIX)) {
    throw new Error('Refusing non-synthetic side-effect target');
  }

  if (action.environment !== 'PRODUCTION') {
    throw new Error('Matrix actions must explicitly exercise production policy');
  }
}

async function enforce(client, conversationId, action, idempotencyKey, parentEvaluationId) {
  assertSafeAction(action);
  return client('/api/enforce', {
    method: 'POST',
    body: { conversationId, action, idempotencyKey, ...(parentEvaluationId ? { parentEvaluationId } : {}) },
  });
}

async function approve(client, conversationId, evaluation, attestationType) {
  return client('/api/enforcement', {
    method: 'POST',
    body: {
      op: 'grant_approval',
      conversationId,
      evaluationId: evaluation.evaluation_id,
      actionDigest: evaluation.action_digest,
      attestationType,
    },
  });
}

async function approvalRows(db, qhubAppId, actionDigest) {
  const { data, error } = await db
    .from('qhub_control_approvals')
    .select(
      'approval_id,org_id,qhub_app_id,attestation_type,action_digest,approver_id,approver_role,status,consumed_by_evaluation,consumed_at',
    )
    .eq('qhub_app_id', qhubAppId)
    .eq('action_digest', actionDigest);

  if (error) {
    throw new Error('Approval postcondition query failed');
  }

  return data ?? [];
}

async function evaluationRow(db, evaluationId) {
  const { data, error } = await db
    .from('qhub_control_evaluations')
    .select(
      'evaluation_id,action_request_id,parent_evaluation_id,org_id,qhub_app_id,action_digest,decision,reason_codes,policy_profile_id,policy_profile_hash,enforcement_plan_id,enforcement_plan_hash,claimed,claimed_at,action_event_state',
    )
    .eq('evaluation_id', evaluationId)
    .single();

  if (error || !data) {
    throw new Error('Evaluation postcondition query failed');
  }

  return data;
}

async function approvalOwnershipOrphanCount(db) {
  const { data: approvals, error: approvalsError } = await db
    .from('qhub_control_approvals')
    .select('approval_id,org_id,qhub_app_id');
  const { data: apps, error: appsError } = await db.from('qhub_applications').select('org_id,qhub_app_id');

  if (approvalsError || appsError) {
    throw new Error('Approval ownership postcondition query failed');
  }

  const owners = new Set((apps ?? []).map((row) => `${row.org_id}:${row.qhub_app_id}`));

  return (approvals ?? []).filter((row) => !owners.has(`${row.org_id}:${row.qhub_app_id}`)).length;
}

function summarizeDecision(response) {
  const body = response.body ?? {};
  return {
    httpStatus: response.status,
    decision: body.decision ?? null,
    reasonCodes: body.reason_codes ?? [],
    appId: body.qhub_app_id ?? null,
    evaluationId: body.evaluation_id ?? null,
    actionRequestId: body.action_request_id ?? null,
    actionDigest: body.action_digest ?? null,
    parentEvaluationId: body.parent_evaluation_id ?? null,
    policyProfileId: body.policy_profile_id ?? null,
    policyProfileHash: body.policy_profile_hash ?? null,
    enforcementPlanId: body.enforcement_plan_id ?? null,
    enforcementPlanHash: body.enforcement_plan_hash ?? null,
    requiredAttestations: body.required_attestations ?? [],
    evidenceRecorded: body.evidence_recorded === true,
    sideEffectPerformed: body.side_effect_performed === true,
  };
}

async function runSchemaChecks({ clients, report }) {
  const authenticated = await clients.requester('/api/system/schema-check?force=1');
  const unauthenticated = await clients.unauthenticated('/api/system/schema-check?force=1');
  const publicHealth = await clients.unauthenticated('/api/health');
  const serialized = JSON.stringify(authenticated.body ?? {});
  const metadataChecks = (authenticated.body?.objects ?? []).filter(
    (object) => object.migration === '20260726_gate04_schema_assurance_approval_cleanup',
  );

  assert(authenticated.status === 200, 'Authenticated schema diagnostic did not return HTTP 200', report);
  assert(authenticated.body?.ready === true, 'Authenticated schema diagnostic is not READY', report);
  assert(authenticated.body?.expectedSchemaVersion === EXPECTED_SCHEMA_VERSION, 'Schema version mismatch', report);
  assert(
    metadataChecks.length === 46 && metadataChecks.every((object) => object.state === 'present'),
    'Schema diagnostic did not return 46 passing metadata checks',
    report,
  );
  assert((authenticated.body?.missing ?? []).length === 0, 'Schema diagnostic reports missing objects', report);
  assert(
    !SQL_LIKE.test(serialized) && !RLS_PREDICATE_LIKE.test(serialized),
    'Schema diagnostic exposed raw SQL or RLS predicates',
    report,
  );
  assert(
    !SECRET_KEY.test(serialized) && !JWT_LIKE.test(serialized),
    'Schema diagnostic exposed authentication material',
    report,
  );
  assert([401, 403].includes(unauthenticated.status), 'Unauthenticated schema diagnostic was not rejected', report);
  assert(
    publicHealth.status === 200 && publicHealth.body?.status === 'healthy',
    'Public health is not healthy',
    report,
  );
  assert(
    Object.keys(publicHealth.body ?? {}).every((key) => ['status', 'timestamp'].includes(key)),
    'Public health exposed internal details',
    report,
  );

  report.schema = {
    authenticated: {
      httpStatus: authenticated.status,
      ready: true,
      expectedSchemaVersion: EXPECTED_SCHEMA_VERSION,
      passedMetadataChecks: metadataChecks.length,
      totalReadinessChecks: authenticated.body.objects.length,
    },
    unauthenticated: { httpStatus: unauthenticated.status },
    publicHealth: { httpStatus: publicHealth.status, status: publicHealth.body.status, generic: true },
  };
}

async function runCaseB({ clients, db, runId, report }) {
  const conversationId = `gate04-r2-t2-${runId}`;
  const app = await setupGovernedApp(
    clients.requester,
    conversationId,
    'T2',
    'Synthetic staging commission reconciliation workflow with confidential financial data and a production external write.',
    report,
  );
  const action = {
    action_type: 'EXTERNAL_DATA_TRANSMISSION',
    target_resource: 'https://commission-staging-noop.invalid/reconcile',
    operation: 'write_simulation',
    material_parameters: { synthetic: true, dataset: 'gate04-redacted-fixture', mode: 'no-op' },
    environment: 'PRODUCTION',
    autonomy_requested: 'RESTRICTED',
    app_version_ref: `gate04-r2-${runId}`,
  };

  const e1Response = await enforce(clients.requester, conversationId, action, `${runId}-t2-e1`);
  const e1 = e1Response.body;
  assert(
    e1Response.status === 200 && e1?.decision === 'REQUIRE_APPROVAL',
    'Case B E1 was not REQUIRE_APPROVAL',
    report,
  );
  assert(e1.side_effect_performed === false, 'Case B E1 performed a side effect', report);

  const approvalsBeforeCrossTenant = await approvalRows(db, app.qhubAppId, e1.action_digest);
  const orphanCountBefore = await approvalOwnershipOrphanCount(db);
  const crossTenant = await approve(clients.otherTenant, conversationId, e1, 'OWNER_ATTESTATION');
  const approvalsAfterCrossTenant = await approvalRows(db, app.qhubAppId, e1.action_digest);
  const orphanCountAfter = await approvalOwnershipOrphanCount(db);
  assert([403, 409].includes(crossTenant.status), 'Cross-tenant approval route was not rejected', report);
  assert(
    approvalsAfterCrossTenant.length === approvalsBeforeCrossTenant.length,
    'Cross-tenant attempt created an approval row',
    report,
  );
  assert(orphanCountAfter === 0 && orphanCountBefore === 0, 'Approval ownership orphan count is nonzero', report);

  const approvalResponse = await approve(clients.owner, conversationId, e1, 'OWNER_ATTESTATION');
  assert(
    approvalResponse.status === 200 && approvalResponse.body?.ok && approvalResponse.body?.approvalId,
    'Case B owner approval failed',
    report,
  );

  const e2Response = await enforce(clients.requester, conversationId, action, `${runId}-t2-e2`, e1.evaluation_id);
  const e2 = e2Response.body;
  assert(e2Response.status === 200 && e2?.decision === 'ALLOW', 'Case B E2 was not ALLOW', report);
  assert(e2.action_digest === e1.action_digest, 'Case B E2 action digest differs from E1', report);

  const replayResponse = await enforce(clients.requester, conversationId, action, `${runId}-t2-e2`, e1.evaluation_id);
  const replay = replayResponse.body;
  assert(
    replayResponse.status === 200 && replay?.evaluation_id === e2.evaluation_id,
    'Case B replay did not resolve to the original E2',
    report,
  );
  assert(replay.reason_codes?.includes('REPLAY_DENIED'), 'Case B replay lacks REPLAY_DENIED', report);
  assert(replay.side_effect_performed === false, 'Case B replay performed a side effect', report);

  const approvals = await approvalRows(db, app.qhubAppId, e1.action_digest);
  const e1Db = await evaluationRow(db, e1.evaluation_id);
  const e2Db = await evaluationRow(db, e2.evaluation_id);
  assert(approvals.length === 1, 'Case B does not have exactly one approval row', report);
  assert(
    approvals[0].status === 'CONSUMED' && approvals[0].consumed_by_evaluation === e2.evaluation_id,
    'Case B approval was not consumed exactly by E2',
    report,
  );
  assert(e1Db.decision === 'REQUIRE_APPROVAL' && !e1Db.claimed, 'Case B E1 persistence is invalid', report);
  assert(e2Db.decision === 'ALLOW' && e2Db.claimed, 'Case B E2 is not the claimed ALLOW', report);
  assert(e2Db.parent_evaluation_id === e1.evaluation_id, 'Case B E2 parent does not reference E1', report);
  assert(
    e1Db.policy_profile_hash === e2Db.policy_profile_hash && e1Db.enforcement_plan_hash === e2Db.enforcement_plan_hash,
    'Case B policy/plan binding changed',
    report,
  );

  report.caseB = {
    conversationRef: conversationId,
    e1: summarizeDecision(e1Response),
    approval: {
      httpStatus: approvalResponse.status,
      approvalId: approvalResponse.body.approvalId,
      status: approvals[0].status,
      consumedByEvaluation: approvals[0].consumed_by_evaluation,
    },
    e2: summarizeDecision(e2Response),
    replay: summarizeDecision(replayResponse),
    crossTenant: {
      httpStatus: crossTenant.status,
      approvalRowsCreated: approvalsAfterCrossTenant.length - approvalsBeforeCrossTenant.length,
      orphanCount: orphanCountAfter,
    },
    sideEffectReceiptCount: Number(e2.side_effect_performed === true),
    actionEventState: e2Db.action_event_state,
  };
  report.caseB.e2.parentEvaluationId = e2Db.parent_evaluation_id;
  report.caseB.replay.parentEvaluationId = e2Db.parent_evaluation_id;

  return { conversationId, appId: app.qhubAppId, e1, e2, approvalId: approvals[0].approval_id };
}

async function runCaseC({ clients, db, runId, report }) {
  const conversationId = `gate04-r2-t3-${runId}`;
  const app = await setupGovernedApp(
    clients.requester,
    conversationId,
    'T3',
    'Synthetic staging autonomous trading and order-execution agent. Its integration type is TRADING_OR_ORDERS, autonomy level is AUTONOMOUS, and deployment surface is PRODUCTION. It routes only simulated TEST-symbol orders to a no-op adapter with no brokerage or market connectivity.',
    report,
    { integrationType: 'TRADING_OR_ORDERS', autonomyLevel: 'AUTONOMOUS' },
  );
  const action = {
    action_type: 'TRADING_OR_ORDER_ROUTING',
    target_resource: 'https://orders-staging-noop.invalid/simulate',
    operation: 'simulate_order',
    material_parameters: { synthetic: true, symbol: 'TEST', quantity: 1, marketConnectivity: false },
    environment: 'PRODUCTION',
    autonomy_requested: 'RESTRICTED',
    app_version_ref: `gate04-r2-${runId}`,
  };

  const e1Response = await enforce(clients.requester, conversationId, action, `${runId}-t3-e1`);
  const e1 = e1Response.body;
  report.caseC = {
    conversationRef: conversationId,
    classificationSignals: app.classificationSignals,
    e1: summarizeDecision(e1Response),
  };
  assert(
    e1Response.status === 200 && e1?.decision === 'REQUIRE_APPROVAL',
    'Case C initial request was not REQUIRE_APPROVAL',
    report,
  );
  assert(e1.side_effect_performed === false, 'Case C E1 performed a side effect', report);

  const beforeSelf = await approvalRows(db, app.qhubAppId, e1.action_digest);
  const selfApproval = await approve(clients.requester, conversationId, e1, 'AUTHORIZED_GOVERNANCE_APPROVAL');
  const afterSelf = await approvalRows(db, app.qhubAppId, e1.action_digest);
  assert([403, 409].includes(selfApproval.status), 'Case C self-approval was not rejected', report);
  assert(afterSelf.length === beforeSelf.length, 'Case C self-approval created authority', report);

  const ownerApproval = await approve(clients.owner, conversationId, e1, 'OWNER_ATTESTATION');
  const governanceApproval = await approve(clients.governance, conversationId, e1, 'AUTHORIZED_GOVERNANCE_APPROVAL');
  assert(ownerApproval.status === 200 && ownerApproval.body?.ok, 'Case C owner approval failed', report);
  assert(governanceApproval.status === 200 && governanceApproval.body?.ok, 'Case C governance approval failed', report);

  const incompleteResponse = await enforce(
    clients.requester,
    conversationId,
    action,
    `${runId}-t3-incomplete`,
    e1.evaluation_id,
  );
  assert(
    ['REQUIRE_APPROVAL', 'DENY'].includes(incompleteResponse.body?.decision),
    'Case C incomplete dual control did not remain closed',
    report,
  );
  assert(
    incompleteResponse.body?.decision !== 'ALLOW' && incompleteResponse.body?.side_effect_performed === false,
    'Case C incomplete dual control authorized execution',
    report,
  );

  const securityApproval = await approve(clients.security, conversationId, e1, 'AUTHORIZED_GOVERNANCE_APPROVAL');
  assert(
    securityApproval.status === 200 && securityApproval.body?.ok,
    'Case C second governance/security approval failed',
    report,
  );

  const e2Response = await enforce(clients.requester, conversationId, action, `${runId}-t3-e2`, e1.evaluation_id);
  const e2 = e2Response.body;
  assert(
    e2Response.status === 200 && e2?.decision === 'ALLOW',
    'Case C complete dual control did not yield ALLOW',
    report,
  );
  assert(e2.action_digest === e1.action_digest, 'Case C E2 action digest differs from E1', report);

  const approvals = await approvalRows(db, app.qhubAppId, e1.action_digest);
  const approverIds = approvals.map((approval) => approval.approver_id);
  assert(
    approvals.length === 3 && new Set(approverIds).size === 3,
    'Case C approvals are not three distinct signers',
    report,
  );
  assert(
    approvals.every(
      (approval) => approval.status === 'CONSUMED' && approval.consumed_by_evaluation === e2.evaluation_id,
    ),
    'Case C approvals were not consumed by E2',
    report,
  );

  const e2Db = await evaluationRow(db, e2.evaluation_id);
  assert(e2Db.claimed === true, 'Case C E2 ALLOW was not claimed', report);

  const { data: appState, error: appStateError } = await db
    .from('qhub_applications')
    .select('kill_switch_active')
    .eq('qhub_app_id', app.qhubAppId)
    .eq('org_id', PRIMARY_TENANT)
    .single();

  if (appStateError || !appState) {
    throw new Error('Kill-switch initial-state query failed');
  }

  const priorKillSwitch = appState.kill_switch_active === true;
  let killResponse;
  let killedActionResponse;

  try {
    killResponse = await clients.requester('/api/enforcement', {
      method: 'POST',
      body: { op: 'kill_switch', conversationId, active: true, reason: 'Gate 04 synthetic staging live-test' },
    });
    assert(
      killResponse.status === 200 && killResponse.body?.ok && killResponse.body?.active === true,
      'Kill switch activation failed',
      report,
    );

    const killedAction = {
      ...action,
      material_parameters: { ...action.material_parameters, request: 'kill-switch-check' },
    };
    killedActionResponse = await enforce(clients.requester, conversationId, killedAction, `${runId}-t3-kill`);
    assert(killedActionResponse.body?.decision === 'DENY', 'Kill switch did not produce DENY', report);
    assert(
      killedActionResponse.body?.reason_codes?.includes('KILL_SWITCH_ACTIVE'),
      'Kill switch DENY lacks KILL_SWITCH_ACTIVE',
      report,
    );
    assert(
      killedActionResponse.body?.side_effect_performed === false,
      'Kill switch DENY performed a side effect',
      report,
    );

    const killedDb = await evaluationRow(db, killedActionResponse.body.evaluation_id);
    assert(
      killedDb.claimed === false && killedDb.action_event_state === 'NONE',
      'Kill switch DENY was claimed or has an action event',
      report,
    );
  } finally {
    const restored = await clients.requester('/api/enforcement', {
      method: 'POST',
      body: {
        op: 'kill_switch',
        conversationId,
        active: priorKillSwitch,
        reason: 'Gate 04 synthetic staging live-test restore',
      },
    });

    if (restored.status !== 200 || !restored.body?.ok || restored.body?.active !== priorKillSwitch) {
      report.failures.push('Kill switch restoration failed');
    }
  }

  const { data: restoredState, error: restoredError } = await db
    .from('qhub_applications')
    .select('kill_switch_active')
    .eq('qhub_app_id', app.qhubAppId)
    .eq('org_id', PRIMARY_TENANT)
    .single();
  assert(
    !restoredError && restoredState?.kill_switch_active === priorKillSwitch,
    'Kill switch final state differs from its prior state',
    report,
  );

  report.caseC = {
    conversationRef: conversationId,
    classificationSignals: app.classificationSignals,
    e1: summarizeDecision(e1Response),
    selfApproval: { httpStatus: selfApproval.status, approvalRowsCreated: afterSelf.length - beforeSelf.length },
    incompleteDualControl: summarizeDecision(incompleteResponse),
    completeDualControl: summarizeDecision(e2Response),
    approvals: approvals.map((approval) => ({
      approvalId: approval.approval_id,
      attestationType: approval.attestation_type,
      approverRole: approval.approver_role,
      status: approval.status,
    })),
    sideEffectReceiptCount: Number(e2.side_effect_performed === true),
    actionEventState: e2Db.action_event_state,
    killSwitch: {
      activated: killResponse?.body?.active === true,
      decision: summarizeDecision(killedActionResponse),
      restored: true,
      finalState: priorKillSwitch,
    },
  };
  report.caseC.completeDualControl.parentEvaluationId = e2Db.parent_evaluation_id;

  return { conversationId, appId: app.qhubAppId, e1, e2 };
}

async function writeReports(report) {
  const safeReport = redactForReport(report);
  assertRedactedReportSafe(safeReport);

  const directory = join(tmpdir(), 'qhub-gate04-live');
  await mkdir(directory, { recursive: true });

  const jsonPath = join(directory, `${report.runId}.json`);
  const textPath = join(directory, `${report.runId}.txt`);
  const human = [
    `Gate 04 authenticated live matrix: ${report.status}`,
    `Run: ${report.runId}`,
    `Schema: ${report.schema?.authenticated?.ready ? 'READY' : 'NOT READY'}`,
    `Case B: ${report.caseB?.e2?.decision ?? 'NOT RUN'}`,
    `Case B replay: ${(report.caseB?.replay?.reasonCodes ?? []).join(',') || 'NOT RUN'}`,
    `Cross-tenant rows created: ${report.caseB?.crossTenant?.approvalRowsCreated ?? 'NOT RUN'}`,
    `Case C: ${report.caseC?.completeDualControl?.decision ?? 'NOT RUN'}`,
    `Kill switch: ${report.caseC?.killSwitch?.decision?.decision ?? 'NOT RUN'}`,
    `Failures: ${report.failures.join(' | ') || 'NONE'}`,
  ].join('\n');
  await writeFile(jsonPath, `${JSON.stringify(safeReport, null, 2)}\n`, { mode: 0o600 });
  await writeFile(textPath, `${human}\n`, { mode: 0o600 });

  return { jsonPath, textPath };
}

async function main() {
  dotenv.config({ path: '.env.local', override: false, quiet: true });
  dotenv.config({ path: '.env', override: false, quiet: true });

  const guard = validateStagingGuards(process.env);
  const runId = `${new Date()
    .toISOString()
    .replace(/[-:.TZ]/g, '')
    .slice(0, 14)}-${createHash('sha256').update(randomUUID()).digest('hex').slice(0, 10)}`;
  const report = {
    reportVersion: 1,
    runId,
    status: 'RUNNING',
    target: guard.target,
    projectRef: guard.projectRef,
    tenants: { primary: guard.primaryTenant, adversarial: guard.otherTenant },
    principals: {},
    schema: null,
    caseB: null,
    caseC: null,
    failures: [],
  };

  try {
    const supabaseUrl = process.env.SUPABASE_URL;
    const anonKey = process.env.SUPABASE_ANON_KEY;
    const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const db = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      realtime: REALTIME_DISABLED,
    });
    const principals = await resolveSyntheticPrincipals(
      db,
      process.env.QHUB_ALLOW_STAGING_PRINCIPAL_PROVISIONING === '1',
    );
    const clients = { unauthenticated: createRouteClient(guard.target) };

    for (const [name, principal] of Object.entries(principals)) {
      const cookie = await mintCookieSession({ admin: db, supabaseUrl, anonKey, principal });
      clients[name] = createRouteClient(guard.target, cookie);
      report.principals[name] = {
        principalId: principal.userId,
        tenant: principal.orgId,
        role: principal.role,
        active: true,
      };
    }

    await runSchemaChecks({ clients, report });
    await runCaseB({ clients, db, runId, report });
    await runCaseC({ clients, db, runId, report });

    /*
     * The matrix requires one safe receipt for each ALLOW. The deployed
     * enforcement path must prove it; the harness never fabricates a receipt.
     * Record both gaps so one cannot mask the other.
     */
    if (report.caseB.sideEffectReceiptCount !== 1) {
      report.failures.push('Case B produced no protected side-effect receipt');
    }

    if (report.caseC.sideEffectReceiptCount !== 1) {
      report.failures.push('Case C produced no protected side-effect receipt');
    }

    report.status = report.failures.length === 0 ? 'PASS' : 'FAIL';
  } catch (error) {
    if (!report.failures.length) {
      report.failures.push(error instanceof Error ? error.message : 'Unclassified harness failure');
    }

    report.status = 'FAIL';
  }

  const paths = await writeReports(report);
  process.stdout.write(
    `${JSON.stringify({ status: report.status, runId: report.runId, reportFiles: paths, failures: report.failures }, null, 2)}\n`,
  );
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';

if (import.meta.url === invokedPath) {
  main().catch(() => {
    process.stderr.write('Gate 04 harness terminated without exposing diagnostic internals.\n');
    process.exitCode = 1;
  });
}
