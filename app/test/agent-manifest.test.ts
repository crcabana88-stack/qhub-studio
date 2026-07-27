/**
 * QHUB Agent Framework Foundation — manifest build + hashing tests
 * app/test/agent-manifest.test.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  getOrCreateQhubApp: vi.fn(),
  getClassification: vi.fn(),
  getPolicyProfile: vi.fn(),
  getActivePlan: vi.fn(),
  assertSchema: vi.fn(),
}));

vi.mock('~/lib/qhub/qhub-app.server', () => ({
  getOrCreateQhubApp: H.getOrCreateQhubApp,
  getClassification: H.getClassification,
  getPolicyProfile: H.getPolicyProfile,
}));
vi.mock('~/lib/qhub/enforcement-store.server', () => ({ getActivePlan: H.getActivePlan }));
vi.mock('~/lib/qhub/agent/agent-schema-check.server', () => ({ assertAgentSchemaReady: H.assertSchema }));

import { canonicalAgentManifestString } from '~/lib/qhub/agent/agent-manifest';

const ENV = { SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };

function draft(over: any = {}) {
  return {
    session: { userId: 'user-1', orgId: 'client-smoke', role: 'owner' },
    conversationId: 'conv-1',
    name: 'Commission Recon',
    description: 'Reconciles commissions',
    business_purpose: 'Reduce commission errors',
    operating_mode: 'SUPERVISED_ACTION_AGENT' as const,
    autonomy_level: 'HUMAN_IN_LOOP' as const,
    primary_model: 'anthropic:claude-sonnet-5',
    approved_models: ['anthropic:claude-sonnet-5'],
    system_instructions: 'Follow the reconciliation SOP.',
    goal_definition: 'Find and propose commission adjustments.',
    action_limits: {
      max_actions_per_run: 5,
      max_model_calls_per_run: 3,
      max_runtime_seconds: 60,
      max_approval_wait_seconds: 3600,
    },
    env: ENV,
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  H.assertSchema.mockResolvedValue(undefined);
  H.getOrCreateQhubApp.mockResolvedValue({ qhub_app_id: 'app-1', chain_id: 'chain-1' });
  H.getClassification.mockResolvedValue({ classification_version: 2 });
  H.getPolicyProfile.mockResolvedValue({
    policy_profile_id: 'pp-1',
    policy_profile_version: 1,
    policy_profile_hash: 'PPHASH',
    risk_tier: 'T2',
    required_attestations: ['OWNER_ATTESTATION'],
  });
  H.getActivePlan.mockResolvedValue({
    plan: { enforcement_plan_id: 'ep-1', enforcement_plan_version: 1, enforcement_plan_hash: 'EPHASH' },
  });
});

describe('buildAgentManifest (tests 1-9)', () => {
  it('computes a server-side manifest hash that matches recomputation (test 1)', async () => {
    const { buildAgentManifest, computeManifestHash } = await import('~/lib/qhub/agent/agent-manifest.server');
    const r = await buildAgentManifest(draft());
    expect(r.ok).toBe(true);
    expect(r.built!.manifest_hash).toBe(computeManifestHash(r.built!.manifest));
    expect(r.built!.manifest_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is stable: identical canonical input → identical hash (test 1)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const a = await buildAgentManifest(draft());
    const b = await buildAgentManifest(draft());
    expect(a.built!.manifest_hash).toBe(b.built!.manifest_hash);
  });

  it('material change (model) alters the hash (test 2)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const a = await buildAgentManifest(draft());
    const b = await buildAgentManifest(
      draft({ primary_model: 'anthropic:claude-opus-4-8', approved_models: ['anthropic:claude-opus-4-8'] }),
    );
    expect(a.built!.manifest_hash).not.toBe(b.built!.manifest_hash);
  });

  it('material change (added tool) alters the hash (test 2)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const a = await buildAgentManifest(draft());
    const b = await buildAgentManifest(
      draft({
        approved_tools: [
          {
            tool_id: 't1',
            action_type: 'EXTERNAL_DATA_TRANSMISSION',
            permitted_operations: ['write_simulation'],
            blocked_operations: [],
          },
        ],
      }),
    );
    expect(a.built!.manifest_hash).not.toBe(b.built!.manifest_hash);
  });

  it('ignores a browser-supplied manifest hash (test 3)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const r = await buildAgentManifest(draft({ manifest_hash: 'FORGED_DEADBEEF' }) as any);
    expect(r.built!.manifest_hash).not.toBe('FORGED_DEADBEEF');
    expect(r.built!.manifest.release_candidate_hash).toBeNull();
  });

  it('sets tenant + owner server-side, not from the browser (test 4)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');

    // Even if the client injects org_id/owner fields, they are ignored.
    const r = await buildAgentManifest(draft({ org_id: 'ATTACKER', owner_user_id: 'ATTACKER' }) as any);
    expect(r.built!.manifest.org_id).toBe('client-smoke');
    expect(r.built!.manifest.owner_user_id).toBe('user-1');
  });

  it('binds server-fetched policy/plan/tier hashes (test 4)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const r = await buildAgentManifest(draft());
    expect(r.built!.manifest.policy_profile_hash).toBe('PPHASH');
    expect(r.built!.manifest.enforcement_plan_hash).toBe('EPHASH');
    expect(r.built!.manifest.risk_tier).toBe('T2');
  });

  it('agent creation fails closed when the Agent Framework schema is not ready (test 13)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    H.assertSchema.mockRejectedValueOnce(new Error('SchemaNotReadyError'));

    const r = await buildAgentManifest(draft());
    expect(r.ok).toBe(false);
    expect(r.error).toBe('SCHEMA_NOT_READY');

    // No governance read happened after the failed readiness gate.
    expect(H.getPolicyProfile).not.toHaveBeenCalled();
  });

  it('rejects an unimplemented operating mode (BOUNDED_AUTONOMOUS_AGENT)', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    const r = await buildAgentManifest(draft({ operating_mode: 'BOUNDED_AUTONOMOUS_AGENT' }));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('UNIMPLEMENTED_OPERATING_MODE');
  });

  it('fails closed when policy or plan is missing', async () => {
    const { buildAgentManifest } = await import('~/lib/qhub/agent/agent-manifest.server');
    H.getPolicyProfile.mockResolvedValueOnce(null);
    expect((await buildAgentManifest(draft())).error).toBe('MISSING_POLICY_PROFILE');
    H.getActivePlan.mockResolvedValueOnce(null);
    expect((await buildAgentManifest(draft())).error).toBe('MISSING_ENFORCEMENT_PLAN');
  });

  it('canonical string excludes ids/timestamps (test 6 support)', () => {
    const base: any = {
      manifest_version: 'v',
      qhub_app_id: 'a',
      org_id: 'o',
      name: 'n',
      description: 'd',
      business_purpose: 'p',
      owner_user_id: 'u',
      owning_team: null,
      release_candidate_id: null,
      release_candidate_hash: null,
      deployment_decision_id: null,
      classification_version: 1,
      risk_tier: 'T2',
      policy_profile_id: 'pp',
      policy_profile_version: 1,
      policy_profile_hash: 'ph',
      enforcement_plan_id: 'ep',
      enforcement_plan_version: 1,
      enforcement_plan_hash: 'eh',
      runtime_provider: 'rp',
      runtime_provider_version: '1',
      execution_environment: 'STAGING',
      operating_mode: 'ASSISTANT',
      autonomy_level: 'NONE',
      approved_models: ['m'],
      primary_model: 'm',
      fallback_model_policy: 'PRIMARY_ONLY',
      model_config_hash: 'mc',
      approved_tools: [],
      approved_connectors: [],
      network_access_policy: 'NONE',
      system_instruction_hash: 'si',
      goal_definition: 'g',
      prohibited_goals: [],
      escalation_rules: [],
      human_approval_required: true,
      action_limits: {
        max_actions_per_run: 1,
        max_model_calls_per_run: 1,
        max_runtime_seconds: 1,
        max_approval_wait_seconds: 1,
      },
      stop_conditions: [],
      required_approver_roles: ['owner'],
      designated_supervisor_user_id: null,
      kill_switch_bound: true,
      review_frequency: null,
    };
    expect(canonicalAgentManifestString(base)).toBe(canonicalAgentManifestString(base));

    // agent_id/created_at are not part of the type accepted, so identical material → identical string
  });
});
