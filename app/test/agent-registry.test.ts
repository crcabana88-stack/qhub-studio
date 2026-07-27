/**
 * QHUB Agent Framework Foundation — registry persistence tests
 * app/test/agent-registry.test.ts
 *
 * Verifies the insert payloads written to Supabase (a regression guard for the
 * NOT NULL columns and the create-rollback atomicity that the mocked-registry
 * suites cannot see).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const CAP: { inserts: Record<string, any[]>; deletes: any[]; failTable: string | null } = {
  inserts: {},
  deletes: [],
  failTable: null,
};

function fakeClient() {
  const from = (table: string) => {
    const filters: [string, unknown][] = [];
    let mode: 'insert' | 'select' | 'update' | 'delete' | null = null;
    let payload: any = null;
    const exec = () => {
      if (mode === 'insert') {
        if (CAP.failTable === table) {
          return Promise.resolve({ data: null, error: { message: `forced ${table} failure` } });
        }

        (CAP.inserts[table] ??= []).push(payload);

        return Promise.resolve({ data: [payload], error: null });
      }

      if (mode === 'delete') {
        CAP.deletes.push({ table, filters: [...filters] });

        return Promise.resolve({ data: null, error: null });
      }

      return Promise.resolve({ data: null, error: null });
    };
    const b: any = {
      insert(r: any) {
        mode = 'insert';
        payload = r;

        return exec();
      },
      select() {
        mode = 'select';
        return b;
      },
      update(p: any) {
        mode = 'update';
        payload = p;

        return b;
      },
      delete() {
        mode = 'delete';
        return b;
      },
      eq() {
        return b;
      },
      is() {
        return b;
      },
      order() {
        return b;
      },
      maybeSingle() {
        return Promise.resolve({ data: null, error: null });
      },
      then(res: any, rej: any) {
        return exec().then(res, rej);
      },
    };

    return b;
  };

  return { from };
}

vi.mock('@supabase/supabase-js', () => ({ createClient: () => fakeClient() }));

const ENV = { SUPABASE_URL: 'https://p.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'k' };

function manifest(over: any = {}): any {
  return {
    manifest_version: 'agent-manifest-1.0.0',
    agent_id: 'agent-1',
    agent_version_id: 'ver-1',
    qhub_app_id: 'app-1',
    org_id: 'client-smoke',
    name: 'Recon',
    description: 'd',
    business_purpose: 'p',
    owner_user_id: 'user-1',
    owning_team: null,
    created_by: 'user-1',
    created_at: 'now',
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
    runtime_provider: 'qhub.runtime.local-simulation',
    runtime_provider_version: '1.0.0',
    execution_environment: 'STAGING',
    operating_mode: 'SUPERVISED_ACTION_AGENT',
    autonomy_level: 'HUMAN_IN_LOOP',
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
      max_actions_per_run: 5,
      max_model_calls_per_run: 3,
      max_runtime_seconds: 60,
      max_approval_wait_seconds: 3600,
    },
    stop_conditions: [],
    required_approver_roles: ['owner'],
    designated_supervisor_user_id: null,
    kill_switch_bound: true,
    review_frequency: null,
    ...over,
  };
}

beforeEach(() => {
  CAP.inserts = {};
  CAP.deletes = [];
  CAP.failTable = null;
});

describe('agent registry persistence', () => {
  it('writes created_by (NOT NULL) on both the agent and version rows', async () => {
    const { createDraftAgent } = await import('~/lib/qhub/agent/agent-registry.server');
    const r = await createDraftAgent({ manifest: manifest(), manifest_hash: 'MH' }, ENV);
    expect(r.ok).toBe(true);
    expect(CAP.inserts.qhub_agents[0].created_by).toBe('user-1');
    expect(CAP.inserts.qhub_agent_versions[0].created_by).toBe('user-1');
    expect(CAP.inserts.qhub_agent_versions[0].manifest_hash).toBe('MH');
  });

  it('rolls back the agent row when the version insert fails (no partial record)', async () => {
    const { createDraftAgent } = await import('~/lib/qhub/agent/agent-registry.server');
    CAP.failTable = 'qhub_agent_versions';

    const r = await createDraftAgent({ manifest: manifest(), manifest_hash: 'MH' }, ENV);
    expect(r.ok).toBe(false);
    expect(CAP.deletes.some((d) => d.table === 'qhub_agents')).toBe(true);
  });
});
