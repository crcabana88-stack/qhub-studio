import { describe, expect, it, vi } from 'vitest';
import { getGovernedActionAdapter } from '~/lib/qhub/governed-action-adapters.server';

const ENV = {
  QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS: '1',
  QHUB_DEPLOY_ENV: 'staging',
  FLY_APP_NAME: 'qhub-studio',
  QHUB_PUBLIC_HOSTNAME: 'qhub-studio.fly.dev',
  SUPABASE_URL: 'https://jsjsanmaahvmynblmzkq.supabase.co',
};

function preflight(actionType: 'EXTERNAL_DATA_TRANSMISSION' | 'TRADING_OR_ORDER_ROUTING', over: any = {}) {
  return {
    tenant_id: 'client-smoke',
    qhub_app_id: 'app-synthetic',
    conversation_id: 'gate04-r2-adapter-test',
    action_type: actionType,
    target_resource:
      actionType === 'EXTERNAL_DATA_TRANSMISSION'
        ? 'https://commission-staging-noop.invalid/reconcile'
        : 'https://orders-staging-noop.invalid/simulate',
    operation: actionType === 'EXTERNAL_DATA_TRANSMISSION' ? 'write_simulation' : 'simulate_order',
    material_parameters:
      actionType === 'EXTERNAL_DATA_TRANSMISSION'
        ? { synthetic: true, dataset: 'redacted', mode: 'no-op' }
        : { synthetic: true, symbol: 'TEST', quantity: 1, marketConnectivity: false },
    environment: 'PRODUCTION' as const,
    app_version_ref: 'gate04-r2-adapter-test',
    risk_tier: actionType === 'TRADING_OR_ORDER_ROUTING' ? ('T3' as const) : ('T2' as const),
    schema_ready: true,
    env: ENV,
    ...over,
  };
}

function execution(actionType: 'EXTERNAL_DATA_TRANSMISSION' | 'TRADING_OR_ORDER_ROUTING', over: any = {}) {
  return {
    ...preflight(actionType),
    evaluation_id: '00000000-0000-4000-a000-000000000001',
    action_request_id: '00000000-0000-4000-a000-000000000002',
    action_digest: 'a'.repeat(64),
    material_parameters_hash: 'b'.repeat(64),
    policy_profile_id: 'pp-1',
    policy_profile_version: 1,
    policy_profile_hash: 'c'.repeat(64),
    enforcement_plan_id: 'ep-1',
    enforcement_plan_version: 1,
    enforcement_plan_hash: 'd'.repeat(64),
    idempotency_key: '00000000-0000-4000-a000-000000000001',
    ...over,
  };
}

describe('Gate 04 staging simulation adapter registry', () => {
  it('external transmission creates a compact simulated receipt without network I/O', async () => {
    const network = vi.spyOn(globalThis, 'fetch');
    const adapter = getGovernedActionAdapter('EXTERNAL_DATA_TRANSMISSION')!;

    expect(adapter.preflight(preflight('EXTERNAL_DATA_TRANSMISSION')).available).toBe(true);

    const receipt = await adapter.execute(execution('EXTERNAL_DATA_TRANSMISSION'));

    expect(network).not.toHaveBeenCalled();
    expect(receipt.execution_mode).toBe('SIMULATION');
    expect(receipt.execution_status).toBe('SIMULATED_SUCCESS');
    expect(receipt.adapter_executed).toBe(true);
    expect(receipt.external_effect_performed).toBe(false);
    expect(receipt.safe_result_metadata).toEqual({
      destination_alias: 'STAGING_SYNTHETIC_SINK',
      payload_hash: 'b'.repeat(64),
      synthetic_byte_count: expect.any(Number),
      content_type_category: 'STRUCTURED_DATA',
    });
    expect(JSON.stringify(receipt)).not.toContain('dataset');
    expect(JSON.stringify(receipt)).not.toContain('redacted');
    network.mockRestore();
  });

  it('order routing creates only a simulated acknowledgment and performs no network I/O', async () => {
    const network = vi.spyOn(globalThis, 'fetch');
    const adapter = getGovernedActionAdapter('TRADING_OR_ORDER_ROUTING')!;

    expect(adapter.preflight(preflight('TRADING_OR_ORDER_ROUTING')).available).toBe(true);

    const receipt = await adapter.execute(execution('TRADING_OR_ORDER_ROUTING'));

    expect(network).not.toHaveBeenCalled();
    expect(receipt.execution_status).toBe('SIMULATED_ACKNOWLEDGED');
    expect(receipt.external_effect_performed).toBe(false);
    expect(receipt.safe_result_metadata).toMatchObject({
      simulated_order_id: expect.any(String),
      instrument_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
      synthetic_quantity_category: 'UNIT',
      risk_category: 'HIGH',
      simulated_route_alias: 'STAGING_SIMULATED_ROUTE',
    });
    expect(JSON.stringify(receipt)).not.toContain('"symbol"');
    expect(JSON.stringify(receipt)).not.toContain('"quantity"');
    network.mockRestore();
  });

  it.each([
    ['disabled', { env: { ...ENV, QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS: '0' } }],
    ['non-staging runtime', { env: { ...ENV, QHUB_DEPLOY_ENV: 'production' } }],
    ['wrong host', { env: { ...ENV, FLY_APP_NAME: 'qhub-prod', QHUB_PUBLIC_HOSTNAME: 'qhub-prod.fly.dev' } }],
    ['wrong project', { env: { ...ENV, SUPABASE_URL: 'https://other.supabase.co' } }],
    ['customer tenant', { tenant_id: 'customer-live' }],
    ['non-synthetic app', { conversation_id: 'customer-app', app_version_ref: 'release-1' }],
    ['real target', { target_resource: 'https://customer.example.com' }],
    ['schema not ready', { schema_ready: false }],
  ])('fails closed for %s', (_label, override) => {
    const adapter = getGovernedActionAdapter('EXTERNAL_DATA_TRANSMISSION')!;
    expect(adapter.preflight(preflight('EXTERNAL_DATA_TRANSMISSION', override)).available).toBe(false);
  });

  it('fails closed when a production connector is configured', () => {
    const adapter = getGovernedActionAdapter('TRADING_OR_ORDER_ROUTING')!;
    const input = preflight('TRADING_OR_ORDER_ROUTING', { env: { ...ENV, FIX_ENDPOINT: 'configured' } });

    expect(adapter.preflight(input).available).toBe(false);
  });

  it('returns no adapter for unknown or unwired action types', () => {
    expect(getGovernedActionAdapter('DATABASE_MUTATION')).toBeNull();
  });
});
