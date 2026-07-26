/**
 * Gate 04 governed-action adapters — SERVER ONLY.
 *
 * The registry is authoritative. A browser can describe action facts, but it
 * cannot select an adapter, tenant, execution mode, decision, or receipt state.
 * The only adapters in this sprint are deterministic staging simulations; they
 * perform no network I/O and persist no raw action material.
 */

import { createHash } from 'node:crypto';
import type { RiskTier } from './classification';
import type { Environment, GovernedActionReceipt, GovernedActionType, GovernedExecutionMode } from './enforcement';

const APPROVED_PROJECT_REF = 'jsjsanmaahvmynblmzkq';
const APPROVED_FLY_APP = 'qhub-studio';
const APPROVED_TENANT = 'client-smoke';
const RECEIPT_SCHEMA_VERSION = 'gate04-receipt-1.0.0' as const;
const ADAPTER_VERSION = '1.0.0';

const CONNECTOR_ENV_KEYS = [
  'BROKER_URL',
  'FIX_ENDPOINT',
  'FIX_HOST',
  'OMS_URL',
  'EMS_URL',
  'EXCHANGE_URL',
  'CLEARING_URL',
  'SMTP_URL',
  'SFTP_URL',
  'FTPS_URL',
];

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`)
    .join(',')}}`;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Deterministic UUID-shaped reconciliation id derived from server-owned data. */
function deterministicUuid(seed: string): string {
  const hex = sha256(seed);

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function value(env: Record<string, string | undefined>, key: string): string {
  return env[key] ?? process.env[key] ?? '';
}

function projectRef(env: Record<string, string | undefined>): string {
  try {
    return new URL(value(env, 'SUPABASE_URL')).hostname.split('.')[0] ?? '';
  } catch {
    return '';
  }
}

function isInvalidHttpsTarget(targetResource: string): boolean {
  try {
    const target = new URL(targetResource);

    return target.protocol === 'https:' && target.hostname.endsWith('.invalid');
  } catch {
    return false;
  }
}

function hasProductionConnector(env: Record<string, string | undefined>): boolean {
  return CONNECTOR_ENV_KEYS.some((key) => value(env, key).trim().length > 0);
}

export interface GovernedAdapterPreflightInput {
  tenant_id: string;
  qhub_app_id: string;
  conversation_id: string;
  action_type: GovernedActionType;
  target_resource: string;
  operation: string;
  material_parameters: unknown;
  environment: Environment;
  app_version_ref: string | null;
  risk_tier: RiskTier;
  schema_ready: boolean;
  env: Record<string, string | undefined>;
}

export interface GovernedAdapterExecutionInput extends GovernedAdapterPreflightInput {
  evaluation_id: string;
  action_request_id: string;
  action_digest: string;
  material_parameters_hash: string;
  policy_profile_id: string;
  policy_profile_version: number;
  policy_profile_hash: string;
  enforcement_plan_id: string;
  enforcement_plan_version: number;
  enforcement_plan_hash: string;
  idempotency_key: string;
}

export interface AdapterAvailability {
  available: boolean;
  reason?: string;
}

export interface GovernedActionAdapter {
  readonly adapter_id: string;
  readonly adapter_version: string;
  readonly action_type: GovernedActionType;
  readonly execution_mode: GovernedExecutionMode;
  preflight(input: GovernedAdapterPreflightInput): AdapterAvailability;
  execute(input: GovernedAdapterExecutionInput): Promise<GovernedActionReceipt>;
}

function commonSimulationPreflight(input: GovernedAdapterPreflightInput): AdapterAvailability {
  const env = input.env;
  const material = input.material_parameters as Record<string, unknown> | null;
  const approvedHost = value(env, 'QHUB_PUBLIC_HOSTNAME') || `${value(env, 'FLY_APP_NAME')}.fly.dev`;

  if (value(env, 'QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS') !== '1') {
    return { available: false, reason: 'simulation adapters are disabled' };
  }

  if (value(env, 'QHUB_DEPLOY_ENV').toLowerCase() !== 'staging') {
    return { available: false, reason: 'runtime is not staging' };
  }

  if (value(env, 'FLY_APP_NAME') !== APPROVED_FLY_APP || approvedHost !== 'qhub-studio.fly.dev') {
    return { available: false, reason: 'runtime host is not approved staging' };
  }

  if (projectRef(env) !== APPROVED_PROJECT_REF) {
    return { available: false, reason: 'database project is not approved staging' };
  }

  if (!input.schema_ready) {
    return { available: false, reason: 'schema is not ready' };
  }

  if (input.tenant_id !== APPROVED_TENANT) {
    return { available: false, reason: 'tenant is not synthetic staging' };
  }

  if (!input.conversation_id.startsWith('gate04-r2-') || !input.app_version_ref?.startsWith('gate04-r2-')) {
    return { available: false, reason: 'app is not an approved synthetic Gate 04 app' };
  }

  if (!isInvalidHttpsTarget(input.target_resource)) {
    return { available: false, reason: 'target is not an approved .invalid sink' };
  }

  if (!material || material.synthetic !== true) {
    return { available: false, reason: 'action is not explicitly synthetic' };
  }

  if (hasProductionConnector(env)) {
    return { available: false, reason: 'a production connector is configured' };
  }

  return { available: true };
}

function receiptBase(
  input: GovernedAdapterExecutionInput,
  adapter: GovernedActionAdapter,
  startedAt: string,
  completedAt: string,
) {
  return {
    receipt_id: deterministicUuid(`receipt:${input.evaluation_id}:${adapter.adapter_id}`),
    evaluation_id: input.evaluation_id,
    action_request_id: input.action_request_id,
    action_digest: input.action_digest,
    action_type: input.action_type,
    adapter_id: adapter.adapter_id,
    adapter_version: adapter.adapter_version,
    execution_mode: adapter.execution_mode,
    adapter_executed: true,
    external_effect_performed: false,
    policy_profile_id: input.policy_profile_id,
    policy_profile_version: input.policy_profile_version,
    policy_profile_hash: input.policy_profile_hash,
    enforcement_plan_id: input.enforcement_plan_id,
    enforcement_plan_version: input.enforcement_plan_version,
    enforcement_plan_hash: input.enforcement_plan_hash,
    started_at: startedAt,
    completed_at: completedAt,
    receipt_schema_version: RECEIPT_SCHEMA_VERSION,
  };
}

const externalTransmissionSimulationAdapter: GovernedActionAdapter = {
  adapter_id: 'qhub.staging.external-data-transmission.simulation',
  adapter_version: ADAPTER_VERSION,
  action_type: 'EXTERNAL_DATA_TRANSMISSION',
  execution_mode: 'SIMULATION',
  preflight(input) {
    const common = commonSimulationPreflight(input);

    if (!common.available) {
      return common;
    }

    if (input.operation !== 'write_simulation') {
      return { available: false, reason: 'operation is not allowlisted' };
    }

    return { available: true };
  },
  async execute(input) {
    const startedAt = new Date().toISOString();
    const safeResultMetadata = {
      destination_alias: 'STAGING_SYNTHETIC_SINK' as const,
      payload_hash: input.material_parameters_hash,
      synthetic_byte_count: Buffer.byteLength(stableStringify(input.material_parameters), 'utf8'),
      content_type_category: 'STRUCTURED_DATA' as const,
    };
    const completedAt = new Date().toISOString();
    const base = receiptBase(input, externalTransmissionSimulationAdapter, startedAt, completedAt);
    const unsignedReceipt = {
      ...base,
      execution_status: 'SIMULATED_SUCCESS' as const,
      safe_result_metadata: safeResultMetadata,
    };

    return {
      ...unsignedReceipt,
      result_hash: sha256(stableStringify(unsignedReceipt)),
    };
  },
};

const orderRoutingSimulationAdapter: GovernedActionAdapter = {
  adapter_id: 'qhub.staging.trading-order-routing.simulation',
  adapter_version: ADAPTER_VERSION,
  action_type: 'TRADING_OR_ORDER_ROUTING',
  execution_mode: 'SIMULATION',
  preflight(input) {
    const common = commonSimulationPreflight(input);

    if (!common.available) {
      return common;
    }

    const material = input.material_parameters as Record<string, unknown>;

    if (input.operation !== 'simulate_order') {
      return { available: false, reason: 'operation is not allowlisted' };
    }

    if (material.marketConnectivity !== false || material.symbol !== 'TEST') {
      return { available: false, reason: 'order intent is not an approved synthetic shape' };
    }

    if (typeof material.quantity !== 'number' || !Number.isFinite(material.quantity) || material.quantity <= 0) {
      return { available: false, reason: 'synthetic quantity is invalid' };
    }

    return { available: true };
  },
  async execute(input) {
    const material = input.material_parameters as { symbol: string; quantity: number };
    const startedAt = new Date().toISOString();
    const acceptedAt = new Date().toISOString();
    const quantityCategory =
      material.quantity === 1
        ? 'UNIT'
        : material.quantity <= 10
          ? 'SMALL'
          : material.quantity <= 100
            ? 'MEDIUM'
            : 'LARGE';
    const safeResultMetadata = {
      simulated_order_id: deterministicUuid(`simulated-order:${input.evaluation_id}`),
      instrument_hash: sha256(material.symbol),
      synthetic_quantity_category: quantityCategory as 'UNIT' | 'SMALL' | 'MEDIUM' | 'LARGE',
      risk_category: (input.risk_tier === 'T3' ? 'HIGH' : input.risk_tier === 'T2' ? 'MEDIUM' : 'LOW') as
        | 'LOW'
        | 'MEDIUM'
        | 'HIGH',
      simulated_route_alias: 'STAGING_SIMULATED_ROUTE' as const,
      accepted_at: acceptedAt,
    };
    const completedAt = new Date().toISOString();
    const base = receiptBase(input, orderRoutingSimulationAdapter, startedAt, completedAt);
    const unsignedReceipt = {
      ...base,
      execution_status: 'SIMULATED_ACKNOWLEDGED' as const,
      safe_result_metadata: safeResultMetadata,
    };

    return {
      ...unsignedReceipt,
      result_hash: sha256(stableStringify(unsignedReceipt)),
    };
  },
};

const REGISTRY = new Map<GovernedActionType, GovernedActionAdapter>([
  [externalTransmissionSimulationAdapter.action_type, externalTransmissionSimulationAdapter],
  [orderRoutingSimulationAdapter.action_type, orderRoutingSimulationAdapter],
]);

export function getGovernedActionAdapter(actionType: GovernedActionType): GovernedActionAdapter | null {
  return REGISTRY.get(actionType) ?? null;
}
