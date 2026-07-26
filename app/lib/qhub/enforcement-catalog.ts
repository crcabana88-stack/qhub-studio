/**
 * QHUB Gate 04 — Enforcement catalog (BROWSER-SAFE, deterministic)
 * app/lib/qhub/enforcement-catalog.ts
 *
 * Maps Gate 03 catalog control_ids to runtime enforcement adapters and the
 * governed-action types they gate, and derives which action types a given
 * classification makes "protected" (governed by the plan). Everything here is
 * data + pure functions — no I/O, no secrets.
 */

import type { ClassificationSignals, RiskTier } from './classification';
import type { EnforcementPhase, GovernedActionType } from './enforcement';

/** The only action type wired to a real executing side effect today. */
export const WIRED_ACTION_TYPES: GovernedActionType[] = ['AI_MODEL_INVOCATION'];

/** Consequential action types (never auto-ALLOW without governing controls). */
export const CONSEQUENTIAL_ACTIONS: GovernedActionType[] = [
  'DEPLOYMENT_EXECUTION',
  'PRODUCTION_EXECUTION',
  'EXTERNAL_DATA_TRANSMISSION',
  'DATABASE_MUTATION',
  'CREDENTIAL_USE',
  'TRADING_OR_ORDER_ROUTING',
  'AGENT_TOOL_EXECUTION',
];

/** Production-capable action types (subject to preview-only / prod-approval). */
export const PRODUCTION_CAPABLE_ACTIONS: GovernedActionType[] = [
  'DEPLOYMENT_EXECUTION',
  'PRODUCTION_EXECUTION',
  'TRADING_OR_ORDER_ROUTING',
];

// ─── Control → enforcement adapter mapping (runtime-relevant Gate 03 controls) ─

export interface ControlEnforcement {
  adapter: string;
  phase: EnforcementPhase;
  /** Action types this control gates at runtime. */
  guards: GovernedActionType[];
  title: string;
}

/**
 * Only the controls that have a real runtime adapter appear here. A mandatory
 * Gate 03 control that is NOT listed is carried on the plan as a BUILD_TIME /
 * ATTESTATION entry (enforceable via evidence, not a runtime action gate).
 */
export const CONTROL_ENFORCEMENT: Record<string, ControlEnforcement> = {
  'IR-KILL-SWITCH': {
    adapter: 'KILL_SWITCH',
    phase: 'RUNTIME',
    title: 'Kill switch / emergency stop',
    guards: ['AI_MODEL_INVOCATION', ...CONSEQUENTIAL_ACTIONS],
  },
  'DE-PREVIEW-ONLY': {
    adapter: 'PREVIEW_ONLY',
    phase: 'PROHIBITION',
    title: 'Preview/sandbox only until approval',
    guards: PRODUCTION_CAPABLE_ACTIONS,
  },
  'DE-EXPLICIT-PROD-APPROVAL': {
    adapter: 'PROD_APPROVAL',
    phase: 'ATTESTATION',
    title: 'Explicit authorized production approval',
    guards: PRODUCTION_CAPABLE_ACTIONS,
  },
  'HO-OWNER-ATTESTATION': {
    adapter: 'OWNER_ATTESTATION',
    phase: 'ATTESTATION',
    title: 'Owner attestation before production',
    guards: ['DEPLOYMENT_EXECUTION', 'PRODUCTION_EXECUTION', 'EXTERNAL_DATA_TRANSMISSION', 'DATABASE_MUTATION', 'TRADING_OR_ORDER_ROUTING'],
  },
  'HO-DUAL-CONTROL': {
    adapter: 'DUAL_CONTROL',
    phase: 'ATTESTATION',
    title: 'Dual control / four-eyes approval',
    guards: ['PRODUCTION_EXECUTION', 'TRADING_OR_ORDER_ROUTING'],
  },
  'RM-NO-UNRESTRICTED-AUTONOMY': {
    adapter: 'NO_UNRESTRICTED_AUTONOMY',
    phase: 'PROHIBITION',
    title: 'No unrestricted autonomous production action',
    guards: ['PRODUCTION_EXECUTION', 'TRADING_OR_ORDER_ROUTING', 'AGENT_TOOL_EXECUTION'],
  },
  'RM-ACTION-LIMITS': {
    adapter: 'ACTION_LIMITS',
    phase: 'RUNTIME',
    title: 'Transaction/action limits',
    guards: ['PRODUCTION_EXECUTION', 'TRADING_OR_ORDER_ROUTING', 'EXTERNAL_DATA_TRANSMISSION'],
  },
  'MG-APPROVED-MODEL': {
    adapter: 'MODEL_ALLOWLIST',
    phase: 'RUNTIME',
    title: 'Approved model/provider',
    guards: ['AI_MODEL_INVOCATION'],
  },
  'IT-STRICT-ALLOWLISTS': {
    adapter: 'MODEL_ALLOWLIST',
    phase: 'RUNTIME',
    title: 'Strict model/tool/data allowlists',
    guards: ['AI_MODEL_INVOCATION', 'AGENT_TOOL_EXECUTION'],
  },
  'IT-INTEGRATION-ALLOWLIST': {
    adapter: 'EGRESS_ALLOWLIST',
    phase: 'RUNTIME',
    title: 'External integration allowlist',
    guards: ['EXTERNAL_DATA_TRANSMISSION', 'AGENT_TOOL_EXECUTION', 'TRADING_OR_ORDER_ROUTING'],
  },
  'IT-EGRESS-ALLOWLIST': {
    adapter: 'EGRESS_ALLOWLIST',
    phase: 'RUNTIME',
    title: 'Outbound egress allowlist',
    guards: ['EXTERNAL_DATA_TRANSMISSION', 'AGENT_TOOL_EXECUTION'],
  },
  'IA-FORMAL-RBAC': {
    adapter: 'RBAC',
    phase: 'RUNTIME',
    title: 'Formal RBAC',
    guards: ['DEPLOYMENT_EXECUTION', 'PRODUCTION_EXECUTION', 'EXTERNAL_DATA_TRANSMISSION', 'DATABASE_MUTATION', 'TRADING_OR_ORDER_ROUTING'],
  },
  'TI-STRICT-ISOLATION': {
    adapter: 'TENANT_ISOLATION',
    phase: 'RUNTIME',
    title: 'Strict tenant isolation',
    guards: ['DATABASE_MUTATION', 'EXTERNAL_DATA_TRANSMISSION'],
  },
};

/**
 * Derive which action types a classification makes protected (governed by the
 * plan). AI model invocation is always protected. Consequential types are added
 * only when the signals imply the app can perform them — an ungoverned
 * consequential action type is DENIED by the engine (ACTION_TYPE_NOT_PROTECTED).
 */
export function protectedActionTypesFor(signals: ClassificationSignals, tier: RiskTier): GovernedActionType[] {
  const set = new Set<GovernedActionType>(['AI_MODEL_INVOCATION']);
  const integ = signals.integration_types;

  if (integ.includes('TRADING_OR_ORDERS')) {
    set.add('TRADING_OR_ORDER_ROUTING');
  }

  if (integ.includes('PAYMENTS_OR_TRANSFERS')) {
    set.add('PRODUCTION_EXECUTION');
  }

  if (integ.includes('EXTERNAL_SYSTEM_OF_RECORD') || integ.includes('BUSINESS_SYSTEM_WRITE')) {
    set.add('EXTERNAL_DATA_TRANSMISSION');
    set.add('DATABASE_MUTATION');
  }

  if (integ.includes('OUTBOUND_COMMUNICATION')) {
    set.add('EXTERNAL_DATA_TRANSMISSION');
  }

  if (signals.autonomy_level === 'AUTONOMOUS') {
    set.add('AGENT_TOOL_EXECUTION');
    set.add('PRODUCTION_EXECUTION');
  }

  if (tier === 'T2' || tier === 'T3') {
    set.add('DEPLOYMENT_EXECUTION');
  }

  return Array.from(set).sort();
}
