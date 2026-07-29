/**
 * QHUB Commercial Launch R2 — CAPABILITY MODEL (BROWSER-SAFE, PURE)
 * app/lib/qhub/commercial/capabilities.ts
 *
 * The commercial capability vocabulary and the pure mapping from an authoritative
 * (entitlements + membership + staff + onboarding) snapshot to the set of granted
 * capabilities. requireCommercialContext (server) uses this to decide access.
 *
 * Launch invariants encoded here: commercial customers can only APP_BUILD at
 * T0/T1 with export + manual publication; agent/consequential/external-write are
 * never granted to a commercial customer. Internal Quantex staff receive the
 * development capability set from their authoritative staff record only.
 */

import type { Entitlements } from '~/lib/qhub/commercial/plans';
import type { ServiceState } from '~/lib/qhub/commercial/entitlements.server';

export type Capability =
  | 'APP_BUILD'
  | 'MODEL_INVOKE'
  | 'PROJECT_CREATE'
  | 'CODE_EXPORT'
  | 'EVIDENCE_EXPORT'
  | 'PUBLISH_REQUEST'
  | 'CHECKOUT'
  | 'PORTAL'
  | 'REVIEW_REQUEST'

  // Denied to commercial customers — only staff hold these:
  | 'AGENT_BUILD'
  | 'AGENT_RUN'
  | 'APP_PLUS_AGENT'
  | 'EXTERNAL_WRITE'
  | 'CONSEQUENTIAL_ACTION'
  | 'STAFF_OVERRIDE'
  | 'REVIEW_DECIDE';

/** Capabilities that are NEVER available to a commercial customer at launch. */
export const STAFF_ONLY_CAPABILITIES: Capability[] = [
  'AGENT_BUILD',
  'AGENT_RUN',
  'APP_PLUS_AGENT',
  'EXTERNAL_WRITE',
  'CONSEQUENTIAL_ACTION',
  'STAFF_OVERRIDE',
  'REVIEW_DECIDE',
];

export interface CapabilityInputs {
  serviceState: ServiceState;
  entitlements: Entitlements;
  membershipActive: boolean;

  /** Membership role (authoritative, from DB). */
  role: 'owner' | 'admin' | 'billing_admin' | 'builder' | 'viewer' | null;
  isStaff: boolean;
  onboardingComplete: boolean;
  suspended: boolean;
}

/** True when the membership role may manage billing (checkout/portal). */
export function isBillingAdminRole(role: CapabilityInputs['role']): boolean {
  return role === 'owner' || role === 'admin' || role === 'billing_admin';
}

/**
 * Compute the granted capability set. Pure. Fails closed: a suspended or inactive
 * membership grants nothing; a commercial customer never receives a staff-only
 * capability; model invocation additionally requires completed onboarding.
 */
export function computeCapabilities(inp: CapabilityInputs): Set<Capability> {
  const caps = new Set<Capability>();

  // Internal staff: development capability set from the authoritative staff record.
  if (inp.isStaff) {
    for (const c of STAFF_ONLY_CAPABILITIES) {
      caps.add(c);
    }

    caps.add('APP_BUILD');
    caps.add('MODEL_INVOKE');
    caps.add('PROJECT_CREATE');
    caps.add('CODE_EXPORT');
    caps.add('EVIDENCE_EXPORT');
    caps.add('PUBLISH_REQUEST');
    caps.add('REVIEW_REQUEST');

    return caps;
  }

  // Commercial customer: fail closed on inactive/suspended membership.
  if (!inp.membershipActive || inp.suspended) {
    return caps;
  }

  const active = inp.serviceState === 'active';
  const readOnly = inp.serviceState === 'restricted'; // past_due: keep read/export, no new consumption

  if ((active || readOnly) && inp.entitlements.codeExport) {
    caps.add('CODE_EXPORT');
  }

  if ((active || readOnly) && inp.entitlements.evidenceExport) {
    caps.add('EVIDENCE_EXPORT');
  }

  // Billing management is available to billing-admin roles regardless of service state.
  if (isBillingAdminRole(inp.role)) {
    caps.add('CHECKOUT');
    caps.add('PORTAL');
  }

  caps.add('REVIEW_REQUEST');

  /*
   * App building + model invocation + project creation require an ACTIVE service
   * state, the entitlement, and completed onboarding.
   */
  if (active && inp.entitlements.appBuilding) {
    caps.add('APP_BUILD');
    caps.add('PROJECT_CREATE');

    if (inp.onboardingComplete) {
      caps.add('MODEL_INVOKE');
    }

    if (inp.entitlements.publishMode === 'manual_review') {
      caps.add('PUBLISH_REQUEST');
    }
  }

  return caps;
}

export function hasCapability(caps: Set<Capability>, c: Capability): boolean {
  return caps.has(c);
}
