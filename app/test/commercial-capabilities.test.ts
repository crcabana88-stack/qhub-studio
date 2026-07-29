/**
 * QHUB Commercial Launch R2 — capability mapping
 * app/test/commercial-capabilities.test.ts
 */

import { describe, it, expect } from 'vitest';
import { computeCapabilities, isBillingAdminRole, STAFF_ONLY_CAPABILITIES } from '~/lib/qhub/commercial/capabilities';
import { resolveEntitlements } from '~/lib/qhub/commercial/entitlements.server';
import { NO_PLAN_ENTITLEMENTS } from '~/lib/qhub/commercial/plans';

const beta = resolveEntitlements({ planId: 'builder_beta', status: 'active' }).entitlements;

describe('computeCapabilities', () => {
  it('grants app build + model invoke to an active, onboarded builder', () => {
    const caps = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'builder',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });
    expect(caps.has('APP_BUILD')).toBe(true);
    expect(caps.has('MODEL_INVOKE')).toBe(true);
    expect(caps.has('PROJECT_CREATE')).toBe(true);
  });

  it('never grants a staff-only capability to a commercial customer', () => {
    const caps = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'owner',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });

    for (const c of STAFF_ONLY_CAPABILITIES) {
      expect(caps.has(c), c).toBe(false);
    }
  });

  it('withholds MODEL_INVOKE until onboarding is complete', () => {
    const caps = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'builder',
      isStaff: false,
      onboardingComplete: false,
      suspended: false,
    });
    expect(caps.has('APP_BUILD')).toBe(true);
    expect(caps.has('MODEL_INVOKE')).toBe(false);
  });

  it('grants nothing on an inactive or suspended membership', () => {
    const inactive = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: false,
      role: 'builder',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });
    expect(inactive.size).toBe(0);

    const suspended = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'builder',
      isStaff: false,
      onboardingComplete: true,
      suspended: true,
    });
    expect(suspended.size).toBe(0);
  });

  it('denies APP_BUILD/MODEL_INVOKE with no active plan', () => {
    const caps = computeCapabilities({
      serviceState: 'inactive',
      entitlements: { ...NO_PLAN_ENTITLEMENTS },
      membershipActive: true,
      role: 'builder',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });
    expect(caps.has('APP_BUILD')).toBe(false);
    expect(caps.has('MODEL_INVOKE')).toBe(false);
  });

  it('grants CHECKOUT/PORTAL only to billing-admin roles', () => {
    const billing = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'billing_admin',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });
    expect(billing.has('CHECKOUT')).toBe(true);
    expect(billing.has('PORTAL')).toBe(true);

    const viewer = computeCapabilities({
      serviceState: 'active',
      entitlements: beta,
      membershipActive: true,
      role: 'viewer',
      isStaff: false,
      onboardingComplete: true,
      suspended: false,
    });
    expect(viewer.has('CHECKOUT')).toBe(false);
  });

  it('grants staff the full development capability set', () => {
    const caps = computeCapabilities({
      serviceState: 'inactive',
      entitlements: { ...NO_PLAN_ENTITLEMENTS },
      membershipActive: false,
      role: null,
      isStaff: true,
      onboardingComplete: false,
      suspended: false,
    });
    expect(caps.has('AGENT_BUILD')).toBe(true);
    expect(caps.has('CONSEQUENTIAL_ACTION')).toBe(true);
    expect(caps.has('MODEL_INVOKE')).toBe(true);
    expect(caps.has('REVIEW_DECIDE')).toBe(true);
  });

  it('billing-admin role predicate', () => {
    expect(isBillingAdminRole('owner')).toBe(true);
    expect(isBillingAdminRole('admin')).toBe(true);
    expect(isBillingAdminRole('billing_admin')).toBe(true);
    expect(isBillingAdminRole('builder')).toBe(false);
    expect(isBillingAdminRole('viewer')).toBe(false);
    expect(isBillingAdminRole(null)).toBe(false);
  });
});
