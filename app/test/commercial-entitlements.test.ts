/**
 * QHUB Commercial Launch — entitlement resolution + decisions
 * app/test/commercial-entitlements.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  resolveEntitlements,
  decideProjectCreation,
  decideSeatAddition,
  decideRiskTier,
  decideAppBuild,
  decideAgentBuild,
  decideExternalWrite,
  decideConsequentialAction,
  decideCodeExport,
  decidePublish,
  decideSensitiveData,
  decideBuildCredit,
  type SubscriptionStatus,
} from '~/lib/qhub/commercial/entitlements.server';

describe('entitlement resolution', () => {
  it('resolves Builder Beta base entitlements when active', () => {
    const r = resolveEntitlements({ planId: 'builder_beta', status: 'active' });
    expect(r.serviceState).toBe('active');
    expect(r.entitlements.seats).toBe(1);
    expect(r.entitlements.maxProjects).toBe(5);
    expect(r.entitlements.appBuilding).toBe(true);
    expect(r.entitlements.agentBuilding).toBe(false);
    expect(r.entitlements.maxRiskTier).toBe('T1');
  });

  it('fails closed to NO_PLAN when there is no active subscription', () => {
    for (const status of ['canceled', 'incomplete', 'none'] as SubscriptionStatus[]) {
      const r = resolveEntitlements({ planId: 'builder_beta', status });
      expect(r.serviceState).toBe('inactive');
      expect(r.entitlements.maxProjects).toBe(0);
      expect(r.entitlements.appBuilding).toBe(false);
      expect(r.entitlements.buildCreditsPerMonth).toBe(0);
    }
  });

  it('restricts (past_due) — keeps read/export but cuts new consumption', () => {
    const r = resolveEntitlements({ planId: 'builder_beta', status: 'past_due' });
    expect(r.serviceState).toBe('restricted');
    expect(r.entitlements.buildCreditsPerMonth).toBe(0);
    expect(r.entitlements.publishMode).toBe('export_only');
    expect(r.entitlements.codeExport).toBe(true); // export still allowed
  });

  it('never allows agent building or consequential actions regardless of config', () => {
    const r = resolveEntitlements({ planId: 'guided_builder', status: 'active' });
    expect(r.entitlements.agentBuilding).toBe(false);
    expect(r.entitlements.consequentialActions).toBe(false);
    expect(r.entitlements.externalWriteConnectors).toBe(false);
  });

  it('honors a Guided manual override for sensitive data + bonus credits', () => {
    const base = resolveEntitlements({ planId: 'guided_builder', status: 'active' });
    const withOverride = resolveEntitlements({
      planId: 'guided_builder',
      status: 'active',
      overrides: { sensitiveDataReviewApproved: true, bonusBuildCredits: 500 },
    });
    expect(withOverride.entitlements.sensitiveDataReviewAllowed).toBe(true);
    expect(withOverride.entitlements.buildCreditsPerMonth).toBe(base.entitlements.buildCreditsPerMonth + 500);
  });

  it('ignores overrides for a plan that does not allow exceptions (Builder Beta)', () => {
    const r = resolveEntitlements({
      planId: 'builder_beta',
      status: 'active',
      overrides: { sensitiveDataReviewApproved: true, bonusBuildCredits: 999 },
    });
    expect(r.entitlements.sensitiveDataReviewAllowed).toBe(false);
    expect(r.entitlements.buildCreditsPerMonth).toBe(200);
  });
});

describe('entitlement decisions', () => {
  const beta = resolveEntitlements({ planId: 'builder_beta', status: 'active' }).entitlements;

  it('enforces the Builder Beta project limit', () => {
    expect(decideProjectCreation(beta, 4).allowed).toBe(true);

    const denied = decideProjectCreation(beta, 5);
    expect(denied.allowed).toBe(false);
    expect(denied.reasonCode).toBe('PROJECT_LIMIT_REACHED');
  });

  it('enforces the Builder Beta seat limit', () => {
    expect(decideSeatAddition(beta, 0).allowed).toBe(true);
    expect(decideSeatAddition(beta, 1).allowed).toBe(false);
  });

  it('rejects T2/T3 risk tiers', () => {
    expect(decideRiskTier(beta, 'T0').allowed).toBe(true);
    expect(decideRiskTier(beta, 'T1').allowed).toBe(true);
    expect(decideRiskTier(beta, 'T2').allowed).toBe(false);
    expect(decideRiskTier(beta, 'T3').allowed).toBe(false);
  });

  it('rejects agent building and consequential actions unconditionally', () => {
    expect(decideAgentBuild(beta).allowed).toBe(false);
    expect(decideConsequentialAction(beta).allowed).toBe(false);
    expect(decideExternalWrite(beta).allowed).toBe(false);
  });

  it('allows app building + code export on Builder Beta', () => {
    expect(decideAppBuild(beta).allowed).toBe(true);
    expect(decideCodeExport(beta).allowed).toBe(true);
  });

  it('rejects sensitive data on Builder Beta, allows it after Guided override', () => {
    expect(decideSensitiveData(beta).allowed).toBe(false);

    const guided = resolveEntitlements({
      planId: 'guided_builder',
      status: 'active',
      overrides: { sensitiveDataReviewApproved: true },
    }).entitlements;
    expect(decideSensitiveData(guided).allowed).toBe(true);
  });

  it('requires manual review before publishing', () => {
    expect(decidePublish(beta, false).allowed).toBe(false);
    expect(decidePublish(beta, false).reasonCode).toBe('PUBLISH_REVIEW_REQUIRED');
    expect(decidePublish(beta, true).allowed).toBe(true);
  });

  it('decrements/exhausts build credits', () => {
    expect(decideBuildCredit(1).allowed).toBe(true);
    expect(decideBuildCredit(0).allowed).toBe(false);
    expect(decideBuildCredit(0).reasonCode).toBe('BUILD_CREDITS_EXHAUSTED');
  });
});
