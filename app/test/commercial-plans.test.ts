/**
 * QHUB Commercial Launch — plan/config consistency
 * app/test/commercial-plans.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  PLAN_CATALOG,
  listPlans,
  getPlan,
  basePlanEntitlements,
  formatPriceRef,
  LAUNCH_MAX_RISK_TIER,
  NO_PLAN_ENTITLEMENTS,
} from '~/lib/qhub/commercial/plans';
import { tierRank } from '~/lib/qhub/classification';

describe('plan catalog consistency', () => {
  it('references the documented commercial prices', () => {
    expect(PLAN_CATALOG.builder_beta.prices.monthly?.amountCents).toBe(7900);
    expect(PLAN_CATALOG.builder_beta.prices.annual?.amountCents).toBe(79000);
    expect(PLAN_CATALOG.guided_builder.prices.monthly?.amountCents).toBe(49900);
    expect(PLAN_CATALOG.guided_builder.prices.setupFee?.amountCents).toBe(150000);
  });

  it('every price references an env-var name for its Stripe id (no literal ids)', () => {
    for (const plan of listPlans()) {
      for (const p of [plan.prices.monthly, plan.prices.annual, plan.prices.setupFee]) {
        if (p) {
          expect(p.stripePriceEnv).toMatch(/^STRIPE_PRICE_[A-Z_]+$/);
        }
      }
    }
  });

  it('no plan exceeds the launch risk cap', () => {
    for (const plan of listPlans()) {
      expect(tierRank(plan.entitlements.maxRiskTier)).toBeLessThanOrEqual(tierRank(LAUNCH_MAX_RISK_TIER));
    }
  });

  it('no plan enables agents, consequential actions, or external writes', () => {
    for (const plan of listPlans()) {
      expect(plan.entitlements.agentBuilding).toBe(false);
      expect(plan.entitlements.consequentialActions).toBe(false);
      expect(plan.entitlements.externalWriteConnectors).toBe(false);
    }
  });

  it('the no-plan default is fully fail-closed', () => {
    expect(NO_PLAN_ENTITLEMENTS.appBuilding).toBe(false);
    expect(NO_PLAN_ENTITLEMENTS.maxProjects).toBe(0);
    expect(NO_PLAN_ENTITLEMENTS.buildCreditsPerMonth).toBe(0);
  });

  it('getPlan returns null for none, config for paid plans', () => {
    expect(getPlan('none')).toBeNull();
    expect(getPlan('builder_beta')?.id).toBe('builder_beta');
    expect(basePlanEntitlements('none').appBuilding).toBe(false);
  });

  it('formats reference prices for display', () => {
    expect(formatPriceRef({ amountCents: 7900, currency: 'usd', interval: 'month', stripePriceEnv: 'X' })).toBe(
      '$79/mo',
    );
    expect(formatPriceRef({ amountCents: 79000, currency: 'usd', interval: 'year', stripePriceEnv: 'X' })).toBe(
      '$790/yr',
    );
    expect(formatPriceRef({ amountCents: 150000, currency: 'usd', interval: 'one_time', stripePriceEnv: 'X' })).toBe(
      '$1,500 one-time',
    );
  });
});
