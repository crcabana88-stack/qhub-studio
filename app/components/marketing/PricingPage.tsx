/**
 * QHUB Commercial Launch — PRICING PAGE
 * app/components/marketing/PricingPage.tsx
 *
 * Plan cards driven entirely by the plan catalog (plans.ts). Reference prices are
 * display-only; nothing here initiates a charge. Pure/presentational.
 */

import { MarketingShell } from '~/components/marketing/MarketingShell';
import { StateBadge } from '~/components/marketing/MarketingPage';
import { listPlans, formatPriceRef } from '~/lib/qhub/commercial/plans';

export function PricingPage() {
  const plans = listPlans();

  return (
    <MarketingShell>
      <section className="max-w-5xl mx-auto px-4 py-12">
        <h1 className="text-3xl font-semibold mb-2">Pricing</h1>
        <p className="text-bolt-elements-textSecondary mb-8">
          Low-risk T0/T1 plans. Reference prices shown below; billing is activated in test mode first.
        </p>

        <div className="grid gap-6 md:grid-cols-2">
          {plans.map((plan) => (
            <div key={plan.id} className="border border-bolt-elements-borderColor rounded-lg p-6 flex flex-col">
              <div className="flex items-center justify-between gap-2 mb-1">
                <h2 className="text-xl font-medium">{plan.name}</h2>
                <StateBadge state={plan.state} />
              </div>
              <p className="text-sm text-bolt-elements-textSecondary mb-4">{plan.tagline}</p>

              <div className="mb-4 space-y-1">
                {plan.prices.monthly ? (
                  <div className="text-2xl font-semibold">{formatPriceRef(plan.prices.monthly)}</div>
                ) : null}
                {plan.prices.annual ? (
                  <div className="text-sm text-bolt-elements-textSecondary">
                    {formatPriceRef(plan.prices.annual)} billed annually
                  </div>
                ) : null}
                {plan.prices.setupFee ? (
                  <div className="text-sm text-bolt-elements-textSecondary">
                    {formatPriceRef(plan.prices.setupFee)} setup
                  </div>
                ) : null}
              </div>

              <ul className="list-disc pl-5 text-sm text-bolt-elements-textSecondary space-y-1 mb-6">
                {plan.highlights.map((h) => (
                  <li key={h}>{h}</li>
                ))}
              </ul>

              <a
                href={plan.id === 'builder_beta' ? '/build' : '/guided-builder'}
                className="mt-auto text-center px-4 py-2 rounded bg-bolt-elements-button-primary-background text-bolt-elements-button-primary-text"
              >
                {plan.id === 'builder_beta' ? 'Start Building' : 'Build It With Quantex'}
              </a>
            </div>
          ))}
        </div>

        <p className="text-xs text-bolt-elements-textSecondary mt-8">
          No autonomous agents, consequential external actions, or sensitive customer data in the launch tier.
        </p>
      </section>
    </MarketingShell>
  );
}
