/**
 * QHUB Commercial Launch — GENERIC MARKETING PAGE
 * app/components/marketing/MarketingPage.tsx
 *
 * Renders a data-driven MarketingPageContent inside the shell. Pure/presentational
 * — no router context — so it is SSR-testable via renderToStaticMarkup.
 */

import { MarketingShell } from '~/components/marketing/MarketingShell';
import { PRODUCT_STATE_LABEL } from '~/lib/qhub/commercial/plans';
import type { MarketingPageContent } from '~/lib/qhub/commercial/marketing-content';

export function StateBadge({ state }: { state: keyof typeof PRODUCT_STATE_LABEL }) {
  return (
    <span className="inline-block text-xs px-2 py-0.5 rounded border border-bolt-elements-borderColor text-bolt-elements-textSecondary">
      {PRODUCT_STATE_LABEL[state]}
    </span>
  );
}

export function MarketingPage({ content }: { content: MarketingPageContent }) {
  return (
    <MarketingShell>
      <article className="max-w-3xl mx-auto px-4 py-10">
        <h1 className="text-3xl font-semibold mb-3">{content.heading}</h1>
        <p className="text-bolt-elements-textSecondary text-lg mb-8">{content.intro}</p>

        <div className="space-y-8">
          {content.sections.map((s, i) => (
            <section key={i}>
              <h2 className="text-xl font-medium mb-2 flex items-center gap-2">
                {s.heading}
                {s.state ? <StateBadge state={s.state} /> : null}
              </h2>
              {s.body.map((p, j) => (
                <p key={j} className="text-bolt-elements-textSecondary mb-2">
                  {p}
                </p>
              ))}
              {s.bullets ? (
                <ul className="list-disc pl-6 text-bolt-elements-textSecondary space-y-1">
                  {s.bullets.map((b, k) => (
                    <li key={k}>{b}</li>
                  ))}
                </ul>
              ) : null}
            </section>
          ))}
        </div>
      </article>
    </MarketingShell>
  );
}
