/**
 * QHUB Commercial Launch — HOMEPAGE
 * app/components/marketing/HomePage.tsx
 *
 * The public homepage: primary message, lifecycle flow, honest capability board,
 * and the three primary calls to action. Pure/presentational (SSR-testable).
 */

import { MarketingShell } from '~/components/marketing/MarketingShell';
import { StateBadge } from '~/components/marketing/MarketingPage';
import {
  PRIMARY_MESSAGE,
  CATEGORY_LINE,
  LIFECYCLE_STEPS,
  CAPABILITY_BOARD,
  PRIMARY_CTAS,
} from '~/lib/qhub/commercial/marketing-content';

export function HomePage() {
  return (
    <MarketingShell>
      <section className="max-w-6xl mx-auto px-4 py-16 text-center">
        <h1 className="text-4xl md:text-5xl font-semibold mb-4">{PRIMARY_MESSAGE}</h1>
        <p className="text-xl text-bolt-elements-textSecondary mb-8">{CATEGORY_LINE}</p>

        <div className="flex flex-wrap items-center justify-center gap-3">
          {PRIMARY_CTAS.map((c) => (
            <a
              key={c.href}
              href={c.href}
              className="px-4 py-2 rounded border border-bolt-elements-borderColor hover:bg-bolt-elements-background-depth-2"
            >
              {c.label}
            </a>
          ))}
        </div>
      </section>

      <section aria-label="Lifecycle" className="max-w-6xl mx-auto px-4 py-8">
        <ol className="flex flex-wrap items-center justify-center gap-2 text-sm">
          {LIFECYCLE_STEPS.map((step, i) => (
            <li key={step} className="flex items-center gap-2">
              <span className="px-3 py-1.5 rounded bg-bolt-elements-background-depth-2">{step}</span>
              {i < LIFECYCLE_STEPS.length - 1 ? <span aria-hidden="true">→</span> : null}
            </li>
          ))}
        </ol>
      </section>

      <section aria-label="Capabilities" className="max-w-6xl mx-auto px-4 py-10">
        <h2 className="text-2xl font-medium mb-4 text-center">What is available now</h2>
        <ul className="grid gap-3 md:grid-cols-2">
          {CAPABILITY_BOARD.map((cap) => (
            <li
              key={cap.name}
              className="border border-bolt-elements-borderColor rounded p-4 flex items-start justify-between gap-3"
            >
              <div>
                <div className="font-medium">{cap.name}</div>
                <div className="text-sm text-bolt-elements-textSecondary">{cap.note}</div>
              </div>
              <StateBadge state={cap.state} />
            </li>
          ))}
        </ul>
      </section>
    </MarketingShell>
  );
}
