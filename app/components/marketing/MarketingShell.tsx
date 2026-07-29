/**
 * QHUB Commercial Launch — MARKETING SHELL
 * app/components/marketing/MarketingShell.tsx
 *
 * Presentational chrome (nav + footer) for the public website. Uses plain anchors
 * so it renders server-side without Remix router context (SSR-testable). Contains
 * the honest shared-responsibility disclaimer in the footer.
 */

import type { ReactNode } from 'react';
import { NAV_LINKS, CATEGORY_LINE } from '~/lib/qhub/commercial/marketing-content';
import { SHARED_RESPONSIBILITY_STATEMENT } from '~/lib/qhub/commercial/governance-essentials';

export interface MarketingShellProps {
  children: ReactNode;
}

export function MarketingShell({ children }: MarketingShellProps) {
  return (
    <div className="min-h-full flex flex-col bg-bolt-elements-background-depth-1 text-bolt-elements-textPrimary">
      <header className="border-b border-bolt-elements-borderColor">
        <nav aria-label="Primary" className="max-w-6xl mx-auto flex items-center gap-4 flex-wrap px-4 py-3">
          <a href="/home" className="font-semibold text-lg mr-2">
            QHub
          </a>
          <ul className="flex items-center gap-3 flex-wrap text-sm">
            {NAV_LINKS.map((l) => (
              <li key={l.href}>
                <a href={l.href} className="hover:underline">
                  {l.label}
                </a>
              </li>
            ))}
          </ul>
          <div className="ml-auto flex items-center gap-2 text-sm">
            <a href="/login" className="px-3 py-1.5 rounded border border-bolt-elements-borderColor">
              Sign In
            </a>
            <a
              href="/build"
              className="px-3 py-1.5 rounded bg-bolt-elements-button-primary-background text-bolt-elements-button-primary-text"
            >
              Start Building
            </a>
          </div>
        </nav>
      </header>

      <main className="flex-1 w-full">{children}</main>

      <footer className="border-t border-bolt-elements-borderColor mt-12">
        <div className="max-w-6xl mx-auto px-4 py-8 text-sm text-bolt-elements-textSecondary space-y-2">
          <p className="font-medium text-bolt-elements-textPrimary">{CATEGORY_LINE}</p>
          <p>{SHARED_RESPONSIBILITY_STATEMENT}</p>
          <p>
            © {new Date().getUTCFullYear()} Quantex Technologies. QHub. Product capabilities are labeled Available,
            Private Beta, Preview, or Planned.
          </p>
        </div>
      </footer>
    </div>
  );
}
