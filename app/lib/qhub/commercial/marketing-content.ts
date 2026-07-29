/**
 * QHUB Commercial Launch — MARKETING CONTENT (BROWSER-SAFE DATA)
 * app/lib/qhub/commercial/marketing-content.ts
 *
 * Data-driven content for the public website. Keeping copy + navigation +
 * honest product-state labels here (not scattered in JSX) makes the pages thin,
 * consistent, and testable. Every capability carries an honest state label
 * (Available / Private Beta / Preview / Planned). Nothing here claims an
 * unearned certification, partnership, or compliance status.
 */

import type { ProductState } from '~/lib/qhub/commercial/plans';

export const PRIMARY_MESSAGE = 'Build AI. Govern Every Action.';
export const CATEGORY_LINE = 'The governed AI creation and execution platform for financial services.';

// ─── Navigation ─────────────────────────────────────────────────────────────────

export interface NavLink {
  label: string;
  href: string;
}

export const NAV_LINKS: NavLink[] = [
  { label: 'Platform', href: '/platform' },
  { label: 'Builder', href: '/builder' },
  { label: 'Governance Essentials', href: '/governance-essentials' },
  { label: 'Guided Builder', href: '/guided-builder' },
  { label: 'Pricing', href: '/pricing' },
  { label: 'Security', href: '/security' },
  { label: 'Trust Center', href: '/trust-center' },
  { label: 'Docs', href: '/docs' },
  { label: 'Company', href: '/company' },
  { label: 'Contact', href: '/contact' },
];

export const PRIMARY_CTAS: NavLink[] = [
  { label: 'Start Building — Builder Beta', href: '/build' },
  { label: 'Build It With Quantex — Guided Builder', href: '/guided-builder' },
  { label: 'Request Institutional Demo', href: '/contact?type=institutional' },
];

// ─── Homepage lifecycle ─────────────────────────────────────────────────────────

export const LIFECYCLE_STEPS: string[] = [
  'Prompt',
  'Classify',
  'Apply Policy',
  'Build',
  'Review',
  'Release',
  'Evidence',
];

// ─── Capability status board (honest labels) ────────────────────────────────────

export interface CapabilityStatus {
  name: string;
  state: ProductState;
  note: string;
}

export const CAPABILITY_BOARD: CapabilityStatus[] = [
  { name: 'Prompt-to-app building (T0/T1)', state: 'private_beta', note: 'Builder Beta and Guided Builder.' },
  {
    name: 'Governance Essentials',
    state: 'private_beta',
    note: 'Classification, policy guidance, version records, human review.',
  },
  { name: 'Controlled source export', state: 'private_beta', note: 'Export the generated application source.' },
  { name: 'Manual / controlled publishing', state: 'private_beta', note: 'Publication passes a manual review gate.' },
  { name: 'Basic evidence export', state: 'private_beta', note: 'Export the governance record for an app version.' },
  { name: 'Institutional autonomous agents', state: 'planned', note: 'Not part of the launch tier.' },
  {
    name: 'Advanced execution governance',
    state: 'preview',
    note: 'Institutional offering — not commercially supported yet.',
  },
  { name: 'MCP connectors', state: 'planned', note: 'Planned; not available in the launch tier.' },
  { name: 'A2A orchestration', state: 'planned', note: 'Planned; not available in the launch tier.' },
  { name: 'FIX / market connectivity', state: 'planned', note: 'Planned; not available in the launch tier.' },
];

// ─── Generic page model ─────────────────────────────────────────────────────────

export interface PageSection {
  heading: string;
  body: string[];
  bullets?: string[];
  state?: ProductState;
}

export interface MarketingPageContent {
  slug: string;
  title: string;
  heading: string;
  intro: string;
  sections: PageSection[];
}

const SHARED_DISCLAIMER =
  'QHub does not claim FINRA, SEC, bank, SOC 2, ISO 27001, or legal compliance, and makes no ' +
  'institutional-assurance claim for the launch tier. Customers remain responsible for their legal, ' +
  'regulatory, security, and organizational obligations.';

export const PAGES: Record<string, MarketingPageContent> = {
  platform: {
    slug: 'platform',
    title: 'Platform — QHub',
    heading: 'The governed AI creation platform',
    intro: 'Prompt to app, with classification, policy guidance, review, and an evidence record at every step.',
    sections: [
      {
        heading: 'What is available now',
        body: ['The launch tier supports low-risk T0/T1 applications built from a prompt, with Governance Essentials.'],
        bullets: [
          'Prompt-to-app building',
          'Basic classification and policy guidance',
          'Human review + version records',
          'Controlled export and publishing',
        ],
        state: 'private_beta',
      },
      {
        heading: 'What is planned',
        body: [
          'Institutional autonomous agents, advanced execution governance, and market connectivity are planned or in preview and are not part of the launch tier.',
        ],
        bullets: [
          'Autonomous agents (Planned)',
          'MCP / A2A / FIX (Planned)',
          'Advanced execution governance (Preview)',
        ],
        state: 'planned',
      },
      { heading: 'Shared responsibility', body: [SHARED_DISCLAIMER] },
    ],
  },

  builder: {
    slug: 'builder',
    title: 'Builder — QHub',
    heading: 'QHub Builder Beta',
    intro: 'Build low-risk T0/T1 applications from a prompt, with Governance Essentials built in.',
    sections: [
      {
        heading: 'Built for low-risk work',
        body: [
          'Builder Beta is for public, synthetic, or ordinary non-sensitive internal data. It does not support autonomous agents, consequential external actions, or sensitive customer data.',
        ],
        state: 'private_beta',
      },
      {
        heading: 'In every build',
        body: ['Governance Essentials runs alongside your build.'],
        bullets: [
          'Purpose + data declaration',
          'T0/T1 classification',
          'Baseline policy card',
          'Version record + human acknowledgment',
          'Basic evidence export',
        ],
      },
    ],
  },

  'governance-essentials': {
    slug: 'governance-essentials',
    title: 'Governance Essentials — QHub',
    heading: 'Governance Essentials',
    intro:
      'Structured risk classification, policy guidance, version records, and human review for low-risk applications.',
    sections: [
      {
        heading: 'The flow',
        body: ['A lightweight, ten-step customer flow that runs alongside your build.'],
        bullets: [
          'Purpose declaration',
          'Use-case description',
          'Data declaration',
          'Basic T0/T1 classification',
          'Model + connector declaration',
          'Baseline policy card',
          'Version record',
          'Human acknowledgment',
          'Basic evidence export',
        ],
      },
      {
        heading: 'Data boundaries',
        body: [
          'Public, synthetic, and approved ordinary-internal data may proceed. Personal, financial, and restricted data require blocking or manual Quantex review. Secrets, credentials, MNPI, regulated records, and consequential actions are prohibited.',
        ],
      },
      { heading: 'What Governance Essentials is — and is not', body: [SHARED_DISCLAIMER] },
    ],
  },

  'guided-builder': {
    slug: 'guided-builder',
    title: 'Guided Builder — QHub',
    heading: 'QHub Guided Builder',
    intro: 'Quantex-supported design, build, and controlled launch of one governed application.',
    sections: [
      {
        heading: 'What you get',
        body: ['A guided path from use-case design to a controlled launch, supported by Quantex.'],
        bullets: [
          'Quantex-supported use-case design',
          'Classification & policy setup',
          'Guided build sessions',
          'Manual release review + deployment assistance',
          'Basic evidence export',
          'Priority support + monthly adoption review',
        ],
        state: 'private_beta',
      },
      {
        heading: 'Still within the low-risk boundary',
        body: [
          'Guided Builder remains a T0/T1 product. Supervised exceptions are only ever unlocked through a Quantex manual-review process — never automatically.',
        ],
      },
    ],
  },

  security: {
    slug: 'security',
    title: 'Security — QHub',
    heading: 'Security overview',
    intro: 'How the launch tier protects tenants, data, and access.',
    sections: [
      {
        heading: 'Access + isolation',
        body: [
          'Access is decided server-side by an entitlement layer, not the browser UI. Tenants are isolated at the data layer with row-level security; billing and governance tables are service-role only.',
        ],
        bullets: [
          'Server-authoritative entitlements',
          'Row-level tenant isolation',
          'Stripe-hosted checkout — no card data stored by QHub',
          'Signed, replay-protected billing webhooks',
        ],
      },
      {
        heading: 'Data restrictions',
        body: [
          'The launch tier does not accept regulated personal data, MNPI, credentials/secrets in prompts, or real-time execution adapters.',
        ],
      },
      { heading: 'No unearned claims', body: [SHARED_DISCLAIMER] },
    ],
  },

  'trust-center': {
    slug: 'trust-center',
    title: 'Trust Center — QHub',
    heading: 'Trust Center',
    intro: 'Honest, current statements about what the product does and does not do.',
    sections: [
      {
        heading: 'Product-state labels',
        body: [
          'Every capability is labeled Available, Private Beta, Preview, or Planned. We do not publish unearned certifications, partnerships, or customer logos.',
        ],
      },
      {
        heading: 'Shared responsibility',
        body: [SHARED_DISCLAIMER],
      },
      {
        heading: 'Known limitations',
        body: [
          'The launch tier is limited to low-risk T0/T1 applications. Autonomous consequential agents and institutional result-continuity are not part of this tier.',
        ],
      },
    ],
  },

  docs: {
    slug: 'docs',
    title: 'Docs — QHub',
    heading: 'Documentation',
    intro: 'Getting started, the builder guide, governance, billing, and limitations.',
    sections: [
      {
        heading: 'Guides',
        body: ['Initial documentation shells for the launch tier.'],
        bullets: [
          'Getting Started',
          'Builder Guide',
          'Governance Essentials',
          'Data Restrictions',
          'Acceptable Use',
          'Publishing Process',
          'Billing and Credits',
          'Security Overview',
          'Shared Responsibility',
          'Known Limitations',
          'Support',
          'Release Notes',
        ],
      },
    ],
  },

  company: {
    slug: 'company',
    title: 'Company — QHub',
    heading: 'Company',
    intro: 'QHub is built by Quantex Technologies.',
    sections: [
      {
        heading: 'Our focus',
        body: [
          'Governed AI creation and execution for financial services, starting with a low-risk commercial builder.',
        ],
      },
      { heading: 'Contact', body: ['Use the contact page to reach us or request an institutional demo.'] },
    ],
  },

  contact: {
    slug: 'contact',
    title: 'Contact — QHub',
    heading: 'Contact / Request Demo',
    intro: 'Get in touch, or request an institutional demo.',
    sections: [
      {
        heading: 'Builder Beta',
        body: ['Ready to try the builder? Start building from the Builder Beta call to action.'],
      },
      { heading: 'Guided Builder', body: ['Want Quantex to help you design and launch? Ask about Guided Builder.'] },
      {
        heading: 'Institutional',
        body: [
          'For the institutional offering (autonomous agents, advanced execution governance), request an institutional demo.',
        ],
      },
    ],
  },
};

export function getPage(slug: string): MarketingPageContent | null {
  return PAGES[slug] ?? null;
}
