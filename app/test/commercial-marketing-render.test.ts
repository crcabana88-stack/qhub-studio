/**
 * QHUB Commercial Launch — website content completeness + route inventory
 * app/test/commercial-marketing-render.test.ts
 *
 * The repo's Remix Vite plugin injects a Fast-Refresh preamble that is
 * incompatible with rendering .tsx via renderToStaticMarkup under vitest, so this
 * suite validates the substance the pages render — content model, honest product-
 * state labels, absence of unearned compliance claims — and that every required
 * public route file exists. Route loader behavior is covered by the route tests.
 */

import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  PAGES,
  NAV_LINKS,
  PRIMARY_CTAS,
  LIFECYCLE_STEPS,
  CAPABILITY_BOARD,
  PRIMARY_MESSAGE,
  CATEGORY_LINE,
} from '~/lib/qhub/commercial/marketing-content';

const ROUTES_DIR = fileURLToPath(new URL('../routes/', import.meta.url));

const REQUIRED_ROUTE_FILES = [
  'home.tsx',
  'platform.tsx',
  'builder.tsx',
  'governance-essentials.tsx',
  'guided-builder.tsx',
  'pricing.tsx',
  'security.tsx',
  'trust-center.tsx',
  'docs.tsx',
  'company.tsx',
  'contact.tsx',
  'build.tsx',
  'api.entitlements.ts',
  'api.billing.checkout.ts',
  'api.billing.portal.ts',
  'api.billing.webhook.ts',
];

describe('website route inventory', () => {
  const files = new Set(readdirSync(ROUTES_DIR));

  for (const f of REQUIRED_ROUTE_FILES) {
    it(`route file exists: ${f}`, () => {
      expect(files.has(f)).toBe(true);
    });
  }
});

describe('homepage content', () => {
  it('carries the primary message + category line', () => {
    expect(PRIMARY_MESSAGE).toBe('Build AI. Govern Every Action.');
    expect(CATEGORY_LINE).toContain('governed AI creation and execution platform for financial services');
  });

  it('has the full 7-step lifecycle', () => {
    expect(LIFECYCLE_STEPS).toEqual(['Prompt', 'Classify', 'Apply Policy', 'Build', 'Review', 'Release', 'Evidence']);
  });

  it('has the three primary CTAs', () => {
    const labels = PRIMARY_CTAS.map((c) => c.label);
    expect(labels.some((l) => l.includes('Builder Beta'))).toBe(true);
    expect(labels.some((l) => l.includes('Guided Builder'))).toBe(true);
    expect(labels.some((l) => l.includes('Institutional Demo'))).toBe(true);
  });

  it('labels institutional capabilities honestly (Planned / Preview, not Available)', () => {
    const institutional = CAPABILITY_BOARD.filter((c) => /agent|MCP|A2A|FIX|execution governance/i.test(c.name));
    expect(institutional.length).toBeGreaterThan(0);

    for (const cap of institutional) {
      expect(['planned', 'preview']).toContain(cap.state);
    }
  });
});

describe('page content completeness', () => {
  const expectedSlugs = [
    'platform',
    'builder',
    'governance-essentials',
    'guided-builder',
    'security',
    'trust-center',
    'docs',
    'company',
    'contact',
  ];

  for (const slug of expectedSlugs) {
    it(`page "${slug}" is complete`, () => {
      const p = PAGES[slug];
      expect(p, slug).toBeTruthy();
      expect(p.heading.length).toBeGreaterThan(0);
      expect(p.intro.length).toBeGreaterThan(0);
      expect(p.sections.length).toBeGreaterThan(0);
    });
  }

  it('nav links point at real pages or dedicated routes', () => {
    const dedicated = new Set(['home', 'pricing']);

    for (const link of NAV_LINKS) {
      const slug = link.href.replace(/^\//, '');
      expect(Boolean(PAGES[slug]) || dedicated.has(slug), link.href).toBe(true);
    }
  });

  it('makes no unearned compliance/certification claims anywhere in content', () => {
    const allText = JSON.stringify(PAGES).toLowerCase();
    expect(allText).not.toContain('soc 2 certified');
    expect(allText).not.toContain('iso 27001 certified');
    expect(allText).not.toContain('finra approved');
    expect(allText).not.toContain('sec approved');
  });

  it('governance-essentials page states the data boundary + prohibitions', () => {
    const text = JSON.stringify(PAGES['governance-essentials']).toLowerCase();
    expect(text).toContain('manual quantex review');
    expect(text).toContain('prohibited');
  });
});
