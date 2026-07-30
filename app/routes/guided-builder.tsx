// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — /guided-builder
 * app/routes/guided-builder.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('guided-builder')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function GuidedBuilderRoute() {
  return <MarketingPage content={CONTENT} />;
}
