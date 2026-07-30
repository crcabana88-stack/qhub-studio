// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — /governance-essentials
 * app/routes/governance-essentials.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('governance-essentials')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function GovernanceEssentialsRoute() {
  return <MarketingPage content={CONTENT} />;
}
