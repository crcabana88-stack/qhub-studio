// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — /security
 * app/routes/security.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('security')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function SecurityRoute() {
  return <MarketingPage content={CONTENT} />;
}
