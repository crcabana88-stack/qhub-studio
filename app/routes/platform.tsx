// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — /platform
 * app/routes/platform.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('platform')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function PlatformRoute() {
  return <MarketingPage content={CONTENT} />;
}
