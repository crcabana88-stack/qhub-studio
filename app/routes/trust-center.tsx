/**
 * QHUB Commercial Launch — /trust-center
 * app/routes/trust-center.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('trust-center')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function TrustCenterRoute() {
  return <MarketingPage content={CONTENT} />;
}
