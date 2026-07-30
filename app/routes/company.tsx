// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — /company
 * app/routes/company.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { MarketingPage } from '~/components/marketing/MarketingPage';
import { getPage } from '~/lib/qhub/commercial/marketing-content';

const CONTENT = getPage('company')!;

export const meta: MetaFunction = () => [{ title: CONTENT.title }, { name: 'description', content: CONTENT.intro }];

export default function CompanyRoute() {
  return <MarketingPage content={CONTENT} />;
}
