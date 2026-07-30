// @qhub-route: PUBLIC_SAFE
/**
 * QHUB Commercial Launch — pricing (/pricing)
 * app/routes/pricing.tsx
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { PricingPage } from '~/components/marketing/PricingPage';

export const meta: MetaFunction = () => [
  { title: 'Pricing — QHub' },
  { name: 'description', content: 'Builder Beta and Guided Builder plans for low-risk T0/T1 applications.' },
];

export default function Pricing() {
  return <PricingPage />;
}
