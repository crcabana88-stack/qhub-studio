/**
 * QHUB Commercial Launch — public homepage (/home)
 * app/routes/home.tsx
 *
 * NOTE: the existing Studio app remains at "/" (_index.tsx). This marketing home
 * lives at /home for the launch. Flipping "/" to the marketing site is a deliberate
 * later cutover decision, not made here.
 */

import type { MetaFunction } from '@remix-run/cloudflare';
import { HomePage } from '~/components/marketing/HomePage';
import { PRIMARY_MESSAGE, CATEGORY_LINE } from '~/lib/qhub/commercial/marketing-content';

export const meta: MetaFunction = () => [
  { title: `QHub — ${PRIMARY_MESSAGE}` },
  { name: 'description', content: CATEGORY_LINE },
];

export default function Home() {
  return <HomePage />;
}
