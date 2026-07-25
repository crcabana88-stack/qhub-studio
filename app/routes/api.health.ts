/**
 * QHUB health check — app/routes/api.health.ts
 *
 * PUBLIC liveness + readiness. Returns a GENERIC status only:
 *   200 { status: 'healthy' }   when the connected schema is ready
 *   503 { status: 'degraded' }  when the project is behind the code
 *
 * It deliberately exposes NO internal schema detail (no project ref, host,
 * expected version, or missing-object names) — anyone can call it. The detailed
 * expected-vs-current diff lives behind authentication at
 * /api/system/schema-check. Drift is still logged loudly server-side by
 * getSchemaReadiness().
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getSchemaReadiness } from '~/lib/qhub/schema-check.server';

export const loader = async ({ context }: LoaderFunctionArgs) => {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  const schema = await getSchemaReadiness(env);

  // Generic body only — never leak schema internals on the public endpoint.
  return json(
    {
      status: schema.ready ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
    },
    { status: schema.ready ? 200 : 503 },
  );
};
