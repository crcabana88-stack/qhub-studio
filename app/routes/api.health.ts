/**
 * QHUB health check — app/routes/api.health.ts
 *
 * Liveness + schema readiness. Returns 503 when the connected Supabase project
 * is behind the code, so orchestrators / smoke checks refuse to treat a
 * schema-drifted deployment as healthy (the failure mode from Gate 03 closure).
 *
 * All fields are NON-SECRET: project ref and Supabase host only — never keys.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getSchemaReadiness } from '~/lib/qhub/schema-check.server';

export const loader = async ({ context }: LoaderFunctionArgs) => {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  const schema = await getSchemaReadiness(env);

  const body = {
    status: schema.ready ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    schema: {
      ready: schema.ready,
      expectedSchemaVersion: schema.expectedSchemaVersion,
      projectRef: schema.projectRef,
      supabaseHost: schema.supabaseHost,
      missing: schema.missing.map((m) => ({ table: m.table, column: m.column, migration: m.migration })),
      ...(schema.error ? { error: schema.error } : {}),
    },
  };

  // 200 when ready, 503 when the project is behind the code — loudly not-healthy.
  return json(body, { status: schema.ready ? 200 : 503 });
};
