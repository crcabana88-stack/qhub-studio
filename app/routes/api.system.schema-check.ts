/**
 * QHUB schema diagnostic — app/routes/api.system.schema-check.ts
 *
 * GET /api/system/schema-check
 *
 * Exposes the NON-SECRET expected-vs-current schema diff for the connected
 * Supabase project: which objects the running code requires and which are
 * present. This is the diagnostic that would have caught the Gate 03 live
 * closure mismatch immediately (deployed Studio pointed at a project missing
 * the classification migration).
 *
 * NEVER returns keys — only the project ref (already public in every API URL)
 * and the Supabase host. Pass ?force=1 to bypass the readiness cache.
 *
 * Returns 200 when ready, 503 when the project is behind the code.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getSchemaReadiness } from '~/lib/qhub/schema-check.server';

export const loader = async ({ request, context }: LoaderFunctionArgs) => {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const force = new URL(request.url).searchParams.get('force') === '1';

  const report = await getSchemaReadiness(env, { force });

  return json(
    {
      ready: report.ready,
      expectedSchemaVersion: report.expectedSchemaVersion,
      projectRef: report.projectRef,
      supabaseHost: report.supabaseHost,
      checkedAt: report.checkedAt,
      objects: report.objects.map((o) => ({
        table: o.table,
        column: o.column,
        migration: o.migration,
        requiredBy: o.requiredBy,
        state: o.state,
        ...(o.detail ? { detail: o.detail } : {}),
      })),
      missing: report.missing.map((m) => ({ table: m.table, column: m.column, migration: m.migration })),
      ...(report.error ? { error: report.error } : {}),
    },
    { status: report.ready ? 200 : 503 },
  );
};

/** POST is not supported — this is a read-only diagnostic. */
export async function action() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
