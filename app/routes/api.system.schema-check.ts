/**
 * QHUB schema diagnostic — app/routes/api.system.schema-check.ts
 *
 * GET /api/system/schema-check   (AUTHENTICATED)
 *
 * Exposes the NON-SECRET expected-vs-current schema diff for the connected
 * Supabase project: which objects the running code requires and which are
 * present. This is the diagnostic that would have caught the Gate 03 live
 * closure mismatch immediately (deployed Studio pointed at a project missing
 * the classification migration).
 *
 * ACCESS: requires an authenticated QHUB session. Unauthenticated callers get
 * 401 — the detailed diff (project ref, host, object inventory) is operator
 * information, so the public surface is limited to the generic /api/health.
 *
 * NEVER returns keys — only the project ref (already public in every API URL)
 * and the Supabase host. Pass ?force=1 to bypass the readiness cache.
 *
 * Returns 200 when ready, 503 when the project is behind the code.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { getSchemaReadiness } from '~/lib/qhub/schema-check.server';
import { getAgentSchemaReadiness } from '~/lib/qhub/agent/agent-schema-check.server';
import {
  getCommercialSchemaReadiness,
  resetCommercialReadinessCache,
} from '~/lib/qhub/commercial/commercial-schema-check.server';

export const loader = async ({ request, context }: LoaderFunctionArgs) => {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  // R3: the detailed schema diagnostic is an internal surface — Quantex-STAFF-ONLY.
  const guard = await requireStaff(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const force = new URL(request.url).searchParams.get('force') === '1';

  if (force) {
    resetCommercialReadinessCache();
  }

  const report = await getSchemaReadiness(env, { force });
  const agent = await getAgentSchemaReadiness(env, { force });
  const commercial = await getCommercialSchemaReadiness(env);

  return json(
    {
      ok: true,
      ready: report.ready,
      expectedSchemaVersion: report.expectedSchemaVersion,
      projectRef: report.projectRef,
      supabaseHost: report.supabaseHost,
      checkedAt: report.checkedAt,
      objects: report.objects.map((o) => ({
        identifier: o.identifier ?? `${o.table}.${o.column}`,
        category: o.category ?? 'COLUMN',
        migration: o.migration,
        requiredBy: o.requiredBy,
        state: o.state,
        ...(o.detail ? { detail: o.detail } : {}),
      })),
      missing: report.missing.map((m) => ({
        identifier: m.identifier ?? `${m.table}.${m.column}`,
        category: m.category ?? 'COLUMN',
        migration: m.migration,
      })),
      ...(report.error ? { error: report.error } : {}),

      // Agent Framework readiness (separate contract; compact, non-secret).
      agent: {
        ready: agent.ready,
        expectedSchemaVersion: agent.expectedSchemaVersion,
        objects: agent.objects.map((o) => ({
          identifier: o.identifier ?? `${o.table}.${o.column}`,
          category: o.category ?? 'COLUMN',
          state: o.state,
          ...(o.detail ? { detail: o.detail } : {}),
        })),
        missing: agent.missing.map((m) => m.identifier ?? `${m.table}.${m.column}`),
        ...(agent.error ? { error: agent.error } : {}),
      },

      // Commercial Launch readiness (separate contract; compact, non-secret).
      commercial: {
        state: commercial.state,
        ready: commercial.state === 'READY',
        expectedSchemaVersion: commercial.expected,
        actualSchemaVersion: commercial.version ?? null,
        failed: commercial.failed,
        checkedAt: commercial.checkedAt,
        ...(commercial.cacheAgeMs !== undefined ? { cacheAgeMs: commercial.cacheAgeMs } : {}),
      },
    },
    { status: report.ready && agent.ready && commercial.state === 'READY' ? 200 : 503 },
  );
};

/** POST is not supported — this is a read-only diagnostic. */
export async function action() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
