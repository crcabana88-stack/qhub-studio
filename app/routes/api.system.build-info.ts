/**
 * QHUB build identity diagnostic — app/routes/api.system.build-info.ts
 *
 * Authenticated (401 for anon). Reports the NON-SECRET build identity injected at
 * deploy time (source commit, artifact hash, build time) so a post-deploy check
 * can confirm the running image matches the intended Git commit. Exposes no
 * secrets, SQL, or customer data. Public /api/health stays generic.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { REQUIRED_BUILD_MARKERS } from '~/lib/qhub/build-identity';

export const loader = async ({ request, context }: LoaderFunctionArgs) => {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  // R3: build/deploy diagnostics are an internal surface — Quantex-STAFF-ONLY.
  const guard = await requireStaff(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const sourceCommit = env.QHUB_BUILD_SOURCE_COMMIT ?? process.env.QHUB_BUILD_SOURCE_COMMIT ?? null;
  const artifactHash = env.QHUB_BUILD_ARTIFACT_HASH ?? process.env.QHUB_BUILD_ARTIFACT_HASH ?? null;
  const builtAt = env.QHUB_BUILD_AT ?? process.env.QHUB_BUILD_AT ?? null;

  return json({
    ok: true,
    source_commit: sourceCommit,
    artifact_hash: artifactHash,
    built_at: builtAt,
    required_markers: REQUIRED_BUILD_MARKERS.length,
    build_identity_present: !!(sourceCommit && artifactHash),
  });
};

export async function action() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
