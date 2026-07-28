/**
 * QHUB build identity diagnostic — app/routes/api.system.build-info.ts
 *
 * Authenticated (401 for anon). Compares the two INDEPENDENT non-secret
 * identities (deployment QHUB_BUILD_* vs on-image QHUB_IMAGE_*) and reports a
 * compact result: present / ready / source_commit / artifact_hash / lockfile_hash
 * / build_at / mismatch reason codes. Returns 200 only when ready (or absent in
 * local dev); 503 when the running image does not match its intended identity.
 * Exposes no secrets, SQL, or customer data. Public /api/health stays generic.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getSession } from '~/lib/auth/session';
import {
  assertBuildIntegrity,
  isEnforcedDeployEnv,
  buildEnvironmentFingerprint,
  ASSURANCE_MODEL,
} from '~/lib/qhub/build-integrity.server';

export const loader = async ({ request, context }: LoaderFunctionArgs) => {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false, error: 'Unauthenticated' }, { status: 401 });
  }

  const gate = assertBuildIntegrity(env);
  const r = gate.result;

  const body = {
    ok: gate.ok,
    assurance_model: ASSURANCE_MODEL, // DEPLOYED_IMAGE_INTEGRITY (not reproducible build)
    present: r.present,
    ready: r.ready,
    source_commit: r.source_commit,
    artifact_hash: r.artifact_hash,
    lockfile_hash: r.lockfile_hash,
    build_at: r.build_at,
    build_environment: buildEnvironmentFingerprint(env),
    enforced_env: isEnforcedDeployEnv(env),
    mismatch_reason_codes: r.mismatch_reason_codes,
  };

  /*
   * 200 only when the integrity gate passes (ready, or absent in local dev);
   * 503 when the running image fails to match its intended identity.
   */
  return json(body, { status: gate.ok ? 200 : 503 });
};

export async function action() {
  return json({ error: 'Method not allowed' }, { status: 405 });
}
