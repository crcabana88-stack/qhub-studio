// @qhub-route: INTERNAL_SERVER_ONLY
/**
 * QHUB Commercial Launch R4 — GET /api/export-api-keys  (STAFF-ONLY, no secrets)
 * app/routes/api.export-api-keys.ts
 *
 * SECURITY: this route previously returned server environment API-key VALUES to the
 * browser. R4 removes that capability entirely. It is Quantex-STAFF-ONLY and returns
 * ONLY the configured provider NAMES and a boolean "configured" status — never any
 * key value from the environment or cookies.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { LLMManager } from '~/lib/modules/llm/manager';

export async function loader({ context, request }: LoaderFunctionArgs) {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const guard = await requireStaff(request, env);

  if (!guard.ok) {
    return guard.response;
  }

  const llmManager = LLMManager.getInstance(context?.cloudflare?.env as never);
  const providers = llmManager.getAllProviders();

  // NON-SECRET status only: provider name + whether a key is configured server-side.
  const configured = providers
    .filter((p) => p.config.apiTokenKey)
    .map((p) => {
      const name = p.config.apiTokenKey as string;
      const present = !!(
        (context?.cloudflare?.env as unknown as Record<string, unknown>)?.[name] ||
        process.env[name] ||
        llmManager.env[name]
      );

      return { provider: p.name, configured: present };
    });

  return json({ providers: configured });
}
