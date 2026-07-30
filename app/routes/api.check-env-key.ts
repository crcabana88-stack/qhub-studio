/*
 * @qhub-route: INTERNAL_SERVER_ONLY
 * @qhub-boundary: INTERNAL_SERVER_ONLY — reports whether a provider key is configured server-side.
 * It reads server env values (dynamically, by provider key name), so it requires an authenticated
 * session and returns ONLY a boolean (isSet) — never a raw key value (R9 §6).
 */
import type { LoaderFunction } from '@remix-run/cloudflare';
import { LLMManager } from '~/lib/modules/llm/manager';
import { getApiKeysFromCookie } from '~/lib/api/cookies';
import { getVerifiedUser } from '~/lib/auth/session';

export const loader: LoaderFunction = async ({ context, request }) => {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};
  const user = await getVerifiedUser(request, env);

  if (user === null || user === 'missing_config') {
    return Response.json({ error: 'unauthenticated' }, { status: 401 });
  }

  const url = new URL(request.url);
  const provider = url.searchParams.get('provider');

  if (!provider) {
    return Response.json({ isSet: false });
  }

  const llmManager = LLMManager.getInstance(context?.cloudflare?.env as any);
  const providerInstance = llmManager.getProvider(provider);

  if (!providerInstance || !providerInstance.config.apiTokenKey) {
    return Response.json({ isSet: false });
  }

  const envVarName = providerInstance.config.apiTokenKey;

  // Get API keys from cookie
  const cookieHeader = request.headers.get('Cookie');
  const apiKeys = getApiKeysFromCookie(cookieHeader);

  /*
   * Check API key in order of precedence:
   * 1. Client-side API keys (from cookies)
   * 2. Server environment variables (from Cloudflare env)
   * 3. Process environment variables (from .env.local)
   * 4. LLMManager environment variables
   */
  const isSet = !!(
    apiKeys?.[provider] ||
    (context?.cloudflare?.env as Record<string, any>)?.[envVarName] ||
    process.env[envVarName] ||
    llmManager.env[envVarName]
  );

  return Response.json({ isSet });
};
