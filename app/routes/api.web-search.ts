// @qhub-route: INTERNAL_SERVER_ONLY
/*
 * R14 web-search SSRF closure. The legacy route was PUBLIC_SAFE + unauthenticated and fetched a
 * caller-controlled URL through a weak allow-list (it accepted http://[::ffff:127.0.0.1]/). It is now an
 * authenticated INTERNAL_SERVER_ONLY route that delegates to the server-only handler whose ONLY outbound
 * path is the shared SSRF-safe validator + fetcher (safeFetch). The route just enforces the auth boundary.
 */
import type { ActionFunctionArgs } from '@remix-run/cloudflare';
import { getVerifiedUser } from '~/lib/auth/session';
import { handleWebSearch } from '~/lib/qhub/web-search.server';

function authEnv(context: unknown): Record<string, string | undefined> {
  return ((context as { cloudflare?: { env?: Record<string, string | undefined> } })?.cloudflare?.env ?? {}) as Record<
    string,
    string | undefined
  >;
}

export async function action({ request, context }: ActionFunctionArgs) {
  return handleWebSearch(request, {
    authenticate: async () => {
      const user = await getVerifiedUser(request, authEnv(context));
      return user && user !== 'missing_config' ? { userId: user.userId } : null;
    },
  });
}
