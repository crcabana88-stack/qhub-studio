// @qhub-route: INTERNAL_SERVER_ONLY
/*
 * Hardened git CORS relay. R13 application-boundary closure: the legacy open proxy (attacker-controlled
 * target, forwarded browser Authorization/x-authorization, arbitrary redirects, header logging) is
 * replaced by a fixed-origin, allowlisted, authenticated relay. All destination validation, credential
 * stripping, redirect revalidation and (absence of) logging live in the server module below; the route
 * only enforces the authenticated boundary and delegates.
 */
import type { ActionFunctionArgs, LoaderFunctionArgs } from '@remix-run/cloudflare';
import { getVerifiedUser } from '~/lib/auth/session';
import { handleGitProxy } from '~/lib/qhub/git-proxy.server';

function authEnv(context: unknown): Record<string, string | undefined> {
  return ((context as { cloudflare?: { env?: Record<string, string | undefined> } })?.cloudflare?.env ?? {}) as Record<
    string,
    string | undefined
  >;
}

function proxy(request: Request, path: string | undefined, context: unknown) {
  return handleGitProxy(request, path, {
    authenticate: async () => {
      const user = await getVerifiedUser(request, authEnv(context));
      return user && user !== 'missing_config' ? { userId: user.userId } : null;
    },
  });
}

export async function action({ request, params, context }: ActionFunctionArgs) {
  return proxy(request, params['*'], context);
}

export async function loader({ request, params, context }: LoaderFunctionArgs) {
  return proxy(request, params['*'], context);
}
