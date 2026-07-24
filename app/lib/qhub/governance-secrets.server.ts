/**
 * QHUB Governance Secret Access — SERVER ONLY
 * app/lib/qhub/governance-secrets.server.ts
 *
 * Single source of truth for the HMAC signing secret.
 * The .server.ts suffix enforces server-only access in Remix/Vite:
 * any client bundle that imports this file will cause a build error.
 *
 * SECURITY RULES:
 *   - NEVER return the result of getHmacSecret() in a loader response.
 *   - NEVER log or print the secret value.
 *   - NEVER pass the secret to client-facing code or types.
 *   - Call only inside Remix actions, server loaders, or .server modules.
 */

/**
 * Retrieve the HMAC-SHA256 signing secret from trusted server configuration.
 *
 * Resolution order:
 *   1. Cloudflare Pages env binding (ctx.env.QHUB_HMAC_SECRET)
 *   2. Node.js process.env (Fly.io / local dev)
 *   3. Empty string — callers must check and refuse to sign
 *
 * DO NOT PRINT THE RETURN VALUE.
 */
export function getHmacSecret(env: Record<string, string | undefined>): string {
  const secret = env.QHUB_HMAC_SECRET ?? process.env.QHUB_HMAC_SECRET ?? '';

  if (!secret) {
    // Warn at startup — do not throw; governance is advisory in dev mode
    console.warn(
      '[QHUB] WARNING: QHUB_HMAC_SECRET is not configured. ' +
        'Events will be missing valid signatures. ' +
        'Set this env var in Cloudflare Pages / Fly.io secrets before production use.',
    );
  }

  return secret;
}
