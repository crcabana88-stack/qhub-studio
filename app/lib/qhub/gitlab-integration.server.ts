/**
 * QHUB Commercial Launch R15 — GitLab project/branch discovery: DISABLED for the initial launch
 * app/lib/qhub/gitlab-integration.server.ts
 *
 * @qhub-service: PURE_NO_IO
 *
 * The legacy GitLab discovery routes accepted a caller-controlled `gitlabUrl` and a browser-supplied
 * personal access token, then forwarded that token as `Authorization: Bearer …` to the caller-selected
 * host (a synthetic probe reached https://attacker.invalid/api/v4/projects with the token attached).
 * withSecurity added rate limits and headers but no authentication.
 *
 * GitLab project/branch discovery is NOT part of the initial commercial surface (Builder Beta, Guided
 * Trial, sales demo). Serving it safely would require either a token-less public mode — which cannot
 * satisfy `membership=true` project listing — or server-side custody of user PATs plus a verified
 * provider-configuration record, i.e. a new secret-management system. Both routes are therefore
 * DISABLED for the beta and answer with a constant feature-disabled response.
 *
 * This module performs NO outbound I/O, reads NO credential, and logs nothing: the disabled response is
 * a constant, so no caller input can reach a destination, a header, or a log line.
 *
 * Private / self-hosted GitLab integration is POST-BETA. Re-enabling it requires: an authenticated
 * classification (getVerifiedUser before any outbound effect), a destination resolved from a
 * server-authorized provider configuration (never from a request-body URL), a credential from approved
 * server-side secret storage (never from a browser token field), and the shared SSRF-safe fetcher.
 */

import { json } from '@remix-run/cloudflare';

export const __QHUB_MODULE_CLASSIFICATION = 'PURE_NO_IO' as const;

/** The GitLab discovery feature is off for the initial launch. Post-beta re-enablement is gated (see above). */
export const GITLAB_DISCOVERY_ENABLED = false as const;

export const GITLAB_DISABLED_CODE = 'gitlab_integration_disabled' as const;

/**
 * The constant response for both disabled GitLab discovery routes. Independent of every request input:
 * no body is parsed, no destination is derived, no credential is read, and nothing is logged.
 */
export function gitlabDiscoveryDisabledResponse(): Response {
  return json(
    {
      error: GITLAB_DISABLED_CODE,
      message: 'GitLab project and branch discovery is unavailable during the beta.',
      availability: 'post_beta',
    },
    { status: 410 },
  );
}
