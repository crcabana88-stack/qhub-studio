// @qhub-route: PUBLIC_SAFE
/*
 * R15 GitLab route closure — DISABLED for the initial launch.
 *
 * This route previously accepted a caller-controlled `gitlabUrl` plus a browser-supplied token and
 * forwarded that token as `Authorization: Bearer …` to the caller-selected host (SSRF + credential
 * exfiltration; the withSecurity wrapper added rate limits but no authentication). GitLab discovery is
 * not part of the initial commercial surface, so the route now answers with a constant feature-disabled
 * response: no request body is parsed, no destination is derived, no credential is read, no outbound
 * request is made, and nothing is logged. Private/self-hosted GitLab integration is POST-BETA — see
 * app/lib/qhub/gitlab-integration.server.ts for the conditions required to re-enable it.
 *
 * With no protected effect remaining, the route is genuinely PUBLIC_SAFE and needs no effect exemption.
 */
import { gitlabDiscoveryDisabledResponse } from '~/lib/qhub/gitlab-integration.server';

export async function action() {
  return gitlabDiscoveryDisabledResponse();
}

export async function loader() {
  return gitlabDiscoveryDisabledResponse();
}
