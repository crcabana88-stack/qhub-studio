/**
 * QHUB Commercial Launch R13 — hardened git CORS relay (SSRF + credential-forwarding closure)
 * app/lib/qhub/git-proxy.server.ts
 *
 * @qhub-service: INTERNAL_SERVER_ONLY
 *
 * The legacy open CORS proxy accepted an attacker-controlled absolute target, forwarded browser
 * Authorization/x-authorization upstream, followed arbitrary redirects, and logged request/response
 * headers (SSRF + credential exfiltration + secret logging). This module replaces it with a
 * fixed-origin relay: the upstream URL is built ONLY from a constant approved-host allowlist plus a
 * validated relative git path; ALL inbound credential/sensitive headers are stripped; redirects are
 * revalidated against the same allowlist; NO server credential is ever attached (public clone only);
 * and NOTHING sensitive (headers, URLs, tokens, cookies, raw errors) is ever logged.
 */

export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;

/** Exact HTTPS hosts the relay may reach — no wildcard suffixes, no user-supplied hosts. */
export const APPROVED_GIT_HOSTS: readonly string[] = [
  'github.com',
  'codeload.github.com',
  'gitlab.com',
  'bitbucket.org',
];

const APPROVED = new Set(APPROVED_GIT_HOSTS);

/*
 * Inbound headers that must NEVER be forwarded upstream (credentials / session / hop-by-hop). Only a
 * tiny fixed allowlist of safe request headers is forwarded (see FORWARD_REQUEST_HEADERS).
 */
export const STRIP_REQUEST_HEADERS: readonly string[] = [
  'authorization',
  'proxy-authorization',
  'x-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'private-token',
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
  'host',
];

/** The only request headers forwarded upstream (git smart-http needs these; none are credentials). */
const FORWARD_REQUEST_HEADERS = new Set(['accept', 'accept-encoding', 'content-type', 'git-protocol']);

/** Response headers exposed back to the browser (never Set-Cookie / auth / opaque credentials). */
const EXPOSE_RESPONSE_HEADERS = new Set([
  'accept-ranges',
  'cache-control',
  'content-type',
  'content-length',
  'content-encoding',
  'date',
  'etag',
  'expires',
  'last-modified',
  'vary',
]);

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);
const MAX_REQUEST_BODY_BYTES = 25 * 1024 * 1024; // git-upload-pack "wants" are tiny; cap defensively.
const UPSTREAM_TIMEOUT_MS = 60_000;
const MAX_REDIRECTS = 2;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export type GitProxyReason =
  | 'missing_path'
  | 'invalid_target'
  | 'absolute_or_protocol_relative'
  | 'userinfo_not_allowed'
  | 'port_not_allowed'
  | 'ip_literal_not_allowed'
  | 'host_not_allowlisted'
  | 'path_traversal'
  | 'method_not_allowed'
  | 'body_too_large'
  | 'redirect_not_allowed'
  | 'unauthenticated'
  | 'upstream_error';

export class GitProxyError extends Error {
  constructor(readonly reason: GitProxyReason) {
    super(reason);
    this.name = 'GitProxyError';
  }
}

/**
 * Build the exact approved upstream URL from a relative `<host>/<path>` splat + an optional query.
 * Throws GitProxyError (a stable reason code) on anything outside the allowlist — never returns an
 * attacker-influenced origin.
 */
export function resolveApprovedTarget(rawPath: string | undefined, search = ''): { url: string; host: string } {
  if (!rawPath) {
    throw new GitProxyError('missing_path');
  }

  // No absolute URL, scheme, or protocol-relative form may appear in the splat.
  if (/^[a-z][a-z0-9+.-]*:/i.test(rawPath) || rawPath.startsWith('//') || rawPath.includes('://')) {
    throw new GitProxyError('absolute_or_protocol_relative');
  }

  if (rawPath.includes('\\') || rawPath.includes('\0')) {
    throw new GitProxyError('invalid_target');
  }

  const firstSlash = rawPath.indexOf('/');
  const host = (firstSlash === -1 ? rawPath : rawPath.slice(0, firstSlash)).toLowerCase();
  const rest = firstSlash === -1 ? '' : rawPath.slice(firstSlash + 1);

  if (host.includes('@')) {
    throw new GitProxyError('userinfo_not_allowed');
  }

  if (host.includes(':')) {
    throw new GitProxyError('port_not_allowed');
  }

  if (IPV4.test(host) || host.includes('[')) {
    throw new GitProxyError('ip_literal_not_allowed');
  }

  if (!APPROVED.has(host)) {
    throw new GitProxyError('host_not_allowlisted');
  }

  // Validate every DECODED path segment: no traversal, no separators, no host confusion.
  for (const seg of rest.split('/')) {
    let decoded: string;

    try {
      decoded = decodeURIComponent(seg);
    } catch {
      throw new GitProxyError('path_traversal');
    }

    if (
      decoded === '..' ||
      decoded === '.' ||
      decoded.includes('/') ||
      decoded.includes('\\') ||
      decoded.includes('\0')
    ) {
      throw new GitProxyError('path_traversal');
    }
  }

  const normalizedSearch = search && search.startsWith('?') ? search : search ? `?${search}` : '';
  const candidate = `https://${host}/${rest}${normalizedSearch}`;

  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new GitProxyError('invalid_target');
  }

  // Re-derive from the parsed URL and re-assert every invariant (defence in depth).
  if (parsed.protocol !== 'https:') {
    throw new GitProxyError('absolute_or_protocol_relative');
  }

  if (parsed.username || parsed.password) {
    throw new GitProxyError('userinfo_not_allowed');
  }

  if (parsed.port) {
    throw new GitProxyError('port_not_allowed');
  }

  if (!APPROVED.has(parsed.hostname.toLowerCase())) {
    throw new GitProxyError('host_not_allowlisted');
  }

  return { url: parsed.toString(), host: parsed.hostname.toLowerCase() };
}

/** A redirect Location is only followed if it is itself an exact approved HTTPS origin. */
function resolveApprovedRedirect(location: string, base: string): string {
  let target: URL;

  try {
    target = new URL(location, base);
  } catch {
    throw new GitProxyError('redirect_not_allowed');
  }

  if (
    target.protocol !== 'https:' ||
    target.username ||
    target.password ||
    target.port ||
    !APPROVED.has(target.hostname.toLowerCase())
  ) {
    throw new GitProxyError('redirect_not_allowed');
  }

  return target.toString();
}

function corsHeaders(): Headers {
  const h = new Headers();
  h.set('Access-Control-Allow-Origin', 'null');
  h.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  h.set('Access-Control-Allow-Headers', 'accept, content-type, git-protocol');
  h.set('Vary', 'Origin');

  return h;
}

export interface GitProxyDeps {
  /** Resolve the authenticated caller; a null/non-user result is rejected (401). Injectable for tests. */
  authenticate: () => Promise<{ userId: string } | null>;

  /** fetch implementation (injectable). Must be called with redirect:'manual'. */
  fetchImpl?: typeof fetch;
}

/**
 * The hardened relay handler. Strips credentials, forwards ONLY safe headers to an approved origin,
 * manually revalidates redirects, and streams the body back. Never logs headers/URLs/credentials.
 */
export async function handleGitProxy(
  request: Request,
  rawPath: string | undefined,
  deps: GitProxyDeps,
): Promise<Response> {
  const doFetch = deps.fetchImpl ?? fetch;

  if (request.method === 'OPTIONS') {
    const headers = corsHeaders();
    headers.set('Access-Control-Max-Age', '86400');

    return new Response(null, { status: 204, headers });
  }

  if (!ALLOWED_METHODS.has(request.method)) {
    return json(405, 'method_not_allowed');
  }

  // Authenticated boundary — no anonymous outbound relay.
  const user = await deps.authenticate();

  if (!user) {
    return json(401, 'unauthenticated');
  }

  let target: { url: string; host: string };

  try {
    const search = new URL(request.url).search;
    target = resolveApprovedTarget(rawPath, search);
  } catch (error) {
    return errorResponse(error);
  }

  // Reject oversized request bodies before any outbound call.
  const declaredLength = Number(request.headers.get('content-length') ?? '0');

  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    return json(413, 'body_too_large');
  }

  // Build a FRESH header set — only the safe allowlist, never a credential/session header.
  const upstreamHeaders = new Headers();

  for (const [name, value] of request.headers.entries()) {
    if (FORWARD_REQUEST_HEADERS.has(name.toLowerCase())) {
      upstreamHeaders.set(name, value);
    }
  }
  upstreamHeaders.set('user-agent', 'QHUB-Studio-git');

  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  const body = hasBody ? await request.arrayBuffer() : undefined;

  if (body && body.byteLength > MAX_REQUEST_BODY_BYTES) {
    return json(413, 'body_too_large');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    let currentUrl = target.url;
    let response: Response | null = null;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      response = await doFetch(currentUrl, {
        method: request.method,
        headers: upstreamHeaders,
        body,
        redirect: 'manual',
        signal: controller.signal,
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');

        if (!location || hop === MAX_REDIRECTS) {
          return json(502, 'redirect_not_allowed');
        }

        currentUrl = resolveApprovedRedirect(location, currentUrl); // throws → rejected below
        continue;
      }

      break;
    }

    if (!response) {
      return json(502, 'upstream_error');
    }

    const responseHeaders = corsHeaders();

    for (const [name, value] of response.headers.entries()) {
      if (EXPOSE_RESPONSE_HEADERS.has(name.toLowerCase())) {
        responseHeaders.set(name, value);
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    // NEVER surface a raw upstream/SDK error (may carry request metadata) — a stable code only.
    if (error instanceof GitProxyError) {
      return errorResponse(error);
    }

    return json(502, 'upstream_error');
  } finally {
    clearTimeout(timer);
  }
}

function errorResponse(error: unknown): Response {
  const reason = error instanceof GitProxyError ? error.reason : 'invalid_target';
  const status = reason === 'unauthenticated' ? 401 : reason === 'method_not_allowed' ? 405 : 400;

  return json(status, reason);
}

function json(status: number, reason: GitProxyReason): Response {
  const headers = corsHeaders();
  headers.set('content-type', 'application/json');

  return new Response(JSON.stringify({ error: reason }), { status, headers });
}
