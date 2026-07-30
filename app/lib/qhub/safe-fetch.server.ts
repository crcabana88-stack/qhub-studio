/**
 * QHUB Commercial Launch R14 — one shared SSRF-safe outbound URL validator + fetcher
 * app/lib/qhub/safe-fetch.server.ts
 *
 * @qhub-service: INTERNAL_SERVER_ONLY
 *
 * A single authority for caller-influenced outbound requests. Every target (and every redirect Location)
 * is validated BEFORE connecting: HTTPS-only, no userinfo/ports/fragments, and a comprehensive private/
 * loopback/link-local/unique-local/multicast/reserved/metadata block — including IPv4-mapped IPv6
 * (::ffff:127.0.0.1), IPv4-compatible IPv6, and the alternate decimal/octal/hex IPv4 forms the URL parser
 * canonicalises. Redirects use redirect:'manual', are capped, must stay on the SAME origin, and are
 * re-validated. Credentials/hop-by-hop headers are stripped; nothing sensitive is logged. Where a DNS
 * resolver is supplied, the host is resolved and every resolved address re-checked (DNS-rebinding defence);
 * on runtimes without a resolver (workerd), the static literal-address checks still block every IP form.
 */

export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;

const ALLOWED_PORTS = new Set(['', '443']);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

/** Inbound headers that must never be forwarded to a caller-influenced upstream. */
const STRIP_OUTBOUND_HEADERS = new Set([
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
]);

export type SsrfReason =
  | 'invalid_url'
  | 'scheme_not_https'
  | 'userinfo_not_allowed'
  | 'port_not_allowed'
  | 'fragment_not_allowed'
  | 'idn_host_not_allowed'
  | 'single_label_host_not_allowed'
  | 'blocked_hostname'
  | 'blocked_ip_address'
  | 'redirect_not_allowed'
  | 'scheme_downgrade'
  | 'cross_origin_redirect'
  | 'response_too_large';

export class SsrfError extends Error {
  constructor(readonly reason: SsrfReason) {
    super(reason);
    this.name = 'SsrfError';
  }
}

const BLOCKED_HOST_NAMES = new Set(['localhost', 'ip6-localhost', 'ip6-loopback']);

/** Parse a dotted-quad IPv4 into octets, or null if not an IPv4 literal. */
function parseIpv4(h: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);

  if (!m) {
    return null;
  }

  const octets = m.slice(1, 5).map((n) => Number(n));

  return octets.every((o) => o >= 0 && o <= 255) ? octets : null;
}

/** True if an IPv4 (octets) falls in any blocked range. */
function isBlockedIpv4([a, b]: number[]): boolean {
  return (
    a === 0 || // 0.0.0.0/8 unspecified
    a === 10 || // 10/8 private
    a === 127 || // 127/8 loopback
    (a === 100 && b >= 64 && b <= 127) || // 100.64/10 CGNAT
    (a === 169 && b === 254) || // 169.254/16 link-local + cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // 172.16/12 private
    (a === 192 && b === 168) || // 192.168/16 private
    (a === 192 && b === 0) || // 192.0.0/24 + 192.0.2/24 (IETF/doc)
    (a === 198 && (b === 18 || b === 19)) || // 198.18/15 benchmarking
    a >= 224 // 224/4 multicast + 240/4 reserved + 255.255.255.255 broadcast
  );
}

/** Expand an IPv6 hostname (no brackets) to 8 hextets, or null if malformed. */
function parseIpv6(h: string): number[] | null {
  if (!/^[0-9a-f:.]+$/i.test(h) || !h.includes(':')) {
    return null;
  }

  const [head, tail, ...extra] = h.split('::');

  if (extra.length > 0) {
    return null; // more than one '::'
  }

  // A trailing embedded IPv4 (e.g. ::ffff:127.0.0.1) → convert to two hextets.
  const toHextets = (part: string): number[] => {
    if (!part) {
      return [];
    }

    const groups = part.split(':');
    const out: number[] = [];

    for (const g of groups) {
      if (g.includes('.')) {
        const v4 = parseIpv4(g);

        if (!v4) {
          throw new SsrfError('invalid_url');
        }

        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        out.push(parseInt(g, 16) & 0xffff);
      }
    }

    return out;
  };

  try {
    const headParts = toHextets(head);

    if (tail === undefined) {
      return headParts.length === 8 ? headParts : null;
    }

    const tailParts = toHextets(tail);
    const fill = 8 - headParts.length - tailParts.length;

    if (fill < 0) {
      return null;
    }

    return [...headParts, ...Array(fill).fill(0), ...tailParts];
  } catch {
    return null;
  }
}

/** True if an expanded IPv6 (8 hextets) is blocked, including IPv4-mapped/compatible embeds. */
function isBlockedIpv6(hx: number[]): boolean {
  const allZero = hx.every((x) => x === 0);
  const loopback = hx.slice(0, 7).every((x) => x === 0) && hx[7] === 1;

  if (allZero || loopback) {
    return true; // :: unspecified, ::1 loopback
  }

  const first = hx[0];

  if ((first & 0xffc0) === 0xfe80) {
    return true; // fe80::/10 link-local
  }

  if ((first & 0xfe00) === 0xfc00) {
    return true; // fc00::/7 unique-local
  }

  if ((first & 0xff00) === 0xff00) {
    return true; // ff00::/8 multicast
  }

  // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible) → validate the embedded IPv4.
  const firstFiveZero = hx.slice(0, 5).every((x) => x === 0);

  if (firstFiveZero && (hx[5] === 0xffff || hx[5] === 0)) {
    const v4 = [hx[6] >> 8, hx[6] & 0xff, hx[7] >> 8, hx[7] & 0xff];

    if (hx[5] === 0xffff || !(hx[6] === 0 && hx[7] <= 1)) {
      return isBlockedIpv4(v4);
    }
  }

  return false;
}

export interface SsrfValidateOptions {
  /** Optional DNS resolver: hostname → resolved addresses. Every address is re-checked (rebinding defence). */
  resolve?: (hostname: string) => Promise<string[]>;
}

/**
 * Validate a caller-influenced URL. Throws SsrfError (a stable reason) on anything unsafe; returns the
 * normalized URL string on success. Purely static unless a resolver is supplied.
 */
export async function assertSafePublicUrl(input: string, opts: SsrfValidateOptions = {}): Promise<string> {
  let url: URL;

  try {
    url = new URL(input);
  } catch {
    throw new SsrfError('invalid_url');
  }

  if (url.protocol !== 'https:') {
    throw new SsrfError('scheme_not_https');
  }

  if (url.username || url.password) {
    throw new SsrfError('userinfo_not_allowed');
  }

  if (!ALLOWED_PORTS.has(url.port)) {
    throw new SsrfError('port_not_allowed');
  }

  if (url.hash) {
    throw new SsrfError('fragment_not_allowed');
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (BLOCKED_HOST_NAMES.has(host) || host.endsWith('.localhost')) {
    throw new SsrfError('blocked_hostname');
  }

  assertHostAddressAllowed(host);

  // No IDN/punycode hosts (confusable) and no single-label hosts (internal names) for public fetch.
  const ipv4 = parseIpv4(host);
  const ipv6 = host.includes(':') ? parseIpv6(host) : null;

  if (!ipv4 && !ipv6) {
    if (host.startsWith('xn--') || host.includes('.xn--')) {
      throw new SsrfError('idn_host_not_allowed');
    }

    if (!host.includes('.')) {
      throw new SsrfError('single_label_host_not_allowed');
    }
  }

  // DNS-rebinding defence when a resolver is available: every resolved address must also be allowed.
  if (opts.resolve && !ipv4 && !ipv6) {
    const addresses = await opts.resolve(host);

    for (const addr of addresses) {
      assertHostAddressAllowed(addr.toLowerCase().replace(/^\[|\]$/g, ''));
    }
  }

  return url.toString();
}

/** Throw if a hostname that IS an IP literal (v4/v6/mapped) resolves to a blocked address. */
function assertHostAddressAllowed(host: string): void {
  const ipv4 = parseIpv4(host);

  if (ipv4) {
    if (isBlockedIpv4(ipv4)) {
      throw new SsrfError('blocked_ip_address');
    }

    return;
  }

  if (host.includes(':')) {
    const ipv6 = parseIpv6(host);

    if (ipv6 && isBlockedIpv6(ipv6)) {
      throw new SsrfError('blocked_ip_address');
    }
  }
}

export interface SafeFetchOptions extends SsrfValidateOptions {
  method?: string;
  headers?: HeadersInit;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxRedirects?: number;
  maxResponseBytes?: number;
}

/**
 * SSRF-safe fetch: validates the target + every redirect hop (same-origin only), strips credential/
 * hop-by-hop headers, and enforces timeout/redirect/response-size caps. Never logs sensitive values.
 */
export async function safeFetch(input: string, opts: SafeFetchOptions = {}): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let currentUrl = await assertSafePublicUrl(input, opts);
  const outboundHeaders = new Headers(opts.headers);

  for (const name of [...outboundHeaders.keys()]) {
    if (STRIP_OUTBOUND_HEADERS.has(name.toLowerCase())) {
      outboundHeaders.delete(name);
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const response = await doFetch(currentUrl, {
        method: opts.method ?? 'GET',
        headers: outboundHeaders,
        redirect: 'manual',
        signal: controller.signal,
      });

      if (response.status < 300 || response.status >= 400) {
        // Cap the response by its declared length (defence-in-depth; the caller also truncates content).
        const declared = Number(response.headers.get('content-length') ?? '0');
        const maxBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

        if (Number.isFinite(declared) && declared > maxBytes) {
          throw new SsrfError('response_too_large');
        }

        return response;
      }

      const location = response.headers.get('location');

      if (!location || hop === maxRedirects) {
        throw new SsrfError('redirect_not_allowed');
      }

      currentUrl = assertSameOriginRedirect(currentUrl, location, opts);
    }

    throw new SsrfError('redirect_not_allowed');
  } finally {
    clearTimeout(timer);
  }
}

/** A redirect must stay on the SAME origin (scheme+host+port), re-validated, with no downgrade. */
function assertSameOriginRedirect(fromUrl: string, location: string, opts: SsrfValidateOptions): string {
  let target: URL;

  try {
    target = new URL(location, fromUrl);
  } catch {
    throw new SsrfError('redirect_not_allowed');
  }

  const from = new URL(fromUrl);

  if (target.protocol !== 'https:') {
    throw new SsrfError('scheme_downgrade');
  }

  if (target.origin !== from.origin) {
    throw new SsrfError('cross_origin_redirect');
  }

  // Re-run the full static validation on the redirect target (still same-origin, but belt + suspenders).
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (BLOCKED_HOST_NAMES.has(host) || host.endsWith('.localhost')) {
    throw new SsrfError('blocked_hostname');
  }

  assertHostAddressAllowed(host);
  void opts;

  return target.toString();
}
