/**
 * QHUB Commercial Launch R14 — authenticated web-search page-scraper (SSRF-safe)
 * app/lib/qhub/web-search.server.ts
 *
 * @qhub-service: INTERNAL_SERVER_ONLY
 *
 * The scraping handler for the reclassified /api/web-search route. Authentication is required and the
 * ONLY outbound path is the shared SSRF-safe validator + fetcher (safeFetch). Never logs sensitive values.
 */

import { json } from '@remix-run/cloudflare';
import { safeFetch, SsrfError, type SafeFetchOptions } from '~/lib/qhub/safe-fetch.server';

export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;

const MAX_CONTENT_LENGTH = 8000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

// A fixed, non-caller-influenced browser-like accept profile (no credentials of any kind).
const OUTBOUND_HEADERS = {
  'User-Agent': 'QHUB-Studio-web-search',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
};

function extractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : '';
}

function extractMetaDescription(html: string): string {
  const match = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i);

  if (match) {
    return match[1].trim();
  }

  const altMatch = html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["'][^>]*>/i);

  return altMatch ? altMatch[1].trim() : '';
}

function extractTextContent(html: string): string {
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<nav\b[^<]*(?:(?!<\/nav>)<[^<]*)*<\/nav>/gi, ' ')
    .replace(/<header\b[^<]*(?:(?!<\/header>)<[^<]*)*<\/header>/gi, ' ')
    .replace(/<footer\b[^<]*(?:(?!<\/footer>)<[^<]*)*<\/footer>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

export interface WebSearchDeps {
  authenticate: () => Promise<{ userId: string } | null>;
  fetchImpl?: SafeFetchOptions['fetchImpl'];
  resolve?: SafeFetchOptions['resolve'];
}

/** Testable core: authenticate, SSRF-validate + fetch via safeFetch, scrape the page. */
export async function handleWebSearch(request: Request, deps: WebSearchDeps): Promise<Response> {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204 }); // side-effect free
  }

  if (request.method !== 'POST') {
    return json({ error: 'method_not_allowed' }, { status: 405 });
  }

  const user = await deps.authenticate();

  if (!user) {
    return json({ error: 'unauthenticated' }, { status: 401 });
  }

  let url: string | undefined;

  try {
    ({ url } = (await request.json()) as { url?: string });
  } catch {
    return json({ error: 'invalid_body' }, { status: 400 });
  }

  if (!url || typeof url !== 'string') {
    return json({ error: 'url_required' }, { status: 400 });
  }

  let response: Response;

  try {
    response = await safeFetch(url, {
      headers: OUTBOUND_HEADERS,
      fetchImpl: deps.fetchImpl,
      resolve: deps.resolve,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    });
  } catch (error) {
    if (error instanceof SsrfError) {
      return json({ error: 'url_not_allowed' }, { status: 400 });
    }

    if (error instanceof DOMException && error.name === 'TimeoutError') {
      return json({ error: 'timeout' }, { status: 504 });
    }

    // Never surface a raw upstream error (may carry request metadata) — a stable code only.
    return json({ error: 'fetch_failed' }, { status: 502 });
  }

  if (!response.ok) {
    return json({ error: `upstream_${response.status}` }, { status: 502 });
  }

  const contentType = response.headers.get('content-type') || '';

  if (!contentType.includes('text/html') && !contentType.includes('text/plain')) {
    return json({ error: 'unsupported_content_type' }, { status: 400 });
  }

  const html = await response.text();
  const content = extractTextContent(html);

  return json({
    success: true,
    data: {
      title: extractTitle(html),
      description: extractMetaDescription(html),
      content: content.length > MAX_CONTENT_LENGTH ? content.slice(0, MAX_CONTENT_LENGTH) + '...' : content,
    },
  });
}
