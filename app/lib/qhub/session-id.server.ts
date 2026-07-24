/**
 * QHUB — Stable Session ID Generator — SERVER ONLY
 * app/lib/qhub/session-id.server.ts
 *
 * Produces a deterministic, stable sessionId for a given (userId, conversationId)
 * pair. This ensures a single application lifecycle is traceable across all
 * governance events: GENESIS → AI_BOM → GATE → DEPLOYMENT.
 *
 * Using a stable ID (vs. Date.now()) means:
 *   - The same conversation always maps to the same QHUB chain
 *   - Multiple AI_BOM events within one conversation link to one GENESIS
 *   - The gate check references the same session as the genesis event
 *
 * The ID is a SHA-256 prefix (12 hex chars) of userId + conversationId,
 * prefixed with 'studio-' for source identification.
 * No secret material is involved — this is a deterministic identifier.
 */

import { createHash } from 'node:crypto';

/**
 * Generate a stable, deterministic session identifier.
 *
 * @param userId         - Authenticated user ID from Supabase JWT
 * @param conversationId - Stable conversation/chat identifier
 * @returns 'studio-{12 hex chars}'
 */
export function generateStableSessionId(userId: string, conversationId: string): string {
  const hash = createHash('sha256')
    .update(`${userId}:${conversationId}`)
    .digest('hex')
    .slice(0, 12);
  return `studio-${hash}`;
}
