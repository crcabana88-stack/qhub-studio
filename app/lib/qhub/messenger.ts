/**
 * QHUB Governance Messenger (client-side only)
 * app/lib/qhub/messenger.ts
 *
 * Broadcasts governance lifecycle events to the parent window via postMessage.
 * When QHUB Studio runs inside an iframe on the Quantex marketing site,
 * these events power the live governance sidebar.
 *
 * Safe to call anywhere in client code — no-ops if:
 *   • Not in a browser (SSR)
 *   • Not inside an iframe (window.parent === window)
 */

export type QhubEventType = 'GENESIS' | 'AI_BOM' | 'GATE_PASSED' | 'GATE_BLOCKED';

export interface QhubPostMessagePayload {
  type: 'QHUB_EVENT';
  event: QhubEventType;
  timestamp: string;
  data?: Record<string, unknown>;
}

/**
 * Post a governance event to the parent window.
 * Fires only when running inside an iframe — otherwise a no-op.
 */
export function postGovernanceEvent(event: QhubEventType, data?: Record<string, unknown>): void {
  // Guard: SSR / no window
  if (typeof window === 'undefined') {
    return;
  }

  // Guard: not embedded in a parent frame
  if (window.parent === window) {
    return;
  }

  const payload: QhubPostMessagePayload = {
    type: 'QHUB_EVENT',
    event,
    timestamp: new Date().toISOString(),
    data,
  };

  try {
    window.parent.postMessage(payload, '*');
  } catch (err) {
    // postMessage can fail in cross-origin edge cases — never throw
    console.warn('[QHUB Messenger] postMessage failed:', err);
  }
}
