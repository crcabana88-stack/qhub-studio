/**
 * QHUB Commercial Launch R2 — real-route enforcement wiring
 * app/test/commercial-route-enforcement.test.ts
 *
 * Proves the protected production routes actually call requireCommercialContext
 * with the correct capability and return its fail-closed response — the browser UI
 * is never the boundary. The guard itself is unit-tested in commercial-context.
 */

import { json } from '@remix-run/cloudflare';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockRequire } = vi.hoisted(() => ({ mockRequire: vi.fn() }));

vi.mock('~/lib/qhub/commercial/commercial-context.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/commercial-context.server')>();
  return { ...actual, requireCommercialContext: mockRequire };
});

import { action as enforceAction } from '~/routes/api.enforce';
import { action as agentAction } from '~/routes/api.agent';
import { action as governanceAction } from '~/routes/api.governance';
import { action as classifyAction } from '~/routes/api.classify';

function ctx(body: unknown = {}) {
  return {
    request: new Request('https://app.qhub.test/x', {
      method: 'POST',
      headers: { origin: 'https://app.qhub.test', 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    context: { cloudflare: { env: {} } },
    params: {},
  } as never;
}

/** Simulate a denied guard (e.g. commercial user lacking the capability). */
function deny() {
  mockRequire.mockResolvedValue({ ok: false, response: json({ ok: false, error: 'forbidden' }, { status: 403 }) });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('protected routes enforce the commercial capability', () => {
  it('POST /api/enforce requires CONSEQUENTIAL_ACTION and returns the denial', async () => {
    deny();

    const res = (await enforceAction(
      ctx({ conversationId: 'c', action: { action_type: 'CONNECTOR_ACTION' } }),
    )) as Response;
    expect(res.status).toBe(403);
    expect(mockRequire).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'CONSEQUENTIAL_ACTION');
  });

  it('POST /api/agent requires AGENT_BUILD and returns the denial', async () => {
    deny();

    const res = (await agentAction(ctx({ op: 'create' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockRequire).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'AGENT_BUILD');
  });

  it('POST /api/governance requires APP_BUILD and returns the denial', async () => {
    deny();

    const res = (await governanceAction(ctx({ action: 'PROJECT_CREATED', conversationId: 'c' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockRequire).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'APP_BUILD');
  });

  it('POST /api/classify requires APP_BUILD and returns the denial', async () => {
    deny();

    const res = (await classifyAction(ctx({ description: 'hello' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockRequire).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'APP_BUILD');
  });
});
