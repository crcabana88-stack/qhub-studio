/**
 * QHUB Commercial Launch R3 — internal routes are Quantex-STAFF-ONLY
 * app/test/commercial-route-enforcement.test.ts
 *
 * The unrestricted internal Studio / agent / Gate 04 / governance / classify
 * surfaces now enforce requireStaff and return its fail-closed response. Commercial
 * customers cannot reach them (they build via /api/commercial/*).
 */

import { json } from '@remix-run/cloudflare';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockStaff } = vi.hoisted(() => ({ mockStaff: vi.fn() }));

vi.mock('~/lib/qhub/commercial/commercial-context.server', async (importActual) => {
  const actual = await importActual<typeof import('~/lib/qhub/commercial/commercial-context.server')>();
  return { ...actual, requireStaff: mockStaff };
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

function denyStaff() {
  mockStaff.mockResolvedValue({ ok: false, response: json({ ok: false, error: 'staff_only' }, { status: 403 }) });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('internal routes are staff-only', () => {
  it('POST /api/enforce denies a non-staff caller', async () => {
    denyStaff();

    const res = (await enforceAction(
      ctx({ conversationId: 'c', action: { action_type: 'CONNECTOR_ACTION' } }),
    )) as Response;
    expect(res.status).toBe(403);
    expect(mockStaff).toHaveBeenCalled();
  });

  it('POST /api/agent denies a non-staff caller', async () => {
    denyStaff();

    const res = (await agentAction(ctx({ op: 'create' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockStaff).toHaveBeenCalled();
  });

  it('POST /api/governance denies a non-staff caller', async () => {
    denyStaff();

    const res = (await governanceAction(ctx({ action: 'PROJECT_CREATED', conversationId: 'c' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockStaff).toHaveBeenCalled();
  });

  it('POST /api/classify denies a non-staff caller', async () => {
    denyStaff();

    const res = (await classifyAction(ctx({ description: 'hello' }))) as Response;
    expect(res.status).toBe(403);
    expect(mockStaff).toHaveBeenCalled();
  });
});
