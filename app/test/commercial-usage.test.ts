/**
 * QHUB Commercial Launch — usage/credit pure logic
 * app/test/commercial-usage.test.ts
 */

import { describe, it, expect } from 'vitest';
import {
  currentUsagePeriod,
  needsReset,
  remainingCredits,
  hasCredit,
  applyDecrement,
} from '~/lib/qhub/commercial/usage';

describe('usage period + reset', () => {
  it('computes the UTC calendar-month period', () => {
    const p = currentUsagePeriod(new Date('2026-07-15T12:00:00Z'));
    expect(p.periodKey).toBe('2026-07');
    expect(p.periodStart).toBe('2026-07-01T00:00:00.000Z');
    expect(p.periodEnd).toBe('2026-08-01T00:00:00.000Z');
  });

  it('resets on a new period or missing key', () => {
    const now = new Date('2026-07-15T00:00:00Z');
    expect(needsReset('2026-07', now)).toBe(false);
    expect(needsReset('2026-06', now)).toBe(true);
    expect(needsReset(null, now)).toBe(true);
    expect(needsReset(undefined, now)).toBe(true);
  });
});

describe('credit math', () => {
  it('computes remaining and availability', () => {
    expect(remainingCredits({ allotted: 200, used: 50 })).toBe(150);
    expect(remainingCredits({ allotted: 200, used: 250 })).toBe(0);
    expect(hasCredit({ allotted: 5, used: 4 })).toBe(true);
    expect(hasCredit({ allotted: 5, used: 5 })).toBe(false);
  });

  it('applies a decrement only when credits remain', () => {
    const first = applyDecrement({ allotted: 2, used: 0 });
    expect(first.applied).toBe(true);
    expect(first.state.used).toBe(1);

    const second = applyDecrement(first.state);
    expect(second.applied).toBe(true);
    expect(second.state.used).toBe(2);

    const third = applyDecrement(second.state);
    expect(third.applied).toBe(false);
    expect(third.state.used).toBe(2); // unchanged — no overdraw
  });

  it('refuses non-positive cost', () => {
    expect(applyDecrement({ allotted: 5, used: 0 }, 0).applied).toBe(false);
    expect(applyDecrement({ allotted: 5, used: 0 }, -1).applied).toBe(false);
  });
});
