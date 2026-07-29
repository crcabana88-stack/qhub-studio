/**
 * QHUB Commercial Launch — USAGE / BUILD-CREDIT LOGIC (BROWSER-SAFE, PURE)
 * app/lib/qhub/commercial/usage.ts
 *
 * Pure helpers for monthly build-credit accounting: period identity, reset
 * detection, and decrement math. No I/O, no secrets — the durable ledger lives in
 * commercial-store.server.ts, which uses these helpers so the reset rule is
 * unit-testable in isolation.
 */

export interface UsagePeriod {
  /** UTC calendar-month key, e.g. "2026-07". */
  periodKey: string;

  /** ISO start (inclusive) of the period. */
  periodStart: string;

  /** ISO start of the NEXT period (exclusive end). */
  periodEnd: string;
}

/** The billing/credit period for a given instant is the UTC calendar month. */
export function currentUsagePeriod(now: Date = new Date()): UsagePeriod {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth(); // 0-based
  const start = new Date(Date.UTC(y, m, 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(y, m + 1, 1, 0, 0, 0, 0));
  const periodKey = `${y}-${String(m + 1).padStart(2, '0')}`;

  return { periodKey, periodStart: start.toISOString(), periodEnd: end.toISOString() };
}

/** True when a stored period key is not the current one → credits should reset. */
export function needsReset(storedPeriodKey: string | null | undefined, now: Date = new Date()): boolean {
  if (!storedPeriodKey) {
    return true;
  }

  return storedPeriodKey !== currentUsagePeriod(now).periodKey;
}

export interface CreditState {
  allotted: number;
  used: number;
}

export function remainingCredits(state: CreditState): number {
  return Math.max(0, state.allotted - state.used);
}

export function hasCredit(state: CreditState, cost = 1): boolean {
  return remainingCredits(state) >= cost;
}

/**
 * Apply a decrement. Returns the new state and whether it was applied. Never lets
 * `used` exceed `allotted` and never applies a decrement that would overdraw.
 */
export function applyDecrement(state: CreditState, cost = 1): { state: CreditState; applied: boolean } {
  if (cost <= 0 || !hasCredit(state, cost)) {
    return { state, applied: false };
  }

  return { state: { allotted: state.allotted, used: state.used + cost }, applied: true };
}
