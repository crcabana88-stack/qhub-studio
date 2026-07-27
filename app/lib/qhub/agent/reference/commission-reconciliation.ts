/**
 * QHUB Agent Framework Foundation — Commission Reconciliation reference agent (PURE)
 * app/lib/qhub/agent/reference/commission-reconciliation.ts
 *
 * The first safe reference workflow. Operates ONLY on synthetic data: compares
 * two synthetic commission datasets, identifies discrepancies, and proposes a
 * single reconciliation adjustment that MUST be approved by the owner before the
 * consequential write. The write is executed only through the existing staging
 * EXTERNAL_DATA_TRANSMISSION simulation adapter — no real accounting write, no
 * real customer data.
 */

export interface CommissionRecord {
  broker_id: string;
  period: string;

  /** Minor units (e.g. cents) to keep arithmetic exact. */
  amount_minor: number;
}

export interface Discrepancy {
  broker_id: string;
  period: string;
  expected_minor: number;
  reported_minor: number;
  delta_minor: number;
}

/** Deterministic synthetic datasets used for SIMULATION runs. */
export function syntheticCommissionDatasets(): { ledger: CommissionRecord[]; statement: CommissionRecord[] } {
  const ledger: CommissionRecord[] = [
    { broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 1250000 },
    { broker_id: 'BRK-002', period: '2026-Q2', amount_minor: 830000 },
    { broker_id: 'BRK-003', period: '2026-Q2', amount_minor: 415000 },
  ];
  const statement: CommissionRecord[] = [
    { broker_id: 'BRK-001', period: '2026-Q2', amount_minor: 1250000 },
    { broker_id: 'BRK-002', period: '2026-Q2', amount_minor: 812500 }, // discrepancy: -17,500
    { broker_id: 'BRK-003', period: '2026-Q2', amount_minor: 415000 },
  ];

  return { ledger, statement };
}

/** Pure discrepancy detection: ledger (expected) vs statement (reported). */
export function detectDiscrepancies(ledger: CommissionRecord[], statement: CommissionRecord[]): Discrepancy[] {
  const key = (r: CommissionRecord) => `${r.broker_id}|${r.period}`;
  const stmt = new Map(statement.map((r) => [key(r), r.amount_minor]));
  const out: Discrepancy[] = [];

  for (const l of ledger) {
    const reported = stmt.get(key(l));

    if (reported === undefined || reported === l.amount_minor) {
      continue;
    }

    out.push({
      broker_id: l.broker_id,
      period: l.period,
      expected_minor: l.amount_minor,
      reported_minor: reported,
      delta_minor: l.amount_minor - reported,
    });
  }

  return out.sort((a, b) => a.broker_id.localeCompare(b.broker_id));
}

export interface ReconciliationProposal {
  broker_id: string;
  period: string;
  adjustment_minor: number;

  /** Safe, human-readable justification — no sensitive data. */
  rationale: string;
}

/** Propose a single consequential adjustment for the largest-magnitude discrepancy. */
export function proposeReconciliation(discrepancies: Discrepancy[]): ReconciliationProposal | null {
  if (discrepancies.length === 0) {
    return null;
  }

  const worst = [...discrepancies].sort((a, b) => Math.abs(b.delta_minor) - Math.abs(a.delta_minor))[0];

  return {
    broker_id: worst.broker_id,
    period: worst.period,
    adjustment_minor: worst.delta_minor,
    rationale:
      `Statement under-reports ledger by ${Math.abs(worst.delta_minor)} minor units for ` +
      `${worst.broker_id} (${worst.period}); propose adjustment to reconcile.`,
  };
}

/** Reference-agent identity used by the manifest + provider selection. */
export const COMMISSION_RECON_REFERENCE = {
  reference_id: 'qhub.reference.commission-reconciliation',
  tool_id: 'qhub.tool.commission-reconciliation-write',
  connector_id: 'qhub.staging.external-data-transmission.simulation',
} as const;
