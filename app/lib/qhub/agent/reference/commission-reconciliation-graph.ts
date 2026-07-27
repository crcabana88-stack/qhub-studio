/**
 * QHUB Agent Framework — Commission Reconciliation LangGraph workflow (PURE)
 * app/lib/qhub/agent/reference/commission-reconciliation-graph.ts
 *
 * Expresses the reference workflow as a LangGraph StateGraph. The graph runs ONLY
 * the pure planning pipeline:
 *
 *   START → VALIDATE_SYNTHETIC_INPUT → COMPARE_RECORDS → ANALYZE_DISCREPANCY
 *         → PROPOSE_RECONCILIATION → END
 *
 * These nodes have no external effect: they read synthetic inputs and produce a
 * deterministic list of GOVERNED actions (`governed_plan`). The consequential
 * nodes of Phase 5 (SUBMIT_TO_GATE_04 / EXECUTE_QHUB_ADAPTER / RECORD_RECEIPT)
 * are NOT executed inside the graph — they are surfaced to QHub as ProposedActions
 * and driven one node at a time through Gate 04, so LangGraph can never authorize
 * or execute a consequential action. Re-running this pure pipeline on restart is
 * the sanctioned "pure recomputation" path and reproduces an identical plan.
 *
 * LangGraph (@langchain/langgraph) is used only for the graph authoring model and
 * routing. No network, no credentials, no tracing.
 */

/* eslint-disable @typescript-eslint/naming-convention -- graph state keys mirror the snake_case governed-action / run-step vocabulary */

import { StateGraph, Annotation, START, END } from '@langchain/langgraph';
import {
  COMMISSION_RECON_REFERENCE,
  detectDiscrepancies,
  proposeReconciliation,
  type CommissionRecord,
  type Discrepancy,
  type ReconciliationProposal,
} from './commission-reconciliation';
import type { ProposedAction, RuntimeManifestView } from '~/lib/qhub/agent/runtime/provider';

export const RECONCILIATION_GRAPH_VERSION = 'commission-reconciliation-graph-1.0.0';

/** Structured, safe graph state. No chain-of-thought, no raw sensitive payloads. */
export const ReconciliationState = Annotation.Root({
  ledger: Annotation<CommissionRecord[]>({ reducer: (_a, b) => b, default: () => [] }),
  statement: Annotation<CommissionRecord[]>({ reducer: (_a, b) => b, default: () => [] }),
  primary_model: Annotation<string>({ reducer: (_a, b) => b, default: () => '' }),
  validated: Annotation<boolean>({ reducer: (_a, b) => b, default: () => false }),
  discrepancies: Annotation<Discrepancy[]>({ reducer: (_a, b) => b, default: () => [] }),
  proposal: Annotation<ReconciliationProposal | null>({ reducer: (_a, b) => b, default: () => null }),
  governed_plan: Annotation<ProposedAction[]>({ reducer: (_a, b) => b, default: () => [] }),

  /** Safe visitation trace (node ids only) for debugging/comparison. */
  trace: Annotation<string[]>({ reducer: (a, b) => a.concat(b), default: () => [] }),
});

export type ReconciliationStateType = typeof ReconciliationState.State;

/** Node ids — also the canonical Phase 5 workflow vocabulary. */
export const NODES = {
  VALIDATE: 'VALIDATE_SYNTHETIC_INPUT',
  COMPARE: 'COMPARE_RECORDS',
  ANALYZE: 'ANALYZE_DISCREPANCY',
  PROPOSE: 'PROPOSE_RECONCILIATION',
} as const;

function validateNode(s: ReconciliationStateType): Partial<ReconciliationStateType> {
  // Pure guard: synthetic datasets must be present and well-formed.
  const ok = Array.isArray(s.ledger) && Array.isArray(s.statement) && s.ledger.length > 0;

  return { validated: ok, trace: [NODES.VALIDATE] };
}

function compareNode(s: ReconciliationStateType): Partial<ReconciliationStateType> {
  return { discrepancies: detectDiscrepancies(s.ledger, s.statement), trace: [NODES.COMPARE] };
}

function analyzeNode(s: ReconciliationStateType): Partial<ReconciliationStateType> {
  return { proposal: proposeReconciliation(s.discrepancies), trace: [NODES.ANALYZE] };
}

function proposeNode(s: ReconciliationStateType): Partial<ReconciliationStateType> {
  const plan: ProposedAction[] = [
    {
      step_kind: 'MODEL_INVOCATION',
      action_type: 'AI_MODEL_INVOCATION',
      target_resource: 'agent://reasoning',
      operation: 'analyze',
      material_parameters: {
        task: 'commission-reconciliation-analysis',
        reference: COMMISSION_RECON_REFERENCE.reference_id,
      },
      model_identity: s.primary_model,
      summary: 'Analyze two synthetic commission datasets for discrepancies.',
    },
  ];

  if (s.proposal) {
    const p = s.proposal;
    plan.push({
      step_kind: 'CONNECTOR_ACTION',
      action_type: 'EXTERNAL_DATA_TRANSMISSION',
      target_resource: `https://commission-recon-${p.broker_id.toLowerCase()}.invalid/reconcile`,
      operation: 'write_simulation',
      material_parameters: {
        synthetic: true,
        connector_id: COMMISSION_RECON_REFERENCE.connector_id,
        broker_id: p.broker_id,
        period: p.period,
        adjustment_minor: p.adjustment_minor,
      },
      summary: `Propose reconciliation adjustment of ${p.adjustment_minor} minor units for ${p.broker_id}.`,
    });
  }

  return { governed_plan: plan, trace: [NODES.PROPOSE] };
}

/** Compile the pure planning graph. Deterministic; no checkpointer, no network. */
export function buildReconciliationGraph() {
  return new StateGraph(ReconciliationState)
    .addNode(NODES.VALIDATE, validateNode)
    .addNode(NODES.COMPARE, compareNode)
    .addNode(NODES.ANALYZE, analyzeNode)
    .addNode(NODES.PROPOSE, proposeNode)
    .addEdge(START, NODES.VALIDATE)
    .addEdge(NODES.VALIDATE, NODES.COMPARE)
    .addEdge(NODES.COMPARE, NODES.ANALYZE)
    .addEdge(NODES.ANALYZE, NODES.PROPOSE)
    .addEdge(NODES.PROPOSE, END)
    .compile();
}

export interface PlanResult {
  governed_plan: ProposedAction[];
  trace: string[];
}

/**
 * Run the pure planning graph over synthetic inputs and return the governed
 * action plan. This performs NO consequential action — it only decides what
 * QHub should be asked to govern. Deterministic across restarts.
 */
export async function computeGovernedPlan(
  view: RuntimeManifestView,
  syntheticInputs: Record<string, unknown>,
): Promise<PlanResult> {
  const graph = buildReconciliationGraph();
  const ledger = (syntheticInputs?.ledger as CommissionRecord[]) ?? [];
  const statement = (syntheticInputs?.statement as CommissionRecord[]) ?? [];

  const final = await graph.invoke({
    ledger,
    statement,
    primary_model: view.primary_model,
  });

  return { governed_plan: final.governed_plan, trace: final.trace };
}
