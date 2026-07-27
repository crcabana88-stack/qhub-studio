/**
 * QHUB Agent Framework — LangGraph runtime provider (EVALUATION)
 * app/lib/qhub/agent/runtime/langgraph-runtime-provider.ts
 *
 * A replaceable AgentRuntimeProvider backed by a LangGraph StateGraph. It fits the
 * SAME contract as the local provider: it only PROPOSES governed actions and
 * receives governed results — it never executes, never holds credentials, and
 * never reaches the network. At init it runs the pure planning graph once to
 * derive a deterministic governed-action plan; each step proposes exactly the one
 * planned action for that index, so an approval pause / restart re-derives the
 * identical plan and re-proposes WITHOUT re-executing any completed node.
 *
 * LangGraph coordinates the workflow. QHub (Gate 04 / Gate 05) remains the sole
 * authority for identity, permissions, enforcement, approval, execution, and
 * evidence.
 */

import type {
  AgentRuntimeProvider,
  GovernedActionResult,
  ProposedAction,
  RuntimeInitContext,
  RuntimeStepInput,
  RuntimeStepOutput,
} from './provider';
import {
  computeGovernedPlan,
  RECONCILIATION_GRAPH_VERSION,
} from '~/lib/qhub/agent/reference/commission-reconciliation-graph';

export const LANGGRAPH_PROVIDER_ID = 'qhub.runtime.langgraph';
export const LANGGRAPH_PROVIDER_VERSION = '0.1.0-eval';

function stepDenied(prior: GovernedActionResult[]): boolean {
  return prior.some((r) => r.decision === 'DENY');
}

export class LangGraphRuntimeProvider implements AgentRuntimeProvider {
  readonly provider_id = LANGGRAPH_PROVIDER_ID;
  readonly provider_version = LANGGRAPH_PROVIDER_VERSION;
  readonly graph_version = RECONCILIATION_GRAPH_VERSION;

  private _plan: ProposedAction[] = [];
  private _initialized = false;
  private _cancelled = false;

  async init(ctx: RuntimeInitContext): Promise<void> {
    this._cancelled = false;

    // Pure planning graph — no external effect, deterministic across restarts.
    const { governed_plan: governedPlan } = await computeGovernedPlan(ctx.manifest, ctx.synthetic_inputs);
    this._plan = governedPlan;
    this._initialized = true;
  }

  /**
   * The deterministic governed-action plan derived by the graph. Read-only; used
   * by the no-replay guard to compute expected input hashes for stored steps.
   */
  plan(): readonly ProposedAction[] {
    return this._plan;
  }

  async step(input: RuntimeStepInput): Promise<RuntimeStepOutput> {
    if (!this._initialized) {
      return { kind: 'FAIL', error_reason: 'PROVIDER_NOT_INITIALIZED' };
    }

    if (this._cancelled) {
      return { kind: 'FAIL', error_reason: 'CANCELLED' };
    }

    if (stepDenied(input.prior_results)) {
      return { kind: 'FAIL', error_reason: 'GOVERNED_ACTION_DENIED' };
    }

    if (input.step_index >= this._plan.length) {
      const wrote = input.prior_results.some((r) => r.decision === 'EXECUTED' || r.decision === 'SIMULATED');

      return {
        kind: 'COMPLETE',
        output_summary: wrote
          ? 'Reconciliation adjustment recorded via simulated transmission adapter.'
          : 'Analysis complete; no reconciliation adjustment required.',
      };
    }

    // Propose exactly the planned action for this index. No execution here.
    return { kind: 'PROPOSE', proposed_actions: [this._plan[input.step_index]] };
  }

  cancel(): void {
    this._cancelled = true;
  }
}
