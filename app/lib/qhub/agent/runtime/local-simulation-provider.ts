/**
 * QHUB Agent Framework Foundation — Local deterministic simulation provider
 * app/lib/qhub/agent/runtime/local-simulation-provider.ts
 *
 * A local, dependency-free reasoning engine for tests + SIMULATION. It computes a
 * fully deterministic action PLAN at init and proposes one planned action per
 * step, so it resumes deterministically by step_index after an approval pause.
 * It NEVER executes anything itself — it only proposes; QHUB governs and executes
 * through Gate 04. No network, no credentials.
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
  COMMISSION_RECON_REFERENCE,
  detectDiscrepancies,
  proposeReconciliation,
  type CommissionRecord,
} from '~/lib/qhub/agent/reference/commission-reconciliation';

export const LOCAL_SIMULATION_PROVIDER_ID = 'qhub.runtime.local-simulation';
export const LOCAL_SIMULATION_PROVIDER_VERSION = '1.0.0';

function stepDenied(prior: GovernedActionResult[]): boolean {
  return prior.some((r) => r.decision === 'DENY');
}

export class LocalSimulationProvider implements AgentRuntimeProvider {
  readonly provider_id = LOCAL_SIMULATION_PROVIDER_ID;
  readonly provider_version = LOCAL_SIMULATION_PROVIDER_VERSION;

  private _plan: ProposedAction[] = [];
  private _cancelled = false;

  async init(ctx: RuntimeInitContext): Promise<void> {
    this._cancelled = false;
    this._plan = this._buildPlan(ctx);
  }

  /**
   * The deterministic governed-action plan. Read-only; used by the no-replay
   * reconstruction guard to compute expected input hashes for stored steps.
   */
  plan(): readonly ProposedAction[] {
    return this._plan;
  }

  /** Deterministic plan for the commission-reconciliation reference workflow. */
  private _buildPlan(ctx: RuntimeInitContext): ProposedAction[] {
    const model = ctx.manifest.primary_model;
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
        model_identity: model,
        summary: 'Analyze two synthetic commission datasets for discrepancies.',
      },
    ];

    const ledger = (ctx.synthetic_inputs?.ledger as CommissionRecord[]) ?? [];
    const statement = (ctx.synthetic_inputs?.statement as CommissionRecord[]) ?? [];
    const proposal = proposeReconciliation(detectDiscrepancies(ledger, statement));

    if (proposal) {
      plan.push({
        step_kind: 'CONNECTOR_ACTION',
        action_type: 'EXTERNAL_DATA_TRANSMISSION',

        /*
         * Shaped for the existing staging simulation adapter: an https '.invalid'
         * synthetic sink + 'write_simulation' allowlisted operation. No real
         * destination — the host resolves nowhere by RFC 6761.
         */
        target_resource: `https://commission-recon-${proposal.broker_id.toLowerCase()}.invalid/reconcile`,
        operation: 'write_simulation',
        material_parameters: {
          synthetic: true,
          connector_id: COMMISSION_RECON_REFERENCE.connector_id,
          broker_id: proposal.broker_id,
          period: proposal.period,
          adjustment_minor: proposal.adjustment_minor,
        },
        summary: `Propose reconciliation adjustment of ${proposal.adjustment_minor} minor units for ${proposal.broker_id}.`,
      });
    }

    return plan;
  }

  async step(input: RuntimeStepInput): Promise<RuntimeStepOutput> {
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

    return { kind: 'PROPOSE', proposed_actions: [this._plan[input.step_index]] };
  }

  cancel(): void {
    this._cancelled = true;
  }
}
