/**
 * QHUB Agent Framework Foundation — Agent Run view (presentational)
 * app/components/agent/AgentRunView.tsx
 *
 * Minimal governed-run inspector: state, current step, per-step ALLOW/DENY/
 * REQUIRE_APPROVAL/SIMULATED decisions, receipts, and timestamps. Shows safe
 * summaries only — no chain-of-thought, no raw parameters.
 */

export interface AgentRunStepView {
  step_index: number;
  step_kind: string;
  action_type: string | null;
  decision: string | null;
  reason_codes: string[];
  receipt_id: string | null;
  summary: string;
  created_at: string;
}

export interface AgentRunViewProps {
  run: {
    run_id: string;
    current_state: string;
    current_step: number;
    proposed_action_count: number;
    approved_action_count: number;
    denied_action_count: number;
    started_at: string;
    completed_at: string | null;
  };
  steps: AgentRunStepView[];
}

const DECISION_COLOR: Record<string, string> = {
  ALLOW: 'text-green-500',
  SIMULATED: 'text-blue-500',
  EXECUTED: 'text-green-600',
  DENY: 'text-red-500',
  REQUIRE_APPROVAL: 'text-amber-500',
};

export function AgentRunView({ run, steps }: AgentRunViewProps) {
  return (
    <div className="rounded-lg border border-bolt-elements-borderColor bg-bolt-elements-background-depth-1 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold text-bolt-elements-textPrimary">Run {run.run_id.slice(0, 8)}</div>
          <div className="text-xs text-bolt-elements-textSecondary">
            {run.proposed_action_count} proposed · {run.approved_action_count} approved · {run.denied_action_count}{' '}
            denied
          </div>
        </div>
        <span className="rounded px-2 py-1 text-xs font-medium bg-bolt-elements-background-depth-2 uppercase">
          {run.current_state}
        </span>
      </div>
      <ol className="space-y-2">
        {steps.map((s) => (
          <li key={s.step_index} className="rounded border border-bolt-elements-borderColor/40 p-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-bolt-elements-textPrimary font-medium">
                #{s.step_index} · {s.step_kind}
                {s.action_type ? ` · ${s.action_type}` : ''}
              </span>
              <span className={`text-xs font-semibold ${s.decision ? (DECISION_COLOR[s.decision] ?? '') : ''}`}>
                {s.decision ?? '—'}
              </span>
            </div>
            <div className="text-bolt-elements-textSecondary text-xs mt-1">{s.summary}</div>
            {s.reason_codes.length > 0 ? (
              <div className="text-bolt-elements-textTertiary text-xs mt-1">{s.reason_codes.join(', ')}</div>
            ) : null}
            {s.receipt_id ? (
              <div className="text-bolt-elements-textTertiary text-xs mt-1">receipt {s.receipt_id.slice(0, 8)}</div>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  );
}
