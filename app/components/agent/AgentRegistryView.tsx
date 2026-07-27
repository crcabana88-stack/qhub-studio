/**
 * QHUB Agent Framework Foundation — Agent Registry view (presentational)
 * app/components/agent/AgentRegistryView.tsx
 *
 * Minimal per-tenant registry table. No cross-customer discovery, no marketplace.
 */

import type { AgentRow } from '~/lib/qhub/agent/agent-registry.server';

export interface AgentRegistryViewProps {
  agents: AgentRow[];
  onSuspend?: (agentId: string) => void;
}

const STATE_COLOR: Record<string, string> = {
  DRAFT: 'text-bolt-elements-textSecondary',
  SIMULATION: 'text-blue-500',
  SUPERVISED: 'text-amber-500',
  ACTIVE: 'text-green-500',
  SUSPENDED: 'text-red-500',
  RETIRED: 'text-bolt-elements-textTertiary',
};

export function AgentRegistryView({ agents, onSuspend }: AgentRegistryViewProps) {
  if (agents.length === 0) {
    return (
      <div className="text-sm text-bolt-elements-textSecondary p-4">
        No agents yet. Choose “Build Agent” to create one.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-bolt-elements-borderColor">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-bolt-elements-textSecondary border-b border-bolt-elements-borderColor">
            <th className="p-2 font-medium">Agent</th>
            <th className="p-2 font-medium">Owner</th>
            <th className="p-2 font-medium">Mode</th>
            <th className="p-2 font-medium">Tier</th>
            <th className="p-2 font-medium">Status</th>
            <th className="p-2 font-medium">Kill switch</th>
            <th className="p-2 font-medium" />
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => (
            <tr key={a.agent_id} className="border-b border-bolt-elements-borderColor/40">
              <td className="p-2 text-bolt-elements-textPrimary font-medium">{a.name}</td>
              <td className="p-2 text-bolt-elements-textSecondary">{a.owner_user_id}</td>
              <td className="p-2">{a.current_operating_mode}</td>
              <td className="p-2">{a.risk_tier}</td>
              <td className={`p-2 font-medium ${STATE_COLOR[a.current_lifecycle_state] ?? ''}`}>
                {a.current_lifecycle_state}
              </td>
              <td className="p-2">{a.kill_switch_active ? 'ACTIVE' : '—'}</td>
              <td className="p-2 text-right">
                {onSuspend && a.current_lifecycle_state !== 'RETIRED' && !a.kill_switch_active ? (
                  <button
                    type="button"
                    onClick={() => onSuspend(a.agent_id)}
                    className="rounded px-2 py-1 text-xs bg-red-500/10 text-red-500 hover:bg-red-500/20"
                  >
                    Suspend
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
