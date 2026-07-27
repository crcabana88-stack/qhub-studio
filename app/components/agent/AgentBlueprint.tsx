/**
 * QHUB Agent Framework Foundation — Agent Blueprint view (presentational)
 * app/components/agent/AgentBlueprint.tsx
 *
 * Read-only summary of one agent version's governed configuration. Shows only
 * safe metadata (purpose, owner, policy, mode, model, tools, limits, status,
 * release state) — never raw instructions, credentials, or hashes to forge with.
 */

import type { AgentManifest } from '~/lib/qhub/agent/agent-manifest';
import type { AgentLifecycleState } from '~/lib/qhub/agent/agent-lifecycle';

export interface AgentBlueprintProps {
  manifest: AgentManifest;
  lifecycle_state: AgentLifecycleState;
  release_bound: boolean;
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 border-b border-bolt-elements-borderColor/40 text-sm">
      <span className="text-bolt-elements-textSecondary">{label}</span>
      <span className="text-bolt-elements-textPrimary text-right font-medium">{value}</span>
    </div>
  );
}

export function AgentBlueprint({
  manifest,
  lifecycle_state: lifecycleState,
  release_bound: releaseBound,
}: AgentBlueprintProps) {
  return (
    <div className="rounded-lg border border-bolt-elements-borderColor bg-bolt-elements-background-depth-1 p-4">
      <div className="mb-3">
        <h3 className="text-base font-semibold text-bolt-elements-textPrimary">{manifest.name}</h3>
        <p className="text-sm text-bolt-elements-textSecondary">{manifest.business_purpose}</p>
      </div>
      <Row label="Owner" value={manifest.owner_user_id} />
      <Row label="Classification" value={`${manifest.risk_tier} (v${manifest.classification_version})`} />
      <Row label="Operating mode" value={manifest.operating_mode} />
      <Row label="Autonomy" value={manifest.autonomy_level} />
      <Row label="Primary model" value={manifest.primary_model} />
      <Row label="Approved tools" value={manifest.approved_tools.map((t) => t.tool_id).join(', ') || '—'} />
      <Row
        label="Approved connectors"
        value={manifest.approved_connectors.map((c) => c.connector_id).join(', ') || '—'}
      />
      <Row label="Network policy" value={manifest.network_access_policy} />
      <Row label="Human approval required" value={manifest.human_approval_required ? 'Yes' : 'No'} />
      <Row
        label="Max actions / model calls"
        value={`${manifest.action_limits.max_actions_per_run} / ${manifest.action_limits.max_model_calls_per_run}`}
      />
      <Row label="Environment" value={manifest.execution_environment} />
      <Row label="Status" value={<span className="uppercase">{lifecycleState}</span>} />
      <Row label="Release approval" value={releaseBound ? 'Bound' : 'Not bound'} />
    </div>
  );
}
