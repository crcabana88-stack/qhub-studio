/**
 * QHUB Gate 04 — Enforcement decision card
 * app/components/chat/EnforcementDecisionCard.tsx
 *
 * Concise, business-readable surface for a governed-action decision. Renders the
 * ALLOW / DENY / REQUIRES APPROVAL outcome, a plain-English reason, the controls
 * involved, any approval needed, and the plan/profile version + evidence status.
 * Shows NO sensitive parameters, internal rule detail, secrets, or model reasoning.
 */

import type { Decision, GovernedExecutionMode, GovernedExecutionStatus, ReasonCode } from '~/lib/qhub/enforcement';

const DECISION_COLOR: Record<Decision, string> = {
  ALLOW: '#1D9E75',
  DENY: '#D1242F',
  REQUIRE_APPROVAL: '#C77700',
};

const DECISION_LABEL: Record<Decision, string> = {
  ALLOW: 'Allowed',
  DENY: 'Blocked',
  REQUIRE_APPROVAL: 'Requires approval',
};

const REASON_TEXT: Partial<Record<ReasonCode, string>> = {
  ALLOWED_BASELINE: 'Permitted under this application’s baseline controls.',
  ALLOWED_APPROVED: 'Permitted — the required approval is present and valid.',
  KILL_SWITCH_ACTIVE: 'The operator kill switch is active; consequential activity is halted.',
  UNRESTRICTED_AUTONOMY_DENIED: 'Unrestricted autonomous production action is prohibited for this tier.',
  PREVIEW_ONLY_PRODUCTION_DENIED: 'This app is preview-only; production requires authorized approval.',
  PRODUCTION_APPROVAL_REQUIRED: 'Production requires authorized governance approval.',
  DUAL_CONTROL_REQUIRED: 'Two independent approvers are required for this action.',
  ATTESTATION_REQUIRED: 'An owner attestation is required before this action.',
  MODEL_NOT_APPROVED: 'The requested model is not on the approved allowlist.',
  ACTION_TYPE_NOT_PROTECTED: 'This action type is not permitted for this application.',
  SCHEMA_NOT_READY: 'Governance storage is not ready; the action is blocked (fail-closed).',
  POLICY_MISSING: 'No policy profile is assigned yet; classify and assign policy first.',
  CLASSIFICATION_MISSING: 'This application has not been classified yet.',
  REPLAY_DENIED: 'This authorization was already used; a fresh decision is required.',
  RBAC_DENIED: 'Your role is not authorized for this action.',
  TENANT_MISMATCH: 'This action is not valid for your tenant.',
  ADAPTER_NOT_CONFIGURED: 'No authorized execution adapter is available; the action is blocked.',
  ADAPTER_EXECUTION_FAILED: 'The authorized adapter failed; no success was reported.',
  RECEIPT_RECORD_FAILED: 'The action receipt could not be committed; reconciliation is required.',
};

export interface EnforcementDecisionView {
  decision: Decision;
  reason_codes: ReasonCode[];
  action_type: string | null;
  required_attestations: string[];
  controls_involved: { control_id: string; status: string }[];
  enforcement_plan_version: number | null;
  policy_profile_version: number | null;
  evidence_recorded: boolean;
  side_effect_performed: boolean;
  adapter_executed?: boolean | null;
  external_effect_performed?: boolean | null;
  execution_mode?: GovernedExecutionMode | null;
  execution_status?: GovernedExecutionStatus | null;
}

export function EnforcementDecisionCard({ view }: { view: EnforcementDecisionView }) {
  const color = DECISION_COLOR[view.decision];
  const primaryReason = view.reason_codes.map((r) => REASON_TEXT[r]).find(Boolean) ?? view.reason_codes[0] ?? '';

  return (
    <div
      style={{
        border: `1px solid ${color}55`,
        borderRadius: 14,
        background: 'var(--bolt-elements-bg-depth-1, rgba(255,255,255,0.04))',
        padding: 18,
        maxWidth: 560,
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span
          style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)' }}
        >
          Control enforcement
        </span>
        <span
          style={{
            marginLeft: 'auto',
            fontSize: 12,
            fontWeight: 700,
            padding: '3px 10px',
            borderRadius: 999,
            background: `${color}18`,
            color,
          }}
        >
          {DECISION_LABEL[view.decision]}
        </span>
      </div>

      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>
        {(view.action_type ?? 'action').replaceAll('_', ' ').toLowerCase()}
      </div>
      <p style={{ fontSize: 13, lineHeight: 1.5, margin: '0 0 12px 0', color: 'rgba(120,130,141,0.95)' }}>
        {primaryReason}
      </p>

      {view.required_attestations.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'rgba(120,130,141,0.9)',
              marginBottom: 4,
            }}
          >
            Approval needed
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {view.required_attestations.map((a) => (
              <span
                key={a}
                style={{
                  fontSize: 12,
                  padding: '2px 8px',
                  borderRadius: 6,
                  background: `${color}12`,
                  border: `1px solid ${color}33`,
                }}
              >
                {a.replaceAll('_', ' ').toLowerCase()}
              </span>
            ))}
          </div>
        </div>
      )}

      {view.controls_involved.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'rgba(120,130,141,0.9)',
              marginBottom: 4,
            }}
          >
            Controls evaluated
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {view.controls_involved.map((c) => (
              <span
                key={c.control_id}
                style={{
                  fontSize: 10.5,
                  fontFamily: 'ui-monospace, monospace',
                  padding: '1px 6px',
                  borderRadius: 5,
                  border: '1px solid rgba(120,130,141,0.25)',
                }}
                title={c.status}
              >
                {c.control_id}
              </span>
            ))}
          </div>
        </div>
      )}

      <div
        style={{
          fontSize: 11,
          color: 'rgba(120,130,141,0.85)',
          borderTop: '1px solid rgba(120,130,141,0.18)',
          paddingTop: 8,
          display: 'flex',
          gap: '2px 14px',
          flexWrap: 'wrap',
        }}
      >
        {view.policy_profile_version != null && <span>policy v{view.policy_profile_version}</span>}
        {view.enforcement_plan_version != null && <span>plan v{view.enforcement_plan_version}</span>}
        <span>{view.evidence_recorded ? 'evidence recorded' : 'evidence not recorded'}</span>
        {view.execution_mode === 'SIMULATION' && view.adapter_executed && (
          <span>
            {view.execution_status === 'SIMULATED_ACKNOWLEDGED' ? 'simulation acknowledged' : 'simulation completed'}
          </span>
        )}
        {view.decision === 'ALLOW' && view.execution_mode !== 'SIMULATION' && (
          <span>{view.side_effect_performed ? 'action executed' : 'not executed'}</span>
        )}
      </div>
    </div>
  );
}
