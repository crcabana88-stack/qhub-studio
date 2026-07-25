/**
 * QHUB Gate 03 — Policy card
 * app/components/chat/PolicyCard.tsx
 *
 * Shown inline in the Studio immediately after the classification is confirmed
 * and before code generation. It presents the DETERMINISTIC control set the
 * server bound to this app (required / conditional / advisory), the required
 * attestations, and the build-stage constraints that will be handed to the
 * builder. The user acknowledges the controls; they cannot remove or weaken
 * them — mandatory controls come only from the versioned catalog.
 */

import { useState } from 'react';
import type { PolicyProfile } from '~/lib/qhub/policy';
import { TIER_DISPLAY, type RiskTier } from '~/lib/qhub/classification';

const TIER_COLOR: Record<RiskTier, string> = {
  T0: '#1D9E75',
  T1: '#2447F0',
  T2: '#C77700',
  T3: '#D1242F',
};

const CATEGORY_LABEL: Record<string, string> = {
  IDENTITY_AND_ACCESS: 'Identity & access',
  TENANT_ISOLATION: 'Tenant isolation',
  DATA_PROTECTION: 'Data protection',
  MODEL_GOVERNANCE: 'Model governance',
  INTEGRATIONS_AND_TOOLS: 'Integrations & tools',
  SECURE_DEVELOPMENT: 'Secure development',
  AUDIT_AND_EVIDENCE: 'Audit & evidence',
  HUMAN_OVERSIGHT: 'Human oversight',
  DEPLOYMENT: 'Deployment',
  RUNTIME_MONITORING: 'Runtime monitoring',
  RECORDS_AND_RETENTION: 'Records & retention',
  INCIDENT_RESPONSE: 'Incident response',
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div
        style={{
          fontSize: 11,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: 'rgba(120,130,141,0.9)',
          marginBottom: 6,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function ControlRow({
  controlId,
  title,
  category,
  color,
}: {
  controlId: string;
  title: string;
  category: string;
  color: string;
}) {
  return (
    <div
      style={{ display: 'flex', alignItems: 'baseline', gap: 8, padding: '4px 0', fontSize: 12.5, lineHeight: 1.45 }}
    >
      <span
        style={{
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          fontSize: 10.5,
          color,
          border: `1px solid ${color}44`,
          borderRadius: 5,
          padding: '1px 5px',
          whiteSpace: 'nowrap',
        }}
      >
        {controlId}
      </span>
      <span style={{ flex: 1 }}>
        {title}
        <span style={{ color: 'rgba(120,130,141,0.8)' }}> · {CATEGORY_LABEL[category] ?? category}</span>
      </span>
    </div>
  );
}

export function PolicyCard({
  profile,
  onAcknowledge,
  busy,
}: {
  profile: PolicyProfile;
  onAcknowledge: () => void;
  busy?: boolean;
}) {
  const tier = profile.risk_tier;
  const color = TIER_COLOR[tier];
  const [showAll, setShowAll] = useState(false);

  const required = profile.required_controls;
  const shown = showAll ? required : required.slice(0, 8);
  const acknowledged = profile.status === 'ACKNOWLEDGED';

  const buildConstraints = profile.build_constraints;
  const nonBuild =
    profile.preview_constraints.length + profile.deployment_constraints.length + profile.runtime_constraints.length;

  return (
    <div
      style={{
        border: `1px solid ${color}55`,
        borderRadius: 14,
        background: 'var(--bolt-elements-bg-depth-1, rgba(255,255,255,0.04))',
        padding: 20,
        maxWidth: 620,
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span
          style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)' }}
        >
          02 · Policy
        </span>
        <span
          style={{
            marginLeft: 'auto',
            fontSize: 11,
            padding: '2px 8px',
            borderRadius: 999,
            background: acknowledged ? 'rgba(29,158,117,0.15)' : `${color}22`,
            color: acknowledged ? '#1D9E75' : color,
          }}
        >
          {acknowledged ? 'Acknowledged' : 'Assigned — needs acknowledgement'}
        </span>
      </div>

      {/* Summary line */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
        <div
          style={{
            width: 46,
            height: 46,
            borderRadius: 12,
            background: `${color}22`,
            border: `1px solid ${color}`,
            color,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 700,
            fontSize: 18,
          }}
        >
          {tier}
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>
            {required.length} mandatory control{required.length === 1 ? '' : 's'} for {TIER_DISPLAY[tier].short} apps
          </div>
          <div style={{ fontSize: 12.5, color: 'rgba(120,130,141,0.95)' }}>
            These controls are required before build, preview, and deployment. They cannot be removed.
          </div>
        </div>
      </div>

      {/* Required controls */}
      <Section title="Required controls (mandatory)">
        <div>
          {shown.map((c) => (
            <ControlRow
              key={c.control_id}
              controlId={c.control_id}
              title={c.title}
              category={c.category}
              color={color}
            />
          ))}
        </div>
        {required.length > 8 && (
          <button
            type="button"
            onClick={() => setShowAll((v) => !v)}
            style={{
              marginTop: 6,
              background: 'transparent',
              border: 'none',
              color,
              fontSize: 12,
              cursor: 'pointer',
              padding: 0,
            }}
          >
            {showAll ? 'Show fewer' : `Show all ${required.length} controls`}
          </button>
        )}
      </Section>

      {/* Build constraints handed to the builder */}
      {buildConstraints.length > 0 && (
        <Section title="Build constraints applied to generation">
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, lineHeight: 1.5 }}>
            {buildConstraints.slice(0, 6).map((c) => (
              <li key={c.constraint_id}>{c.statement}</li>
            ))}
            {buildConstraints.length > 6 && (
              <li style={{ color: 'rgba(120,130,141,0.85)' }}>
                +{buildConstraints.length - 6} more enforced at generation
              </li>
            )}
          </ul>
        </Section>
      )}

      {/* Required attestations */}
      {profile.required_attestations.length > 0 && (
        <Section title="Attestations required before production">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {profile.required_attestations.map((a) => (
              <span
                key={a}
                style={{
                  fontSize: 12,
                  padding: '2px 8px',
                  borderRadius: 6,
                  background: `${color}14`,
                  border: `1px solid ${color}33`,
                }}
              >
                {a.replaceAll('_', ' ').toLowerCase()}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Provenance footer */}
      <div
        style={{
          fontSize: 11,
          color: 'rgba(120,130,141,0.85)',
          borderTop: '1px solid rgba(120,130,141,0.18)',
          paddingTop: 10,
          marginBottom: 14,
          display: 'flex',
          flexWrap: 'wrap',
          gap: '2px 14px',
        }}
      >
        <span>catalog {profile.policy_catalog_version}</span>
        <span>profile v{profile.policy_profile_version}</span>
        <span>
          {profile.conditional_controls.length} conditional · {profile.advisory_controls.length} advisory
        </span>
        {nonBuild > 0 && <span>{nonBuild} preview/deploy/runtime constraints</span>}
        {profile.policy_profile_hash && (
          <span style={{ fontFamily: 'ui-monospace, monospace' }}>
            hash {profile.policy_profile_hash.slice(0, 12)}…
          </span>
        )}
      </div>

      <button
        type="button"
        disabled={busy || acknowledged}
        onClick={onAcknowledge}
        style={{
          width: '100%',
          padding: '11px 18px',
          borderRadius: 10,
          border: 'none',
          background: busy ? 'rgba(120,130,141,0.4)' : color,
          color: '#fff',
          fontWeight: 600,
          fontSize: 14,
          cursor: busy || acknowledged ? 'default' : 'pointer',
        }}
      >
        {acknowledged
          ? 'Policy acknowledged — starting build'
          : busy
            ? 'Acknowledging controls…'
            : 'Acknowledge controls & begin governed build'}
      </button>
    </div>
  );
}
