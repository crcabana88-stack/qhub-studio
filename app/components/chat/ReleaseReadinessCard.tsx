/**
 * QHUB Gate 05 — Release readiness & attestation card
 * app/components/chat/ReleaseReadinessCard.tsx
 *
 * Business-readable release-readiness surface: exact version + short release hash,
 * target environment, tier, required vs completed attestations, and deployment
 * status. Shows NO raw source, secrets, private data, or internal attack detail.
 */

import type { RiskTier } from '~/lib/qhub/classification';
import type { AttestationPurpose } from '~/lib/qhub/release-candidate';

const TIER_COLOR: Record<RiskTier, string> = { T0: '#1D9E75', T1: '#2447F0', T2: '#C77700', T3: '#D1242F' };

export interface ReleaseReadinessView {
  app_name: string;
  qhub_app_version: number;
  release_candidate_hash: string;
  target_environment: string;
  risk_tier: RiskTier;
  policy_profile_version: number;
  enforcement_plan_version: number;
  changed_components: string[];
  required_attestations: { purpose: AttestationPurpose; roles: string[]; min_signers: number; satisfied: boolean }[];
  deployment_status: 'DRAFT' | 'FROZEN' | 'AWAITING_ATTESTATION' | 'APPROVED' | 'REJECTED' | 'SUPERSEDED' | 'DEPLOYED';
  known_exceptions: string[];
}

const STATUS_COLOR: Record<ReleaseReadinessView['deployment_status'], string> = {
  DRAFT: '#5f6b73',
  FROZEN: '#2447F0',
  AWAITING_ATTESTATION: '#C77700',
  APPROVED: '#1D9E75',
  REJECTED: '#D1242F',
  SUPERSEDED: '#5f6b73',
  DEPLOYED: '#1D9E75',
};

export function ReleaseReadinessCard({
  view,
  onSign,
  onEvaluate,
  busy,
}: {
  view: ReleaseReadinessView;
  onSign?: (purpose: AttestationPurpose) => void;
  onEvaluate?: () => void;
  busy?: boolean;
}) {
  const color = TIER_COLOR[view.risk_tier];
  const missing = view.required_attestations.filter((a) => !a.satisfied);

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
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span
          style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)' }}
        >
          05 · Attest &amp; Release
        </span>
        <span
          style={{
            marginLeft: 'auto',
            fontSize: 12,
            fontWeight: 700,
            padding: '3px 10px',
            borderRadius: 999,
            background: `${STATUS_COLOR[view.deployment_status]}18`,
            color: STATUS_COLOR[view.deployment_status],
          }}
        >
          {view.deployment_status.replaceAll('_', ' ').toLowerCase()}
        </span>
      </div>

      <div style={{ fontWeight: 700, fontSize: 16 }}>
        {view.app_name} · v{view.qhub_app_version}
      </div>
      <div
        style={{
          fontSize: 12,
          color: 'rgba(120,130,141,0.95)',
          fontFamily: 'ui-monospace, monospace',
          marginBottom: 12,
        }}
      >
        release {view.release_candidate_hash.slice(0, 16)}… → {view.target_environment.toLowerCase()} · {view.risk_tier}{' '}
        · policy v{view.policy_profile_version} · plan v{view.enforcement_plan_version}
      </div>

      {view.changed_components.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'rgba(120,130,141,0.9)',
              marginBottom: 4,
            }}
          >
            Changed since last version
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {view.changed_components.map((c) => (
              <span
                key={c}
                style={{
                  fontSize: 12,
                  padding: '2px 8px',
                  borderRadius: 6,
                  background: 'rgba(199,119,0,0.12)',
                  border: '1px solid rgba(199,119,0,0.3)',
                }}
              >
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginBottom: 12 }}>
        <div
          style={{
            fontSize: 11,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            color: 'rgba(120,130,141,0.9)',
            marginBottom: 6,
          }}
        >
          Required attestations
        </div>
        {view.required_attestations.length === 0 && (
          <div style={{ fontSize: 13, color: 'rgba(120,130,141,0.95)' }}>None required by policy for this tier.</div>
        )}
        {view.required_attestations.map((a) => (
          <div
            key={a.purpose}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 13.5 }}
          >
            <span style={{ color: a.satisfied ? '#1D9E75' : '#C77700' }}>{a.satisfied ? '✓' : '◷'}</span>
            <span style={{ flex: 1 }}>
              {a.purpose.replaceAll('_', ' ').toLowerCase()}{' '}
              <span style={{ color: 'rgba(120,130,141,0.8)', fontSize: 12 }}>
                · {a.roles.join('/')}
                {a.min_signers > 1 ? ` · ${a.min_signers} distinct` : ''}
              </span>
            </span>
            {!a.satisfied && onSign && (
              <button
                type="button"
                disabled={busy}
                onClick={() => onSign(a.purpose)}
                style={{
                  fontSize: 12,
                  padding: '4px 10px',
                  borderRadius: 8,
                  border: `1px solid ${color}`,
                  background: `${color}12`,
                  color,
                  cursor: busy ? 'wait' : 'pointer',
                }}
              >
                Sign
              </button>
            )}
          </div>
        ))}
      </div>

      {onEvaluate && (
        <button
          type="button"
          disabled={busy}
          onClick={onEvaluate}
          style={{
            width: '100%',
            padding: '11px 18px',
            borderRadius: 10,
            border: 'none',
            background: busy ? 'rgba(120,130,141,0.4)' : color,
            color: '#fff',
            fontWeight: 600,
            fontSize: 14,
            cursor: busy ? 'wait' : 'pointer',
          }}
        >
          {missing.length === 0
            ? 'Evaluate for deployment'
            : `${missing.length} attestation${missing.length === 1 ? '' : 's'} outstanding`}
        </button>
      )}
    </div>
  );
}
