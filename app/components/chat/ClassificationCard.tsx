/**
 * QHUB Gate 02 — Classification card
 * app/components/chat/ClassificationCard.tsx
 *
 * Shown inline in the Studio immediately after the app description and before
 * substantive generation. The user confirms or corrects the proposed tier.
 * The tier can be raised freely; it CANNOT be lowered below the deterministic
 * risk floor (those options are disabled — spec §8).
 */

import { useState } from 'react';
import {
  RISK_TIERS,
  TIER_DISPLAY,
  tierRank,
  type ClassificationResult,
  type RiskTier,
} from '~/lib/qhub/classification';

const TIER_COLOR: Record<RiskTier, string> = {
  T0: '#1D9E75',
  T1: '#2447F0',
  T2: '#C77700',
  T3: '#D1242F',
};

const CONFIRM_NOTE: Record<RiskTier, string> = {
  T0: 'Build and deploy permitted under baseline controls.',
  T1: 'Build and deploy permitted after your confirmation and baseline checks.',
  T2: 'Build permitted. Production deployment requires application-owner attestation.',
  T3: 'Build permitted in isolated preview only. Production deployment requires authorized governance / compliance / security approval.',
};

function Chips({ label, items }: { label: string; items: string[] }) {
  if (!items || items.length === 0) {
    return null;
  }
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 11, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)', marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {items.map((it) => (
          <span
            key={it}
            style={{
              fontSize: 12,
              padding: '2px 8px',
              borderRadius: 6,
              background: 'rgba(120,130,141,0.12)',
              border: '1px solid rgba(120,130,141,0.2)',
              color: 'inherit',
            }}
          >
            {it.replaceAll('_', ' ').toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

export function ClassificationCard({
  classification,
  onConfirm,
  busy,
}: {
  classification: ClassificationResult;
  onConfirm: (tier: RiskTier) => void;
  busy?: boolean;
}) {
  const floorRank = tierRank(classification.risk_floor);
  const [selected, setSelected] = useState<RiskTier>(classification.risk_tier);
  const color = TIER_COLOR[selected];

  return (
    <div
      style={{
        border: `1px solid ${color}55`,
        borderRadius: 14,
        background: 'var(--bolt-elements-bg-depth-1, rgba(255,255,255,0.04))',
        padding: 20,
        maxWidth: 560,
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)' }}>
          01 · Classify
        </span>
        <span
          style={{
            marginLeft: 'auto',
            fontSize: 11,
            padding: '2px 8px',
            borderRadius: 999,
            background: classification.confirmed_at ? 'rgba(29,158,117,0.15)' : 'rgba(199,119,0,0.15)',
            color: classification.confirmed_at ? '#1D9E75' : '#C77700',
          }}
        >
          {classification.confirmed_at ? 'Confirmed' : 'Provisional — needs confirmation'}
        </span>
      </div>

      {/* Tier badge */}
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
          {selected}
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>{TIER_DISPLAY[selected].label}</div>
          <div style={{ fontSize: 12.5, color: 'rgba(120,130,141,0.95)' }}>{TIER_DISPLAY[selected].blurb}</div>
        </div>
      </div>

      {/* Rationale */}
      <p style={{ fontSize: 13.5, lineHeight: 1.5, margin: '0 0 14px 0' }}>{classification.rationale}</p>

      {/* Detected signals */}
      <Chips label="Data types" items={classification.data_classes} />
      <Chips label="Integrations" items={classification.integration_types} />
      <Chips label="AI behavior / autonomy" items={[classification.ai_behavior, classification.autonomy_level]} />
      <Chips label="Regulatory applicability" items={classification.regulatory_domains} />

      {/* Floor reasons */}
      {classification.floor_reasons.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)', marginBottom: 4 }}>
            Factors that set the minimum tier (T{floorRank})
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, lineHeight: 1.5 }}>
            {classification.floor_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tier selector (cannot go below floor) */}
      <div style={{ marginBottom: 8, fontSize: 11, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'rgba(120,130,141,0.9)' }}>
        Confirm or raise the tier
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        {RISK_TIERS.map((t) => {
          const belowFloor = tierRank(t) < floorRank;
          const active = t === selected;
          return (
            <button
              key={t}
              type="button"
              disabled={belowFloor || busy}
              onClick={() => setSelected(t)}
              title={belowFloor ? `Blocked: below the required minimum (${classification.risk_floor})` : TIER_DISPLAY[t].short}
              style={{
                flex: 1,
                padding: '8px 6px',
                borderRadius: 9,
                border: `1px solid ${active ? TIER_COLOR[t] : 'rgba(120,130,141,0.25)'}`,
                background: active ? `${TIER_COLOR[t]}18` : 'transparent',
                color: belowFloor ? 'rgba(120,130,141,0.5)' : 'inherit',
                cursor: belowFloor || busy ? 'not-allowed' : 'pointer',
                fontWeight: active ? 700 : 500,
                fontSize: 12.5,
              }}
            >
              {t}
              <div style={{ fontSize: 10.5, opacity: 0.8 }}>{TIER_DISPLAY[t].short}</div>
            </button>
          );
        })}
      </div>

      {/* Consequence note */}
      <div
        style={{
          fontSize: 12.5,
          lineHeight: 1.5,
          padding: '10px 12px',
          borderRadius: 9,
          background: `${color}12`,
          border: `1px solid ${color}33`,
          marginBottom: 14,
        }}
      >
        {CONFIRM_NOTE[selected]}
      </div>

      <button
        type="button"
        disabled={busy}
        onClick={() => onConfirm(selected)}
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
        {busy ? 'Recording classification…' : `Confirm ${selected} & continue build`}
      </button>
    </div>
  );
}
