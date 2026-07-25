/**
 * QHUB Gate 03 — Deterministic policy engine (PURE, INDEPENDENTLY TESTABLE)
 * app/lib/qhub/policy-engine.ts
 *
 * Given a confirmed classification, produces a PolicyProfile deterministically
 * from the versioned catalog: tier baseline + signal overlays + regulatory
 * overlays → deduplicated controls (with merged applicability reasons) →
 * required/conditional/advisory partition → constraints & attestations.
 *
 * Mandatory controls come ONLY from the catalog. Nothing here consults the AI
 * or the browser. `canonicalPolicyString` yields a stable string for hashing —
 * identical canonical input always yields an identical string (and thus hash).
 */

import type { ClassificationSignals, RegulatoryDomain, RiskTier } from './classification';
import {
  CONTROLS,
  POLICY_CATALOG_VERSION,
  REGULATORY_OVERLAYS,
  SIGNAL_OVERLAYS,
  TIER_BASELINE,
  tierBaselineReason,
} from './policy-catalog';
import type { AppliedControl, Constraint, PolicyProfile } from './policy';

export interface PolicyEngineInput {
  qhub_app_id: string;
  classification_version: number;
  classification_reference: string | null;
  risk_tier: RiskTier;
  regulatory_domains: RegulatoryDomain[];
  signals: ClassificationSignals;
  policy_profile_version: number;
  generated_by: string;
}

function sortUnique(arr: string[]): string[] {
  return Array.from(new Set(arr)).sort();
}

/**
 * Collect { control_id → reasons[] } deterministically from baseline + overlays.
 * A control triggered multiple ways appears once with all reasons preserved.
 */
function collectApplicable(input: PolicyEngineInput): Map<string, Set<string>> {
  const acc = new Map<string, Set<string>>();
  const add = (id: string, reason: string) => {
    if (!CONTROLS[id]) {
      return; // unknown id — ignore defensively
    }

    if (!acc.has(id)) {
      acc.set(id, new Set());
    }

    acc.get(id)!.add(reason);
  };

  // 1. Tier baseline
  for (const id of TIER_BASELINE[input.risk_tier]) {
    add(id, tierBaselineReason(input.risk_tier));
  }

  // 2. Signal overlays (deterministic order)
  for (const overlay of SIGNAL_OVERLAYS) {
    if (overlay.when(input.signals)) {
      for (const id of overlay.controlIds) {
        add(id, overlay.reason);
      }
    }
  }

  // 3. Regulatory overlays (sorted domains for determinism)
  for (const domain of [...input.regulatory_domains].sort()) {
    const ov = REGULATORY_OVERLAYS[domain];

    if (ov) {
      for (const id of ov.controlIds) {
        add(id, ov.reason);
      }
    }
  }

  return acc;
}

function toAppliedControls(acc: Map<string, Set<string>>): AppliedControl[] {
  return Array.from(acc.entries())
    .map(([id, reasons]) => ({
      ...CONTROLS[id],
      applicability_reasons: Array.from(reasons).sort(),
    }))
    .sort((a, b) => a.control_id.localeCompare(b.control_id));
}

function constraintsForStage(controls: AppliedControl[], stages: string[]): Constraint[] {
  return controls
    .filter((c) => c.constraint && stages.includes(c.lifecycle_stage))
    .map((c) => ({ constraint_id: c.control_id, statement: c.constraint as string, control_ids: [c.control_id] }))
    .sort((a, b) => a.constraint_id.localeCompare(b.constraint_id));
}

/**
 * Build the deterministic policy profile. `policy_profile_hash` is left empty —
 * the server computes it from `canonicalPolicyString` (crypto is server-only).
 */
export function buildPolicyProfile(input: PolicyEngineInput): PolicyProfile {
  const applicable = collectApplicable(input);
  const all = toAppliedControls(applicable);

  const required = all.filter((c) => c.enforcement_level === 'MANDATORY');
  const conditional = all.filter((c) => c.enforcement_level === 'CONDITIONAL');
  const advisory = all.filter((c) => c.enforcement_level === 'ADVISORY');

  // Attestations & evidence derived from controls (deterministic).
  const required_attestations = sortUnique(
    required
      .filter((c) => c.control_id === 'HO-OWNER-ATTESTATION')
      .map(() => 'OWNER_ATTESTATION')
      .concat(
        required
          .filter((c) => c.control_id === 'DE-EXPLICIT-PROD-APPROVAL')
          .map(() => 'AUTHORIZED_GOVERNANCE_APPROVAL'),
      )
      .concat(required.filter((c) => c.control_id === 'HO-CHANGE-ATTESTATION').map(() => 'CHANGE_ATTESTATION')),
  );
  const required_evidence = sortUnique(required.map((c) => c.evidence_required));

  return {
    policy_profile_id: '', // assigned by the server (uuid)
    qhub_app_id: input.qhub_app_id,
    classification_version: input.classification_version,
    classification_reference: input.classification_reference,
    policy_profile_version: input.policy_profile_version,
    policy_catalog_version: POLICY_CATALOG_VERSION,
    risk_tier: input.risk_tier,
    regulatory_domains: [...input.regulatory_domains].sort(),

    required_controls: required,
    conditional_controls: conditional,
    advisory_controls: advisory,

    build_constraints: constraintsForStage(all, ['PRE_BUILD', 'BUILD']),
    preview_constraints: constraintsForStage(all, ['PREVIEW']),
    deployment_constraints: constraintsForStage(all, ['PRE_DEPLOY', 'DEPLOY']),
    runtime_constraints: constraintsForStage(all, ['RUNTIME']),

    required_attestations,
    required_evidence,

    generated_at: '', // set by server
    generated_by: input.generated_by,
    confirmed_by: null,
    confirmed_at: null,
    policy_profile_hash: '', // set by server from canonicalPolicyString
    status: 'PROVISIONAL',
  };
}

/**
 * Deterministic canonical string over the POLICY-DETERMINING content only
 * (never timestamps, ids, or actor). Identical canonical input → identical
 * string → identical hash. This is the hash preimage.
 */
/**
 * Render the policy profile as a compact, structured constraints block for the
 * governed-build handoff. This is APPENDED to the builder system prompt (never
 * replaces it). It states what the generated app MUST and MUST NOT do. It never
 * carries secrets and is deterministic given the profile.
 *
 * Kept intentionally terse — the immutable ledger holds the authoritative
 * record; the prompt only needs the actionable constraints.
 */
export function formatBuildConstraintsForPrompt(p: PolicyProfile): string {
  const lines: string[] = [];
  lines.push('# QHUB GOVERNED BUILD CONSTRAINTS (Gate 03 — POLICY)');
  lines.push(
    `This application is classified risk tier ${p.risk_tier}. A deterministic policy profile ` +
      `(catalog ${p.policy_catalog_version}, profile v${p.policy_profile_version}) has been bound to it and ` +
      `recorded in the immutable governance ledger. You MUST generate code that complies with the ` +
      `constraints below. These are mandatory controls — you may not remove, weaken, or work around them, ` +
      `and you may not silently skip any. If a request conflicts with a constraint, honor the constraint ` +
      `and say so.`,
  );

  const buildC = [...p.build_constraints, ...p.preview_constraints];

  if (buildC.length > 0) {
    lines.push('');
    lines.push('## Constraints you must apply during generation');

    for (const c of buildC) {
      lines.push(`- [${c.constraint_id}] ${c.statement}`);
    }
  }

  const runtimeC = p.runtime_constraints;

  if (runtimeC.length > 0) {
    lines.push('');
    lines.push('## Runtime behavior the app must implement');

    for (const c of runtimeC) {
      lines.push(`- [${c.constraint_id}] ${c.statement}`);
    }
  }

  const deployC = p.deployment_constraints;

  if (deployC.length > 0) {
    lines.push('');
    lines.push('## Deployment constraints (do not violate; production gating is enforced separately)');

    for (const c of deployC) {
      lines.push(`- [${c.constraint_id}] ${c.statement}`);
    }
  }

  if (p.required_attestations.length > 0) {
    lines.push('');
    lines.push(
      `## Human attestation required before production: ${p.required_attestations.join(', ')}. ` +
        `Do not represent the app as production-ready; it must pass the deployment gate.`,
    );
  }

  return lines.join('\n');
}

export function canonicalPolicyString(p: PolicyProfile): string {
  const canonical = {
    catalog: p.policy_catalog_version,
    tier: p.risk_tier,
    classification_version: p.classification_version,
    regulatory_domains: [...p.regulatory_domains].sort(),
    required: p.required_controls.map((c) => `${c.control_id}:${c.applicability_reasons.join('|')}`).sort(),
    conditional: p.conditional_controls.map((c) => c.control_id).sort(),
    advisory: p.advisory_controls.map((c) => c.control_id).sort(),
    required_attestations: [...p.required_attestations].sort(),
  };
  return JSON.stringify(canonical);
}
