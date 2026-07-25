/**
 * QHUB Gate 03 — Versioned policy catalog (BROWSER-SAFE, deterministic)
 * app/lib/qhub/policy-catalog.ts
 *
 * The single source of truth for policy control definitions, tier baselines,
 * and deterministic overlays. Mandatory controls come ONLY from here — the AI
 * may explain them but can never remove or weaken them.
 *
 * Regulatory/framework references are APPLICABILITY mappings, not legal
 * conclusions. Framework mappings live in data (source_refs), not logic.
 */

import type { ClassificationSignals, RegulatoryDomain, RiskTier } from './classification';
import type { ControlCategory, EnforcementLevel, LifecycleStage, PolicyControl } from './policy';

export const POLICY_CATALOG_VERSION = 'gate03-catalog-1.0.0';

// ─── Control factory (keeps definitions terse but complete) ───────────────────

function ctl(
  control_id: string,
  category: ControlCategory,
  title: string,
  requirement: string,
  rationale: string,
  enforcement_level: EnforcementLevel,
  lifecycle_stage: LifecycleStage,
  extra: Partial<PolicyControl> = {},
): PolicyControl {
  return {
    control_id,
    category,
    title,
    requirement,
    rationale,
    enforcement_level,
    lifecycle_stage,
    verification_method: extra.verification_method ?? 'Automated build check or human review',
    evidence_required: extra.evidence_required ?? 'Governance event / build attestation',
    source_refs: extra.source_refs ?? ['INTERNAL_POLICY'],
    status: 'ACTIVE',
    constraint: extra.constraint,
  };
}

// ─── Catalog ──────────────────────────────────────────────────────────────────

export const CONTROLS: Record<string, PolicyControl> = {
  // T0 baseline
  'SD-NO-CLIENT-SECRETS': ctl(
    'SD-NO-CLIENT-SECRETS',
    'SECURE_DEVELOPMENT',
    'No secrets in client code',
    'No API keys, tokens, or credentials may be embedded in client-side code or bundles.',
    'Client bundles are public; embedded secrets are immediately compromised.',
    'MANDATORY',
    'BUILD',
    { constraint: 'No secrets, API keys, or tokens in client-side code — use server-side env only.' },
  ),
  'SD-DEP-LOCKFILE': ctl(
    'SD-DEP-LOCKFILE',
    'SECURE_DEVELOPMENT',
    'Dependency lockfile',
    'A committed dependency lockfile must pin all dependency versions.',
    'Reproducible builds and supply-chain integrity.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Produce a committed lockfile pinning all dependencies.' },
  ),
  'SD-SECURE-DEFAULTS': ctl(
    'SD-SECURE-DEFAULTS',
    'SECURE_DEVELOPMENT',
    'Secure default configuration',
    'The application must ship with secure-by-default configuration.',
    'Insecure defaults are the most common cause of avoidable exposure.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Use secure defaults (no debug endpoints, no open CORS, no default credentials).' },
  ),
  'AE-BASELINE-EVENTS': ctl(
    'AE-BASELINE-EVENTS',
    'AUDIT_AND_EVIDENCE',
    'Baseline audit events',
    'Material application actions must emit basic audit/evidence events.',
    'A minimum audit trail is required for any governed build.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Emit audit events for material actions (create/update/delete of records).' },
  ),
  'SD-BUILD-CHECKS': ctl(
    'SD-BUILD-CHECKS',
    'SECURE_DEVELOPMENT',
    'Baseline build/vuln checks',
    'The build must pass baseline vulnerability and configuration checks.',
    'Catch known-vulnerable dependencies and misconfiguration before release.',
    'MANDATORY',
    'PRE_DEPLOY',
  ),
  'IT-NO-UNDECLARED-INTEGRATIONS': ctl(
    'IT-NO-UNDECLARED-INTEGRATIONS',
    'INTEGRATIONS_AND_TOOLS',
    'No undeclared integrations',
    'The app must not call external systems that were not declared at classification.',
    'Undeclared egress defeats classification and data-protection controls.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Do not add external integrations beyond those declared in the classification.' },
  ),

  // T1 additions
  'IA-AUTHENTICATED-ACCESS': ctl(
    'IA-AUTHENTICATED-ACCESS',
    'IDENTITY_AND_ACCESS',
    'Authenticated access',
    'Access to non-public functionality must require authentication.',
    'Business data and actions must not be anonymously accessible.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Require authentication for all non-public functionality.' },
  ),
  'IA-BASIC-RBAC': ctl(
    'IA-BASIC-RBAC',
    'IDENTITY_AND_ACCESS',
    'Basic role separation',
    'At least basic role separation (e.g. admin vs user) must be enforced.',
    'Least privilege begins with distinguishing privileged from ordinary users.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Implement basic role separation (admin vs standard user).' },
  ),
  'MG-APPROVED-MODEL': ctl(
    'MG-APPROVED-MODEL',
    'MODEL_GOVERNANCE',
    'Approved model/provider',
    'Only approved AI models/providers may be used at runtime.',
    'Model provenance is part of the AI bill of materials.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Use only approved AI models/providers; record provider + model.' },
  ),
  'TI-TENANT-SEPARATION': ctl(
    'TI-TENANT-SEPARATION',
    'TENANT_ISOLATION',
    'Tenant separation (multi-user)',
    'Multi-user apps must separate data by tenant/user.',
    'One customer must never see another customer’s data.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Scope every data query by the authenticated tenant/user id.' },
  ),
  'AE-MATERIAL-ACTION-LOG': ctl(
    'AE-MATERIAL-ACTION-LOG',
    'AUDIT_AND_EVIDENCE',
    'Logging of material actions',
    'Material actions must be logged with actor and timestamp.',
    'Attributable logs are the basis of governance evidence.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Log material actions with actor id and timestamp.' },
  ),
  'DP-SECRETS-MANAGEMENT': ctl(
    'DP-SECRETS-MANAGEMENT',
    'DATA_PROTECTION',
    'Controlled secrets management',
    'Secrets must be stored in a managed secret store, never in code or plain config.',
    'Centralized, rotatable secret management limits blast radius.',
    'MANDATORY',
    'BUILD',
  ),
  'DE-DEPLOY-PROVENANCE': ctl(
    'DE-DEPLOY-PROVENANCE',
    'DEPLOYMENT',
    'Deployment provenance',
    'Deployments must record what was deployed, by whom, and when.',
    'Provenance links running software to its governed build.',
    'MANDATORY',
    'DEPLOY',
  ),

  // T2 additions
  'IA-MFA-PRIVILEGED': ctl(
    'IA-MFA-PRIVILEGED',
    'IDENTITY_AND_ACCESS',
    'MFA for privileged access',
    'Privileged/administrative access must require multi-factor authentication.',
    'Privileged accounts are high-value targets.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Require MFA for privileged/admin access.' },
  ),
  'IA-FORMAL-RBAC': ctl(
    'IA-FORMAL-RBAC',
    'IDENTITY_AND_ACCESS',
    'Formal RBAC',
    'A formal role-based access control model must gate sensitive operations.',
    'Elevated data/actions require explicit, reviewable authorization.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Enforce formal RBAC roles on sensitive operations.' },
  ),
  'TI-STRICT-ISOLATION': ctl(
    'TI-STRICT-ISOLATION',
    'TENANT_ISOLATION',
    'Strict tenant isolation',
    'Tenant isolation must be enforced at the data layer (row-level or equivalent).',
    'Client/transaction data requires enforced, not incidental, isolation.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Enforce strict tenant isolation at the data layer (e.g. row-level security).' },
  ),
  'DP-ENCRYPTION': ctl(
    'DP-ENCRYPTION',
    'DATA_PROTECTION',
    'Encryption in transit and at rest',
    'Sensitive data must be encrypted in transit (TLS) and at rest.',
    'Baseline confidentiality control for regulated/client data.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Encrypt sensitive data in transit (TLS) and at rest.' },
  ),
  'DP-DATA-MINIMIZATION': ctl(
    'DP-DATA-MINIMIZATION',
    'DATA_PROTECTION',
    'Data minimization',
    'Collect and retain only the data required for the stated purpose.',
    'Minimizing data reduces regulatory and breach exposure.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Collect only the data required; do not log full sensitive records.' },
  ),
  'DP-SENSITIVE-HANDLING': ctl(
    'DP-SENSITIVE-HANDLING',
    'DATA_PROTECTION',
    'Sensitive-data handling',
    'Sensitive fields must be masked/redacted in logs and non-privileged views.',
    'Prevents inadvertent disclosure of client/financial data.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Mask/redact sensitive fields in logs and non-privileged views.' },
  ),
  'IT-EGRESS-ALLOWLIST': ctl(
    'IT-EGRESS-ALLOWLIST',
    'INTEGRATIONS_AND_TOOLS',
    'Outbound egress allowlist',
    'Outbound network egress must be restricted to an allowlist.',
    'Constrains exfiltration and undeclared data flows.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Restrict outbound network calls to an explicit allowlist.' },
  ),
  'IT-INTEGRATION-ALLOWLIST': ctl(
    'IT-INTEGRATION-ALLOWLIST',
    'INTEGRATIONS_AND_TOOLS',
    'External integration allowlist',
    'External integrations must be limited to an approved allowlist.',
    'Only vetted connectors may touch regulated systems.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Use only allowlisted, approved external integrations.' },
  ),
  'HO-HUMAN-REVIEW-CONSEQUENTIAL': ctl(
    'HO-HUMAN-REVIEW-CONSEQUENTIAL',
    'HUMAN_OVERSIGHT',
    'Human review of consequential recommendations',
    'Consequential AI recommendations must be reviewed by a human before acting.',
    'AI recommendations must not auto-execute consequential outcomes.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Require human review before acting on consequential AI recommendations.' },
  ),
  'RR-BOOKS-RECORDS': ctl(
    'RR-BOOKS-RECORDS',
    'RECORDS_AND_RETENTION',
    'Books-and-records evidence',
    'Records with books-and-records relevance must be captured as durable evidence.',
    'Supervisory recordkeeping obligations.',
    'MANDATORY',
    'RUNTIME',
    { source_refs: ['BOOKS_AND_RECORDS', 'SEC', 'FINRA'] },
  ),
  'IT-CONTROLLED-SOR-WRITES': ctl(
    'IT-CONTROLLED-SOR-WRITES',
    'INTEGRATIONS_AND_TOOLS',
    'Controlled system-of-record writes',
    'Writes to external systems of record must be controlled and auditable.',
    'Uncontrolled writes to records systems create integrity and compliance risk.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Gate and audit every write to an external system of record.' },
  ),
  'HO-OWNER-ATTESTATION': ctl(
    'HO-OWNER-ATTESTATION',
    'HUMAN_OVERSIGHT',
    'Owner attestation before production',
    'The application owner must attest before production deployment.',
    'A named human accepts responsibility before elevated apps go live.',
    'MANDATORY',
    'PRE_DEPLOY',
    { evidence_required: 'ATTESTATION_SIGNED event' },
  ),
  'RR-RETENTION': ctl(
    'RR-RETENTION',
    'RECORDS_AND_RETENTION',
    'Retention requirements',
    'Data and evidence retention periods must be defined and enforced.',
    'Regulated data has minimum retention obligations.',
    'MANDATORY',
    'RUNTIME',
  ),
  'SD-SECURITY-TESTING': ctl(
    'SD-SECURITY-TESTING',
    'SECURE_DEVELOPMENT',
    'Security and policy testing',
    'Security and policy tests must run before deployment.',
    'Verifies controls are actually implemented, not just declared.',
    'MANDATORY',
    'PRE_DEPLOY',
  ),

  // T3 additions
  'IA-LEAST-PRIVILEGE-SVC': ctl(
    'IA-LEAST-PRIVILEGE-SVC',
    'IDENTITY_AND_ACCESS',
    'Least-privilege service identities',
    'Service identities must hold only the minimum permissions required.',
    'Limits blast radius of a compromised or misbehaving agent.',
    'MANDATORY',
    'BUILD',
    { constraint: 'Grant service identities least-privilege scopes only.' },
  ),
  'HO-DUAL-CONTROL': ctl(
    'HO-DUAL-CONTROL',
    'HUMAN_OVERSIGHT',
    'Dual control / four-eyes approval',
    'Consequential actions must require two-person (four-eyes) approval where applicable.',
    'High-consequence actions must not be unilaterally executable.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Require two-person approval for consequential actions.' },
  ),
  'DE-EXPLICIT-PROD-APPROVAL': ctl(
    'DE-EXPLICIT-PROD-APPROVAL',
    'DEPLOYMENT',
    'Explicit authorized production approval',
    'Production deployment requires explicit approval by authorized governance/compliance/security.',
    'High-risk apps must not reach production without authorized sign-off.',
    'MANDATORY',
    'PRE_DEPLOY',
    { evidence_required: 'DEPLOYMENT_APPROVED event by authorized approver' },
  ),
  'DE-PREVIEW-ONLY': ctl(
    'DE-PREVIEW-ONLY',
    'DEPLOYMENT',
    'Preview/sandbox only until approval',
    'The app is restricted to isolated preview/sandbox until production is authorized.',
    'Contains consequential capability during development.',
    'MANDATORY',
    'PREVIEW',
    { constraint: 'Run in isolated preview/sandbox only; no production endpoints or live credentials.' },
  ),
  'RM-NO-UNRESTRICTED-AUTONOMY': ctl(
    'RM-NO-UNRESTRICTED-AUTONOMY',
    'RUNTIME_MONITORING',
    'No unrestricted autonomous production action',
    'Autonomous production actions must be bounded and authorized; unrestricted autonomy is prohibited.',
    'Unbounded autonomous action is the highest-consequence failure mode.',
    'MANDATORY',
    'RUNTIME',
    {
      constraint:
        'No unrestricted autonomous production actions; every consequential action is bounded and authorized.',
    },
  ),
  'RM-ACTION-LIMITS': ctl(
    'RM-ACTION-LIMITS',
    'RUNTIME_MONITORING',
    'Transaction/action limits',
    'Consequential actions must be subject to explicit limits (value, rate, count).',
    'Limits cap the damage of an error or compromise.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Enforce explicit limits (value/rate/count) on consequential actions.' },
  ),
  'IR-KILL-SWITCH': ctl(
    'IR-KILL-SWITCH',
    'INCIDENT_RESPONSE',
    'Kill switch / emergency stop',
    'An operator kill switch must be able to halt consequential activity immediately.',
    'Operators must be able to stop the system fast.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Provide an operator kill switch that halts all consequential activity.' },
  ),
  'RM-RUNTIME-MONITORING': ctl(
    'RM-RUNTIME-MONITORING',
    'RUNTIME_MONITORING',
    'Runtime monitoring and alerting',
    'Runtime behavior and consequential actions must be monitored with alerting.',
    'Detects anomalous or runaway behavior in production.',
    'MANDATORY',
    'RUNTIME',
  ),
  'AE-ENHANCED-EVIDENCE': ctl(
    'AE-ENHANCED-EVIDENCE',
    'AUDIT_AND_EVIDENCE',
    'Enhanced audit evidence',
    'Each consequential action must produce an enhanced, tamper-evident evidence record.',
    'High-risk actions require defensible, detailed evidence.',
    'MANDATORY',
    'RUNTIME',
  ),
  'HO-CHANGE-ATTESTATION': ctl(
    'HO-CHANGE-ATTESTATION',
    'HUMAN_OVERSIGHT',
    'Change/version attestation',
    'Material changes must be attested before promotion.',
    'Ties each production version to a human sign-off.',
    'MANDATORY',
    'PRE_DEPLOY',
  ),
  'IR-INCIDENT-PLAN': ctl(
    'IR-INCIDENT-PLAN',
    'INCIDENT_RESPONSE',
    'Incident-response plan',
    'A documented incident-response plan must exist before production.',
    'Consequential systems need a defined response path.',
    'MANDATORY',
    'PRE_DEPLOY',
  ),
  'DE-ROLLBACK': ctl(
    'DE-ROLLBACK',
    'DEPLOYMENT',
    'Rollback controls',
    'A tested rollback path must exist.',
    'Fast, safe reversal limits incident duration.',
    'MANDATORY',
    'DEPLOY',
  ),
  'IT-STRICT-ALLOWLISTS': ctl(
    'IT-STRICT-ALLOWLISTS',
    'INTEGRATIONS_AND_TOOLS',
    'Strict model/tool/data allowlists',
    'Models, tools, and data sources must be strictly allowlisted.',
    'Minimizes the attack and error surface for high-risk agents.',
    'MANDATORY',
    'RUNTIME',
    { constraint: 'Restrict models, tools, and data sources to a strict allowlist.' },
  ),
};

// ─── Tier baselines (cumulative control-id packs) ─────────────────────────────

const T0 = [
  'SD-NO-CLIENT-SECRETS',
  'SD-DEP-LOCKFILE',
  'SD-SECURE-DEFAULTS',
  'AE-BASELINE-EVENTS',
  'SD-BUILD-CHECKS',
  'IT-NO-UNDECLARED-INTEGRATIONS',
];
const T1 = [
  ...T0,
  'IA-AUTHENTICATED-ACCESS',
  'IA-BASIC-RBAC',
  'MG-APPROVED-MODEL',
  'TI-TENANT-SEPARATION',
  'AE-MATERIAL-ACTION-LOG',
  'DP-SECRETS-MANAGEMENT',
  'DE-DEPLOY-PROVENANCE',
];
const T2 = [
  ...T1,
  'IA-MFA-PRIVILEGED',
  'IA-FORMAL-RBAC',
  'TI-STRICT-ISOLATION',
  'DP-ENCRYPTION',
  'DP-DATA-MINIMIZATION',
  'DP-SENSITIVE-HANDLING',
  'IT-EGRESS-ALLOWLIST',
  'IT-INTEGRATION-ALLOWLIST',
  'HO-HUMAN-REVIEW-CONSEQUENTIAL',
  'RR-BOOKS-RECORDS',
  'IT-CONTROLLED-SOR-WRITES',
  'HO-OWNER-ATTESTATION',
  'RR-RETENTION',
  'SD-SECURITY-TESTING',
];
const T3 = [
  ...T2,
  'IA-LEAST-PRIVILEGE-SVC',
  'HO-DUAL-CONTROL',
  'DE-EXPLICIT-PROD-APPROVAL',
  'DE-PREVIEW-ONLY',
  'RM-NO-UNRESTRICTED-AUTONOMY',
  'RM-ACTION-LIMITS',
  'IR-KILL-SWITCH',
  'RM-RUNTIME-MONITORING',
  'AE-ENHANCED-EVIDENCE',
  'HO-CHANGE-ATTESTATION',
  'IR-INCIDENT-PLAN',
  'DE-ROLLBACK',
  'IT-STRICT-ALLOWLISTS',
];

export const TIER_BASELINE: Record<RiskTier, string[]> = { T0, T1, T2, T3 };

/** Baseline reason per control (why the tier requires it). */
export function tierBaselineReason(tier: RiskTier): string {
  return `Baseline control for risk tier ${tier}`;
}

// ─── Signal overlays (deterministic; a control may be triggered many ways) ────

export interface Overlay {
  reason: string;
  controlIds: string[];
  when: (s: ClassificationSignals) => boolean;
}

export const SIGNAL_OVERLAYS: Overlay[] = [
  {
    reason: 'Handles client PII / client data',
    controlIds: [
      'DP-ENCRYPTION',
      'DP-DATA-MINIMIZATION',
      'DP-SENSITIVE-HANDLING',
      'RR-RETENTION',
      'AE-MATERIAL-ACTION-LOG',
    ],
    when: (s) => s.data_classes.includes('CLIENT_PII'),
  },
  {
    reason: 'Exposes or transmits MNPI',
    controlIds: ['DP-SENSITIVE-HANDLING', 'IT-EGRESS-ALLOWLIST', 'IT-STRICT-ALLOWLISTS', 'AE-ENHANCED-EVIDENCE'],
    when: (s) => s.data_classes.includes('MNPI'),
  },
  {
    reason: 'Integrates with an external system of record',
    controlIds: [
      'IT-INTEGRATION-ALLOWLIST',
      'IA-LEAST-PRIVILEGE-SVC',
      'IT-CONTROLLED-SOR-WRITES',
      'AE-MATERIAL-ACTION-LOG',
    ],
    when: (s) => s.integration_types.includes('EXTERNAL_SYSTEM_OF_RECORD'),
  },
  {
    reason: 'Writes to business systems',
    controlIds: [
      'IT-CONTROLLED-SOR-WRITES',
      'HO-HUMAN-REVIEW-CONSEQUENTIAL',
      'RM-ACTION-LIMITS',
      'DE-ROLLBACK',
      'AE-ENHANCED-EVIDENCE',
    ],
    when: (s) => s.integration_types.includes('BUSINESS_SYSTEM_WRITE'),
  },
  {
    reason: 'Produces AI financial recommendations',
    controlIds: ['HO-HUMAN-REVIEW-CONSEQUENTIAL', 'MG-APPROVED-MODEL', 'RR-BOOKS-RECORDS'],
    when: (s) => s.ai_behavior === 'FINANCIAL_RECOMMENDATION',
  },
  {
    reason: 'Trading / order-execution capability',
    controlIds: [
      'DE-PREVIEW-ONLY',
      'DE-EXPLICIT-PROD-APPROVAL',
      'RM-ACTION-LIMITS',
      'IR-KILL-SWITCH',
      'AE-ENHANCED-EVIDENCE',
      'HO-DUAL-CONTROL',
      'RM-RUNTIME-MONITORING',
    ],
    when: (s) => s.integration_types.includes('TRADING_OR_ORDERS'),
  },
  {
    reason: 'Moves money or assets',
    controlIds: [
      'DE-EXPLICIT-PROD-APPROVAL',
      'RM-ACTION-LIMITS',
      'IR-KILL-SWITCH',
      'HO-DUAL-CONTROL',
      'AE-ENHANCED-EVIDENCE',
    ],
    when: (s) => s.integration_types.includes('PAYMENTS_OR_TRANSFERS'),
  },
  {
    reason: 'External communication on behalf of the firm',
    controlIds: ['HO-HUMAN-REVIEW-CONSEQUENTIAL', 'RR-RETENTION', 'IT-INTEGRATION-ALLOWLIST'],
    when: (s) => s.integration_types.includes('OUTBOUND_COMMUNICATION'),
  },
  {
    reason: 'Autonomous action in production',
    controlIds: [
      'RM-NO-UNRESTRICTED-AUTONOMY',
      'DE-EXPLICIT-PROD-APPROVAL',
      'RM-RUNTIME-MONITORING',
      'IR-KILL-SWITCH',
      'AE-ENHANCED-EVIDENCE',
      'RM-ACTION-LIMITS',
    ],
    when: (s) => s.autonomy_level === 'AUTONOMOUS',
  },
];

/*
 * ─── Regulatory overlays (applicability tags → governance references) ─────────
 * These add source_refs / evidence emphasis; they never assert legal conclusions.
 */

export const REGULATORY_OVERLAYS: Partial<Record<RegulatoryDomain, { reason: string; controlIds: string[] }>> = {
  BOOKS_AND_RECORDS: { reason: 'Books-and-records applicability', controlIds: ['RR-BOOKS-RECORDS', 'RR-RETENTION'] },
  SUPERVISION: {
    reason: 'Supervisory workflow applicability',
    controlIds: ['HO-HUMAN-REVIEW-CONSEQUENTIAL', 'AE-MATERIAL-ACTION-LOG'],
  },
  PRIVACY: {
    reason: 'Privacy applicability',
    controlIds: ['DP-DATA-MINIMIZATION', 'DP-SENSITIVE-HANDLING', 'RR-RETENTION'],
  },
  CYBERSECURITY: {
    reason: 'Cybersecurity applicability',
    controlIds: ['DP-ENCRYPTION', 'IA-MFA-PRIVILEGED', 'IR-INCIDENT-PLAN'],
  },
};
