/**
 * QHUB Commercial Launch — TEMPLATE GALLERY (BROWSER-SAFE)
 * app/lib/qhub/commercial/templates.ts
 *
 * Low-risk starter templates only. Every template is constrained to the launch
 * boundary: public / synthetic / ordinary-internal data, T0/T1, no autonomous
 * execution, no consequential actions. Trading, payments, investment advice,
 * customer-account actions, and regulated records are intentionally absent.
 */

import type { RiskTier } from '~/lib/qhub/classification';
import type { DataClass } from '~/lib/qhub/commercial/governance-essentials';

export interface AppTemplate {
  id: string;
  name: string;
  description: string;
  tier: RiskTier;
  suggestedData: DataClass[];
}

export const APP_TEMPLATES: AppTemplate[] = [
  {
    id: 'internal-faq',
    name: 'Internal FAQ assistant',
    description: 'Answer questions from a set of approved internal documents.',
    tier: 'T1',
    suggestedData: ['ordinary_internal'],
  },
  {
    id: 'meeting-summary',
    name: 'Meeting summary & action tracker',
    description: 'Summarize meeting notes and track action items.',
    tier: 'T1',
    suggestedData: ['ordinary_internal'],
  },
  {
    id: 'marketing-planner',
    name: 'Marketing content planner',
    description: 'Plan and draft marketing content from public inputs.',
    tier: 'T0',
    suggestedData: ['public'],
  },
  {
    id: 'research-dashboard',
    name: 'Public website research dashboard',
    description: 'Organize research from public web sources.',
    tier: 'T0',
    suggestedData: ['public'],
  },
  {
    id: 'sales-call-prep',
    name: 'Sales call preparation workspace',
    description: 'Prepare for calls using public and ordinary-internal notes.',
    tier: 'T1',
    suggestedData: ['public', 'ordinary_internal'],
  },
  {
    id: 'policy-ack-tracker',
    name: 'Policy acknowledgment tracker',
    description: 'Track who has acknowledged internal policies.',
    tier: 'T1',
    suggestedData: ['ordinary_internal'],
  },
  {
    id: 'doc-intake',
    name: 'Non-sensitive document intake organizer',
    description: 'Organize and label incoming non-sensitive documents.',
    tier: 'T1',
    suggestedData: ['ordinary_internal'],
  },
  {
    id: 'workflow-dashboard',
    name: 'Basic workflow dashboard',
    description: 'A simple dashboard for a low-risk internal workflow.',
    tier: 'T1',
    suggestedData: ['ordinary_internal'],
  },
];

export function listTemplates(): AppTemplate[] {
  return APP_TEMPLATES;
}

export function getTemplate(id: string): AppTemplate | null {
  return APP_TEMPLATES.find((t) => t.id === id) ?? null;
}
