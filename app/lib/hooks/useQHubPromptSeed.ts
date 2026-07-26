/**
 * useQHubPromptSeed
 *
 * Reads ?prompt and ?source from the URL on mount.
 * When source=landing (i.e. the user came from the quantex-tech.com hero),
 * wraps the raw prompt with the QHUB governance preamble so the LLM knows
 * to build in compliance mode from the first message.
 *
 * Usage in ChatImpl:
 *   const { seededPrompt, wasSeeded } = useQHubPromptSeed();
 *   useEffect(() => {
 *     if (wasSeeded && seededPrompt) {
 *       runAnimation();
 *       append({ role: 'user', content: seededPrompt });
 *     }
 *   }, [wasSeeded]);
 */

import { useSearchParams } from '@remix-run/react';
import { useMemo } from 'react';

const QHUB_GOVERNANCE_PREAMBLE = `You are QHUB Studio, a governed AI application builder built by Quantex Technologies.

Every app you build must go through the four-stage QHUB compliance lifecycle:
  01 CLASSIFY  — determine the regulatory domain (SEC, FINRA, CFTC, NFA, etc.) and risk tier (Low / Medium / High / Critical)
  02 POLICY    — surface the firm's applicable policies and flag any conflicts before writing code
  03 BUILD     — generate the app, API routes, and data models; emit a QHUB manifest (app_name, version, risk_tier, policy_refs)
  04 ATTEST    — produce a signed attestation payload that will be written to the WORM audit ledger

Start your response by briefly acknowledging which stage you are in and what you understand the request to be, then proceed with building.

User's request:
`;

export interface QHubPromptSeedResult {
  /** The prompt to fire (governance-wrapped if source=landing, raw otherwise) */
  seededPrompt: string | null;

  /** True if a ?prompt param was found and consumed */
  wasSeeded: boolean;

  /** True if the prompt was wrapped with the QHUB governance preamble */
  isGovernanceWrapped: boolean;
}

export function useQHubPromptSeed(): QHubPromptSeedResult {
  const [searchParams, setSearchParams] = useSearchParams();

  const result = useMemo<QHubPromptSeedResult>(() => {
    const rawPrompt = searchParams.get('prompt');
    const source = searchParams.get('source');

    if (!rawPrompt) {
      return { seededPrompt: null, wasSeeded: false, isGovernanceWrapped: false };
    }

    const fromLanding = source === 'landing';
    const seededPrompt = fromLanding ? `${QHUB_GOVERNANCE_PREAMBLE}${rawPrompt}` : rawPrompt;

    return {
      seededPrompt,
      wasSeeded: true,
      isGovernanceWrapped: fromLanding,
    };
  }, [
    // Only evaluate once on mount — searchParams reference is stable until cleared
    searchParams.get('prompt'),
    searchParams.get('source'),
  ]);

  // Clear params immediately so they don't re-fire on re-render
  if (result.wasSeeded) {
    // Defer to avoid state update during render
    setTimeout(() => setSearchParams({}, { replace: true }), 0);
  }

  return result;
}
