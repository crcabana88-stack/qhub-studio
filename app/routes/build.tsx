/**
 * QHUB Commercial Launch — authenticated builder entry (/build)
 * app/routes/build.tsx
 *
 * The entitlement layer — not the browser — decides access. The loader resolves
 * the org's effective entitlements server-side and returns what is buildable.
 * "Build an App" is enabled only when the plan allows app building AND a project
 * slot is free; "Build an Agent" and "Build an App + Agent" are always shown as
 * Institutional Preview (disabled) in the launch tier.
 */

import { json, redirect, type LoaderFunctionArgs, type MetaFunction } from '@remix-run/cloudflare';
import { useLoaderData } from '@remix-run/react';
import { requireCommercialContext } from '~/lib/qhub/commercial/commercial-context.server';
import { decideAppBuild, decideProjectCreation, decideAgentBuild } from '~/lib/qhub/commercial/entitlements.server';
import { countProjects } from '~/lib/qhub/commercial/commercial-store.server';

export const meta: MetaFunction = () => [{ title: 'Start Building — QHub' }];

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context?.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  // Authoritative context (membership/entitlements from the DB, not user_metadata).
  const guard = await requireCommercialContext(request, env);

  if (!guard.ok) {
    /*
     * Unauthenticated / unconfigured → login; anything else surfaces as-is.
     * Thrown Responses short-circuit the loader (keeps the success type clean).
     */
    if (guard.response.status === 401 || guard.response.status === 503) {
      throw redirect('/login');
    }

    throw guard.response;
  }

  const ctx = guard.ctx;
  const resolved = ctx.resolved;

  let projectCount = 0;

  try {
    projectCount = ctx.orgId ? await countProjects(ctx.orgId, env) : 0;
  } catch {
    projectCount = 0; // fail closed to "no known projects"; creation still gated below
  }

  const appDecision = decideAppBuild(resolved.entitlements);
  const projectDecision = decideProjectCreation(resolved.entitlements, projectCount);
  const agentDecision = decideAgentBuild(resolved.entitlements);

  /*
   * Build an App requires the capability, a free project slot, and (server-side)
   * the resolved APP_BUILD capability from the authoritative context.
   */
  const canBuildApp = ctx.capabilities.has('APP_BUILD') && appDecision.allowed && projectDecision.allowed;
  const appReason = !appDecision.allowed ? appDecision : !projectDecision.allowed ? projectDecision : null;

  return json({
    email: ctx.email,
    planId: resolved.planId,
    serviceState: resolved.serviceState,
    projectCount,
    maxProjects: resolved.entitlements.maxProjects,
    canBuildApp,
    appReasonCode: appReason?.reasonCode ?? null,
    appReasonMessage: appReason?.message ?? null,

    // Agent building is never available in the launch tier.
    canBuildAgent: false,
    agentReasonMessage: agentDecision.message,
  });
}

export default function Build() {
  const data = useLoaderData<typeof loader>();

  return (
    <div className="min-h-full bg-bolt-elements-background-depth-1 text-bolt-elements-textPrimary">
      <div className="max-w-4xl mx-auto px-4 py-12">
        <h1 className="text-3xl font-semibold mb-1">Start building</h1>
        <p className="text-bolt-elements-textSecondary mb-8">
          Signed in as {data.email} · Plan: {data.planId} · Projects: {data.projectCount}/{data.maxProjects}
        </p>

        <div className="grid gap-4 md:grid-cols-3">
          <EntryCard
            title="Build an App"
            description="Prompt-to-app building for low-risk T0/T1 work."
            enabled={data.canBuildApp}
            href="/"
            disabledReason={data.appReasonMessage}
          />
          <EntryCard
            title="Build an Agent"
            description="Autonomous agent building."
            enabled={false}
            badge="Institutional Preview"
            disabledReason={data.agentReasonMessage}
          />
          <EntryCard
            title="Build an App + Agent"
            description="Combined app and agent build."
            enabled={false}
            badge="Institutional Preview"
            disabledReason={data.agentReasonMessage}
          />
        </div>
      </div>
    </div>
  );
}

function EntryCard(props: {
  title: string;
  description: string;
  enabled: boolean;
  href?: string;
  badge?: string;
  disabledReason?: string | null;
}) {
  return (
    <div className="border border-bolt-elements-borderColor rounded-lg p-5 flex flex-col">
      <div className="flex items-center justify-between gap-2 mb-1">
        <h2 className="text-lg font-medium">{props.title}</h2>
        {props.badge ? (
          <span className="text-xs px-2 py-0.5 rounded border border-bolt-elements-borderColor text-bolt-elements-textSecondary">
            {props.badge}
          </span>
        ) : null}
      </div>
      <p className="text-sm text-bolt-elements-textSecondary mb-4">{props.description}</p>

      {props.enabled && props.href ? (
        <a
          href={props.href}
          className="mt-auto text-center px-4 py-2 rounded bg-bolt-elements-button-primary-background text-bolt-elements-button-primary-text"
        >
          Continue
        </a>
      ) : (
        <div className="mt-auto">
          <button
            type="button"
            disabled
            className="w-full px-4 py-2 rounded border border-bolt-elements-borderColor text-bolt-elements-textSecondary opacity-60 cursor-not-allowed"
          >
            Not available
          </button>
          {props.disabledReason ? (
            <p className="text-xs text-bolt-elements-textSecondary mt-2">{props.disabledReason}</p>
          ) : null}
        </div>
      )}
    </div>
  );
}
