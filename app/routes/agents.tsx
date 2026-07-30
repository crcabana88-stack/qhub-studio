// @qhub-route: INTERNAL_SERVER_ONLY
/**
 * QHUB Agent Framework Foundation — Agents page (registry + creation choice)
 * app/routes/agents.tsx
 *
 * A minimal, additive Studio surface: the BUILD APP / BUILD AGENT / BUILD APP +
 * AGENT choice plus the private per-tenant Agent Registry. Does not touch the
 * existing app-building flow.
 */

import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { useLoaderData, useFetcher, Link } from '@remix-run/react';
import { requireStaff } from '~/lib/qhub/commercial/commercial-context.server';
import { listAgents, type AgentRow } from '~/lib/qhub/agent/agent-registry.server';
import { AgentRegistryView } from '~/components/agent/AgentRegistryView';

export async function loader({ request, context }: LoaderFunctionArgs) {
  const env = (context.cloudflare?.env as unknown as Record<string, string | undefined>) ?? {};

  // R3: the agent registry is an internal surface — Quantex-STAFF-ONLY.
  const guard = await requireStaff(request, env);

  if (!guard.ok || !guard.ctx.orgId) {
    return json({ authenticated: false, agents: [] as AgentRow[] }, { status: 200 });
  }

  const agents = await listAgents(guard.ctx.orgId, env);

  return json({ authenticated: true, agents });
}

const CHOICES = [
  { key: 'app', title: 'Build App', desc: 'Generate a governed application (Gates 01–05).' },
  { key: 'agent', title: 'Build Agent', desc: 'Create a governed, supervised agent.' },
  { key: 'app_agent', title: 'Build App + Agent', desc: 'An application with a governed companion agent.' },
];

export default function AgentsRoute() {
  const data = useLoaderData<typeof loader>();
  const fetcher = useFetcher();

  const suspend = (agentId: string) => {
    fetcher.submit(JSON.stringify({ op: 'suspend', agent_id: agentId }), {
      method: 'post',
      action: '/api/agent',
      encType: 'application/json',
    });
  };

  return (
    <div className="mx-auto max-w-4xl p-6 space-y-8">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-bolt-elements-textPrimary">QHUB Studio</h1>
        <p className="text-sm text-bolt-elements-textSecondary">
          Choose what to build. Every agent is identified, versioned, policy-bound, release-bound, and supervised.
        </p>
      </header>

      <section className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {CHOICES.map((c) => (
          <Link
            key={c.key}
            to={c.key === 'app' ? '/' : `/agents?mode=${c.key}`}
            className="rounded-lg border border-bolt-elements-borderColor bg-bolt-elements-background-depth-1 p-4 hover:border-bolt-elements-borderColorActive transition-colors"
          >
            <div className="font-semibold text-bolt-elements-textPrimary">{c.title}</div>
            <div className="text-xs text-bolt-elements-textSecondary mt-1">{c.desc}</div>
          </Link>
        ))}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-bolt-elements-textPrimary">Agent Registry</h2>
        {data.authenticated ? (
          <AgentRegistryView agents={data.agents as AgentRow[]} onSuspend={suspend} />
        ) : (
          <div className="text-sm text-bolt-elements-textSecondary">Sign in to view your agents.</div>
        )}
      </section>
    </div>
  );
}
