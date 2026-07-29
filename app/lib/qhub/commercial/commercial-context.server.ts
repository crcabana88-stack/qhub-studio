/**
 * QHUB Commercial Launch R2 — AUTHORITATIVE REQUEST CONTEXT (SERVER ONLY)
 * app/lib/qhub/commercial/commercial-context.server.ts
 *
 * THE single server entry point for authorization. Resolves an authoritative
 * context from the verified user identity + DATABASE membership/staff/subscription
 * records (never user_metadata), computes the granted capability set, and fails
 * closed. All protected routes call requireCommercialContext(request, env, cap).
 *
 * Fail-closed guarantees:
 *   - missing Supabase auth config in staging/production → configuration error,
 *     no synthetic user/org/entitlement (dev fallback only when explicitly allowed)
 *   - no browser-supplied org_id or role becomes authority
 *   - inactive/suspended/removed/cross-tenant membership grants nothing
 *   - a commercial customer never receives a staff-only capability
 */

import { json } from '@remix-run/cloudflare';
import { getVerifiedUser, isDevAuthAllowed } from '~/lib/auth/session';
import {
  resolveMembership,
  resolveStaff,
  type Membership,
  type OrgRole,
} from '~/lib/qhub/commercial/membership.server';
import { loadOrgEntitlements, type ResolvedEntitlements } from '~/lib/qhub/commercial/entitlements.server';
import { getOnboardingState } from '~/lib/qhub/commercial/commercial-store.server';
import { computeCapabilities, hasCapability, type Capability } from '~/lib/qhub/commercial/capabilities';
import { NO_PLAN_ENTITLEMENTS } from '~/lib/qhub/commercial/plans';
import { resolveEntitlements } from '~/lib/qhub/commercial/entitlements.server';

function hasSupabaseConfig(env: Record<string, string | undefined>): boolean {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

  return !!url && !!key;
}

export interface CommercialContext {
  userId: string;
  email: string;
  orgId: string | null;
  role: OrgRole | null;
  membershipStatus: Membership['status'] | null;
  isStaff: boolean;
  staffRole: string | null;
  resolved: ResolvedEntitlements;
  capabilities: Set<Capability>;
  onboardingComplete: boolean;
  suspended: boolean;
}

export type GuardResult = { ok: true; ctx: CommercialContext } | { ok: false; response: Response };

/** Adapt an authoritative context to the legacy downstream session shape. */
export function ctxToSession(ctx: CommercialContext): { userId: string; orgId: string; role: string } {
  return { userId: ctx.userId, orgId: ctx.orgId ?? '', role: ctx.role ?? (ctx.isStaff ? 'staff' : 'viewer') };
}

/**
 * Authoritative Quantex-staff gate for internal / legacy routes. Non-staff callers
 * (including any commercial customer) are denied. Internal Studio, agent, Gate 04,
 * governance, raw-query, and deploy surfaces use THIS — they are never commercially
 * reachable.
 */
export async function requireStaff(request: Request, env: Record<string, string | undefined>): Promise<GuardResult> {
  const guard = await requireCommercialContext(request, env);

  if (!guard.ok) {
    return guard;
  }

  if (!guard.ctx.isStaff) {
    return { ok: false, response: json({ ok: false, error: 'staff_only' }, { status: 403 }) };
  }

  return guard;
}

/**
 * Bind a verified project to the context: the project must be owned by the
 * caller's authoritative org (browser-supplied ownership is never trusted).
 * Returns the CommercialExecutionContext or a fail-closed response.
 */
export async function requireCommercialProject(
  request: Request,
  env: Record<string, string | undefined>,
  projectId: string,
  requiredCapability?: Capability,
): Promise<{ ok: true; ctx: CommercialExecutionContext } | { ok: false; response: Response }> {
  const guard = await requireCommercialContext(request, env, requiredCapability);

  if (!guard.ok) {
    return guard;
  }

  const ctx = guard.ctx;

  if (!ctx.orgId) {
    return { ok: false, response: json({ ok: false, error: 'no_org_context' }, { status: 403 }) };
  }

  const { getProjectOwnership } = await import('~/lib/qhub/commercial/commercial-store.server');
  const ownerOrg = await getProjectOwnership(projectId, env).catch(() => null);

  if (!ownerOrg || ownerOrg !== ctx.orgId) {
    // Not found OR owned by another tenant → deny (no cross-tenant project access).
    return { ok: false, response: json({ ok: false, error: 'project_forbidden' }, { status: 403 }) };
  }

  return { ok: true, ctx: { ...ctx, projectId, projectOrgId: ownerOrg } };
}

/** The execution context carried into protected commercial service functions. */
export interface CommercialExecutionContext extends CommercialContext {
  projectId: string;
  projectOrgId: string;
}

/** Read a browser-requested org selection (validated against membership later). */
function requestedOrg(request: Request): string | null {
  const header = request.headers.get('x-qhub-org');

  if (header) {
    return header;
  }

  try {
    return new URL(request.url).searchParams.get('org');
  } catch {
    return null;
  }
}

/**
 * Resolve the authoritative context and (optionally) require a capability.
 * Returns a fail-closed Response when identity/config/authorization fails.
 */
export async function requireCommercialContext(
  request: Request,
  env: Record<string, string | undefined>,
  requiredCapability?: Capability,
): Promise<GuardResult> {
  const user = await getVerifiedUser(request, env);

  if (user === 'missing_config') {
    return { ok: false, response: json({ ok: false, error: 'auth_not_configured' }, { status: 503 }) };
  }

  if (!user) {
    return { ok: false, response: json({ ok: false, error: 'unauthenticated' }, { status: 401 }) };
  }

  /*
   * Local development only: with no Supabase config and dev auth explicitly
   * allowed (impossible in staging/production), grant a staff-equivalent dev
   * context so the internal Studio remains usable locally.
   */
  if (!hasSupabaseConfig(env) && isDevAuthAllowed(env)) {
    const resolved = resolveEntitlements({ planId: 'none', status: 'none' });
    const capabilities = computeCapabilities({
      serviceState: resolved.serviceState,
      entitlements: { ...NO_PLAN_ENTITLEMENTS },
      membershipActive: true,
      role: 'admin',
      isStaff: true,
      onboardingComplete: true,
      suspended: false,
    });

    return {
      ok: true,
      ctx: {
        userId: user.userId,
        email: user.email,
        orgId: 'dev-org',
        role: 'admin',
        membershipStatus: 'active',
        isStaff: true,
        staffRole: 'engineer',
        resolved,
        capabilities,
        onboardingComplete: true,
        suspended: false,
      },
    };
  }

  const [membership, staff] = await Promise.all([
    resolveMembership(user.userId, requestedOrg(request), env),
    resolveStaff(user.userId, env),
  ]);

  const suspended = membership?.status === 'suspended' || membership?.status === 'removed';
  const membershipActive = membership?.status === 'active';

  // Resolve entitlements against the AUTHORITATIVE org only.
  let resolved: ResolvedEntitlements;
  let onboardingComplete = false;

  if (membership?.orgId) {
    resolved = await loadOrgEntitlements(membership.orgId, env);

    try {
      const ob = await getOnboardingState(membership.orgId, env);
      onboardingComplete = !!ob?.completed;
    } catch {
      onboardingComplete = false;
    }
  } else {
    resolved = resolveEntitlements({ planId: 'none', status: 'none' });
  }

  const capabilities = computeCapabilities({
    serviceState: resolved.serviceState,
    entitlements: membership?.orgId ? resolved.entitlements : { ...NO_PLAN_ENTITLEMENTS },
    membershipActive: !!membershipActive,
    role: membership?.role ?? null,
    isStaff: staff.isStaff,
    onboardingComplete,
    suspended,
  });

  const ctx: CommercialContext = {
    userId: user.userId,
    email: user.email,
    orgId: membership?.orgId ?? null,
    role: membership?.role ?? null,
    membershipStatus: membership?.status ?? null,
    isStaff: staff.isStaff,
    staffRole: staff.staffRole,
    resolved,
    capabilities,
    onboardingComplete,
    suspended,
  };

  // A commercial (non-staff) caller with no membership cannot act.
  if (!staff.isStaff && !membership) {
    return { ok: false, response: json({ ok: false, error: 'no_membership' }, { status: 403 }) };
  }

  if (requiredCapability && !hasCapability(capabilities, requiredCapability)) {
    return {
      ok: false,
      response: json({ ok: false, error: 'forbidden', capability: requiredCapability }, { status: 403 }),
    };
  }

  return { ok: true, ctx };
}

/** AST-readable module authority classification (commercial-architecture.test.ts). */
export const __QHUB_MODULE_CLASSIFICATION = 'INTERNAL_SERVER_ONLY' as const;
