/**
 * QHUB Commercial Launch R2 — AUTHORITATIVE MEMBERSHIP (SERVER ONLY)
 * app/lib/qhub/commercial/membership.server.ts
 *
 * Resolves organization membership, role, status, and internal Quantex staff
 * standing from the DATABASE — never from user_metadata. This is the authority
 * for org_id + role used by requireCommercialContext. Service-role only.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

function admin(env: Record<string, string | undefined>): SupabaseClient {
  const url = env.SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
  const key = env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

  if (!url || !key) {
    throw new Error('[Membership] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.');
  }

  return createClient(url, key, { auth: { persistSession: false } });
}

export type OrgRole = 'owner' | 'admin' | 'billing_admin' | 'builder' | 'viewer';
export type MembershipStatus = 'active' | 'invited' | 'suspended' | 'removed';

export interface Membership {
  userId: string;
  orgId: string;
  role: OrgRole;
  status: MembershipStatus;
}

/**
 * Resolve the authoritative membership for a user. When `requestedOrgId` is
 * supplied (a browser-selected org), it is honored ONLY if it is one of the
 * user's own memberships — otherwise it is ignored (a browser cannot assert an
 * org it does not belong to). Falls back to the user's first ACTIVE membership.
 * Returns null when the user has no membership.
 */
export async function resolveMembership(
  userId: string,
  requestedOrgId: string | null,
  env: Record<string, string | undefined>,
): Promise<Membership | null> {
  const sb = admin(env);
  const { data, error } = await sb.from('qhub_org_members').select('user_id,org_id,role,status').eq('user_id', userId);

  if (error || !data || data.length === 0) {
    return null;
  }

  const rows: Membership[] = data.map((r) => ({
    userId: r.user_id as string,
    orgId: r.org_id as string,
    role: (r.role as OrgRole) ?? 'viewer',
    status: (r.status as MembershipStatus) ?? 'removed',
  }));

  // Honor a browser-selected org only if the user actually belongs to it.
  if (requestedOrgId) {
    const match = rows.find((m) => m.orgId === requestedOrgId);

    if (match) {
      return match;
    }

    // Requested an org they are not a member of → do not grant it; fall through.
  }

  return rows.find((m) => m.status === 'active') ?? rows[0];
}

export interface StaffStanding {
  isStaff: boolean;
  staffRole: 'reviewer' | 'admin' | 'engineer' | null;
}

/** Authoritative internal-staff standing (active staff record only). */
export async function resolveStaff(userId: string, env: Record<string, string | undefined>): Promise<StaffStanding> {
  const sb = admin(env);
  const { data } = await sb.from('qhub_quantex_staff').select('staff_role,active').eq('user_id', userId).maybeSingle();

  if (!data || !data.active) {
    return { isStaff: false, staffRole: null };
  }

  return { isStaff: true, staffRole: (data.staff_role as StaffStanding['staffRole']) ?? 'reviewer' };
}

/** True when the user has an active Quantex staff record. */
export async function isActiveStaff(userId: string, env: Record<string, string | undefined>): Promise<boolean> {
  return (await resolveStaff(userId, env)).isStaff;
}
