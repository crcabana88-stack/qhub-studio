/**
 * QHUB build identity + integrity (PURE, browser-safe)
 * app/lib/qhub/build-identity.ts
 *
 * Prevents the stale-build deployment defect and proves the RUNNING image matches
 * the intended source. Two independent identities are compared at runtime:
 *   - EXPECTED (deployment): QHUB_BUILD_SOURCE_COMMIT / _ARTIFACT_HASH /
 *     _LOCKFILE_HASH / _AT — injected at deploy time.
 *   - IMAGE (on-image): read from build/qhub-build-identity.json at container
 *     startup and forwarded as QHUB_IMAGE_* bindings (see bindings.sh).
 * `evaluateBuildIntegrity` compares source, artifact, AND lockfile hashes and
 * fails closed on any mismatch. The canonical artifact hash lives in the single
 * shared implementation `scripts/lib/canonical-artifact-hash.mjs`.
 */

/**
 * Code markers that MUST be present in the built server bundle. Each names a
 * distinctive string from a route/module added in source, so a stale build (that
 * predates the source) fails the marker check. KEEP CURRENT with new routes.
 */
export const REQUIRED_BUILD_MARKERS: string[] = [
  'canonicalAgentManifestString', // agent manifest
  'qhub_verify_agent_schema', // agent schema verifier
  'freeze_release', // agent release-binding route op
  'bind_release',
  'AGENT_MANIFEST_NOT_IN_RELEASE', // exact-version binding
  'qhub_verify_governance_schema', // Gate 04 verifier (regression marker)
  'reconstructForResume', // production no-replay reconstruction guard
];

export interface BuildIdentity {
  source_commit: string;
  built_at: string;
  artifact_hash: string;
  lockfile_hash: string;
  markers_ok: boolean;
}

/** A non-secret source/artifact/lockfile identity triple (+ optional timestamp). */
export interface BuildIdentityTriple {
  source_commit: string | null;
  artifact_hash: string | null;
  lockfile_hash: string | null;
  build_at?: string | null;
}

export type BuildIntegrityReason =
  | 'MISSING_EXPECTED_IDENTITY'
  | 'MISSING_IMAGE_IDENTITY'
  | 'SOURCE_COMMIT_MISMATCH'
  | 'ARTIFACT_HASH_MISMATCH'
  | 'LOCKFILE_HASH_MISMATCH';

export interface BuildIntegrityResult {
  /** Both identities are fully present (all three hashes on each side). */
  present: boolean;

  /** Present AND every hash matches — safe to serve / run. */
  ready: boolean;

  source_commit: string | null;
  artifact_hash: string | null;
  lockfile_hash: string | null;
  build_at: string | null;
  mismatch_reason_codes: BuildIntegrityReason[];
}

function complete(t: BuildIdentityTriple): boolean {
  return !!t.source_commit && !!t.artifact_hash && !!t.lockfile_hash;
}

/**
 * Compare the EXPECTED (deployment) identity against the independent IMAGE
 * (on-image) identity across source commit, artifact hash, AND lockfile hash.
 * Never compares a binding against itself. Missing either side ⇒ not ready.
 */
export function evaluateBuildIntegrity(
  expected: BuildIdentityTriple,
  image: BuildIdentityTriple,
): BuildIntegrityResult {
  const reasons: BuildIntegrityReason[] = [];
  const base: BuildIntegrityResult = {
    present: false,
    ready: false,
    source_commit: expected.source_commit,
    artifact_hash: expected.artifact_hash,
    lockfile_hash: expected.lockfile_hash,
    build_at: expected.build_at ?? null,
    mismatch_reason_codes: reasons,
  };

  if (!complete(expected)) {
    reasons.push('MISSING_EXPECTED_IDENTITY');

    return base;
  }

  if (!complete(image)) {
    reasons.push('MISSING_IMAGE_IDENTITY');

    return base;
  }

  base.present = true;

  if (expected.source_commit !== image.source_commit) {
    reasons.push('SOURCE_COMMIT_MISMATCH');
  }

  if (expected.artifact_hash !== image.artifact_hash) {
    reasons.push('ARTIFACT_HASH_MISMATCH');
  }

  if (expected.lockfile_hash !== image.lockfile_hash) {
    reasons.push('LOCKFILE_HASH_MISMATCH');
  }

  base.ready = reasons.length === 0;

  return base;
}

/** Markers absent from the bundle text (empty ⇒ the build matches current source). */
export function missingMarkers(bundleText: string, markers: string[] = REQUIRED_BUILD_MARKERS): string[] {
  return markers.filter((m) => !bundleText.includes(m));
}

/** Untracked paths permitted (never enter source/Docker context): narrow allowlist. */
export const BUILD_CONTEXT_ALLOWLIST_UNTRACKED = /^(\.claude\/|\.pnpm-store\/|build\/|node_modules\/)/;

/**
 * Every path that can affect the production image or runtime — the union of the
 * bundler/config discovery surface and the Dockerfile COPY sources
 * (build, public, FUNCTIONS, wrangler.toml, bindings.sh, worker-configuration.d.ts,
 * package.json, pnpm-lock.yaml). Kept in sync with scripts/build-with-identity.mjs.
 */
const BUILD_RELEVANT_UNTRACKED =
  /^(app\/|functions\/|scripts\/|public\/|supabase\/|electron\/|package\.json|package-lock\.json|pnpm-lock\.yaml|tsconfig[^/]*\.json|vite\.config\.|vite-electron\.config\.|remix\.config\.|uno\.config\.|wrangler\.|postcss\.config\.|tailwind\.config\.|worker-configuration\.d\.ts|bindings\.sh|Dockerfile|fly\.toml|\.dockerignore|\.eslintrc|eslint\.config\.)/;

/**
 * From `git status --porcelain` lines, the TRACKED source changes that must block
 * a verified build. Untracked and the known excluded artifact dirs are ignored —
 * only committed source integrity matters for "no uncommitted source shipped".
 */
export function dirtySourcePaths(porcelainLines: string[]): string[] {
  return porcelainLines
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0)
    .filter((l) => !l.startsWith('?? ')) // untracked handled separately
    .map((l) => l.slice(3))
    .filter((p) => p && !BUILD_CONTEXT_ALLOWLIST_UNTRACKED.test(p));
}

/**
 * From `git status --porcelain` lines, UNTRACKED files that could enter the source
 * or Docker build context and must block a verified build. Only the narrow
 * allowlist (.claude/, .pnpm-store/, build/, node_modules/) is permitted; any
 * other untracked build-relevant path (app/, scripts/, config, Docker/Fly, …) is
 * rejected so a clean exact commit — not a dirty context — is what ships.
 */
export function untrackedBuildInputs(porcelainLines: string[]): string[] {
  return porcelainLines
    .map((l) => l.trimEnd())
    .filter((l) => l.startsWith('?? '))
    .map((l) => l.slice(3))
    .filter((p) => p && !BUILD_CONTEXT_ALLOWLIST_UNTRACKED.test(p))
    .filter((p) => BUILD_RELEVANT_UNTRACKED.test(p));
}

/**
 * From a filesystem/`git ls-files --others --ignored` path list, the .env files
 * VITE ACTUALLY LOADS — `.env`, `.env.local`, `.env.[mode]`, `.env.[mode].local`
 * (at repo root or under functions/). These can change the built artifact while
 * remaining invisible to `git status`, so a verified build must fail when any is
 * present. Non-loaded templates (`.env.example`, `.sample`) and `.env.d.ts` type
 * files are NOT flagged.
 */
export function viteLoadedEnvFiles(paths: string[]): string[] {
  return paths
    .map((p) => p.replace(/\\/g, '/').trim())
    .filter((p) => p.length > 0)
    .filter((p) => {
      const base = p.split('/').pop() ?? '';

      if (base.endsWith('.example') || base.endsWith('.sample') || base.endsWith('.d.ts')) {
        return false;
      }

      // .env, or .env.<mode>[.local] — but not .env.example (handled above).
      return /^\.env(\.[A-Za-z0-9_-]+)*$/.test(base);
    });
}

/** Build-env variables that inline into the artifact and must be an explicit allowlist. */
const BUILD_ENV_ALLOWLIST = new Set<string>([
  // Non-inlining build controls (documented, safe):
  'NODE_OPTIONS',
  'QHUB_ALLOW_DIRTY_BUILD',
]);

/**
 * Unexpected build-time environment variables that could alter the built
 * artifact: any `VITE_*` or `PUBLIC_*` (Vite inlines these) or build-time
 * `QHUB_BUILD_*` (identity is injected at DEPLOY, never at build) not on the
 * explicit allowlist. A verified build runs under a sanitized environment and
 * fails when any is present.
 */
export function unexpectedBuildEnv(envKeys: string[]): string[] {
  return envKeys.filter(
    (k) => (/^VITE_/.test(k) || /^PUBLIC_/.test(k) || /^QHUB_BUILD_/.test(k)) && !BUILD_ENV_ALLOWLIST.has(k),
  );
}
