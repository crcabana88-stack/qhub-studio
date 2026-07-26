# Gate 04 authenticated staging matrix

`gate04-authenticated-live-matrix.mjs` is a trusted-operator CLI for the
synthetic Gate 04 staging tenants. It is not an application route.

Required environment variable names:

- `QHUB_ALLOW_STAGING_LIVE_TESTS=1`
- `QHUB_LIVE_TEST_ENV=staging`
- `QHUB_STAGING_BASE_URL=https://qhub-studio.fly.dev`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

The deployed staging service must independently have:

- `QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS=1`
- `QHUB_DEPLOY_ENV=staging`
- `FLY_APP_NAME=qhub-studio`
- `QHUB_PUBLIC_HOSTNAME=qhub-studio.fly.dev`

Those server-side guards authorize only the two Gate 04 synthetic simulation
adapters. They do not authorize a real external connector.

If the five named synthetic staging principals do not yet exist, the separate
guard `QHUB_ALLOW_STAGING_PRINCIPAL_PROVISIONING=1` authorizes creation through
Supabase Auth admin APIs. It does not create application routes or database
approval rows. Principal sessions are minted passwordlessly and kept only in
memory.

For an approved Fly one-off process, set that process's `NODE_ENV=staging`.
This does not change the deployed application environment; it makes the
operator process independently attest that it is targeting staging. The exact
hostname and Supabase project guards still apply.

The script refuses other hosts, Supabase projects, tenants, non-HTTPS targets,
and production environment markers. Actions target `.invalid` no-op resources.
Approvals and kill-switch transitions go exclusively through the deployed
authenticated routes. Database reads are limited to postcondition checks.
The matrix also drives one real governed model-provider call and verifies that
its ALLOW was claimed and its `AI_MODEL_INVOKED` evidence state reached
`COMMITTED`; the provider-throws-before-handle path remains a deterministic
automated regression so no deliberate provider outage or secret mutation is
required in staging.

Reports are redacted and written with restrictive permissions beneath the
operating system temporary directory. Authentication material is never
included. Case B/C receipt counts come from distinct durable receipt identities,
not the legacy `side_effect_performed` boolean.
