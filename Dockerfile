# QHUB Studio — Production Dockerfile
# Based on bolt.diy's official Dockerfile with QHUB governance env vars added.
# Build: docker build -f Dockerfile.qhub -t qhub-studio .
# Run:  docker run -p 5173:5173 --env-file .env qhub-studio
#
# DEPLOY WORKFLOW:
#   1. pnpm run build         (local — Depot builder has insufficient RAM)
#   2. git add build/ ...
#   3. flyctl deploy          (Docker copies pre-built artifacts, no build step)

FROM node:20-slim AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
# Install bash (bindings.sh needs #!/bin/bash) and ca-certificates.
# ca-certificates is REQUIRED: `wrangler pages dev` runs the worker in
# self-hosted workerd, whose outbound fetch() TLS uses the system CA store.
# Without it, HTTPS to Supabase/AWS fails with
# "unable to get local issuer certificate" and every auth/ledger call errors.
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN corepack enable

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Point OpenSSL/workerd and Node at the installed CA bundle so outbound
# HTTPS (Supabase auth, AWS ledger) can verify certificate chains.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# Install deps. --prod=false forces devDependencies to be installed even
# though NODE_ENV=production: the runtime start command is
# `wrangler pages dev ./build/client`, and wrangler is a devDependency.
# --ignore-scripts skips the `prepare` husky hook (no .git in the image).
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts --prod=false

# Copy pre-built client + server artifacts (built locally before deploy)
# .dockerignore has !build to allow the root build/ into the context.
COPY build ./build
COPY public ./public
# Cloudflare Pages Functions: functions/[[path]].ts is the catch-all SSR
# handler that runs build/server. Without it, `wrangler pages dev` serves
# only static assets and every dynamic route (including /) returns 404.
COPY functions ./functions
# wrangler.toml carries compatibility_flags = ["nodejs_compat"] and the
# compatibility_date. Without it in the image, wrangler pages dev runs with
# no node compat, so the SSR bundle's node: imports (e.g. node:crypto in the
# governance service) fail to bundle and the worker crashes on boot.
COPY wrangler.toml ./
COPY bindings.sh ./
# worker-configuration.d.ts lists the env var names that bindings.sh
# reads from process.env and forwards to wrangler as --binding flags.
COPY worker-configuration.d.ts ./
# Normalize line endings: the repo is checked out on Windows (core.autocrlf),
# so bindings.sh can arrive with CRLF. A CRLF shebang (`#!/bin/bash\r`) makes
# the kernel look for an interpreter named "/bin/bash\r" → "not found" at boot.
# Strip CRs before making it executable so startup is deterministic.
RUN sed -i 's/\r$//' bindings.sh && chmod +x bindings.sh

# Runtime secrets — injected via Fly.io secrets, NOT baked in:
# QHUB_HMAC_SECRET, QHUB_LEDGER_INGEST_URL,
# SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY

EXPOSE 5173

# Probe /login (always 200 for an unauthenticated request); / now 302-redirects
# to /login once auth is enforced. Accept any 2xx/3xx. Longer start-period covers
# wrangler pages dev's cold-start bundling (~40s).
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5173/login', r => process.exit(r.statusCode >= 200 && r.statusCode < 400 ? 0 : 1))"

# dockerstart binds to 0.0.0.0:5173 (required for Fly.io proxy to reach it)
CMD ["pnpm", "run", "dockerstart"]
