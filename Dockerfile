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
# Install bash (node:20-slim is Debian Bookworm slim — bash not included by default,
# but bindings.sh requires it via #!/bin/bash shebang)
RUN apt-get update && apt-get install -y bash && rm -rf /var/lib/apt/lists/*
RUN corepack enable

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production

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

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5173/', r => process.exit(r.statusCode === 200 ? 0 : 1))"

# dockerstart binds to 0.0.0.0:5173 (required for Fly.io proxy to reach it)
CMD ["pnpm", "run", "dockerstart"]
