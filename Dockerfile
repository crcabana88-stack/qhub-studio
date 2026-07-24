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

# Install deps (--ignore-scripts skips the `prepare` husky hook that
# fails when devDependencies are absent in a production install)
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts

# Copy pre-built client + server artifacts (built locally before deploy)
# .dockerignore has !build to allow the root build/ into the context.
COPY build ./build
COPY public ./public
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
