# QHUB Studio — Production Dockerfile
# Based on bolt.diy's official Dockerfile with QHUB governance env vars added.
# Build: docker build -f Dockerfile.qhub -t qhub-studio .
# Run:  docker run -p 5173:5173 --env-file .env qhub-studio

FROM node:20-slim AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# ── Dependencies ──────────────────────────────────────────────────────────────
FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

# ── Runtime ───────────────────────────────────────────────────────────────────
# NOTE: The Vite/Remix build runs LOCALLY (not inside Docker) because the
# Depot builder is memory-constrained and kills the Node process during
# chunk rendering (exit 137). Run `pnpm run build` on your local machine
# before deploying. The local build/ directory is included via .dockerignore
# negation (!build) and copied here.
FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Install production dependencies inside Docker (no build step)
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

# Copy pre-built client + server artifacts from the local build
COPY build ./build
COPY public ./public
COPY package.json ./
COPY bindings.sh ./

# Runtime secrets — injected via AWS App Runner / Fly.io secrets, NOT baked in
# QHUB_API_BASE, QHUB_HMAC_SECRET, SUPABASE_URL, SUPABASE_ANON_KEY,
# SUPABASE_SERVICE_ROLE_KEY

EXPOSE 5173

# Health check for App Runner / ALB
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5173/', r => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["pnpm", "run", "start"]
