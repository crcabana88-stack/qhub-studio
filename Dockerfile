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

# ── Build ─────────────────────────────────────────────────────────────────────
FROM base AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time env (non-secret, safe to bake)
ARG VITE_LOG_LEVEL=warn
ARG NODE_ENV=production
ENV NODE_ENV=$NODE_ENV
ENV VITE_LOG_LEVEL=$VITE_LOG_LEVEL
# Vite's chunk-rendering phase is memory-hungry on this large codebase.
# 4 GB gives it enough headroom to complete without OOM.
ENV NODE_OPTIONS="--max-old-space-size=4096"

RUN pnpm run build

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/build ./build
COPY --from=build /app/public ./public
# functions/ contains the Cloudflare Pages Functions entry point (functions/[[path]].ts
# compiled output). wrangler pages dev reads this directory at runtime to register
# server-side routes (POST /api/governance, POST /api/chat, etc.).
# WITHOUT this copy, all Remix server routes return 404 on Fly.io. CRITICAL.
COPY --from=build /app/functions ./functions
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./

# Runtime secrets — injected via AWS App Runner / Fly.io secrets, NOT baked in
# QHUB_API_BASE, QHUB_HMAC_SECRET, SUPABASE_URL, SUPABASE_ANON_KEY,
# SUPABASE_SERVICE_ROLE_KEY

EXPOSE 5173

# Health check for App Runner / ALB
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5173/', r => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["pnpm", "run", "start"]
