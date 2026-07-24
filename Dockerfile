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

# Runtime secrets — injected via Fly.io secrets, NOT baked in:
# QHUB_HMAC_SECRET, QHUB_LEDGER_INGEST_URL,
# SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5173/', r => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["pnpm", "run", "start"]
