interface Env {
  RUNNING_IN_DOCKER: Settings;
  DEFAULT_NUM_CTX: Settings;
  ANTHROPIC_API_KEY: string;
  OPENAI_API_KEY: string;
  GROQ_API_KEY: string;
  HuggingFace_API_KEY: string;
  OPEN_ROUTER_API_KEY: string;
  OLLAMA_API_BASE_URL: string;
  OPENAI_LIKE_API_KEY: string;
  OPENAI_LIKE_API_BASE_URL: string;
  OPENAI_LIKE_API_MODELS: string;
  TOGETHER_API_KEY: string;
  TOGETHER_API_BASE_URL: string;
  DEEPSEEK_API_KEY: string;
  LMSTUDIO_API_BASE_URL: string;
  GOOGLE_GENERATIVE_AI_API_KEY: string;
  MISTRAL_API_KEY: string;
  XAI_API_KEY: string;
  PERPLEXITY_API_KEY: string;
  AWS_BEDROCK_CONFIG: string;

  // ── QHUB governance + Supabase auth ──────────────────────────────────────
  /*
   * These MUST be declared here: bindings.sh extracts the env-var names from
   * this interface and forwards them to `wrangler pages dev` as --binding
   * flags. Without a binding, the value never reaches the worker's ctx.env.
   */
  QHUB_LEDGER_INGEST_URL: string;
  QHUB_API_BASE: string;
  QHUB_HMAC_SECRET: string;
  QHUB_DEPLOY_ENV: string;
  QHUB_PUBLIC_HOSTNAME: string;
  QHUB_ENABLE_GATE04_SIMULATION_ADAPTERS: string;

  /*
   * Non-secret build identity. Two INDEPENDENT sources are declared so bindings.sh
   * forwards both to context.cloudflare.env, letting the runtime compare them:
   *   - QHUB_BUILD_* : EXPECTED (deployment) identity, injected at deploy time.
   *   - QHUB_IMAGE_* : ACTUAL on-image identity, read from
   *     build/qhub-build-identity.json by bindings.sh at container startup.
   * A mismatch fails closed (see build-integrity.server.ts).
   */
  QHUB_BUILD_SOURCE_COMMIT: string;
  QHUB_BUILD_ARTIFACT_HASH: string;
  QHUB_BUILD_LOCKFILE_HASH: string;
  QHUB_BUILD_AT: string;
  QHUB_IMAGE_SOURCE_COMMIT: string;
  QHUB_IMAGE_ARTIFACT_HASH: string;
  QHUB_IMAGE_LOCKFILE_HASH: string;
  QHUB_IMAGE_BUILD_AT: string;
  FLY_APP_NAME: string;
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
}
