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
  // These MUST be declared here: bindings.sh extracts the env-var names from
  // this interface and forwards them to `wrangler pages dev` as --binding
  // flags. Without a binding, the value never reaches the worker's ctx.env,
  // so getSession() falls back to the dev session and GovernanceService sees
  // no HMAC secret (events skipped, gate returns UNKNOWN).
  QHUB_LEDGER_INGEST_URL: string;
  QHUB_API_BASE: string;
  QHUB_HMAC_SECRET: string;
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
}
