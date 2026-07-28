#!/bin/bash

bindings=""

# Read the IMMUTABLE on-image build identity (written into the artifact by
# build:verified) and export it as independent QHUB_IMAGE_* bindings, so the
# runtime can compare the deployment-injected QHUB_BUILD_* identity against the
# image's own identity (never a binding against itself).
IDFILE="build/qhub-build-identity.json"
if [ -f "$IDFILE" ]; then
  json_val() { grep "\"$1\"" "$IDFILE" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/'; }
  export QHUB_IMAGE_SOURCE_COMMIT="$(json_val source_commit)"
  export QHUB_IMAGE_ARTIFACT_HASH="$(json_val artifact_hash)"
  export QHUB_IMAGE_LOCKFILE_HASH="$(json_val lockfile_hash)"
  export QHUB_IMAGE_BUILD_AT="$(json_val built_at)"
  export QHUB_IMAGE_BUILD_ENVIRONMENT="$(json_val build_environment)"
fi

# Function to extract variable names from the TypeScript interface
extract_env_vars() {
  grep -o '[A-Z_][A-Z0-9_]*:' worker-configuration.d.ts | sed 's/://'
}

# First try to read from .env.local if it exists
if [ -f ".env.local" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ ! "$line" =~ ^# ]] && [[ -n "$line" ]]; then
      name=$(echo "$line" | cut -d '=' -f 1)
      value=$(echo "$line" | cut -d '=' -f 2-)
      value=$(echo $value | sed 's/^"\(.*\)"$/\1/')
      bindings+="--binding ${name}=${value} "
    fi
  done < .env.local
else
  # If .env.local doesn't exist, use environment variables defined in .d.ts
  env_vars=($(extract_env_vars))
  # Generate bindings for each environment variable if it exists
  for var in "${env_vars[@]}"; do
    if [ -n "${!var}" ]; then
      bindings+="--binding ${var}=${!var} "
    fi
  done
fi

bindings=$(echo $bindings | sed 's/[[:space:]]*$//')

echo $bindings
