/**
 * QHUB Commercial Launch R4 — TEST-ONLY readiness token helper
 * app/test/helpers/commercial-ready-token.ts
 *
 * Mints a CommercialReadyToken bound to the current test target. The `as` cast is
 * permitted ONLY in the readiness module and in tests (the architecture test enforces
 * this). Production code can never construct a token — it can only receive one from the
 * central readiness service after an exact READY result.
 */

import {
  commercialTargetKey,
  EXPECTED_COMMERCIAL_SCHEMA_VERSION,
  type CommercialReadyToken,
} from '~/lib/qhub/commercial/commercial-schema-check.server';

/** A valid token for `env` (its targetKey matches commercialTargetKey(env)). */
export function testReadyToken(env: Record<string, string | undefined>): CommercialReadyToken {
  return {
    schemaVersion: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
    targetKey: commercialTargetKey(env),
    checkedAt: new Date().toISOString(),
  } as CommercialReadyToken;
}

/** An intentionally wrong-target token, for target-mismatch tests. */
export function testWrongTargetToken(): CommercialReadyToken {
  return {
    schemaVersion: EXPECTED_COMMERCIAL_SCHEMA_VERSION,
    targetKey: 'deadbeef',
    checkedAt: new Date().toISOString(),
  } as CommercialReadyToken;
}
