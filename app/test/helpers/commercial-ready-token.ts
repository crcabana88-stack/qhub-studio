/**
 * QHUB Commercial Launch R5 — TEST-ONLY readiness token helper
 * app/test/helpers/commercial-ready-token.ts
 *
 * Mints GENUINE, registry-backed CommercialReadyToken instances via the readiness module's
 * test-only mint (guarded to throw in production). These are authentic tokens — NOT `as`
 * casts — so they pass the runtime WeakSet authenticity check. Forgery-rejection is proven
 * separately in the isolated negative tests in commercial-readiness.test.ts.
 */

import {
  __mintReadyTokenForTests,
  type CommercialReadyToken,
} from '~/lib/qhub/commercial/commercial-schema-check.server';

/** A genuine token valid for `env`'s exact target. */
export function testReadyToken(env: Record<string, string | undefined>): CommercialReadyToken {
  return __mintReadyTokenForTests(env);
}

/** A genuine token minted for a DIFFERENT target (for target-mismatch tests). */
export function testWrongTargetToken(): CommercialReadyToken {
  return __mintReadyTokenForTests({
    SUPABASE_URL: 'https://a-totally-different-project.supabase.co',
    QHUB_DEPLOY_ENV: 'someotherenv',
  });
}
