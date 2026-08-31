import {defineComponent} from 'convex/server';
import {v} from 'convex/values';

export default defineComponent('agentAuth', {
  env: {
    /** Kinde domain, e.g. "myapp.kinde.com" (no protocol). Required. */
    KINDE_DOMAIN: v.string(),
    /**
     * Expected `aud` claim for M2M tokens. Required in live mode (config.get
     * fails without it); optional in test mode. Schema stays optional so test
     * mode can omit it — the live-mode requirement is enforced at runtime.
     */
    KINDE_AUDIENCE: v.optional(v.string()),
    /** Secret used to HMAC-sign delegations. Required. */
    DELEGATION_SIGNING_SECRET: v.string(),
    /** "test" relaxes external calls for local development. */
    MODE: v.optional(v.union(v.literal('test'), v.literal('live'))),
    /** Max age of the cached Kinde JWKS in ms before refresh. Default 24h. */
    JWKS_MAX_AGE_MS: v.optional(v.string())
  }
});
