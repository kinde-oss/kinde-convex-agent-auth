import {v} from 'convex/values';
import {env, query} from './_generated/server.js';
import {fail} from './helpers.js';
import {nullableString} from './validators.js';

/**
 * Validate the component's MODE env var, defaulting to "live". An unset value
 * is fine; any value other than "test" or "live" is a configuration error and
 * fails with a typed code rather than a generic return-validation failure.
 */
function requireMode(): 'test' | 'live' {
  const mode = env.MODE;
  if (mode === undefined || mode === 'live') {
    return 'live';
  }
  if (mode === 'test') {
    return 'test';
  }
  fail('invalid_mode', 'MODE must be either "test" or "live".');
}

/** Default lifetime of the cached Kinde JWKS before it is refreshed: 24h. */
export const DEFAULT_JWKS_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * How long a cached JWKS may be served before it is treated as stale and
 * refreshed, from JWKS_MAX_AGE_MS (milliseconds) or a 24h default. A
 * non-positive or non-numeric value is a configuration error.
 */
function requireJwksMaxAgeMs(): number {
  const raw = env.JWKS_MAX_AGE_MS;
  if (raw === undefined || raw === '') {
    return DEFAULT_JWKS_MAX_AGE_MS;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    fail(
      'invalid_jwks_max_age',
      'JWKS_MAX_AGE_MS must be a positive number of milliseconds.'
    );
  }
  return parsed;
}

/**
 * Read the component's configuration (from its typed environment variables).
 * The client layer uses this so the Kinde domain and audience only need to
 * be configured once, on the component. The signing secret is never exposed.
 */
export const get = query({
  args: {},
  returns: v.object({
    domain: v.string(),
    audience: nullableString,
    mode: v.union(v.literal('test'), v.literal('live')),
    jwksMaxAgeMs: v.number()
  }),
  handler: async () => {
    const domain = env.KINDE_DOMAIN;
    if (!domain) {
      fail(
        'kinde_domain_unset',
        'The KINDE_DOMAIN environment variable is not set for the agentAuth component.'
      );
    }
    return {
      domain,
      audience: env.KINDE_AUDIENCE ?? null,
      mode: requireMode(),
      jwksMaxAgeMs: requireJwksMaxAgeMs()
    };
  }
});
