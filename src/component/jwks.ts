import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import {action, env, internalMutation, query} from './_generated/server.js';
import {internal} from './_generated/api.js';
import schema from './schema.js';
import {fail} from './helpers.js';
import {jwksKeysValidator} from './validators.js';

type Jwk = Infer<typeof jwksKeysValidator>[number];

const jwksCacheDoc = schema.tables.jwksCache.validator.extend({
  _id: v.id('jwksCache'),
  _creationTime: v.number()
});

function requireDomain(): string {
  const domain = env.KINDE_DOMAIN;
  if (!domain) {
    fail(
      'kinde_domain_unset',
      'The KINDE_DOMAIN environment variable is not set for the agentAuth component.'
    );
  }
  return domain;
}

/**
 * Narrow an untrusted JSON value to a JWKS key array. JWK members are
 * strings or string arrays per RFC 7517; members of other types (e.g. the
 * boolean `ext`) are dropped — they are not needed for signature checks.
 */
function toJwkArray(value: unknown): Jwk[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const keys: Jwk[] = [];
  for (const entry of value) {
    if (typeof entry !== 'object' || entry === null) {
      return null;
    }
    const jwk: Jwk = {};
    for (const [member, memberValue] of Object.entries(entry)) {
      if (typeof memberValue === 'string') {
        jwk[member] = memberValue;
      } else if (
        Array.isArray(memberValue) &&
        memberValue.every((item): item is string => typeof item === 'string')
      ) {
        jwk[member] = memberValue;
      }
    }
    keys.push(jwk);
  }
  return keys;
}

/** The cached JWKS for the configured Kinde domain, or null if not cached. */
export const get = query({
  args: {},
  returns: v.union(jwksCacheDoc, v.null()),
  handler: async (ctx) => {
    const domain = requireDomain();
    return await ctx.db
      .query('jwksCache')
      .withIndex('by_domain', (q) => q.eq('domain', domain))
      .unique();
  }
});

export const store = internalMutation({
  args: {domain: v.string(), keys: jwksKeysValidator},
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('jwksCache')
      .withIndex('by_domain', (q) => q.eq('domain', args.domain))
      .unique();
    if (existing !== null) {
      await ctx.db.patch('jwksCache', existing._id, {
        keys: args.keys,
        fetchedAt: Date.now()
      });
    } else {
      await ctx.db.insert('jwksCache', {
        domain: args.domain,
        keys: args.keys,
        fetchedAt: Date.now()
      });
    }
    return null;
  }
});

/**
 * Fetch the JWKS for the configured Kinde domain via its OpenID configuration
 * document and cache it. Returns the fresh keys.
 */
export const refresh = action({
  args: {},
  returns: jwksKeysValidator,
  handler: async (ctx) => {
    const domain = requireDomain();
    const configUrl = `https://${domain}/.well-known/openid-configuration`;
    const configResponse = await fetch(configUrl);
    if (!configResponse.ok) {
      fail(
        'oidc_config_fetch_failed',
        `Fetching ${configUrl} failed with status ${configResponse.status}.`
      );
    }
    const config: unknown = await configResponse.json();
    const jwksUri =
      typeof config === 'object' &&
      config !== null &&
      'jwks_uri' in config &&
      typeof (config as {jwks_uri: unknown}).jwks_uri === 'string'
        ? (config as {jwks_uri: string}).jwks_uri
        : null;
    if (jwksUri === null) {
      fail(
        'jwks_uri_missing',
        `The OpenID configuration at ${configUrl} has no jwks_uri.`
      );
    }
    const jwksResponse = await fetch(jwksUri);
    if (!jwksResponse.ok) {
      fail(
        'jwks_fetch_failed',
        `Fetching ${jwksUri} failed with status ${jwksResponse.status}.`
      );
    }
    const jwks: unknown = await jwksResponse.json();
    const keys =
      typeof jwks === 'object' && jwks !== null && 'keys' in jwks
        ? toJwkArray((jwks as {keys: unknown}).keys)
        : null;
    if (keys === null) {
      fail('jwks_malformed', `The JWKS at ${jwksUri} is not a valid key set.`);
    }
    await ctx.runMutation(internal.jwks.store, {domain, keys});
    return keys;
  }
});
