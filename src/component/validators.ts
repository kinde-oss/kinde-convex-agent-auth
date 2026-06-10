import {v} from 'convex/values';

export const ownerKindValidator = v.union(
  v.literal('user'),
  v.literal('org'),
  v.literal('platform')
);

export const agentKindValidator = v.union(
  v.literal('autonomous'),
  v.literal('supervised')
);

export const agentStatusValidator = v.union(
  v.literal('active'),
  v.literal('suspended')
);

export const instanceStatusValidator = v.union(
  v.literal('running'),
  v.literal('completed'),
  v.literal('revoked'),
  v.literal('expired')
);

export const issuerKindValidator = v.union(v.literal('user'), v.literal('org'));

export const revocationTargetKindValidator = v.union(
  v.literal('instance'),
  v.literal('agent'),
  v.literal('org'),
  v.literal('global')
);

export const elevationStatusValidator = v.union(
  v.literal('pending'),
  v.literal('approved'),
  v.literal('denied'),
  v.literal('expired')
);

export const decisionValidator = v.union(v.literal('allow'), v.literal('deny'));

/**
 * Flat string-keyed metadata. Values are limited to primitives and string
 * arrays so the whole document stays fully typed (no `any` anywhere in the
 * generated types).
 */
export const metadataValidator = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null(), v.array(v.string()))
);

/**
 * A single JSON Web Key as served by Kinde's `jwks_uri`. JWK members are
 * strings except for `x5c`/`key_ops` style members, which are string arrays.
 */
export const jwkValidator = v.record(
  v.string(),
  v.union(v.string(), v.array(v.string()))
);

export const jwksKeysValidator = v.array(jwkValidator);

export const nullableString = v.union(v.string(), v.null());
export const nullableNumber = v.union(v.number(), v.null());
export const nullableStringArray = v.union(v.array(v.string()), v.null());
