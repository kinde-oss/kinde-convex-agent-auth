import {createLocalJWKSet, jwtVerify} from 'jose';
import type {JWTPayload, JWTVerifyOptions} from 'jose';
import {ConvexError} from 'convex/values';
import type {GenericActionCtx, GenericDataModel} from 'convex/server';
import type {ComponentApi} from '../component/_generated/component.js';

/**
 * The verified identity of a calling agent. THIS TYPE AND THE SIGNATURE OF
 * `verifyCaller` ARE A STABLE CONTRACT: other components (e.g. billing)
 * plug into this seam. Fields are only ever added, never changed or removed,
 * within a major version.
 */
export interface VerifiedAgent {
  /** The token's `sub` claim, falling back to `azp` (the M2M client id). */
  subject: string;
  /**
   * The registry id of the agent mapped from the token's `azp` claim, or
   * null when no agent is registered for that Kinde client id.
   */
  agentId: string | null;
  /**
   * The Kinde organization the token is scoped to (the trusted `org_code`
   * claim). This is the ONLY source of tenant context — it is a binding
   * contract and can never be overridden by input (invariant I3).
   */
  orgCode: string | null;
  /** Scopes granted by Kinde (`scp` array, or `scope` split on spaces). */
  scopes: string[];
  /** The full verified JWT payload. */
  claims: Record<string, unknown>;
}

export interface VerifyCallerOptions {
  /** Kinde domain override. Defaults to the component's KINDE_DOMAIN. */
  domain?: string;
  /** Audience override. Defaults to the component's KINDE_AUDIENCE. */
  audience?: string;
  /**
   * If set, the token's org_code must equal this value exactly; any other
   * value (or an org-less token) is denied and audited (invariant I3).
   */
  expectedOrgCode?: string;
  /**
   * Require the token's `azp` to map to a registered agent. When true (THE
   * DEFAULT), a valid token whose `azp` has no `agents` row — or a token with
   * no `azp` at all — is denied with `agent_not_registered` instead of
   * resolving to a null `agentId`.
   *
   * THIS DEFAULT IS THE ONE INTENTIONAL BEHAVIORAL CHANGE OF THIS RELEASE:
   * earlier versions allowed unregistered callers through. Pass
   * `requireRegisteredAgent: false` to restore that behavior (e.g. for
   * cross-app introspection where the caller need not be registered here).
   */
  requireRegisteredAgent?: boolean;
  /**
   * Require the token to carry an `org_code`. When true, an org-less token is
   * denied with `org_code_required`. Defaults to false, preserving the current
   * behavior where org-less (personal agent) tokens are allowed but skip org
   * revocation and tenant policy gates. Org-scoped deployments should set this
   * (or `expectedOrgCode`) so those gates are never silently skipped.
   */
  requireOrgCode?: boolean;
}

/**
 * The minimal ctx verifyCaller needs: it runs from an app action or HTTP
 * action (queries/mutations cannot refresh the JWKS cache).
 */
export type RunActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation' | 'runAction'
>;

type Jwk = Record<string, string | string[]>;

type ErrorData = {code: string; message: string};

function joseErrorInfo(error: unknown): {
  code: string | null;
  claim: string | null;
} {
  if (typeof error !== 'object' || error === null) {
    return {code: null, claim: null};
  }
  const code =
    'code' in error && typeof (error as {code: unknown}).code === 'string'
      ? (error as {code: string}).code
      : null;
  const claim =
    'claim' in error && typeof (error as {claim: unknown}).claim === 'string'
      ? (error as {claim: string}).claim
      : null;
  return {code, claim};
}

function mapJoseError(error: unknown): ConvexError<ErrorData> {
  const {code, claim} = joseErrorInfo(error);
  switch (code) {
    case 'ERR_JWT_EXPIRED':
      return new ConvexError({
        code: 'token_expired',
        message: 'The token has expired.'
      });
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      if (claim === 'iss') {
        return new ConvexError({
          code: 'invalid_issuer',
          message: 'The token was not issued by the configured Kinde domain.'
        });
      }
      if (claim === 'aud') {
        return new ConvexError({
          code: 'invalid_audience',
          message: 'The token audience does not match the configured audience.'
        });
      }
      return new ConvexError({
        code: 'invalid_claims',
        message: `The token's "${claim ?? 'unknown'}" claim failed validation.`
      });
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
      return new ConvexError({
        code: 'invalid_signature',
        message: 'The token signature is invalid.'
      });
    case 'ERR_JWKS_NO_MATCHING_KEY':
      return new ConvexError({
        code: 'unknown_key',
        message: 'No key in the Kinde JWKS matches the token, after refresh.'
      });
    default:
      return new ConvexError({
        code: 'invalid_token',
        message: 'The token could not be verified.'
      });
  }
}

function convexErrorData(error: unknown): ErrorData | null {
  if (!(error instanceof ConvexError)) {
    return null;
  }
  const data: unknown = error.data;
  if (typeof data !== 'object' || data === null) {
    return null;
  }
  const {code, message} = data as {code?: unknown; message?: unknown};
  return typeof code === 'string' && typeof message === 'string'
    ? {code, message}
    : null;
}

function extractScopes(payload: JWTPayload): string[] {
  const scp = payload['scp'];
  if (
    Array.isArray(scp) &&
    scp.length > 0 &&
    scp.every((item): item is string => typeof item === 'string')
  ) {
    return scp;
  }
  const scope = payload['scope'];
  if (typeof scope === 'string' && scope.length > 0) {
    return scope.split(' ').filter((item) => item.length > 0);
  }
  return [];
}

async function verifyTokenSignature(
  ctx: RunActionCtx,
  component: ComponentApi,
  token: string,
  opts: {issuer: string; audience: string | undefined; jwksMaxAgeMs: number}
): Promise<JWTPayload> {
  const cached = await ctx.runQuery(component.jwks.get, {});
  // A cache older than maxAgeMs is treated as empty and refreshed before the
  // first verify attempt, so a rotated-out key never lingers past its TTL. The
  // refresh-on-unknown-kid retry below still handles rotations within the TTL.
  const stale =
    cached !== null && cached.fetchedAt <= Date.now() - opts.jwksMaxAgeMs;
  let keys: Jwk[] | null =
    cached === null || cached.keys.length === 0 || stale ? null : cached.keys;
  let refreshed = false;
  if (keys === null) {
    keys = await ctx.runAction(component.jwks.refresh, {});
    refreshed = true;
  }
  for (;;) {
    try {
      const verifyOptions: JWTVerifyOptions = {
        issuer: opts.issuer,
        ...(opts.audience === undefined ? {} : {audience: opts.audience})
      };
      const {payload} = await jwtVerify(
        token,
        createLocalJWKSet({keys}),
        verifyOptions
      );
      return payload;
    } catch (error) {
      // Refresh the JWKS cache once if the token's key id is unknown
      // (e.g. after a Kinde key rotation), then retry.
      if (
        joseErrorInfo(error).code === 'ERR_JWKS_NO_MATCHING_KEY' &&
        !refreshed
      ) {
        keys = await ctx.runAction(component.jwks.refresh, {});
        refreshed = true;
        continue;
      }
      throw mapJoseError(error);
    }
  }
}

/**
 * Verify a Kinde M2M access token and resolve the calling agent.
 *
 * Pipeline: verify the JWT signature against the cached Kinde JWKS
 * (refreshing the cache if the key id is unknown) → validate iss/aud/exp →
 * extract `org_code` as a binding contract → map the `azp` client id to a
 * registered agent → consult the revocation overlay (global > org > agent,
 * invariant I2), tenant policy, and agent status → audit the outcome.
 *
 * Throws a `ConvexError` with machine-readable `{code, message}` data on
 * any failure. Every outcome — allow, deny, or unverifiable token — writes
 * one audit row.
 *
 * BEHAVIORAL CHANGE (this release): unregistered callers are now rejected by
 * default. See {@link VerifyCallerOptions.requireRegisteredAgent} — pass
 * `requireRegisteredAgent: false` to restore the previous allow-through.
 *
 * Org-scoped deployments should pass `expectedOrgCode` or at least
 * `requireOrgCode: true` (see {@link VerifyCallerOptions.requireOrgCode});
 * otherwise org revocation and tenant policy gates are silently skipped for
 * org-less tokens.
 *
 * To make an authorization decision for a specific instance, prefer
 * {@link authorize} over calling this and `authz.can` separately — it binds
 * the verified caller to the instance and prevents the confused-deputy class
 * of bug.
 *
 * THIS FUNCTION'S SIGNATURE IS A STABLE CONTRACT (see {@link VerifiedAgent}).
 */
export async function verifyCaller(
  ctx: RunActionCtx,
  component: ComponentApi,
  token: string,
  options: VerifyCallerOptions = {}
): Promise<VerifiedAgent> {
  const config = await ctx.runQuery(component.config.get, {});
  const domain = options.domain ?? config.domain;
  const audience = options.audience ?? config.audience ?? undefined;
  const issuer = `https://${domain}`;

  let payload: JWTPayload;
  try {
    payload = await verifyTokenSignature(ctx, component, token, {
      issuer,
      audience,
      jwksMaxAgeMs: config.jwksMaxAgeMs
    });
  } catch (error) {
    const data = convexErrorData(error);
    if (data !== null) {
      await ctx.runMutation(component.verification.recordRejection, {
        code: data.code,
        reason: data.message
      });
    }
    throw error;
  }

  const orgCodeClaim = payload['org_code'];
  const orgCode = typeof orgCodeClaim === 'string' ? orgCodeClaim : null;
  const azp = typeof payload.azp === 'string' ? payload.azp : null;
  const subject = typeof payload.sub === 'string' ? payload.sub : azp;
  if (subject === null) {
    const error = new ConvexError({
      code: 'missing_subject',
      message: `The token has neither a sub nor an azp claim. Token actually carries these claim keys: [${Object.keys(payload).join(', ')}].`
    });
    await ctx.runMutation(component.verification.recordRejection, {
      code: error.data.code,
      reason: error.data.message
    });
    throw error;
  }
  const scopes = extractScopes(payload);

  const result = await ctx.runMutation(component.verification.check, {
    subject,
    kindeClientId: azp,
    orgCode,
    tokenScopes: scopes,
    requireRegisteredAgent: options.requireRegisteredAgent ?? true,
    requireOrgCode: options.requireOrgCode ?? false,
    ...(options.expectedOrgCode === undefined
      ? {}
      : {expectedOrgCode: options.expectedOrgCode})
  });
  if (!result.allowed) {
    throw new ConvexError({code: result.code, message: result.reason});
  }

  return {
    subject,
    agentId: result.agentId,
    orgCode,
    scopes,
    claims: {...payload}
  };
}
