import {httpRouter} from 'convex/server';
import {createRemoteJWKSet, jwtVerify} from 'jose';
import type {JWTPayload, JWTVerifyOptions} from 'jose';
import {ConvexError} from 'convex/values';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-auth';
import {components} from './_generated/api.js';

const http = httpRouter();

// Default mount: `/agent/verify` and `/agent/elevation/respond`. With no
// authorizeApprover hook, `/agent/elevation/respond` fails closed with 501 — it
// refuses to run rather than let the request body assert who approved. Only the
// hooked mount below can actually resolve elevations.
registerRoutes(http, components.agentAuth);

/**
 * Resolve the mode the app is running in, mirroring the component's `MODE`
 * handling in `config.get`: unset means "live", so the audience gate below
 * fails closed by default rather than by configuration.
 */
function requireMode(): 'test' | 'live' {
  const mode = process.env.MODE;
  if (mode === undefined || mode === 'live') {
    return 'live';
  }
  if (mode === 'test') {
    return 'test';
  }
  throw new ConvexError({
    code: 'invalid_mode',
    message: 'MODE must be either "test" or "live".'
  });
}

/**
 * The expected `aud` claim for approver tokens, applying the SAME rule the
 * component applies to agent tokens in `config.get`. The hook has no Convex
 * ctx and so cannot read the component's config; it reads the same
 * `KINDE_AUDIENCE` env var the app already hands the component in
 * `convex.config.ts`.
 *
 * In live mode the audience is mandatory: without it jose skips the `aud`
 * check, so ANY valid JWT from this Kinde tenant would authenticate an
 * approver — including a token minted for a different API, or an agent's own
 * M2M token being replayed to approve that agent's elevation request. Test
 * mode legitimately omits it, exactly as on the component.
 */
function requireAudience(): string | undefined {
  const audience = process.env.KINDE_AUDIENCE;
  if (requireMode() === 'live' && audience === undefined) {
    throw new ConvexError({
      code: 'kinde_audience_required_in_live',
      message:
        'KINDE_AUDIENCE must be set in live mode; without it any valid JWT from this Kinde tenant verifies regardless of audience, enabling cross-audience token replay.'
    });
  }
  return audience;
}

/**
 * Whether jose rejected the token on its `aud` claim. Both a wrong audience
 * and a missing one surface as the same claim validation failure, exactly as
 * they do inside the component's client layer.
 */
function isAudienceFailure(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const {code, claim} = error as {code?: unknown; claim?: unknown};
  return code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && claim === 'aud';
}

/**
 * Authenticate the human approver from a REAL Kinde user access token in the
 * Authorization header, and return their verified `sub`. This is the identity
 * `/agent-admin/elevation/respond` records as the approver — the request body
 * is never trusted for it.
 *
 * The hook has no Convex ctx, so it verifies the token against the tenant JWKS
 * directly with jose (already a dependency of the auth flow). In a production
 * app you would also confirm the subject is actually an authorized approver
 * (e.g. an org admin) before returning it.
 */
async function authorizeApprover(request: Request): Promise<string> {
  // 1. Pull the bearer token — an admin's Kinde USER access token, not an M2M
  //    token and never a value copied out of the request body.
  const header = request.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ')
    ? header.slice('Bearer '.length).trim()
    : '';
  if (token === '') {
    throw new Error('Missing approver bearer token.');
  }
  // 2. Resolve the app's own Kinde domain (the app configures this separately
  //    from the component) and build the issuer + JWKS endpoint from it.
  const domain = process.env.KINDE_DOMAIN;
  if (!domain) {
    throw new Error('KINDE_DOMAIN is not configured for the app.');
  }
  const issuer = `https://${domain}`;
  // 3. Resolve the expected audience under the component's rule — required in
  //    live mode, so a missing KINDE_AUDIENCE fails the request rather than
  //    silently dropping the `aud` check.
  const audience = requireAudience();
  // 4. Verify the signature, issuer AND audience against the tenant's published
  //    keys. jose fetches and caches the JWKS; a forged, wrong-issuer,
  //    wrong-audience or audience-less token throws.
  const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));
  const verifyOptions: JWTVerifyOptions = {
    issuer,
    ...(audience === undefined ? {} : {audience})
  };
  let payload: JWTPayload;
  try {
    ({payload} = await jwtVerify(token, jwks, verifyOptions));
  } catch (error) {
    // Report an audience rejection under the same `invalid_audience` code the
    // component's client layer uses, so both token paths in this app fail
    // identically. Every other verification failure is rethrown untouched.
    if (isAudienceFailure(error)) {
      throw new ConvexError({
        code: 'invalid_audience',
        message: 'The token audience does not match the configured audience.'
      });
    }
    throw error;
  }
  // 5. The verified `sub` is the approver identity we can trust.
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('The approver token has no sub claim.');
  }
  return payload.sub;
}

// A second mount demonstrating the supported step-up pattern: the app
// authenticates the human via a Kinde user token whose signature, issuer AND
// audience it verifies, then supplies the approverSubject itself. The
// header-trusting shortcut is deliberately gone.
registerRoutes(http, components.agentAuth, {
  pathPrefix: '/agent-admin',
  authorizeApprover
});

export default http;
