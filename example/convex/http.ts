import {httpRouter} from 'convex/server';
import {createRemoteJWKSet, jwtVerify} from 'jose';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-auth';
import {components} from './_generated/api.js';

const http = httpRouter();

// Default mount: `/agent/verify` and `/agent/elevation/respond`. With no
// authorizeApprover hook, `/agent/elevation/respond` fails closed with 501 — it
// refuses to run rather than let the request body assert who approved. Only the
// hooked mount below can actually resolve elevations.
registerRoutes(http, components.agentAuth);

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
  // 3. Verify the signature and issuer against the tenant's published keys.
  //    jose fetches and caches the JWKS; a forged or wrong-issuer token throws.
  const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));
  const {payload} = await jwtVerify(token, jwks, {issuer});
  // 4. The verified `sub` is the approver identity we can trust.
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('The approver token has no sub claim.');
  }
  return payload.sub;
}

// A second mount demonstrating the supported step-up pattern: the app
// authenticates the human via a verified Kinde user token and supplies the
// approverSubject itself. The header-trusting shortcut is deliberately gone.
registerRoutes(http, components.agentAuth, {
  pathPrefix: '/agent-admin',
  authorizeApprover
});

export default http;
