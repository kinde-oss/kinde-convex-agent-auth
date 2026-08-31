import {httpActionGeneric} from 'convex/server';
import type {FunctionArgs, HttpRouter} from 'convex/server';
import {ConvexError} from 'convex/values';
import type {ComponentApi} from '../component/_generated/component.js';
import {verifyCaller} from './verifyCaller.js';

/**
 * Options for {@link registerRoutes}. ALL request authentication happens in the
 * app's HTTP context — component HTTP actions cannot read `ctx.auth` or the
 * app's environment, so the routes are defined here in client code and mounted
 * by the app (the Twilio component pattern).
 */
export interface RegisterRoutesOptions {
  /** Mount the routes under this prefix. Default `/agent`. */
  pathPrefix?: string;
  /** Kinde domain override passed through to {@link verifyCaller}. */
  domain?: string;
  /** Audience override passed through to {@link verifyCaller}. */
  audience?: string;
  /** If set, `/verify` requires the token's org_code to equal this (I3). */
  expectedOrgCode?: string;
  /**
   * Authenticate the human approving an elevation and return their subject.
   * THE APP IS RESPONSIBLE FOR AUTHENTICATING THE HUMAN. This hook is the sole
   * source of `approverSubject` for `/elevation/respond` — the request body is
   * never trusted for approver identity — so throw to reject the caller. When
   * OMITTED, `/elevation/respond` fails closed with 501: an unauthenticated
   * approval endpoint that lets the request body assert who approved would be an
   * open approval hole, so the route refuses to run rather than default to it.
   */
  authorizeApprover?: (request: Request) => Promise<string>;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {'Content-Type': 'application/json'}
  });
}

function errorInfo(error: unknown): {code: string; message: string} {
  if (error instanceof ConvexError) {
    const data: unknown = error.data;
    if (
      typeof data === 'object' &&
      data !== null &&
      'code' in data &&
      'message' in data
    ) {
      const {code, message} = data as {code: unknown; message: unknown};
      if (typeof code === 'string' && typeof message === 'string') {
        return {code, message};
      }
    }
  }
  return {
    code: 'internal_error',
    message: 'The request could not be processed.'
  };
}

// Failures that mean "authenticated identity established but not permitted" map
// to 403; everything else (bad/expired/forged token) is a 401.
const FORBIDDEN_CODES = new Set([
  'revoked_global',
  'revoked_org',
  'revoked_agent',
  'revoked_instance',
  'agent_suspended',
  'org_mismatch'
]);
function verifyStatus(code: string): number {
  return FORBIDDEN_CODES.has(code) ? 403 : 401;
}

interface RespondBody {
  requestId: string;
  decision: 'approve' | 'deny';
}

// `approverSubject` is intentionally NOT parsed off the body: approver identity
// comes only from the authorizeApprover hook (a verified human session), never
// from attacker-controlled request contents.
function parseRespondBody(value: unknown): RespondBody | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const {requestId, decision} = value as Record<string, unknown>;
  if (typeof requestId !== 'string' || requestId.length === 0) {
    return null;
  }
  if (decision !== 'approve' && decision !== 'deny') {
    return null;
  }
  return {requestId, decision};
}

/**
 * Mount the component's HTTP routes onto the app's router. Call this from the
 * app's `convex/http.ts`:
 *
 * ```ts
 * import {httpRouter} from 'convex/server';
 * import {registerRoutes} from '@kinde-oss/kinde-convex-agent-auth';
 * import {components} from './_generated/api.js';
 *
 * const http = httpRouter();
 * registerRoutes(http, components.agentAuth);
 * export default http;
 * ```
 *
 * It mounts two POST routes (under `opts.pathPrefix`, default `/agent`):
 * - `/verify` — bearer-token introspection for cross-app callers. Returns the
 *   {@link verifyCaller} result as JSON (200), or `{code, message}` with a 401
 *   (bad token) / 403 (revoked, suspended, org mismatch) status.
 * - `/elevation/respond` — a human-approval webhook. Returns 501 unless mounted
 *   with an {@link RegisterRoutesOptions.authorizeApprover} hook that returns
 *   the verified approver subject; the app owns authenticating the human. The
 *   request body is never trusted for approver identity.
 */
export function registerRoutes(
  http: HttpRouter,
  component: ComponentApi,
  opts: RegisterRoutesOptions = {}
): void {
  const prefix = opts.pathPrefix ?? '/agent';
  const verifyOptions = {
    ...(opts.domain === undefined ? {} : {domain: opts.domain}),
    ...(opts.audience === undefined ? {} : {audience: opts.audience}),
    ...(opts.expectedOrgCode === undefined
      ? {}
      : {expectedOrgCode: opts.expectedOrgCode})
  };

  http.route({
    path: `${prefix}/verify`,
    method: 'POST',
    handler: httpActionGeneric(async (ctx, request) => {
      const header = request.headers.get('Authorization') ?? '';
      const token = header.startsWith('Bearer ')
        ? header.slice('Bearer '.length).trim()
        : null;
      if (token === null || token.length === 0) {
        return json(401, {
          code: 'missing_token',
          message: 'An "Authorization: Bearer <token>" header is required.'
        });
      }
      try {
        const verified = await verifyCaller(
          ctx,
          component,
          token,
          verifyOptions
        );
        return json(200, verified);
      } catch (error) {
        const info = errorInfo(error);
        return json(verifyStatus(info.code), info);
      }
    })
  });

  http.route({
    path: `${prefix}/elevation/respond`,
    method: 'POST',
    handler: httpActionGeneric(async (ctx, request) => {
      // Fail closed: without a hook to verify the human, there is no trustworthy
      // source of approver identity, so the route refuses rather than accept one
      // the caller could forge. Checked before the body is even read.
      const authorizeApprover = opts.authorizeApprover;
      if (authorizeApprover === undefined) {
        return json(501, {
          error: 'elevation_respond_requires_authorize_approver',
          message:
            'Mount this route with an authorizeApprover hook that returns the verified approver subject. The request body is never trusted for approver identity.'
        });
      }

      const raw: unknown = await request.json().catch(() => null);
      const body = parseRespondBody(raw);
      if (body === null) {
        return json(400, {
          code: 'invalid_body',
          message: 'Expected JSON {requestId, decision: "approve"|"deny"}.'
        });
      }

      let approverSubject: string;
      try {
        approverSubject = await authorizeApprover(request);
      } catch (error) {
        const info = errorInfo(error);
        return json(403, {
          code:
            info.code === 'internal_error'
              ? 'approver_unauthorized'
              : info.code,
          message: 'The approver could not be authenticated.'
        });
      }

      const requestId = body.requestId as FunctionArgs<
        ComponentApi['elevation']['approve']
      >['requestId'];
      try {
        if (body.decision === 'approve') {
          await ctx.runMutation(component.elevation.approve, {
            requestId,
            approverSubject
          });
        } else {
          await ctx.runMutation(component.elevation.deny, {
            requestId,
            approverSubject
          });
        }
        return json(200, {ok: true, decision: body.decision, approverSubject});
      } catch (error) {
        const info = errorInfo(error);
        // already_resolved is a conflict; everything else here is a bad request.
        return json(info.code === 'already_resolved' ? 409 : 400, info);
      }
    })
  });
}
