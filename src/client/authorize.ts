import type {FunctionArgs, FunctionReturnType} from 'convex/server';
import type {ComponentApi} from '../component/_generated/component.js';
import {verifyCaller} from './verifyCaller.js';
import type {
  RunActionCtx,
  VerifiedAgent,
  VerifyCallerOptions
} from './verifyCaller.js';

type CanArgs = FunctionArgs<ComponentApi['authz']['can']>;

/** The decision returned by the component's `authz.can` mutation. */
export type CanResult = FunctionReturnType<ComponentApi['authz']['can']>;

export interface AuthorizeOptions extends VerifyCallerOptions {
  /** The instance the action is being authorized for. */
  instanceId: CanArgs['instanceId'];
  /** The action (tool/scope) to authorize. */
  action: string;
  /** Optional resource the action targets, recorded on the audit row. */
  resource?: string;
}

export interface AuthorizeResult {
  /** The verified calling agent. */
  caller: VerifiedAgent;
  /** The authorization decision for `{instanceId, action, resource}`. */
  decision: CanResult;
}

/**
 * Verify a Kinde M2M token AND authorize an action for an instance in one call,
 * binding the verified caller to that instance.
 *
 * HOST APPS SHOULD PREFER THIS over calling {@link verifyCaller} and `authz.can`
 * separately. When an app takes `instanceId` from request input, calling `can`
 * without the caller identity lets an agent authenticated in org A obtain
 * decisions for an org B instance (the confused-deputy bug). `authorize` always
 * threads the verified `agentId`/`orgCode`/`subject` into `can`, so a caller
 * that does not own the instance is denied with `caller_instance_mismatch`.
 *
 * Returns `{caller, decision}` — the {@link VerifiedAgent} and the
 * {@link CanResult}. Throws the same `ConvexError`s as {@link verifyCaller} when
 * the token itself is invalid; an authorization denial is returned as
 * `decision.allowed === false`, not thrown.
 */
export async function authorize(
  ctx: RunActionCtx,
  component: ComponentApi,
  token: string,
  options: AuthorizeOptions
): Promise<AuthorizeResult> {
  const {instanceId, action, resource, ...verifyOptions} = options;
  const caller = await verifyCaller(ctx, component, token, verifyOptions);
  const decision = await ctx.runMutation(component.authz.can, {
    instanceId,
    action,
    ...(resource === undefined ? {} : {resource}),
    callerAgentId: caller.agentId as CanArgs['callerAgentId'],
    callerOrgCode: caller.orgCode,
    callerSubject: caller.subject
  });
  return {caller, decision};
}
