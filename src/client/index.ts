import type {
  FunctionArgs,
  FunctionReturnType,
  GenericActionCtx,
  GenericDataModel
} from 'convex/server';
import type {ComponentApi} from '../component/_generated/component.js';
import {verifyCaller} from './verifyCaller.js';
import type {VerifyCallerOptions} from './verifyCaller.js';

export {verifyCaller} from './verifyCaller.js';
export type {
  VerifiedAgent,
  VerifyCallerOptions,
  RunActionCtx
} from './verifyCaller.js';
export type {ComponentApi} from '../component/_generated/component.js';

export type RunQueryCtx = Pick<GenericActionCtx<GenericDataModel>, 'runQuery'>;
export type RunMutationCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation'
>;
export type RunFullCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation' | 'runAction'
>;

export type ElevationRequest = NonNullable<
  FunctionReturnType<ComponentApi['elevation']['getStatus']>
>;

export interface WaitForElevationOptions {
  /** How often to re-read the request while it is pending. Default 1000ms. */
  intervalMs?: number;
  /** Give up and return the still-pending row after this long. Default 60s. */
  timeoutMs?: number;
}

/**
 * Wait for an elevation request to leave `pending` (becoming approved, denied,
 * or — via the effective-status overlay — expired), then resolve with the row
 * (or null if it was deleted).
 *
 * This is a convenience wrapper over `elevation.getStatus`. In a real app you
 * usually do NOT need it: the agent's run lives in a reactive context, so a
 * `useQuery`/subscription on the elevation row re-fires the moment a human
 * approves and the run resumes with no polling at all. Use this helper from
 * non-reactive contexts (e.g. a one-shot action) where you must block until a
 * decision is made; it polls `getStatus` on `intervalMs` up to `timeoutMs`.
 */
export async function waitForElevation(
  ctx: RunQueryCtx,
  component: ComponentApi,
  requestId: FunctionArgs<ComponentApi['elevation']['getStatus']>['requestId'],
  opts: WaitForElevationOptions = {}
): Promise<ElevationRequest | null> {
  const intervalMs = opts.intervalMs ?? 1000;
  const deadline = Date.now() + (opts.timeoutMs ?? 60_000);
  for (;;) {
    const row = await ctx.runQuery(component.elevation.getStatus, {requestId});
    if (row === null || row.status !== 'pending') {
      return row;
    }
    if (Date.now() >= deadline) {
      return row;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

export interface AgentAuthOptions {
  /** Kinde domain override. Defaults to the component's KINDE_DOMAIN. */
  domain?: string;
  /** Audience override. Defaults to the component's KINDE_AUDIENCE. */
  audience?: string;
}

/**
 * Client for the Kinde agent auth component.
 *
 * Construct it with the component reference from your app's generated
 * `components` object:
 *
 * ```ts
 * import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
 * import {components} from './_generated/api.js';
 *
 * export const agentAuth = new AgentAuth(components.agentAuth);
 * ```
 */
export class AgentAuth {
  constructor(
    public readonly component: ComponentApi,
    public readonly options: AgentAuthOptions = {}
  ) {}

  // --- Agent registry ---

  registerAgent(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['agents']['register']>
  ) {
    return ctx.runMutation(this.component.agents.register, args);
  }

  getAgent(
    ctx: RunQueryCtx,
    args: FunctionArgs<ComponentApi['agents']['get']>
  ) {
    return ctx.runQuery(this.component.agents.get, args);
  }

  listAgents(
    ctx: RunQueryCtx,
    args: FunctionArgs<ComponentApi['agents']['list']> = {}
  ) {
    return ctx.runQuery(this.component.agents.list, args);
  }

  suspendAgent(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['agents']['suspend']>
  ) {
    return ctx.runMutation(this.component.agents.suspend, args);
  }

  reactivateAgent(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['agents']['reactivate']>
  ) {
    return ctx.runMutation(this.component.agents.reactivate, args);
  }

  setAgentPolicy(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['agents']['setPolicy']>
  ) {
    return ctx.runMutation(this.component.agents.setPolicy, args);
  }

  // --- Instances ---

  startInstance(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['instances']['start']>
  ) {
    return ctx.runMutation(this.component.instances.start, args);
  }

  completeInstance(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['instances']['complete']>
  ) {
    return ctx.runMutation(this.component.instances.complete, args);
  }

  getInstance(
    ctx: RunQueryCtx,
    args: FunctionArgs<ComponentApi['instances']['get']>
  ) {
    return ctx.runQuery(this.component.instances.get, args);
  }

  listActiveInstances(
    ctx: RunQueryCtx,
    args: FunctionArgs<ComponentApi['instances']['listActive']> = {}
  ) {
    return ctx.runQuery(this.component.instances.listActive, args);
  }

  // --- Revocations (the kill switch) ---

  revoke(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['revocations']['revoke']>
  ) {
    return ctx.runMutation(this.component.revocations.revoke, args);
  }

  clearRevocation(
    ctx: RunMutationCtx,
    args: FunctionArgs<ComponentApi['revocations']['clear']>
  ) {
    return ctx.runMutation(this.component.revocations.clear, args);
  }

  checkRevoked(
    ctx: RunQueryCtx,
    args: FunctionArgs<ComponentApi['revocations']['check']> = {}
  ) {
    return ctx.runQuery(this.component.revocations.check, args);
  }

  // --- JWKS / config ---

  getJwks(ctx: RunQueryCtx) {
    return ctx.runQuery(this.component.jwks.get, {});
  }

  refreshJwks(ctx: RunFullCtx) {
    return ctx.runAction(this.component.jwks.refresh, {});
  }

  getConfig(ctx: RunQueryCtx) {
    return ctx.runQuery(this.component.config.get, {});
  }

  // --- Verification ---

  /** See {@link verifyCaller} — the stable verification seam. */
  verifyCaller(
    ctx: RunFullCtx,
    token: string,
    options: VerifyCallerOptions = {}
  ) {
    return verifyCaller(ctx, this.component, token, {
      ...this.options,
      ...options
    });
  }
}
