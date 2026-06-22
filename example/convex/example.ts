import {action, mutation, query} from './_generated/server.js';
import {components} from './_generated/api.js';
import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
import {paginationOptsValidator} from 'convex/server';
import type {FunctionArgs} from 'convex/server';
import {v} from 'convex/values';

/**
 * The component client. Construct it once with the component reference from the
 * app's generated `components` object, then call its thin wrapper methods (or
 * the component API directly, as the functions below show both styles).
 */
export const agentAuth = new AgentAuth(components.agentAuth);

// Component ids surface in the app as opaque strings; these aliases recover the
// exact branded id types each component function expects, so the wrappers can
// accept plain `v.string()` from the client and pass them through type-safely.
type StartArgs = FunctionArgs<typeof components.agentAuth.instances.start>;
type CanArgs = FunctionArgs<typeof components.agentAuth.authz.can>;
type RequestArgs = FunctionArgs<typeof components.agentAuth.elevation.request>;
type ApproveArgs = FunctionArgs<typeof components.agentAuth.elevation.approve>;
type AuditArgs = FunctionArgs<typeof components.agentAuth.audit.query>;

export const health = query({
  args: {},
  returns: v.string(),
  handler: async () => 'ok'
});

/**
 * Provision an org-scoped agent from a Kinde M2M client_id. The agent is bound
 * to `orgCode` (invariant I3) and matched to verified tokens by `kindeClientId`.
 */
export const provisionAgent = mutation({
  args: {
    name: v.string(),
    slug: v.string(),
    orgCode: v.string(),
    kindeClientId: v.string(),
    allowedTools: v.array(v.string()),
    scopes: v.array(v.string())
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await agentAuth.registerAgent(ctx, {
      name: args.name,
      slug: args.slug,
      ownerKind: 'org',
      orgCode: args.orgCode,
      kindeClientId: args.kindeClientId,
      kind: 'autonomous',
      allowedTools: args.allowedTools,
      scopes: args.scopes
    });
  }
});

/** Start an instance (a single run) for an agent acting for a user subject. */
export const startRun = mutation({
  args: {
    agentId: v.string(),
    runId: v.string(),
    actingForSubject: v.string(),
    orgCode: v.string(),
    ttlMs: v.optional(v.number())
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await agentAuth.startInstance(ctx, {
      agentId: args.agentId as StartArgs['agentId'],
      runId: args.runId,
      actingForSubject: args.actingForSubject,
      orgCode: args.orgCode,
      expiresAt: Date.now() + (args.ttlMs ?? 60 * 60 * 1000)
    });
  }
});

/** Ask whether this run may perform `action` on an optional `resource`. */
export const checkAction = mutation({
  args: {
    instanceId: v.string(),
    action: v.string(),
    resource: v.optional(v.string())
  },
  returns: v.object({
    allowed: v.boolean(),
    reason: v.string(),
    requiredScopes: v.optional(v.array(v.string())),
    correlationId: v.string()
  }),
  handler: async (ctx, args) => {
    return await ctx.runMutation(components.agentAuth.authz.can, {
      instanceId: args.instanceId as CanArgs['instanceId'],
      action: args.action,
      ...(args.resource === undefined ? {} : {resource: args.resource})
    });
  }
});

/** The agent hit a scope wall and files an elevation request for `scopes`. */
export const requestElevation = mutation({
  args: {
    instanceId: v.string(),
    requestedScopes: v.array(v.string()),
    reason: v.string()
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await ctx.runMutation(components.agentAuth.elevation.request, {
      instanceId: args.instanceId as RequestArgs['instanceId'],
      requestedScopes: args.requestedScopes,
      reason: args.reason
    });
  }
});

/**
 * Resolve an elevation request directly (the HTTP webhook in `http.ts` is the
 * other, route-based path). The APP is responsible for authenticating the human
 * before calling this; `approverSubject` is their step-up identity.
 */
export const respondElevation = mutation({
  args: {
    requestId: v.string(),
    decision: v.union(v.literal('approve'), v.literal('deny')),
    approverSubject: v.string()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const requestId = args.requestId as ApproveArgs['requestId'];
    if (args.decision === 'approve') {
      await ctx.runMutation(components.agentAuth.elevation.approve, {
        requestId,
        approverSubject: args.approverSubject
      });
    } else {
      await ctx.runMutation(components.agentAuth.elevation.deny, {
        requestId,
        approverSubject: args.approverSubject
      });
    }
    return null;
  }
});

/** The kill switch: revoke an agent so the next authz check denies it (I2). */
export const revokeAgent = mutation({
  args: {agentId: v.string(), reason: v.optional(v.string())},
  returns: v.string(),
  handler: async (ctx, args) => {
    return await agentAuth.revoke(ctx, {
      targetKind: 'agent',
      targetId: args.agentId,
      ...(args.reason === undefined ? {} : {reason: args.reason})
    });
  }
});

const auditRow = v.object({
  _id: v.string(),
  _creationTime: v.number(),
  at: v.number(),
  eventType: v.string(),
  agentId: v.union(v.string(), v.null()),
  instanceId: v.union(v.string(), v.null()),
  actingFor: v.union(v.string(), v.null()),
  orgCode: v.union(v.string(), v.null()),
  scopesUsed: v.union(v.array(v.string()), v.null()),
  decision: v.union(v.literal('allow'), v.literal('deny'), v.null()),
  correlationId: v.union(v.string(), v.null()),
  detail: v.record(
    v.string(),
    v.union(v.string(), v.number(), v.boolean(), v.null(), v.array(v.string()))
  )
});

/** A paginated, filterable read of the audit trail (read-only, invariant I4). */
export const recentAudit = query({
  args: {
    paginationOpts: paginationOptsValidator,
    agentId: v.optional(v.string()),
    orgCode: v.optional(v.string()),
    eventType: v.optional(v.string())
  },
  returns: v.object({
    page: v.array(auditRow),
    isDone: v.boolean(),
    continueCursor: v.string(),
    splitCursor: v.optional(v.union(v.string(), v.null())),
    pageStatus: v.optional(
      v.union(
        v.literal('SplitRecommended'),
        v.literal('SplitRequired'),
        v.null()
      )
    )
  }),
  handler: async (ctx, args) => {
    return await ctx.runQuery(components.agentAuth.audit.query, {
      paginationOpts: args.paginationOpts,
      ...(args.agentId === undefined
        ? {}
        : {agentId: args.agentId as AuditArgs['agentId']}),
      ...(args.orgCode === undefined ? {} : {orgCode: args.orgCode}),
      ...(args.eventType === undefined ? {} : {eventType: args.eventType})
    });
  }
});

/**
 * Token introspection via the client seam (the `/agent/verify` HTTP route is
 * the other, cross-app path). Returns the resolved identity, dropping the raw
 * claims for a tidy example payload.
 */
export const introspectToken = action({
  args: {token: v.string(), expectedOrgCode: v.optional(v.string())},
  returns: v.object({
    subject: v.string(),
    agentId: v.union(v.string(), v.null()),
    orgCode: v.union(v.string(), v.null()),
    scopes: v.array(v.string())
  }),
  handler: async (ctx, args) => {
    const verified = await agentAuth.verifyCaller(ctx, args.token, {
      ...(args.expectedOrgCode === undefined
        ? {}
        : {expectedOrgCode: args.expectedOrgCode})
    });
    return {
      subject: verified.subject,
      agentId: verified.agentId,
      orgCode: verified.orgCode,
      scopes: verified.scopes
    };
  }
});
