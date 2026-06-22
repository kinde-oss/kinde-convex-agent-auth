import {v} from 'convex/values';
import {mutation} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import type {Doc, Id} from './_generated/dataModel.js';
import {effectiveInstanceStatus, writeAudit} from './helpers.js';
import {findActiveRevocation} from './revocations.js';
import {intersectScopes} from './scopes.js';

const canResultValidator = v.object({
  allowed: v.boolean(),
  reason: v.string(),
  requiredScopes: v.optional(v.array(v.string())),
  correlationId: v.string()
});

/** Maps a revocation's target level to its stable deny code (invariant I2). */
const REVOKED_CODE = {
  global: 'revoked_global',
  org: 'revoked_org',
  agent: 'revoked_agent',
  instance: 'revoked_instance'
} as const;

/**
 * Find a usable delegation for this agent + acting-for subject: not revoked and
 * not yet expired. Returns the first match, or null if the subject is anonymous
 * or no active delegation exists.
 */
async function findActiveDelegation(
  ctx: MutationCtx,
  agentId: Id<'agents'>,
  actingForSubject: string | null,
  now: number
): Promise<Doc<'delegations'> | null> {
  if (actingForSubject === null) {
    return null;
  }
  const candidates = await ctx.db
    .query('delegations')
    .withIndex('by_agent', (q) => q.eq('agentId', agentId))
    .collect();
  for (const delegation of candidates) {
    if (
      delegation.issuerSubject === actingForSubject &&
      delegation.revokedAt === null &&
      delegation.expiresAt > now
    ) {
      return delegation;
    }
  }
  return null;
}

/**
 * The authorization decision pipeline. Deny short-circuits at the first failed
 * gate; every path — allow or deny — writes exactly one `authz.decision` audit
 * row carrying the correlationId returned to the caller (invariant I4). The
 * `reason` is always a stable, machine-readable code.
 */
export const can = mutation({
  args: {
    instanceId: v.id('instances'),
    action: v.string(),
    resource: v.optional(v.string())
  },
  returns: canResultValidator,
  handler: async (ctx, args) => {
    const now = Date.now();
    const resource = args.resource ?? null;

    // One audit row per decision (I4). All exits funnel through here.
    const decide = async (
      allowed: boolean,
      reason: string,
      context: {
        agentId?: Id<'agents'> | null;
        orgCode?: string | null;
        scopesUsed?: string[] | null;
        requiredScopes?: string[];
      } = {}
    ) => {
      const correlationId = await writeAudit(ctx, {
        eventType: 'authz.decision',
        agentId: context.agentId ?? null,
        instanceId: args.instanceId,
        orgCode: context.orgCode ?? null,
        scopesUsed: context.scopesUsed ?? null,
        decision: allowed ? 'allow' : 'deny',
        detail: {action: args.action, resource, reason}
      });
      return {
        allowed,
        reason,
        ...(context.requiredScopes === undefined
          ? {}
          : {requiredScopes: context.requiredScopes}),
        correlationId
      };
    };

    // 1. The instance must exist.
    const instance = await ctx.db.get('instances', args.instanceId);
    if (instance === null) {
      return await decide(false, 'instance_not_found');
    }
    const orgCode = instance.orgCode;

    // 2. The instance must still be running (expired behaves as revoked — I5).
    if (effectiveInstanceStatus(instance, now) !== 'running') {
      return await decide(false, 'instance_not_active', {
        agentId: instance.agentId,
        orgCode
      });
    }

    // 3. Revocation overlay, highest precedence first (I2).
    const revocation = await findActiveRevocation(ctx, {
      agentId: instance.agentId,
      instanceId: args.instanceId,
      orgCode: orgCode ?? undefined
    });
    if (revocation !== null) {
      return await decide(false, REVOKED_CODE[revocation.targetKind], {
        agentId: instance.agentId,
        orgCode
      });
    }

    // 4. The agent must exist and be active.
    const agent = await ctx.db.get('agents', instance.agentId);
    if (agent === null) {
      return await decide(false, 'agent_not_found', {
        agentId: instance.agentId,
        orgCode
      });
    }
    if (agent.status !== 'active') {
      return await decide(false, 'agent_suspended', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }

    // 5. Tenant policy gates.
    const tenantPolicy =
      orgCode === null
        ? null
        : await ctx.db
            .query('tenantPolicies')
            .withIndex('by_org_code', (q) => q.eq('orgCode', orgCode))
            .unique();
    if (tenantPolicy !== null && tenantPolicy.disabled) {
      return await decide(false, 'tenant_disabled', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }
    if (tenantPolicy !== null && tenantPolicy.requireApprovalForAll) {
      return await decide(false, 'approval_required', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }
    const override = tenantPolicy?.allowedToolsOverride ?? null;

    // 6. Delegation-optional rule: compute the effective scope set (I1).
    const delegation = await findActiveDelegation(
      ctx,
      agent._id,
      instance.actingForSubject,
      now
    );
    let effective: string[];
    if (delegation !== null) {
      effective = intersectScopes(agent.scopes, delegation.scopes, override);
    } else if (agent.kind === 'autonomous') {
      if (tenantPolicy !== null && !tenantPolicy.allowAutonomous) {
        return await decide(false, 'autonomous_not_allowed', {
          agentId: agent._id,
          orgCode,
          scopesUsed: agent.scopes
        });
      }
      effective = intersectScopes(agent.scopes, agent.scopes, override);
    } else {
      return await decide(false, 'delegation_required', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }

    // 7. Tool gate, then scope gate.
    if (
      agent.allowedTools.length > 0 &&
      !agent.allowedTools.includes(args.action)
    ) {
      return await decide(false, 'tool_not_allowed', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective
      });
    }
    if (!effective.includes(args.action)) {
      return await decide(false, 'insufficient_scope', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective,
        requiredScopes: [args.action]
      });
    }

    // 8. Authorized.
    return await decide(true, 'authorized', {
      agentId: agent._id,
      orgCode,
      scopesUsed: effective
    });
  }
});
