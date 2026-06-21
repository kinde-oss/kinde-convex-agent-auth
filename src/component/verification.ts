import {v} from 'convex/values';
import {mutation} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import {writeAudit} from './helpers.js';
import {nullableString} from './validators.js';

const checkResultValidator = v.union(
  v.object({
    allowed: v.literal(true),
    agentId: v.union(v.id('agents'), v.null()),
    correlationId: v.string()
  }),
  v.object({
    allowed: v.literal(false),
    code: v.string(),
    reason: v.string(),
    correlationId: v.string()
  })
);

interface CheckArgs {
  subject: string;
  kindeClientId: string | null;
  orgCode: string | null;
  tokenScopes: string[];
}

async function findRevocation(
  ctx: MutationCtx,
  targetKind: 'global' | 'org' | 'agent',
  targetId: string | null
) {
  return await ctx.db
    .query('revocations')
    .withIndex('by_target', (q) =>
      q.eq('targetKind', targetKind).eq('targetId', targetId)
    )
    .first();
}

/**
 * The trust checks this component owns for a Kinde-verified caller. The
 * client layer has already verified the JWT cryptographically; this mutation
 * applies the registry, revocation overlay (I2), tenant policy, and org
 * binding (I3) checks, and writes exactly one audit row for the outcome.
 */
export const check = mutation({
  args: {
    subject: v.string(),
    kindeClientId: nullableString,
    orgCode: nullableString,
    tokenScopes: v.array(v.string()),
    expectedOrgCode: v.optional(v.string())
  },
  returns: checkResultValidator,
  handler: async (ctx, args) => {
    const audit = async (
      decision: 'allow' | 'deny',
      agentId: Id<'agents'> | null,
      denial?: {code: string; reason: string}
    ) =>
      writeAudit(ctx, {
        eventType: 'caller.verified',
        agentId,
        orgCode: args.orgCode,
        scopesUsed: args.tokenScopes,
        decision,
        detail: {
          subject: args.subject,
          kindeClientId: args.kindeClientId,
          ...(denial === undefined ? {} : denial)
        }
      });

    const deny = async (
      code: string,
      reason: string,
      agentId: Id<'agents'> | null = null
    ) => ({
      allowed: false as const,
      code,
      reason,
      correlationId: await audit('deny', agentId, {code, reason})
    });

    // Revocation overlay, highest precedence first (invariant I2).
    const globalRevocation = await findRevocation(ctx, 'global', null);
    if (globalRevocation !== null) {
      return await deny('revoked_global', 'All agent access is revoked.');
    }

    // The token's org_code is the only source of tenant context. A caller
    // claiming a different org is rejected and audited (invariant I3).
    if (
      args.expectedOrgCode !== undefined &&
      args.expectedOrgCode !== args.orgCode
    ) {
      return await deny(
        'org_mismatch',
        `The token's org_code ${args.orgCode === null ? 'is absent' : `is "${args.orgCode}"`}, not the expected "${args.expectedOrgCode}".`
      );
    }

    const orgCode = args.orgCode;
    if (orgCode !== null) {
      const orgRevocation = await findRevocation(ctx, 'org', orgCode);
      if (orgRevocation !== null) {
        return await deny(
          'revoked_org',
          `Agent access for org "${orgCode}" is revoked.`
        );
      }
      const tenantPolicy = await ctx.db
        .query('tenantPolicies')
        .withIndex('by_org_code', (q) => q.eq('orgCode', orgCode))
        .unique();
      if (tenantPolicy !== null && tenantPolicy.disabled) {
        return await deny(
          'tenant_disabled',
          `Agents are disabled for org "${orgCode}".`
        );
      }
    }

    let agentId: Id<'agents'> | null = null;
    if (args.kindeClientId !== null) {
      const agent = await ctx.db
        .query('agents')
        .withIndex('by_kinde_client_id', (q) =>
          q.eq('kindeClientId', args.kindeClientId)
        )
        .unique();
      if (agent !== null) {
        if (agent.orgCode !== null && agent.orgCode !== args.orgCode) {
          return await deny(
            'org_mismatch',
            `The agent is bound to org "${agent.orgCode}" but the token's org_code ${args.orgCode === null ? 'is absent' : `is "${args.orgCode}"`}.`,
            agent._id
          );
        }
        if (agent.status !== 'active') {
          return await deny(
            'agent_suspended',
            'The agent is suspended.',
            agent._id
          );
        }
        const agentRevocation = await findRevocation(ctx, 'agent', agent._id);
        if (agentRevocation !== null) {
          return await deny(
            'revoked_agent',
            'The agent is revoked.',
            agent._id
          );
        }
        agentId = agent._id;
      }
    }

    return {
      allowed: true as const,
      agentId,
      correlationId: await audit('allow', agentId)
    };
  }
});

/**
 * Audit a token that failed cryptographic or claim validation before any
 * trusted identity could be established.
 */
export const recordRejection = mutation({
  args: {code: v.string(), reason: v.string()},
  returns: v.string(),
  handler: async (ctx, args) => {
    return await writeAudit(ctx, {
      eventType: 'caller.rejected',
      decision: 'deny',
      detail: {code: args.code, reason: args.reason}
    });
  }
});
