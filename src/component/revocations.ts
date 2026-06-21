import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import type {QueryCtx} from './_generated/server.js';
import schema from './schema.js';
import {fail, writeAudit} from './helpers.js';
import {nullableString, revocationTargetKindValidator} from './validators.js';

type TargetKind = Infer<typeof revocationTargetKindValidator>;

const revocationDoc = schema.tables.revocations.validator.extend({
  _id: v.id('revocations'),
  _creationTime: v.number()
});

async function findRevocation(
  ctx: QueryCtx,
  targetKind: TargetKind,
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
 * Revoke at one of four levels. `targetId` is the agent/instance id or the
 * org code; it must be null (or omitted) for "global". Idempotent: an
 * existing identical revocation is returned unchanged.
 */
export const revoke = mutation({
  args: {
    targetKind: revocationTargetKindValidator,
    targetId: v.optional(nullableString),
    reason: v.optional(v.string())
  },
  returns: v.id('revocations'),
  handler: async (ctx, args) => {
    const targetId =
      args.targetKind === 'global' ? null : (args.targetId ?? null);
    if (args.targetKind !== 'global' && targetId === null) {
      fail(
        'target_id_required',
        `targetKind "${args.targetKind}" requires a targetId.`
      );
    }
    const existing = await findRevocation(ctx, args.targetKind, targetId);
    if (existing !== null) {
      return existing._id;
    }
    const revocationId = await ctx.db.insert('revocations', {
      targetKind: args.targetKind,
      targetId,
      reason: args.reason ?? 'unspecified',
      createdAt: Date.now()
    });
    await writeAudit(ctx, {
      eventType: 'revocation.created',
      orgCode: args.targetKind === 'org' ? targetId : null,
      detail: {
        targetKind: args.targetKind,
        targetId,
        reason: args.reason ?? 'unspecified'
      }
    });
    return revocationId;
  }
});

/** Remove revocations for a target. Returns the number removed. */
export const clear = mutation({
  args: {
    targetKind: revocationTargetKindValidator,
    targetId: v.optional(nullableString)
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    const targetId =
      args.targetKind === 'global' ? null : (args.targetId ?? null);
    if (args.targetKind !== 'global' && targetId === null) {
      fail(
        'target_id_required',
        `targetKind "${args.targetKind}" requires a targetId.`
      );
    }
    const rows = await ctx.db
      .query('revocations')
      .withIndex('by_target', (q) =>
        q.eq('targetKind', args.targetKind).eq('targetId', targetId)
      )
      .collect();
    for (const row of rows) {
      await ctx.db.delete('revocations', row._id);
    }
    if (rows.length > 0) {
      await writeAudit(ctx, {
        eventType: 'revocation.cleared',
        orgCode: args.targetKind === 'org' ? targetId : null,
        detail: {
          targetKind: args.targetKind,
          targetId,
          cleared: rows.length
        }
      });
    }
    return rows.length;
  }
});

/**
 * The revocation overlay check (invariant I2). Returns the highest-precedence
 * matching revocation — global > org > agent > instance — or null.
 */
export const check = query({
  args: {
    agentId: v.optional(v.string()),
    instanceId: v.optional(v.string()),
    orgCode: v.optional(v.string())
  },
  returns: v.union(revocationDoc, v.null()),
  handler: async (ctx, args) => {
    const global = await findRevocation(ctx, 'global', null);
    if (global !== null) {
      return global;
    }
    if (args.orgCode !== undefined) {
      const org = await findRevocation(ctx, 'org', args.orgCode);
      if (org !== null) {
        return org;
      }
    }
    if (args.agentId !== undefined) {
      const agent = await findRevocation(ctx, 'agent', args.agentId);
      if (agent !== null) {
        return agent;
      }
    }
    if (args.instanceId !== undefined) {
      const instance = await findRevocation(ctx, 'instance', args.instanceId);
      if (instance !== null) {
        return instance;
      }
    }
    return null;
  }
});
