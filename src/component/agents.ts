import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import schema from './schema.js';
import {fail, writeAudit} from './helpers.js';
import {
  agentKindValidator,
  agentStatusValidator,
  metadataValidator,
  nullableString,
  ownerKindValidator
} from './validators.js';

const agentDoc = schema.tables.agents.validator.extend({
  _id: v.id('agents'),
  _creationTime: v.number()
});

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

export const register = mutation({
  args: {
    name: v.string(),
    slug: v.string(),
    ownerKind: ownerKindValidator,
    ownerId: v.optional(nullableString),
    orgCode: v.optional(nullableString),
    kindeClientId: v.optional(nullableString),
    kind: agentKindValidator,
    allowedTools: v.array(v.string()),
    scopes: v.array(v.string()),
    metadata: v.optional(metadataValidator)
  },
  returns: v.id('agents'),
  handler: async (ctx, args) => {
    if (!SLUG_PATTERN.test(args.slug)) {
      fail(
        'invalid_slug',
        `Slug "${args.slug}" must be lowercase alphanumeric with hyphens.`
      );
    }
    const ownerId = args.ownerId ?? null;
    const orgCode = args.orgCode ?? null;
    const kindeClientId = args.kindeClientId ?? null;
    if (args.ownerKind === 'user' && ownerId === null) {
      fail('owner_id_required', 'ownerKind "user" requires an ownerId.');
    }
    if (args.ownerKind === 'org' && orgCode === null) {
      fail('org_code_required', 'ownerKind "org" requires an orgCode.');
    }
    const existing = await ctx.db
      .query('agents')
      .withIndex('by_slug', (q) => q.eq('slug', args.slug))
      .unique();
    if (existing !== null) {
      fail('slug_taken', `An agent with slug "${args.slug}" already exists.`);
    }
    if (kindeClientId !== null) {
      const duplicate = await ctx.db
        .query('agents')
        .withIndex('by_kinde_client_id', (q) =>
          q.eq('kindeClientId', kindeClientId)
        )
        .unique();
      if (duplicate !== null) {
        fail(
          'kinde_client_id_taken',
          `An agent is already registered for Kinde client id "${kindeClientId}".`
        );
      }
    }
    const agentId = await ctx.db.insert('agents', {
      name: args.name,
      slug: args.slug,
      ownerKind: args.ownerKind,
      ownerId,
      orgCode,
      kindeClientId,
      kind: args.kind,
      status: 'active',
      allowedTools: args.allowedTools,
      scopes: args.scopes,
      metadata: args.metadata ?? {}
    });
    await writeAudit(ctx, {
      eventType: 'agent.registered',
      agentId,
      orgCode,
      detail: {slug: args.slug, ownerKind: args.ownerKind, kind: args.kind}
    });
    return agentId;
  }
});

export const get = query({
  args: {agentId: v.id('agents')},
  returns: v.union(agentDoc, v.null()),
  handler: async (ctx, args) => {
    return await ctx.db.get('agents', args.agentId);
  }
});

export const list = query({
  args: {
    orgCode: v.optional(nullableString),
    status: v.optional(agentStatusValidator),
    limit: v.optional(v.number())
  },
  returns: v.array(agentDoc),
  handler: async (ctx, args) => {
    const limit = Math.min(Math.max(args.limit ?? 100, 1), 200);
    const {orgCode, status} = args;
    if (orgCode !== undefined && status !== undefined) {
      return await ctx.db
        .query('agents')
        .withIndex('by_org_code', (q) =>
          q.eq('orgCode', orgCode).eq('status', status)
        )
        .take(limit);
    }
    if (orgCode !== undefined) {
      return await ctx.db
        .query('agents')
        .withIndex('by_org_code', (q) => q.eq('orgCode', orgCode))
        .take(limit);
    }
    const all = await ctx.db.query('agents').take(limit);
    return status === undefined
      ? all
      : all.filter((agent) => agent.status === status);
  }
});

export const suspend = mutation({
  args: {agentId: v.id('agents'), reason: v.optional(v.string())},
  returns: v.null(),
  handler: async (ctx, args) => {
    const agent = await ctx.db.get('agents', args.agentId);
    if (agent === null) {
      fail('agent_not_found', 'No such agent.');
    }
    if (agent.status === 'suspended') {
      return null;
    }
    await ctx.db.patch('agents', args.agentId, {status: 'suspended'});
    await writeAudit(ctx, {
      eventType: 'agent.suspended',
      agentId: args.agentId,
      orgCode: agent.orgCode,
      detail: {reason: args.reason ?? null}
    });
    return null;
  }
});

export const reactivate = mutation({
  args: {agentId: v.id('agents')},
  returns: v.null(),
  handler: async (ctx, args) => {
    const agent = await ctx.db.get('agents', args.agentId);
    if (agent === null) {
      fail('agent_not_found', 'No such agent.');
    }
    if (agent.status === 'active') {
      return null;
    }
    await ctx.db.patch('agents', args.agentId, {status: 'active'});
    await writeAudit(ctx, {
      eventType: 'agent.reactivated',
      agentId: args.agentId,
      orgCode: agent.orgCode
    });
    return null;
  }
});

export const setPolicy = mutation({
  args: {
    agentId: v.id('agents'),
    allowedTools: v.array(v.string()),
    scopes: v.array(v.string())
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const agent = await ctx.db.get('agents', args.agentId);
    if (agent === null) {
      fail('agent_not_found', 'No such agent.');
    }
    await ctx.db.patch('agents', args.agentId, {
      allowedTools: args.allowedTools,
      scopes: args.scopes
    });
    await writeAudit(ctx, {
      eventType: 'agent.policy_updated',
      agentId: args.agentId,
      orgCode: agent.orgCode,
      detail: {allowedTools: args.allowedTools, scopes: args.scopes}
    });
    return null;
  }
});
