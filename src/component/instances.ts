import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import schema from './schema.js';
import {effectiveInstanceStatus, fail, writeAudit} from './helpers.js';
import {instanceStatusValidator, nullableString} from './validators.js';

const instanceDoc = schema.tables.instances.validator.extend({
  _id: v.id('instances'),
  _creationTime: v.number()
});

export const start = mutation({
  args: {
    agentId: v.id('agents'),
    runId: v.string(),
    actingForSubject: v.optional(nullableString),
    orgCode: v.optional(nullableString),
    expiresAt: v.number()
  },
  returns: v.id('instances'),
  handler: async (ctx, args) => {
    const now = Date.now();
    const agent = await ctx.db.get('agents', args.agentId);
    if (agent === null) {
      fail('agent_not_found', 'No such agent.');
    }
    if (agent.status !== 'active') {
      fail('agent_suspended', 'Cannot start an instance of a suspended agent.');
    }
    if (args.expiresAt <= now) {
      fail('invalid_expiry', 'expiresAt must be in the future.');
    }
    const actingForSubject = args.actingForSubject ?? null;
    const orgCode = args.orgCode ?? null;
    // Data-level org consistency. The binding of orgCode to the verified
    // token (invariant I3) is enforced in the client layer, which is the only
    // place the token is visible.
    if (agent.orgCode !== null && orgCode !== agent.orgCode) {
      fail(
        'org_mismatch',
        `Instance orgCode "${String(orgCode)}" does not match the agent's orgCode "${agent.orgCode}".`
      );
    }
    const duplicate = await ctx.db
      .query('instances')
      .withIndex('by_run_id', (q) => q.eq('runId', args.runId))
      .unique();
    if (duplicate !== null) {
      fail('run_id_taken', `An instance with runId "${args.runId}" exists.`);
    }
    const instanceId = await ctx.db.insert('instances', {
      agentId: args.agentId,
      runId: args.runId,
      actingForSubject,
      orgCode,
      status: 'running',
      expiresAt: args.expiresAt,
      createdAt: now
    });
    await writeAudit(ctx, {
      eventType: 'instance.started',
      agentId: args.agentId,
      instanceId,
      actingFor: actingForSubject,
      orgCode,
      detail: {runId: args.runId, expiresAt: args.expiresAt}
    });
    return instanceId;
  }
});

export const complete = mutation({
  args: {instanceId: v.id('instances')},
  returns: instanceStatusValidator,
  handler: async (ctx, args) => {
    const instance = await ctx.db.get('instances', args.instanceId);
    if (instance === null) {
      fail('instance_not_found', 'No such instance.');
    }
    if (instance.status !== 'running') {
      fail(
        'instance_not_running',
        `Instance is "${instance.status}", not "running".`
      );
    }
    // An instance past its expiry behaves as revoked (invariant I5): it can
    // no longer complete successfully; we materialize the expiry instead.
    if (instance.expiresAt <= Date.now()) {
      await ctx.db.patch('instances', args.instanceId, {status: 'expired'});
      await writeAudit(ctx, {
        eventType: 'instance.expired',
        agentId: instance.agentId,
        instanceId: args.instanceId,
        actingFor: instance.actingForSubject,
        orgCode: instance.orgCode,
        detail: {runId: instance.runId}
      });
      return 'expired';
    }
    await ctx.db.patch('instances', args.instanceId, {status: 'completed'});
    await writeAudit(ctx, {
      eventType: 'instance.completed',
      agentId: instance.agentId,
      instanceId: args.instanceId,
      actingFor: instance.actingForSubject,
      orgCode: instance.orgCode,
      detail: {runId: instance.runId}
    });
    return 'completed';
  }
});

export const get = query({
  args: {instanceId: v.id('instances')},
  returns: v.union(instanceDoc, v.null()),
  handler: async (ctx, args) => {
    const instance = await ctx.db.get('instances', args.instanceId);
    if (instance === null) {
      return null;
    }
    return {
      ...instance,
      status: effectiveInstanceStatus(instance, Date.now())
    };
  }
});

export const listActive = query({
  args: {
    agentId: v.optional(v.id('agents')),
    orgCode: v.optional(nullableString),
    limit: v.optional(v.number())
  },
  returns: v.array(instanceDoc),
  handler: async (ctx, args) => {
    const now = Date.now();
    const limit = Math.min(Math.max(args.limit ?? 100, 1), 200);
    const {agentId, orgCode} = args;
    if (agentId !== undefined) {
      const rows = await ctx.db
        .query('instances')
        .withIndex('by_agent', (q) =>
          q.eq('agentId', agentId).eq('status', 'running')
        )
        .take(limit);
      return rows.filter((row) => row.expiresAt > now);
    }
    if (orgCode !== undefined) {
      const rows = await ctx.db
        .query('instances')
        .withIndex('by_org_code', (q) =>
          q.eq('orgCode', orgCode).eq('status', 'running')
        )
        .take(limit);
      return rows.filter((row) => row.expiresAt > now);
    }
    return await ctx.db
      .query('instances')
      .withIndex('by_status', (q) =>
        q.eq('status', 'running').gt('expiresAt', now)
      )
      .take(limit);
  }
});
