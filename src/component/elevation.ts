import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import schema from './schema.js';
import {
  effectiveElevationStatus,
  effectiveInstanceStatus,
  fail,
  writeAudit
} from './helpers.js';
import {elevationStatusValidator} from './validators.js';

const elevationDoc = schema.tables.elevationRequests.validator.extend({
  _id: v.id('elevationRequests'),
  _creationTime: v.number()
});

/**
 * File an elevation request for an instance that hit a scope wall. The grant
 * defaults to the instance's own `expiresAt` so it can never outlive the run.
 * The instance must exist and still be running.
 */
export const request = mutation({
  args: {
    instanceId: v.id('instances'),
    requestedScopes: v.array(v.string()),
    reason: v.string(),
    expiresAt: v.optional(v.number())
  },
  returns: v.id('elevationRequests'),
  handler: async (ctx, args) => {
    const now = Date.now();
    const instance = await ctx.db.get('instances', args.instanceId);
    if (instance === null) {
      fail('instance_not_found', 'No such instance.');
    }
    if (effectiveInstanceStatus(instance, now) !== 'running') {
      fail(
        'instance_not_active',
        'Cannot request elevation for an instance that is not running.'
      );
    }
    const expiresAt = args.expiresAt ?? instance.expiresAt;
    const requestId = await ctx.db.insert('elevationRequests', {
      instanceId: args.instanceId,
      requestedScopes: args.requestedScopes,
      reason: args.reason,
      status: 'pending',
      approverSubject: null,
      resolvedAt: null,
      expiresAt
    });
    await writeAudit(ctx, {
      eventType: 'elevation.requested',
      agentId: instance.agentId,
      instanceId: args.instanceId,
      actingFor: instance.actingForSubject,
      orgCode: instance.orgCode,
      scopesUsed: args.requestedScopes,
      detail: {reason: args.reason, expiresAt}
    });
    return requestId;
  }
});

/**
 * Approve a pending elevation. `approverSubject` is the step-up identity of the
 * human who approved and is required. Approval records `approvedScopes` (the
 * subset actually granted, currently the whole `requestedScopes`) so an
 * elevation can never authorize an action the approver did not approve. Only a
 * `pending` request can be approved; re-approving fails rather than re-granting
 * (idempotency by rejection).
 */
export const approve = mutation({
  args: {requestId: v.id('elevationRequests'), approverSubject: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    return await resolve(ctx, args, 'approved', 'elevation.approved');
  }
});

/** Deny a pending elevation. Same pending-only and step-up rules as approve. */
export const deny = mutation({
  args: {requestId: v.id('elevationRequests'), approverSubject: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    return await resolve(ctx, args, 'denied', 'elevation.denied');
  }
});

export const getStatus = query({
  args: {requestId: v.id('elevationRequests')},
  returns: v.union(elevationDoc, v.null()),
  handler: async (ctx, args) => {
    const row = await ctx.db.get('elevationRequests', args.requestId);
    if (row === null) {
      return null;
    }
    return {...row, status: effectiveElevationStatus(row, Date.now())};
  }
});

export const listForInstance = query({
  args: {
    instanceId: v.id('instances'),
    status: v.optional(elevationStatusValidator),
    limit: v.optional(v.number())
  },
  returns: v.array(elevationDoc),
  handler: async (ctx, args) => {
    const now = Date.now();
    const limit = Math.min(Math.max(args.limit ?? 100, 1), 200);
    const {instanceId, status} = args;
    const rows =
      status === undefined
        ? await ctx.db
            .query('elevationRequests')
            .withIndex('by_instance', (q) => q.eq('instanceId', instanceId))
            .take(limit)
        : await ctx.db
            .query('elevationRequests')
            .withIndex('by_instance', (q) =>
              q.eq('instanceId', instanceId).eq('status', status)
            )
            .take(limit);
    return rows.map((row) => ({
      ...row,
      status: effectiveElevationStatus(row, now)
    }));
  }
});

async function resolve(
  ctx: MutationCtx,
  args: {requestId: Id<'elevationRequests'>; approverSubject: string},
  status: 'approved' | 'denied',
  eventType: string
): Promise<null> {
  if (args.approverSubject.length === 0) {
    fail(
      'approver_required',
      'approverSubject is required to resolve an elevation.'
    );
  }
  const row = await ctx.db.get('elevationRequests', args.requestId);
  if (row === null) {
    fail('request_not_found', 'No such elevation request.');
  }
  if (row.status !== 'pending') {
    fail(
      'already_resolved',
      `Elevation request is "${row.status}", not "pending".`
    );
  }
  await ctx.db.patch('elevationRequests', args.requestId, {
    status,
    approverSubject: args.approverSubject,
    resolvedAt: Date.now(),
    ...(status === 'approved' ? {approvedScopes: row.requestedScopes} : {})
  });
  const instance = await ctx.db.get('instances', row.instanceId);
  await writeAudit(ctx, {
    eventType,
    agentId: instance?.agentId ?? null,
    instanceId: row.instanceId,
    orgCode: instance?.orgCode ?? null,
    scopesUsed: row.requestedScopes,
    detail: {approverSubject: args.approverSubject}
  });
  return null;
}
