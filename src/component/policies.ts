import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import schema from './schema.js';
import {writeAudit} from './helpers.js';
import {nullableStringArray} from './validators.js';

const tenantPolicyDoc = schema.tables.tenantPolicies.validator.extend({
  _id: v.id('tenantPolicies'),
  _creationTime: v.number()
});

/**
 * Upsert the policy for one Kinde org. Idempotent on `orgCode`: an existing
 * row is patched in place, otherwise a new one is created. Returns the row id.
 */
export const setTenantPolicy = mutation({
  args: {
    orgCode: v.string(),
    allowAutonomous: v.boolean(),
    requireApprovalForAll: v.boolean(),
    allowedToolsOverride: v.optional(nullableStringArray),
    disabled: v.boolean()
  },
  returns: v.id('tenantPolicies'),
  handler: async (ctx, args) => {
    const allowedToolsOverride = args.allowedToolsOverride ?? null;
    const fields = {
      orgCode: args.orgCode,
      allowAutonomous: args.allowAutonomous,
      requireApprovalForAll: args.requireApprovalForAll,
      allowedToolsOverride,
      disabled: args.disabled
    };
    const existing = await ctx.db
      .query('tenantPolicies')
      .withIndex('by_org_code', (q) => q.eq('orgCode', args.orgCode))
      .unique();
    let policyId;
    if (existing !== null) {
      await ctx.db.patch('tenantPolicies', existing._id, fields);
      policyId = existing._id;
    } else {
      policyId = await ctx.db.insert('tenantPolicies', fields);
    }
    await writeAudit(ctx, {
      eventType: 'tenant_policy.set',
      orgCode: args.orgCode,
      detail: {
        allowAutonomous: args.allowAutonomous,
        requireApprovalForAll: args.requireApprovalForAll,
        allowedToolsOverride,
        disabled: args.disabled
      }
    });
    return policyId;
  }
});

export const getTenantPolicy = query({
  args: {orgCode: v.string()},
  returns: v.union(tenantPolicyDoc, v.null()),
  handler: async (ctx, args) => {
    return await ctx.db
      .query('tenantPolicies')
      .withIndex('by_org_code', (q) => q.eq('orgCode', args.orgCode))
      .unique();
  }
});
