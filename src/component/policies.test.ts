import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

describe('policies', () => {
  test('setTenantPolicy creates then getTenantPolicy reads it back', async () => {
    const t = initConvexTest();
    const id = await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      allowedToolsOverride: ['read'],
      disabled: false
    });
    const policy = await t.query(api.policies.getTenantPolicy, {
      orgCode: 'org_1'
    });
    expect(policy?._id).toBe(id);
    expect(policy).toMatchObject({
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      allowedToolsOverride: ['read'],
      disabled: false
    });
  });

  test('allowedToolsOverride defaults to null when omitted', async () => {
    const t = initConvexTest();
    await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      disabled: false
    });
    const policy = await t.query(api.policies.getTenantPolicy, {
      orgCode: 'org_1'
    });
    expect(policy?.allowedToolsOverride).toBeNull();
  });

  test('upsert is idempotent on orgCode: one row, updated in place', async () => {
    const t = initConvexTest();
    const first = await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      allowedToolsOverride: null,
      disabled: false
    });
    const second = await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: false,
      requireApprovalForAll: true,
      allowedToolsOverride: ['read'],
      disabled: true
    });
    expect(second).toBe(first);
    const rows = await t.run(async (ctx) =>
      ctx.db.query('tenantPolicies').collect()
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      allowAutonomous: false,
      requireApprovalForAll: true,
      allowedToolsOverride: ['read'],
      disabled: true
    });
  });

  test('getTenantPolicy returns null for an unknown org', async () => {
    const t = initConvexTest();
    expect(
      await t.query(api.policies.getTenantPolicy, {orgCode: 'nope'})
    ).toBeNull();
  });
});
