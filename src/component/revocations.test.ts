import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

describe('revocations', () => {
  test('revoke and check at each level, with precedence', async () => {
    const t = initConvexTest();
    await t.mutation(api.revocations.revoke, {
      targetKind: 'instance',
      targetId: 'instance-1',
      reason: 'runaway'
    });
    await t.mutation(api.revocations.revoke, {
      targetKind: 'agent',
      targetId: 'agent-1'
    });
    await t.mutation(api.revocations.revoke, {
      targetKind: 'org',
      targetId: 'org_123'
    });

    // Each level matches on its own.
    const byInstance = await t.query(api.revocations.check, {
      instanceId: 'instance-1'
    });
    expect(byInstance?.targetKind).toBe('instance');
    const byAgent = await t.query(api.revocations.check, {
      agentId: 'agent-1'
    });
    expect(byAgent?.targetKind).toBe('agent');
    const byOrg = await t.query(api.revocations.check, {orgCode: 'org_123'});
    expect(byOrg?.targetKind).toBe('org');

    // Org beats agent beats instance when several match.
    const combined = await t.query(api.revocations.check, {
      instanceId: 'instance-1',
      agentId: 'agent-1',
      orgCode: 'org_123'
    });
    expect(combined?.targetKind).toBe('org');

    // Global beats everything.
    await t.mutation(api.revocations.revoke, {targetKind: 'global'});
    const global = await t.query(api.revocations.check, {
      instanceId: 'instance-1',
      agentId: 'agent-1',
      orgCode: 'org_123'
    });
    expect(global?.targetKind).toBe('global');

    // Non-matching targets return null.
    await t.mutation(api.revocations.clear, {targetKind: 'global'});
    expect(
      await t.query(api.revocations.check, {agentId: 'agent-other'})
    ).toBeNull();
  });

  test('revoke is idempotent per target', async () => {
    const t = initConvexTest();
    const first = await t.mutation(api.revocations.revoke, {
      targetKind: 'agent',
      targetId: 'agent-1'
    });
    const second = await t.mutation(api.revocations.revoke, {
      targetKind: 'agent',
      targetId: 'agent-1',
      reason: 'again'
    });
    expect(second).toBe(first);
    const rows = await t.run(async (ctx) =>
      ctx.db.query('revocations').collect()
    );
    expect(rows).toHaveLength(1);
  });

  test('non-global revocations require a targetId', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.revocations.revoke, {targetKind: 'agent'}),
      'target_id_required'
    );
    await expectFail(
      t.mutation(api.revocations.clear, {targetKind: 'org'}),
      'target_id_required'
    );
  });

  test('clear removes the revocation and returns the count', async () => {
    const t = initConvexTest();
    await t.mutation(api.revocations.revoke, {
      targetKind: 'org',
      targetId: 'org_123'
    });
    expect(
      await t.mutation(api.revocations.clear, {
        targetKind: 'org',
        targetId: 'org_123'
      })
    ).toBe(1);
    expect(
      await t.query(api.revocations.check, {orgCode: 'org_123'})
    ).toBeNull();
    expect(
      await t.mutation(api.revocations.clear, {
        targetKind: 'org',
        targetId: 'org_123'
      })
    ).toBe(0);
  });

  test('revoke and clear write audit rows', async () => {
    const t = initConvexTest();
    await t.mutation(api.revocations.revoke, {
      targetKind: 'global',
      reason: 'incident'
    });
    await t.mutation(api.revocations.clear, {targetKind: 'global'});
    const events = await t.run(async (ctx) => {
      const rows = await ctx.db.query('auditLog').collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toEqual(['revocation.created', 'revocation.cleared']);
  });
});
