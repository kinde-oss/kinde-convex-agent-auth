import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

const baseAgent = {
  name: 'Support Bot',
  slug: 'support-bot',
  ownerKind: 'platform' as const,
  kind: 'autonomous' as const,
  allowedTools: ['tickets.read'],
  scopes: ['read:tickets']
};

describe('agents.register', () => {
  test('registers a platform-owned agent and returns its document', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {...baseAgent});
    const agent = await t.query(api.agents.get, {agentId});
    expect(agent).not.toBeNull();
    expect(agent?.slug).toBe('support-bot');
    expect(agent?.ownerKind).toBe('platform');
    expect(agent?.ownerId).toBeNull();
    expect(agent?.orgCode).toBeNull();
    expect(agent?.kindeClientId).toBeNull();
    expect(agent?.status).toBe('active');
    expect(agent?.allowedTools).toEqual(['tickets.read']);
    expect(agent?.scopes).toEqual(['read:tickets']);
    expect(agent?.metadata).toEqual({});
  });

  test('registers a user-owned agent', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {
      ...baseAgent,
      slug: 'user-bot',
      ownerKind: 'user',
      ownerId: 'kp_user_1',
      kind: 'supervised'
    });
    const agent = await t.query(api.agents.get, {agentId});
    expect(agent?.ownerKind).toBe('user');
    expect(agent?.ownerId).toBe('kp_user_1');
    expect(agent?.kind).toBe('supervised');
  });

  test('registers an org-owned agent bound to a Kinde client id', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {
      ...baseAgent,
      slug: 'org-bot',
      ownerKind: 'org',
      orgCode: 'org_123',
      kindeClientId: 'client_abc',
      metadata: {team: 'support'}
    });
    const agent = await t.query(api.agents.get, {agentId});
    expect(agent?.ownerKind).toBe('org');
    expect(agent?.orgCode).toBe('org_123');
    expect(agent?.kindeClientId).toBe('client_abc');
    expect(agent?.metadata).toEqual({team: 'support'});
  });

  test('rejects a user-owned agent without ownerId', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.agents.register, {...baseAgent, ownerKind: 'user'}),
      'owner_id_required'
    );
  });

  test('rejects an org-owned agent without orgCode', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.agents.register, {...baseAgent, ownerKind: 'org'}),
      'org_code_required'
    );
  });

  test('rejects an invalid slug', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.agents.register, {...baseAgent, slug: 'Bad Slug!'}),
      'invalid_slug'
    );
  });

  test('rejects a duplicate slug', async () => {
    const t = initConvexTest();
    await t.mutation(api.agents.register, {...baseAgent});
    await expectFail(
      t.mutation(api.agents.register, {...baseAgent, name: 'Other'}),
      'slug_taken'
    );
  });

  test('rejects a duplicate kindeClientId', async () => {
    const t = initConvexTest();
    await t.mutation(api.agents.register, {
      ...baseAgent,
      kindeClientId: 'client_abc'
    });
    await expectFail(
      t.mutation(api.agents.register, {
        ...baseAgent,
        slug: 'other-bot',
        kindeClientId: 'client_abc'
      }),
      'kinde_client_id_taken'
    );
  });

  test('writes an audit row on registration', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {...baseAgent});
    const rows = await t.run(async (ctx) => {
      return await ctx.db.query('auditLog').collect();
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].eventType).toBe('agent.registered');
    expect(rows[0].agentId).toBe(agentId);
    expect(rows[0].correlationId).not.toBeNull();
  });
});

describe('agents.list', () => {
  test('filters by orgCode and status', async () => {
    const t = initConvexTest();
    await t.mutation(api.agents.register, {
      ...baseAgent,
      slug: 'org-a-bot',
      ownerKind: 'org',
      orgCode: 'org_a'
    });
    const orgBId = await t.mutation(api.agents.register, {
      ...baseAgent,
      slug: 'org-b-bot',
      ownerKind: 'org',
      orgCode: 'org_b'
    });
    await t.mutation(api.agents.register, {...baseAgent, slug: 'global-bot'});
    await t.mutation(api.agents.suspend, {agentId: orgBId});

    const all = await t.query(api.agents.list, {});
    expect(all).toHaveLength(3);

    const orgA = await t.query(api.agents.list, {orgCode: 'org_a'});
    expect(orgA.map((agent) => agent.slug)).toEqual(['org-a-bot']);

    const platform = await t.query(api.agents.list, {orgCode: null});
    expect(platform.map((agent) => agent.slug)).toEqual(['global-bot']);

    const suspended = await t.query(api.agents.list, {status: 'suspended'});
    expect(suspended.map((agent) => agent.slug)).toEqual(['org-b-bot']);

    const orgBActive = await t.query(api.agents.list, {
      orgCode: 'org_b',
      status: 'active'
    });
    expect(orgBActive).toHaveLength(0);
  });
});

describe('agents.suspend / reactivate', () => {
  test('suspends and reactivates an agent, with audit rows', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {...baseAgent});

    await t.mutation(api.agents.suspend, {agentId, reason: 'compromised'});
    let agent = await t.query(api.agents.get, {agentId});
    expect(agent?.status).toBe('suspended');

    // Idempotent: suspending again is a no-op, no extra audit row.
    await t.mutation(api.agents.suspend, {agentId});

    await t.mutation(api.agents.reactivate, {agentId});
    agent = await t.query(api.agents.get, {agentId});
    expect(agent?.status).toBe('active');

    const events = await t.run(async (ctx) => {
      const rows = await ctx.db.query('auditLog').collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toEqual([
      'agent.registered',
      'agent.suspended',
      'agent.reactivated'
    ]);
  });

  test('suspend of a missing agent fails', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {...baseAgent});
    const missingId = await t.run(async (ctx) => {
      await ctx.db.delete('agents', agentId);
      return agentId;
    });
    await expectFail(
      t.mutation(api.agents.suspend, {agentId: missingId}),
      'agent_not_found'
    );
  });
});

describe('agents.setPolicy', () => {
  test('updates allowedTools and scopes', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.agents.register, {...baseAgent});
    await t.mutation(api.agents.setPolicy, {
      agentId,
      allowedTools: ['tickets.read', 'tickets.write'],
      scopes: ['read:tickets', 'write:tickets']
    });
    const agent = await t.query(api.agents.get, {agentId});
    expect(agent?.allowedTools).toEqual(['tickets.read', 'tickets.write']);
    expect(agent?.scopes).toEqual(['read:tickets', 'write:tickets']);

    const events = await t.run(async (ctx) => {
      const rows = await ctx.db.query('auditLog').collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toContain('agent.policy_updated');
  });
});
