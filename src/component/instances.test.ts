import {afterEach, beforeEach, describe, expect, test, vi} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

const HOUR = 60 * 60 * 1000;

const orgAgent = {
  name: 'Org Bot',
  slug: 'org-bot',
  ownerKind: 'org' as const,
  orgCode: 'org_123',
  kind: 'autonomous' as const,
  allowedTools: ['tickets.read'],
  scopes: ['read:tickets']
};

async function setup() {
  const t = initConvexTest();
  const agentId = await t.mutation(api.agents.register, {...orgAgent});
  return {t, agentId};
}

describe('instances lifecycle', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('starts an instance and reads it back', async () => {
    const {t, agentId} = await setup();
    const expiresAt = Date.now() + HOUR;
    const instanceId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      actingForSubject: 'kp_user_1',
      orgCode: 'org_123',
      expiresAt
    });
    const instance = await t.query(api.instances.get, {instanceId});
    expect(instance?.status).toBe('running');
    expect(instance?.runId).toBe('run-1');
    expect(instance?.actingForSubject).toBe('kp_user_1');
    expect(instance?.orgCode).toBe('org_123');
    expect(instance?.expiresAt).toBe(expiresAt);
  });

  test('completes a running instance', async () => {
    const {t, agentId} = await setup();
    const instanceId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });
    const status = await t.mutation(api.instances.complete, {instanceId});
    expect(status).toBe('completed');
    const instance = await t.query(api.instances.get, {instanceId});
    expect(instance?.status).toBe('completed');

    await expectFail(
      t.mutation(api.instances.complete, {instanceId}),
      'instance_not_running'
    );
  });

  test('rejects starting for a suspended agent', async () => {
    const {t, agentId} = await setup();
    await t.mutation(api.agents.suspend, {agentId});
    await expectFail(
      t.mutation(api.instances.start, {
        agentId,
        runId: 'run-1',
        orgCode: 'org_123',
        expiresAt: Date.now() + HOUR
      }),
      'agent_suspended'
    );
  });

  test('rejects an orgCode that does not match the agent', async () => {
    const {t, agentId} = await setup();
    await expectFail(
      t.mutation(api.instances.start, {
        agentId,
        runId: 'run-1',
        orgCode: 'org_other',
        expiresAt: Date.now() + HOUR
      }),
      'org_mismatch'
    );
    // Omitting orgCode for an org-bound agent is also a mismatch.
    await expectFail(
      t.mutation(api.instances.start, {
        agentId,
        runId: 'run-2',
        expiresAt: Date.now() + HOUR
      }),
      'org_mismatch'
    );
  });

  test('rejects duplicate runIds and past expiry', async () => {
    const {t, agentId} = await setup();
    await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });
    await expectFail(
      t.mutation(api.instances.start, {
        agentId,
        runId: 'run-1',
        orgCode: 'org_123',
        expiresAt: Date.now() + HOUR
      }),
      'run_id_taken'
    );
    await expectFail(
      t.mutation(api.instances.start, {
        agentId,
        runId: 'run-2',
        orgCode: 'org_123',
        expiresAt: Date.now() - 1
      }),
      'invalid_expiry'
    );
  });

  test('writes audit rows for start and complete', async () => {
    const {t, agentId} = await setup();
    const instanceId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });
    await t.mutation(api.instances.complete, {instanceId});
    const events = await t.run(async (ctx) => {
      const rows = await ctx.db.query('auditLog').collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toEqual([
      'agent.registered',
      'instance.started',
      'instance.completed'
    ]);
  });
});

describe('instance expiry (invariant I5, partial)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('an expired instance reads as "expired" even while stored as running', async () => {
    const {t, agentId} = await setup();
    const instanceId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });

    vi.setSystemTime(new Date('2026-06-10T14:00:00Z'));

    const instance = await t.query(api.instances.get, {instanceId});
    expect(instance?.status).toBe('expired');
    // The stored row is still "running"; only the read is overlaid.
    const stored = await t.run(async (ctx) =>
      ctx.db.get('instances', instanceId)
    );
    expect(stored?.status).toBe('running');
  });

  test('completing an expired instance materializes expiry instead', async () => {
    const {t, agentId} = await setup();
    const instanceId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-1',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });

    vi.setSystemTime(new Date('2026-06-10T14:00:00Z'));

    const status = await t.mutation(api.instances.complete, {instanceId});
    expect(status).toBe('expired');
    const stored = await t.run(async (ctx) =>
      ctx.db.get('instances', instanceId)
    );
    expect(stored?.status).toBe('expired');
    const events = await t.run(async (ctx) => {
      const rows = await ctx.db.query('auditLog').collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toContain('instance.expired');
  });

  test('listActive excludes expired and non-running instances', async () => {
    const {t, agentId} = await setup();
    await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-live',
      orgCode: 'org_123',
      expiresAt: Date.now() + 2 * HOUR
    });
    await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-short',
      orgCode: 'org_123',
      expiresAt: Date.now() + HOUR
    });
    const doneId = await t.mutation(api.instances.start, {
      agentId,
      runId: 'run-done',
      orgCode: 'org_123',
      expiresAt: Date.now() + 2 * HOUR
    });
    await t.mutation(api.instances.complete, {instanceId: doneId});

    vi.setSystemTime(new Date('2026-06-10T13:30:00Z'));

    const active = await t.query(api.instances.listActive, {});
    expect(active.map((row) => row.runId)).toEqual(['run-live']);

    const byAgent = await t.query(api.instances.listActive, {agentId});
    expect(byAgent.map((row) => row.runId)).toEqual(['run-live']);

    const byOrg = await t.query(api.instances.listActive, {
      orgCode: 'org_123'
    });
    expect(byOrg.map((row) => row.runId)).toEqual(['run-live']);

    const otherOrg = await t.query(api.instances.listActive, {
      orgCode: 'org_other'
    });
    expect(otherOrg).toHaveLength(0);
  });
});
