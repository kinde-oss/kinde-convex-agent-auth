import {describe, expect, test} from 'vitest';
import type {Id} from './_generated/dataModel.js';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

const HOUR = 60 * 60 * 1000;
type ConvexTest = ReturnType<typeof initConvexTest>;

let runCounter = 0;
async function startInstance(t: ConvexTest): Promise<Id<'instances'>> {
  const agentId = await t.mutation(api.agents.register, {
    name: `bot-${runCounter}`,
    slug: `bot-${runCounter}`,
    ownerKind: 'platform',
    kind: 'autonomous',
    allowedTools: [],
    scopes: ['read']
  });
  runCounter += 1;
  return await t.mutation(api.instances.start, {
    agentId,
    runId: `run-${runCounter}`,
    expiresAt: Date.now() + HOUR
  });
}

async function eventTypes(t: ConvexTest, prefix: string) {
  return await t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect())
      .map((row) => row.eventType)
      .filter((type) => type.startsWith(prefix))
  );
}

describe('elevation', () => {
  test('request creates a pending row defaulting to the instance expiry', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need to file the ticket'
    });
    const row = await t.query(api.elevation.getStatus, {requestId});
    expect(row).toMatchObject({
      status: 'pending',
      requestedScopes: ['write'],
      approverSubject: null,
      resolvedAt: null
    });
    const instance = await t.query(api.instances.get, {instanceId});
    expect(row?.expiresAt).toBe(instance?.expiresAt);
  });

  test('request fails for a missing or non-running instance', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    await t.mutation(api.instances.complete, {instanceId});
    await expectFail(
      t.mutation(api.elevation.request, {
        instanceId,
        requestedScopes: ['write'],
        reason: 'too late'
      }),
      'instance_not_active'
    );
  });

  test('approve flips to approved and records the step-up approver', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    const row = await t.query(api.elevation.getStatus, {requestId});
    expect(row).toMatchObject({
      status: 'approved',
      approverSubject: 'human_admin'
    });
    expect(row?.resolvedAt).not.toBeNull();
  });

  test('approve records approvedScopes equal to requestedScopes; deny does not', async () => {
    const t = initConvexTest();
    const i1 = await startInstance(t);
    const approved = await t.mutation(api.elevation.request, {
      instanceId: i1,
      requestedScopes: ['write', 'read'],
      reason: 'r'
    });
    await t.mutation(api.elevation.approve, {
      requestId: approved,
      approverSubject: 'human_admin'
    });
    const approvedRow = await t.run(async (ctx) =>
      ctx.db.get('elevationRequests', approved)
    );
    expect(approvedRow?.approvedScopes).toEqual(['write', 'read']);

    const i2 = await startInstance(t);
    const denied = await t.mutation(api.elevation.request, {
      instanceId: i2,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.deny, {
      requestId: denied,
      approverSubject: 'human_admin'
    });
    const deniedRow = await t.run(async (ctx) =>
      ctx.db.get('elevationRequests', denied)
    );
    expect(deniedRow?.approvedScopes).toBeUndefined();
  });

  test('deny flips to denied and records the approver', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.deny, {
      requestId,
      approverSubject: 'human_admin'
    });
    const row = await t.query(api.elevation.getStatus, {requestId});
    expect(row).toMatchObject({
      status: 'denied',
      approverSubject: 'human_admin'
    });
  });

  test('step-up: an empty approverSubject is rejected', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await expectFail(
      t.mutation(api.elevation.approve, {requestId, approverSubject: ''}),
      'approver_required'
    );
  });

  test('only a pending request can be resolved (idempotency by rejection)', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    await expectFail(
      t.mutation(api.elevation.approve, {
        requestId,
        approverSubject: 'human_admin'
      }),
      'already_resolved'
    );
    await expectFail(
      t.mutation(api.elevation.deny, {requestId, approverSubject: 'human2'}),
      'already_resolved'
    );
  });

  test('getStatus returns null for an unknown id', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.run(async (ctx) => ctx.db.delete('elevationRequests', requestId));
    expect(await t.query(api.elevation.getStatus, {requestId})).toBeNull();
  });

  test('listForInstance lists and filters by status', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const a = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'a'
    });
    await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['delete'],
      reason: 'b'
    });
    await t.mutation(api.elevation.approve, {
      requestId: a,
      approverSubject: 'human_admin'
    });

    const all = await t.query(api.elevation.listForInstance, {instanceId});
    expect(all).toHaveLength(2);
    const pending = await t.query(api.elevation.listForInstance, {
      instanceId,
      status: 'pending'
    });
    expect(pending).toHaveLength(1);
    expect(pending[0].reason).toBe('b');
  });

  test('getStatus reflects effective expiry without mutating the row (I6)', async () => {
    const t = initConvexTest();
    const instanceId = await startInstance(t);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    await t.run(async (ctx) =>
      ctx.db.patch('elevationRequests', requestId, {
        expiresAt: Date.now() - 1000
      })
    );
    const row = await t.query(api.elevation.getStatus, {requestId});
    expect(row?.status).toBe('expired');
    // Stored status is untouched.
    const stored = await t.run(async (ctx) =>
      ctx.db.get('elevationRequests', requestId)
    );
    expect(stored?.status).toBe('approved');
  });

  test('I4: request/approve/deny each write exactly one audit row', async () => {
    const t = initConvexTest();
    const i1 = await startInstance(t);
    const r1 = await t.mutation(api.elevation.request, {
      instanceId: i1,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.approve, {
      requestId: r1,
      approverSubject: 'human_admin'
    });
    const i2 = await startInstance(t);
    const r2 = await t.mutation(api.elevation.request, {
      instanceId: i2,
      requestedScopes: ['write'],
      reason: 'r'
    });
    await t.mutation(api.elevation.deny, {
      requestId: r2,
      approverSubject: 'human_admin'
    });

    expect(await eventTypes(t, 'elevation.')).toEqual([
      'elevation.requested',
      'elevation.approved',
      'elevation.requested',
      'elevation.denied'
    ]);
    const approved = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (row) => row.eventType === 'elevation.approved'
      )
    );
    expect(approved).toHaveLength(1);
    expect(approved[0].detail).toMatchObject({approverSubject: 'human_admin'});
  });
});
