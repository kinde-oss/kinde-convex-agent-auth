import {describe, expect, test} from 'vitest';
import type {Id} from './_generated/dataModel.js';
import {api} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

let agentCounter = 0;
// Insert the agent row directly so no `agent.registered` audit row is written,
// keeping the audit log to exactly the rows the test seeds.
async function makeAgent(t: ConvexTest): Promise<Id<'agents'>> {
  agentCounter += 1;
  const slug = `agent-${agentCounter}`;
  return await t.run(
    async (ctx) =>
      await ctx.db.insert('agents', {
        name: slug,
        slug,
        ownerKind: 'platform',
        ownerId: null,
        orgCode: null,
        kindeClientId: null,
        kind: 'autonomous',
        status: 'active',
        allowedTools: [],
        scopes: [],
        metadata: {}
      })
  );
}

interface SeedRow {
  at: number;
  eventType: string;
  agentId?: Id<'agents'> | null;
  orgCode?: string | null;
}

async function seed(t: ConvexTest, rows: SeedRow[]): Promise<void> {
  await t.run(async (ctx) => {
    for (const row of rows) {
      await ctx.db.insert('auditLog', {
        at: row.at,
        eventType: row.eventType,
        agentId: row.agentId ?? null,
        instanceId: null,
        actingFor: null,
        orgCode: row.orgCode ?? null,
        scopesUsed: null,
        decision: null,
        correlationId: `corr-${row.at}`,
        detail: {}
      });
    }
  });
}

async function countAudit(t: ConvexTest): Promise<number> {
  return await t.run(
    async (ctx) => (await ctx.db.query('auditLog').collect()).length
  );
}

const page = {numItems: 100, cursor: null};

describe('audit.query', () => {
  test('no filter returns everything, newest-first', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'a'},
      {at: 300, eventType: 'b'},
      {at: 200, eventType: 'c'}
    ]);
    const result = await t.query(api.audit.query, {paginationOpts: page});
    expect(result.page.map((r) => r.at)).toEqual([300, 200, 100]);
    expect(result.isDone).toBe(true);
  });

  test('agentId filter narrows to one agent (uses by_agent)', async () => {
    const t = initConvexTest();
    const agentA = await makeAgent(t);
    const agentB = await makeAgent(t);
    await seed(t, [
      {at: 100, eventType: 'x', agentId: agentA},
      {at: 200, eventType: 'x', agentId: agentB},
      {at: 300, eventType: 'x', agentId: agentA}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      agentId: agentA
    });
    expect(result.page.map((r) => r.at)).toEqual([300, 100]);
    expect(result.page.every((r) => r.agentId === agentA)).toBe(true);
  });

  test('orgCode filter narrows to one org (uses by_org_code)', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'x', orgCode: 'org_1'},
      {at: 200, eventType: 'x', orgCode: 'org_2'},
      {at: 300, eventType: 'x', orgCode: 'org_1'}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      orgCode: 'org_1'
    });
    expect(result.page.map((r) => r.at)).toEqual([300, 100]);
  });

  test('eventType filter narrows to one type (uses by_event_type)', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'authz.decision'},
      {at: 200, eventType: 'elevation.requested'},
      {at: 300, eventType: 'authz.decision'}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      eventType: 'authz.decision'
    });
    expect(result.page.map((r) => r.at)).toEqual([300, 100]);
  });

  test('combined filters AND together', async () => {
    const t = initConvexTest();
    const agentA = await makeAgent(t);
    const agentB = await makeAgent(t);
    await seed(t, [
      {at: 100, eventType: 'x', agentId: agentA},
      {at: 150, eventType: 'y', agentId: agentA},
      {at: 200, eventType: 'x', agentId: agentB}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      agentId: agentA,
      eventType: 'x'
    });
    expect(result.page.map((r) => r.at)).toEqual([100]);
  });

  test('time range is inclusive on both ends', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'x'},
      {at: 200, eventType: 'x'},
      {at: 300, eventType: 'x'},
      {at: 400, eventType: 'x'}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      startAt: 200,
      endAt: 300
    });
    expect(result.page.map((r) => r.at)).toEqual([300, 200]);
  });

  test('time range combines with an equality filter', async () => {
    const t = initConvexTest();
    const agentA = await makeAgent(t);
    await seed(t, [
      {at: 100, eventType: 'x', agentId: agentA},
      {at: 250, eventType: 'x', agentId: agentA},
      {at: 500, eventType: 'x', agentId: agentA}
    ]);
    const result = await t.query(api.audit.query, {
      paginationOpts: page,
      agentId: agentA,
      startAt: 200,
      endAt: 400
    });
    expect(result.page.map((r) => r.at)).toEqual([250]);
  });

  test('pagination returns a cursor and the next page continues', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'x'},
      {at: 200, eventType: 'x'},
      {at: 300, eventType: 'x'},
      {at: 400, eventType: 'x'},
      {at: 500, eventType: 'x'}
    ]);
    const first = await t.query(api.audit.query, {
      paginationOpts: {numItems: 2, cursor: null}
    });
    expect(first.page.map((r) => r.at)).toEqual([500, 400]);
    expect(first.isDone).toBe(false);
    expect(typeof first.continueCursor).toBe('string');

    const second = await t.query(api.audit.query, {
      paginationOpts: {numItems: 2, cursor: first.continueCursor}
    });
    expect(second.page.map((r) => r.at)).toEqual([300, 200]);
    expect(second.isDone).toBe(false);

    const third = await t.query(api.audit.query, {
      paginationOpts: {numItems: 2, cursor: second.continueCursor}
    });
    expect(third.page.map((r) => r.at)).toEqual([100]);
    expect(third.isDone).toBe(true);
  });

  test('the query performs no writes (I4: read-only)', async () => {
    const t = initConvexTest();
    await seed(t, [
      {at: 100, eventType: 'x'},
      {at: 200, eventType: 'y'}
    ]);
    const before = await countAudit(t);
    await t.query(api.audit.query, {paginationOpts: page});
    await t.query(api.audit.query, {paginationOpts: page, eventType: 'x'});
    const after = await countAudit(t);
    expect(after).toBe(before);
    expect(after).toBe(2);
  });
});
