import {afterEach, beforeEach, describe, expect, test, vi} from 'vitest';
import type {Id} from './_generated/dataModel.js';
import {api} from './_generated/api.js';
import {signDelegation} from './delegations.js';
import {expectFail, initConvexTest} from './setup.test.js';

const SECRET = 'test-delegation-secret';
const HOUR = 60 * 60 * 1000;

type ConvexTest = ReturnType<typeof initConvexTest>;

async function registerAgent(t: ConvexTest): Promise<Id<'agents'>> {
  return await t.mutation(api.agents.register, {
    name: 'Reporter',
    slug: 'reporter',
    ownerKind: 'platform',
    kind: 'autonomous',
    allowedTools: ['read'],
    scopes: ['read', 'write']
  });
}

describe('delegations', () => {
  beforeEach(() => {
    vi.stubEnv('DELEGATION_SIGNING_SECRET', SECRET);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('issue signs a delegation that verify and get can read back', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      resources: ['doc:1'],
      expiresAt: Date.now() + HOUR
    });

    const stored = await t.query(api.delegations.get, {delegationId});
    expect(stored?.issuerSubject).toBe('user_alice');
    expect(stored?.revokedAt).toBeNull();
    expect(stored?.signature).toMatch(/^[0-9a-f]{64}$/);

    expect(await t.query(api.delegations.verify, {delegationId})).toEqual({
      valid: true
    });
  });

  test('issue rejects a non-future expiry', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    await expectFail(
      t.mutation(api.delegations.issue, {
        agentId,
        issuerSubject: 'user_alice',
        issuerKind: 'user',
        scopes: ['read'],
        expiresAt: Date.now() - 1
      }),
      'invalid_expiry'
    );
  });

  test('issue rejects an unknown agent', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    // Delete it so the id is well-formed but dangling.
    await t.run(async (ctx) => ctx.db.delete('agents', agentId));
    await expectFail(
      t.mutation(api.delegations.issue, {
        agentId,
        issuerSubject: 'user_alice',
        issuerKind: 'user',
        scopes: ['read'],
        expiresAt: Date.now() + HOUR
      }),
      'agent_not_found'
    );
  });

  test('I5: an expired delegation verifies as invalid', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    // A genuinely-signed delegation whose expiry is in the past. Signing it
    // here (rather than mutating a fresh row) keeps the signature valid so the
    // failure is attributable to expiry, not tampering.
    const core = {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user' as const,
      scopes: ['read'],
      resources: null,
      expiresAt: Date.now() - HOUR
    };
    const signature = await signDelegation(SECRET, core);
    const delegationId = await t.run(
      async (ctx) =>
        await ctx.db.insert('delegations', {
          ...core,
          revokedAt: null,
          signature
        })
    );

    expect(await t.query(api.delegations.verify, {delegationId})).toEqual({
      valid: false,
      code: 'expired',
      reason: 'The delegation has expired.'
    });
  });

  test('I5: a revoked delegation verifies as invalid; revoke is idempotent', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });

    await t.mutation(api.delegations.revoke, {delegationId, reason: 'leaked'});
    const result = await t.query(api.delegations.verify, {delegationId});
    expect(result).toEqual({
      valid: false,
      code: 'revoked',
      reason: 'The delegation has been revoked.'
    });

    const firstRevokedAt = await t.run(async (ctx) => {
      const row = await ctx.db.get('delegations', delegationId);
      return row?.revokedAt ?? null;
    });
    // A second revoke is a no-op and does not move the timestamp.
    await t.mutation(api.delegations.revoke, {delegationId});
    const secondRevokedAt = await t.run(async (ctx) => {
      const row = await ctx.db.get('delegations', delegationId);
      return row?.revokedAt ?? null;
    });
    expect(secondRevokedAt).toBe(firstRevokedAt);
  });

  test('a tampered delegation fails signature verification', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    // Widen the granted scopes without re-signing — the integrity check (I1's
    // backstop) must catch it before any expiry/revocation logic runs.
    await t.run(async (ctx) =>
      ctx.db.patch('delegations', delegationId, {scopes: ['read', 'admin']})
    );

    expect(await t.query(api.delegations.verify, {delegationId})).toEqual({
      valid: false,
      code: 'bad_signature',
      reason: 'The delegation signature does not match its contents.'
    });
  });

  test('verify reports not_found for a dangling id', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    await t.run(async (ctx) => ctx.db.delete('delegations', delegationId));

    expect(await t.query(api.delegations.verify, {delegationId})).toEqual({
      valid: false,
      code: 'not_found',
      reason: 'No such delegation.'
    });
  });

  test('listForAgent returns only that agent’s delegations', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const otherAgentId = await t.mutation(api.agents.register, {
      name: 'Other',
      slug: 'other',
      ownerKind: 'platform',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_bob',
      issuerKind: 'user',
      scopes: ['write'],
      expiresAt: Date.now() + HOUR
    });
    await t.mutation(api.delegations.issue, {
      agentId: otherAgentId,
      issuerSubject: 'user_carol',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });

    const rows = await t.query(api.delegations.listForAgent, {agentId});
    expect(rows).toHaveLength(2);
    expect(rows.every((row) => row.agentId === agentId)).toBe(true);
  });

  test('issue writes a delegation.issued audit row', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    const events = await t.run(async (ctx) => {
      const rows = await ctx.db
        .query('auditLog')
        .withIndex('by_event_type', (q) =>
          q.eq('eventType', 'delegation.issued')
        )
        .collect();
      return rows.map((row) => row.eventType);
    });
    expect(events).toEqual(['delegation.issued']);
  });

  test('issue and verify fail fast when the signing secret is unset', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });

    vi.stubEnv('DELEGATION_SIGNING_SECRET', '');
    await expectFail(
      t.query(api.delegations.verify, {delegationId}),
      'delegation_secret_unset'
    );
    await expectFail(
      t.mutation(api.delegations.issue, {
        agentId,
        issuerSubject: 'user_alice',
        issuerKind: 'user',
        scopes: ['read'],
        expiresAt: Date.now() + HOUR
      }),
      'delegation_secret_unset'
    );
  });

  test('a delegation signed with a different secret fails verification', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t);
    const core = {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user' as const,
      scopes: ['read'],
      resources: null,
      expiresAt: Date.now() + HOUR
    };
    const signature = await signDelegation('the-wrong-secret', core);
    const delegationId = await t.run(
      async (ctx) =>
        await ctx.db.insert('delegations', {
          ...core,
          revokedAt: null,
          signature
        })
    );

    expect(await t.query(api.delegations.verify, {delegationId})).toMatchObject(
      {
        valid: false,
        code: 'bad_signature'
      }
    );
  });
});
