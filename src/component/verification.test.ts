import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

const baseArgs = {
  subject: 'client_abc',
  kindeClientId: 'client_abc',
  orgCode: 'org_123' as string | null,
  tokenScopes: ['read:tickets']
};

async function registerOrgAgent(t: ReturnType<typeof initConvexTest>) {
  return await t.mutation(api.agents.register, {
    name: 'Org Bot',
    slug: 'org-bot',
    ownerKind: 'org' as const,
    orgCode: 'org_123',
    kindeClientId: 'client_abc',
    kind: 'autonomous' as const,
    allowedTools: ['tickets.read'],
    scopes: ['read:tickets']
  });
}

async function auditRows(t: ReturnType<typeof initConvexTest>) {
  return await t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter(
      (row) => row.eventType === 'caller.verified'
    )
  );
}

describe('verification.check', () => {
  test('allows a registered, active agent and audits the decision', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.agentId).toBe(agentId);
    }
    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('allow');
    expect(rows[0].agentId).toBe(agentId);
    expect(rows[0].orgCode).toBe('org_123');
    expect(rows[0].scopesUsed).toEqual(['read:tickets']);
    expect(rows[0].correlationId).toBe(result.correlationId);
  });

  test('allows an unregistered client id with a null agentId', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.agentId).toBeNull();
    }
  });

  test('denies when globally revoked, even for a valid caller (I2)', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    await t.mutation(api.revocations.revoke, {targetKind: 'global'});
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result).toMatchObject({allowed: false, code: 'revoked_global'});
  });

  test('denies when the org is revoked (I2)', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    await t.mutation(api.revocations.revoke, {
      targetKind: 'org',
      targetId: 'org_123'
    });
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result).toMatchObject({allowed: false, code: 'revoked_org'});
  });

  test('denies when the agent is revoked (I2)', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    await t.mutation(api.revocations.revoke, {
      targetKind: 'agent',
      targetId: agentId
    });
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result).toMatchObject({allowed: false, code: 'revoked_agent'});
  });

  test('denies when the expected org differs from the token org (I3)', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      expectedOrgCode: 'org_other'
    });
    expect(result).toMatchObject({allowed: false, code: 'org_mismatch'});
    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
  });

  test('denies when the agent is bound to a different org (I3)', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      orgCode: 'org_other'
    });
    expect(result).toMatchObject({allowed: false, code: 'org_mismatch'});
  });

  test('denies an org-bound agent presenting an org-less token (I3)', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      orgCode: null
    });
    expect(result).toMatchObject({allowed: false, code: 'org_mismatch'});
  });

  test('denies a suspended agent', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    await t.mutation(api.agents.suspend, {agentId});
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result).toMatchObject({allowed: false, code: 'agent_suspended'});
  });

  test('denies when the tenant is disabled', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('tenantPolicies', {
        orgCode: 'org_123',
        allowAutonomous: true,
        requireApprovalForAll: false,
        allowedToolsOverride: null,
        disabled: true
      });
    });
    const result = await t.mutation(api.verification.check, {...baseArgs});
    expect(result).toMatchObject({allowed: false, code: 'tenant_disabled'});
  });

  test('writes exactly one audit row per decision', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    await t.mutation(api.verification.check, {...baseArgs});
    await t.mutation(api.verification.check, {
      ...baseArgs,
      expectedOrgCode: 'org_other'
    });
    const rows = await auditRows(t);
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.decision)).toEqual(['allow', 'deny']);
  });

  test('recordRejection writes a deny audit row', async () => {
    const t = initConvexTest();
    const correlationId = await t.mutation(api.verification.recordRejection, {
      code: 'token_expired',
      reason: 'The token has expired.'
    });
    const rows = await t.run(async (ctx) => ctx.db.query('auditLog').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0].eventType).toBe('caller.rejected');
    expect(rows[0].decision).toBe('deny');
    expect(rows[0].correlationId).toBe(correlationId);
  });

  test('the org-binding deny message is correctly spaced ("org_code is absent")', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      orgCode: null
    });
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("token's org_code is absent");
      expect(result.reason).not.toContain('org_codeis');
    }
  });
});

describe('verification.check requireOrgCode (I3)', () => {
  test('denies an org-less token when requireOrgCode is set', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      orgCode: null,
      requireOrgCode: true
    });
    expect(result).toMatchObject({allowed: false, code: 'org_code_required'});
    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
  });

  test('an org-less token is allowed when requireOrgCode is omitted', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      orgCode: null
    });
    expect(result.allowed).toBe(true);
  });

  test('an org-scoped token is unaffected by requireOrgCode', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      requireOrgCode: true
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.agentId).toBe(agentId);
    }
  });
});

describe('verification.check requireRegisteredAgent', () => {
  test('denies an unregistered client id when requireRegisteredAgent is set', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      requireRegisteredAgent: true
    });
    expect(result).toMatchObject({
      allowed: false,
      code: 'agent_not_registered'
    });
  });

  test('denies a token with no azp when requireRegisteredAgent is set', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      kindeClientId: null,
      requireRegisteredAgent: true
    });
    expect(result).toMatchObject({
      allowed: false,
      code: 'agent_not_registered'
    });
  });

  test('allows a registered agent when requireRegisteredAgent is set', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    const result = await t.mutation(api.verification.check, {
      ...baseArgs,
      requireRegisteredAgent: true
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.agentId).toBe(agentId);
    }
  });
});
