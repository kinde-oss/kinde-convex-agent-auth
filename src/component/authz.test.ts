import {afterEach, beforeEach, describe, expect, test, vi} from 'vitest';
import type {Id} from './_generated/dataModel.js';
import {api} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

const SECRET = 'test-delegation-secret';
const HOUR = 60 * 60 * 1000;

type ConvexTest = ReturnType<typeof initConvexTest>;

async function registerAgent(
  t: ConvexTest,
  opts: {
    slug: string;
    kind: 'autonomous' | 'supervised';
    allowedTools: string[];
    scopes: string[];
    orgCode?: string | null;
  }
): Promise<Id<'agents'>> {
  const orgCode = opts.orgCode ?? null;
  return await t.mutation(api.agents.register, {
    name: opts.slug,
    slug: opts.slug,
    ownerKind: orgCode === null ? 'platform' : 'org',
    orgCode,
    kind: opts.kind,
    allowedTools: opts.allowedTools,
    scopes: opts.scopes
  });
}

let runCounter = 0;
async function startInstance(
  t: ConvexTest,
  agentId: Id<'agents'>,
  opts: {actingForSubject?: string | null; orgCode?: string | null} = {}
): Promise<Id<'instances'>> {
  runCounter += 1;
  return await t.mutation(api.instances.start, {
    agentId,
    runId: `run-${runCounter}`,
    actingForSubject: opts.actingForSubject ?? null,
    orgCode: opts.orgCode ?? null,
    expiresAt: Date.now() + HOUR
  });
}

async function authzRows(t: ConvexTest) {
  return await t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter(
      (row) => row.eventType === 'authz.decision'
    )
  );
}

describe('authz.can', () => {
  beforeEach(() => {
    vi.stubEnv('DELEGATION_SIGNING_SECRET', SECRET);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('allows an authorized action and audits exactly one allow row (I4)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: ['read', 'write'],
      scopes: ['read', 'write']
    });
    const instanceId = await startInstance(t, agentId);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read',
      resource: 'doc:1'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});

    const rows = await authzRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('allow');
    expect(rows[0].correlationId).toBe(result.correlationId);
    expect(rows[0].scopesUsed).toEqual(['read', 'write']);
    expect(rows[0].detail).toMatchObject({action: 'read', resource: 'doc:1'});
  });

  test('deny writes exactly one deny row with a correlationId (I4)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(result.allowed).toBe(false);
    const rows = await authzRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
    expect(rows[0].correlationId).toBe(result.correlationId);
  });

  test('deny: instance_not_found', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    await t.run(async (ctx) => ctx.db.delete('instances', instanceId));
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'instance_not_found'
    });
  });

  test('deny: instance_not_active for an expired instance (I5)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    await t.run(async (ctx) =>
      ctx.db.patch('instances', instanceId, {expiresAt: Date.now() - 1000})
    );
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'instance_not_active'
    });
  });

  test('deny: instance_not_active for a completed instance', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    await t.mutation(api.instances.complete, {instanceId});
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'instance_not_active'
    });
  });

  test('deny: revocation at each level, instance-level included (I2)', async () => {
    const cases: Array<{
      label: string;
      revoke: (
        t: ConvexTest,
        ids: {agentId: Id<'agents'>; instanceId: Id<'instances'>}
      ) => Promise<unknown>;
      code: string;
    }> = [
      {
        label: 'global',
        revoke: (t) =>
          t.mutation(api.revocations.revoke, {targetKind: 'global'}),
        code: 'revoked_global'
      },
      {
        label: 'org',
        revoke: (t) =>
          t.mutation(api.revocations.revoke, {
            targetKind: 'org',
            targetId: 'org_1'
          }),
        code: 'revoked_org'
      },
      {
        label: 'agent',
        revoke: (t, ids) =>
          t.mutation(api.revocations.revoke, {
            targetKind: 'agent',
            targetId: ids.agentId
          }),
        code: 'revoked_agent'
      },
      {
        label: 'instance',
        revoke: (t, ids) =>
          t.mutation(api.revocations.revoke, {
            targetKind: 'instance',
            targetId: ids.instanceId
          }),
        code: 'revoked_instance'
      }
    ];
    for (const {label, revoke, code} of cases) {
      const t = initConvexTest();
      const agentId = await registerAgent(t, {
        slug: 'a',
        kind: 'autonomous',
        allowedTools: [],
        scopes: ['read'],
        orgCode: 'org_1'
      });
      const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
      await revoke(t, {agentId, instanceId});
      const result = await t.mutation(api.authz.can, {
        instanceId,
        action: 'read'
      });
      expect(result, label).toMatchObject({allowed: false, reason: code});
    }
  });

  test('deny: agent_suspended', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    await t.mutation(api.agents.suspend, {agentId});
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({allowed: false, reason: 'agent_suspended'});
  });

  test('deny: tenant_disabled', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
    await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      disabled: true
    });
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({allowed: false, reason: 'tenant_disabled'});
  });

  test('deny: approval_required when requireApprovalForAll', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
    await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: true,
      disabled: false
    });
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({allowed: false, reason: 'approval_required'});
  });

  test('deny: delegation_required for a supervised agent with no delegation', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'supervised',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId, {
      actingForSubject: 'user_alice'
    });
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'delegation_required'
    });
  });

  test('deny: autonomous_not_allowed when the tenant forbids autonomy', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
    await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: false,
      requireApprovalForAll: false,
      disabled: false
    });
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'autonomous_not_allowed'
    });
  });

  test('deny: tool_not_allowed when action is outside allowedTools', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: ['read'],
      scopes: ['read', 'write']
    });
    const instanceId = await startInstance(t, agentId);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(result).toMatchObject({allowed: false, reason: 'tool_not_allowed'});
  });

  test('deny: insufficient_scope returns requiredScopes', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope',
      requiredScopes: ['write']
    });
  });

  test('delegation-optional: autonomous agent with no delegation is allowed on its own scopes', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});
  });

  test('I1: a present delegation narrows an autonomous agent further', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read', 'write']
    });
    const instanceId = await startInstance(t, agentId, {
      actingForSubject: 'user_alice'
    });
    await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    // "write" is in the agent's scopes but not the delegation's → denied.
    const denied = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(denied).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope',
      requiredScopes: ['write']
    });
    // "read" is in both → allowed.
    const allowed = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(allowed).toMatchObject({allowed: true, reason: 'authorized'});
  });

  test('an expired delegation is ignored; autonomous falls back to its own scopes', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read', 'write']
    });
    const instanceId = await startInstance(t, agentId, {
      actingForSubject: 'user_alice'
    });
    const delegationId = await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read'],
      expiresAt: Date.now() + HOUR
    });
    await t.run(async (ctx) =>
      ctx.db.patch('delegations', delegationId, {expiresAt: Date.now() - 1000})
    );
    // The expired delegation no longer constrains: "write" (own scope) allowed.
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});
  });

  test('tenant allowedToolsOverride narrows agent+delegation scopes', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read', 'write'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {
      orgCode: 'org_1',
      actingForSubject: 'user_alice'
    });
    await t.mutation(api.delegations.issue, {
      agentId,
      issuerSubject: 'user_alice',
      issuerKind: 'user',
      scopes: ['read', 'write'],
      expiresAt: Date.now() + HOUR
    });
    await t.mutation(api.policies.setTenantPolicy, {
      orgCode: 'org_1',
      allowAutonomous: true,
      requireApprovalForAll: false,
      allowedToolsOverride: ['read'],
      disabled: false
    });
    // "write" is in agent ∩ delegation but excluded by the override → denied.
    const denied = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(denied).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope'
    });
    const allowed = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(allowed).toMatchObject({allowed: true, reason: 'authorized'});
  });
});
