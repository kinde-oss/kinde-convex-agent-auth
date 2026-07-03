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

describe('authz.can + elevation (I6)', () => {
  test('an approved elevation grants the action and audits grantedVia (I4)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });

    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'write'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});

    const rows = await authzRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('allow');
    expect(rows[0].detail).toMatchObject({
      action: 'write',
      grantedVia: 'elevation'
    });
  });

  test('the same approval does not leak to a sibling instance (I6)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceA = await startInstance(t, agentId);
    const instanceB = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId: instanceA,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });

    expect(
      await t.mutation(api.authz.can, {instanceId: instanceA, action: 'write'})
    ).toMatchObject({allowed: true, reason: 'authorized'});
    // Instance B has no elevation of its own → still denied.
    expect(
      await t.mutation(api.authz.can, {instanceId: instanceB, action: 'write'})
    ).toMatchObject({allowed: false, reason: 'insufficient_scope'});
  });

  test('an action outside the requestedScopes is still denied (I6)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    // "delete" is covered by neither the agent's scopes nor the elevation.
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'delete'})
    ).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope',
      requiredScopes: ['delete']
    });
  });

  test('an expired elevation stops applying (I6)', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: true});

    await t.run(async (ctx) =>
      ctx.db.patch('elevationRequests', requestId, {
        expiresAt: Date.now() - 1000
      })
    );
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: false, reason: 'insufficient_scope'});
  });

  test('requireApprovalForAll: denied without elevation, allowed with one', async () => {
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

    // "read" is in scope, but requireApprovalForAll denies it without approval.
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'read'})
    ).toMatchObject({allowed: false, reason: 'approval_required'});

    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['read'],
      reason: 'approval gate'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});
  });
});

describe('authz.can caller/instance binding (confused deputy)', () => {
  beforeEach(() => {
    vi.stubEnv('DELEGATION_SIGNING_SECRET', SECRET);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('a caller authenticated as a different agent is denied', async () => {
    const t = initConvexTest();
    const agentA = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const agentB = await registerAgent(t, {
      slug: 'b',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentA);
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read',
      callerAgentId: agentB
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'caller_instance_mismatch'
    });
    const rows = await authzRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].agentId).toBe(agentA);
    expect(rows[0].detail).toMatchObject({callerAgentId: agentB});
  });

  test('a caller from a different org is denied', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read',
      callerOrgCode: 'org_2'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'caller_instance_mismatch'
    });
    const rows = await authzRows(t);
    expect(rows[0].orgCode).toBe('org_1');
    expect(rows[0].detail).toMatchObject({callerOrgCode: 'org_2'});
  });

  test('matching caller values proceed to the normal pipeline', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read'],
      orgCode: 'org_1'
    });
    const instanceId = await startInstance(t, agentId, {orgCode: 'org_1'});
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read',
      callerAgentId: agentId,
      callerOrgCode: 'org_1',
      callerSubject: 'client_x'
    });
    expect(result).toMatchObject({allowed: true, reason: 'authorized'});
    const rows = await authzRows(t);
    expect(rows[0].detail).toMatchObject({
      callerAgentId: agentId,
      callerOrgCode: 'org_1',
      callerSubject: 'client_x'
    });
  });

  test('omitting the caller args behaves exactly as before (backward compat)', async () => {
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
    const rows = await authzRows(t);
    expect(rows[0].detail).not.toHaveProperty('callerAgentId');
    expect(rows[0].detail).not.toHaveProperty('callerOrgCode');
    expect(rows[0].detail).not.toHaveProperty('callerSubject');
  });
});

describe('authz.can approvedScopes invariant (I6)', () => {
  beforeEach(() => {
    vi.stubEnv('DELEGATION_SIGNING_SECRET', SECRET);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('an elevation approved for X does not authorize a different action Y', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: true, reason: 'authorized'});
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'delete'})
    ).toMatchObject({allowed: false, reason: 'insufficient_scope'});
  });

  test('authorization uses approvedScopes, not a requestedScopes widened after approval', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    // Widen the stored requestedScopes after the fact: approvedScopes still governs.
    await t.run(async (ctx) =>
      ctx.db.patch('elevationRequests', requestId, {
        requestedScopes: ['write', 'delete']
      })
    );
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'delete'})
    ).toMatchObject({allowed: false, reason: 'insufficient_scope'});
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: true, reason: 'authorized'});
  });

  test('an expired approved elevation authorizes nothing', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
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
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: false, reason: 'insufficient_scope'});
  });

  test('a legacy approved row without approvedScopes falls back to requestedScopes', async () => {
    const t = initConvexTest();
    const agentId = await registerAgent(t, {
      slug: 'a',
      kind: 'autonomous',
      allowedTools: [],
      scopes: ['read']
    });
    const instanceId = await startInstance(t, agentId);
    const requestId = await t.mutation(api.elevation.request, {
      instanceId,
      requestedScopes: ['write'],
      reason: 'need write'
    });
    await t.mutation(api.elevation.approve, {
      requestId,
      approverSubject: 'human_admin'
    });
    // Simulate a row approved before the approvedScopes field existed.
    await t.run(async (ctx) =>
      ctx.db.patch('elevationRequests', requestId, {approvedScopes: undefined})
    );
    expect(
      await t.mutation(api.authz.can, {instanceId, action: 'write'})
    ).toMatchObject({allowed: true, reason: 'authorized'});
  });

  test('deny: delegation_required for a supervised agent whose delegation expired', async () => {
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
    const result = await t.mutation(api.authz.can, {
      instanceId,
      action: 'read'
    });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'delegation_required'
    });
  });
});
