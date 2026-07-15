import {v} from 'convex/values';
import {mutation} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import type {Doc, Id} from './_generated/dataModel.js';
import {
  effectiveElevationStatus,
  effectiveInstanceStatus,
  writeAudit
} from './helpers.js';
import {findActiveRevocation} from './revocations.js';
import {requireSigningSecret, verifyDelegation} from './delegations.js';
import {intersectScopes} from './scopes.js';
import {nullableString} from './validators.js';

const canResultValidator = v.object({
  allowed: v.boolean(),
  reason: v.string(),
  requiredScopes: v.optional(v.array(v.string())),
  correlationId: v.string()
});

/** Maps a revocation's target level to its stable deny code (invariant I2). */
const REVOKED_CODE = {
  global: 'revoked_global',
  org: 'revoked_org',
  agent: 'revoked_agent',
  instance: 'revoked_instance'
} as const;

/**
 * Find a usable delegation for this agent + acting-for subject. Returns null if
 * the subject is anonymous or no active delegation exists.
 *
 * The signature is re-verified here, at decision time, so authz never trusts an
 * unverified row regardless of how it entered the table — a tampered or
 * directly-inserted delegation whose HMAC does not match its contents is
 * skipped (treated as if it doesn't exist) and recorded as a
 * `delegation.signature_invalid` audit event so tampering is visible. We reuse
 * `verifyDelegation` (the same machinery `delegations.issue`/`verify` use)
 * rather than re-implementing the HMAC. `verifyDelegation` also re-checks
 * revocation/expiry, so those are no longer filtered separately here.
 *
 * Ambiguous-delegation policy: when several signature-valid, unrevoked,
 * unexpired delegations match the same agent + acting-for subject, the one with
 * the newest `expiresAt` wins. This is deterministic (no reliance on `.collect()`
 * order) and least-surprising, and stays attenuation-safe because the winner is
 * still intersected with the agent's scopes downstream.
 */
async function findActiveDelegation(
  ctx: MutationCtx,
  agentId: Id<'agents'>,
  actingForSubject: string | null,
  now: number
): Promise<Doc<'delegations'> | null> {
  if (actingForSubject === null) {
    return null;
  }
  const secret = requireSigningSecret();
  const candidates = await ctx.db
    .query('delegations')
    .withIndex('by_agent', (q) => q.eq('agentId', agentId))
    .collect();
  let best: Doc<'delegations'> | null = null;
  for (const delegation of candidates) {
    if (delegation.issuerSubject !== actingForSubject) {
      continue;
    }
    const result = await verifyDelegation(secret, delegation, now);
    if (!result.valid) {
      // A signature mismatch means the row was tampered with or inserted
      // directly, bypassing `issue`. Fail closed and leave a trail.
      if (result.code === 'bad_signature') {
        await writeAudit(ctx, {
          eventType: 'delegation.signature_invalid',
          agentId,
          scopesUsed: delegation.scopes,
          detail: {
            delegationId: delegation._id,
            issuerSubject: delegation.issuerSubject
          }
        });
      }
      continue;
    }
    if (best === null || delegation.expiresAt > best.expiresAt) {
      best = delegation;
    }
  }
  return best;
}

/**
 * Whether an approved, non-expired elevation grants `action` to THIS instance
 * (invariant I6). Elevations are keyed by instance, never widen beyond the
 * scopes the approver actually approved (`approvedScopes`, falling back to
 * `requestedScopes` for rows approved before that field existed), and stop
 * applying once expired — all enforced here.
 */
async function hasApprovedElevation(
  ctx: MutationCtx,
  instanceId: Id<'instances'>,
  action: string,
  now: number
): Promise<boolean> {
  const rows = await ctx.db
    .query('elevationRequests')
    .withIndex('by_instance', (q) =>
      q.eq('instanceId', instanceId).eq('status', 'approved')
    )
    .collect();
  return rows.some(
    (row) =>
      effectiveElevationStatus(row, now) === 'approved' &&
      (row.approvedScopes ?? row.requestedScopes).includes(action)
  );
}

/**
 * The authorization decision pipeline. Deny short-circuits at the first failed
 * gate; every path — allow or deny — writes exactly one `authz.decision` audit
 * row carrying the correlationId returned to the caller (invariant I4). The
 * `reason` is always a stable, machine-readable code.
 */
export const can = mutation({
  args: {
    instanceId: v.id('instances'),
    action: v.string(),
    // Audit metadata only. Recorded on the decision's audit row but NOT
    // evaluated in the allow/deny decision today; do not rely on it for ABAC or
    // any resource-scoping. The allow/deny gate is action/scope-based only.
    resource: v.optional(v.string()),
    callerAgentId: v.optional(v.union(v.id('agents'), v.null())),
    callerOrgCode: v.optional(nullableString),
    callerSubject: v.optional(nullableString),
    // The caller's live Kinde token scopes. Only sent when the app opts into
    // enforceTokenScopes; when present it is one more attenuating input to the
    // effective-scope intersection (step 6), so the M2M token's scopes and
    // agent.scopes cannot silently drift apart. Omitting it changes nothing.
    callerTokenScopes: v.optional(v.array(v.string()))
  },
  returns: canResultValidator,
  handler: async (ctx, args) => {
    const now = Date.now();
    const resource = args.resource ?? null;

    // One audit row per decision (I4). All exits funnel through here.
    const decide = async (
      allowed: boolean,
      reason: string,
      context: {
        agentId?: Id<'agents'> | null;
        orgCode?: string | null;
        scopesUsed?: string[] | null;
        requiredScopes?: string[];
        grantedVia?: 'elevation';
      } = {}
    ) => {
      const correlationId = await writeAudit(ctx, {
        eventType: 'authz.decision',
        agentId: context.agentId ?? null,
        instanceId: args.instanceId,
        orgCode: context.orgCode ?? null,
        scopesUsed: context.scopesUsed ?? null,
        decision: allowed ? 'allow' : 'deny',
        detail: {
          action: args.action,
          resource,
          reason,
          ...(context.grantedVia === undefined
            ? {}
            : {grantedVia: context.grantedVia}),
          ...(args.callerAgentId === undefined
            ? {}
            : {callerAgentId: args.callerAgentId}),
          ...(args.callerOrgCode === undefined
            ? {}
            : {callerOrgCode: args.callerOrgCode}),
          ...(args.callerSubject === undefined
            ? {}
            : {callerSubject: args.callerSubject})
        }
      });
      return {
        allowed,
        reason,
        ...(context.requiredScopes === undefined
          ? {}
          : {requiredScopes: context.requiredScopes}),
        correlationId
      };
    };

    // 1. The instance must exist.
    const instance = await ctx.db.get('instances', args.instanceId);
    if (instance === null) {
      return await decide(false, 'instance_not_found');
    }
    const orgCode = instance.orgCode;

    // 1a. Bind the verified caller to this instance. A host app may take the
    // instanceId from request input, so an agent authenticated in one org (or
    // as one agent) must not obtain decisions for another's instance — the
    // confused deputy. Only checked when the caller identity was threaded in.
    if (
      (args.callerAgentId !== undefined &&
        instance.agentId !== args.callerAgentId) ||
      (args.callerOrgCode !== undefined &&
        instance.orgCode !== args.callerOrgCode)
    ) {
      return await decide(false, 'caller_instance_mismatch', {
        agentId: instance.agentId,
        orgCode
      });
    }

    // 2. The instance must still be running (expired behaves as revoked — I5).
    if (effectiveInstanceStatus(instance, now) !== 'running') {
      return await decide(false, 'instance_not_active', {
        agentId: instance.agentId,
        orgCode
      });
    }

    // 3. Revocation overlay, highest precedence first (I2).
    const revocation = await findActiveRevocation(ctx, {
      agentId: instance.agentId,
      instanceId: args.instanceId,
      orgCode: orgCode ?? undefined
    });
    if (revocation !== null) {
      return await decide(false, REVOKED_CODE[revocation.targetKind], {
        agentId: instance.agentId,
        orgCode
      });
    }

    // 4. The agent must exist and be active.
    const agent = await ctx.db.get('agents', instance.agentId);
    if (agent === null) {
      return await decide(false, 'agent_not_found', {
        agentId: instance.agentId,
        orgCode
      });
    }
    if (agent.status !== 'active') {
      return await decide(false, 'agent_suspended', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }

    // An approved, non-expired human elevation covering this action augments
    // the decision for this instance only (invariant I6). Computed once and
    // reused by both the approval gate and the final scope check.
    const elevated = await hasApprovedElevation(
      ctx,
      args.instanceId,
      args.action,
      now
    );

    // 5. Tenant policy gates.
    const tenantPolicy =
      orgCode === null
        ? null
        : await ctx.db
            .query('tenantPolicies')
            .withIndex('by_org_code', (q) => q.eq('orgCode', orgCode))
            .unique();
    if (tenantPolicy !== null && tenantPolicy.disabled) {
      return await decide(false, 'tenant_disabled', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }
    // requireApprovalForAll denies every action unless a human has elevated
    // this specific one.
    if (
      tenantPolicy !== null &&
      tenantPolicy.requireApprovalForAll &&
      !elevated
    ) {
      return await decide(false, 'approval_required', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }
    const override = tenantPolicy?.allowedToolsOverride ?? null;

    // 6. Delegation-optional rule: compute the effective scope set (I1).
    const delegation = await findActiveDelegation(
      ctx,
      agent._id,
      instance.actingForSubject,
      now
    );
    // callerTokenScopes is undefined unless the app opted into
    // enforceTokenScopes, in which case it further attenuates `effective`.
    const callerTokenScopes = args.callerTokenScopes;
    let effective: string[];
    if (delegation !== null) {
      effective = intersectScopes(
        agent.scopes,
        delegation.scopes,
        override,
        callerTokenScopes
      );
    } else if (agent.kind === 'autonomous') {
      if (tenantPolicy !== null && !tenantPolicy.allowAutonomous) {
        return await decide(false, 'autonomous_not_allowed', {
          agentId: agent._id,
          orgCode,
          scopesUsed: agent.scopes
        });
      }
      effective = intersectScopes(
        agent.scopes,
        agent.scopes,
        override,
        callerTokenScopes
      );
    } else {
      return await decide(false, 'delegation_required', {
        agentId: agent._id,
        orgCode,
        scopesUsed: agent.scopes
      });
    }

    // 7. Tool gate, then scope gate.
    if (
      agent.allowedTools.length > 0 &&
      !agent.allowedTools.includes(args.action)
    ) {
      return await decide(false, 'tool_not_allowed', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective
      });
    }

    // 8. Authorize. Under requireApprovalForAll the only way to reach here is a
    // covering elevation, so the grant is via elevation. Otherwise a normal
    // in-scope action is authorized directly; an out-of-scope action is allowed
    // only if a human elevation covers it (I6), else denied.
    const requireApproval = tenantPolicy?.requireApprovalForAll ?? false;
    if (requireApproval) {
      return await decide(true, 'authorized', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective,
        grantedVia: 'elevation'
      });
    }
    if (effective.includes(args.action)) {
      return await decide(true, 'authorized', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective
      });
    }
    if (elevated) {
      return await decide(true, 'authorized', {
        agentId: agent._id,
        orgCode,
        scopesUsed: effective,
        grantedVia: 'elevation'
      });
    }
    return await decide(false, 'insufficient_scope', {
      agentId: agent._id,
      orgCode,
      scopesUsed: effective,
      requiredScopes: [args.action]
    });
  }
});
