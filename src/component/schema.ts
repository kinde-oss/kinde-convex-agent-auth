import {defineSchema, defineTable} from 'convex/server';
import {v} from 'convex/values';
import {
  agentKindValidator,
  agentStatusValidator,
  decisionValidator,
  elevationStatusValidator,
  instanceStatusValidator,
  issuerKindValidator,
  jwksKeysValidator,
  metadataValidator,
  nullableNumber,
  nullableString,
  nullableStringArray,
  ownerKindValidator,
  revocationTargetKindValidator
} from './validators.js';

export default defineSchema({
  /** Agent type registry. One row per agent definition. */
  agents: defineTable({
    name: v.string(),
    slug: v.string(),
    ownerKind: ownerKindValidator,
    ownerId: nullableString,
    orgCode: nullableString,
    kindeClientId: nullableString,
    kind: agentKindValidator,
    status: agentStatusValidator,
    allowedTools: v.array(v.string()),
    scopes: v.array(v.string()),
    metadata: metadataValidator
  })
    .index('by_slug', ['slug'])
    .index('by_kinde_client_id', ['kindeClientId'])
    .index('by_org_code', ['orgCode', 'status']),

  /** Ephemeral agent runs. */
  instances: defineTable({
    agentId: v.id('agents'),
    runId: v.string(),
    actingForSubject: nullableString,
    orgCode: nullableString,
    status: instanceStatusValidator,
    expiresAt: v.number(),
    createdAt: v.number()
  })
    .index('by_run_id', ['runId'])
    .index('by_agent', ['agentId', 'status'])
    .index('by_status', ['status', 'expiresAt'])
    .index('by_org_code', ['orgCode', 'status']),

  /**
   * Scope delegations from a principal to an agent, HMAC-signed with
   * DELEGATION_SIGNING_SECRET so they are verifiable without external calls.
   */
  delegations: defineTable({
    agentId: v.id('agents'),
    issuerSubject: v.string(),
    issuerKind: issuerKindValidator,
    scopes: v.array(v.string()),
    // Audit metadata only (not evaluated in allow/deny; see delegations.issue).
    resources: nullableStringArray,
    expiresAt: v.number(),
    revokedAt: nullableNumber,
    signature: v.string()
  })
    .index('by_agent', ['agentId'])
    .index('by_issuer', ['issuerSubject']),

  /**
   * Reactive revocation overlay. Token verification always consults this
   * table, so a revocation takes effect on the next call regardless of JWT
   * expiry. `targetId` is null for global revocations.
   */
  revocations: defineTable({
    targetKind: revocationTargetKindValidator,
    targetId: nullableString,
    reason: v.string(),
    createdAt: v.number()
  }).index('by_target', ['targetKind', 'targetId']),

  /** Human-in-the-loop scope elevation requests. */
  elevationRequests: defineTable({
    instanceId: v.id('instances'),
    requestedScopes: v.array(v.string()),
    approvedScopes: v.optional(v.array(v.string())),
    reason: v.string(),
    status: elevationStatusValidator,
    approverSubject: nullableString,
    resolvedAt: nullableNumber,
    expiresAt: v.number()
  })
    .index('by_instance', ['instanceId', 'status'])
    .index('by_status', ['status', 'expiresAt']),

  /** Per-tenant policy overrides, keyed by Kinde org code. */
  tenantPolicies: defineTable({
    orgCode: v.string(),
    allowAutonomous: v.boolean(),
    requireApprovalForAll: v.boolean(),
    allowedToolsOverride: nullableStringArray,
    disabled: v.boolean()
  }).index('by_org_code', ['orgCode']),

  /** Append-only audit log. Never updated or deleted. */
  auditLog: defineTable({
    at: v.number(),
    eventType: v.string(),
    agentId: v.union(v.id('agents'), v.null()),
    instanceId: v.union(v.id('instances'), v.null()),
    actingFor: nullableString,
    orgCode: nullableString,
    scopesUsed: nullableStringArray,
    decision: v.union(decisionValidator, v.null()),
    correlationId: nullableString,
    detail: metadataValidator
  })
    .index('by_at', ['at'])
    .index('by_agent', ['agentId', 'at'])
    .index('by_org_code', ['orgCode', 'at'])
    .index('by_event_type', ['eventType', 'at']),

  /** Cached Kinde JWKS, keyed by Kinde domain. */
  jwksCache: defineTable({
    domain: v.string(),
    keys: jwksKeysValidator,
    fetchedAt: v.number()
  }).index('by_domain', ['domain'])
});
