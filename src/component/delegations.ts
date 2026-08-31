import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import {env, mutation, query} from './_generated/server.js';
import schema from './schema.js';
import {fail, writeAudit} from './helpers.js';
import {issuerKindValidator, nullableStringArray} from './validators.js';

const delegationDoc = schema.tables.delegations.validator.extend({
  _id: v.id('delegations'),
  _creationTime: v.number()
});

const verifyResultValidator = v.union(
  v.object({valid: v.literal(true)}),
  v.object({
    valid: v.literal(false),
    code: v.string(),
    reason: v.string()
  })
);

export type VerifyResult = Infer<typeof verifyResultValidator>;

type IssuerKind = Infer<typeof issuerKindValidator>;

/** The canonical, signature-bearing fields of a delegation. */
export interface SignedDelegationCore {
  agentId: string;
  issuerSubject: string;
  issuerKind: IssuerKind;
  scopes: string[];
  resources: string[] | null;
  expiresAt: number;
}

const encoder = new TextEncoder();

/**
 * The exact bytes that get signed. A leading version tag and an ordered array
 * (rather than an object) make the encoding unambiguous and stable, so a
 * delegation signed by `issue` re-hashes identically in `verify`. `revokedAt`
 * is deliberately excluded: revocation is a mutable, separately-checked state,
 * not part of the immutable signed grant.
 */
function canonicalPayload(core: SignedDelegationCore): string {
  return JSON.stringify([
    'kinde.delegation.v1',
    core.agentId,
    core.issuerSubject,
    core.issuerKind,
    core.scopes,
    core.resources,
    core.expiresAt
  ]);
}

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

/** Length-independent equality so signature checks leak no timing signal. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * HMAC-SHA256 the canonical payload with the component's signing secret and
 * return it hex-encoded. Pure given the secret and core fields — no database
 * or network access — so the same call is used by `issue` and `verify`.
 */
export async function signDelegation(
  secret: string,
  core: SignedDelegationCore
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    {name: 'HMAC', hash: 'SHA-256'},
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(canonicalPayload(core))
  );
  return toHex(new Uint8Array(signature));
}

/**
 * Validate a stored delegation against the signing secret. Pure given the
 * secret: it recomputes the HMAC and rejects a mismatch, then treats a revoked
 * or expired delegation as invalid (invariant I5). Order matters — integrity
 * is checked before state so a tampered row can never read as merely expired.
 * Exported for reuse by `authz.can` in Phase 4.
 */
export async function verifyDelegation(
  secret: string,
  delegation: SignedDelegationCore & {
    signature: string;
    revokedAt: number | null;
  },
  now: number
): Promise<VerifyResult> {
  const expected = await signDelegation(secret, delegation);
  if (!constantTimeEqual(expected, delegation.signature)) {
    return {
      valid: false,
      code: 'bad_signature',
      reason: 'The delegation signature does not match its contents.'
    };
  }
  if (delegation.revokedAt !== null) {
    return {
      valid: false,
      code: 'revoked',
      reason: 'The delegation has been revoked.'
    };
  }
  if (delegation.expiresAt <= now) {
    return {
      valid: false,
      code: 'expired',
      reason: 'The delegation has expired.'
    };
  }
  return {valid: true};
}

/**
 * The component signing secret, or a machine-readable failure if unset. Shared
 * with `authz.can` so it can re-verify delegation signatures at decision time
 * with the exact same secret `issue`/`verify` use.
 */
export function requireSigningSecret(): string {
  const secret = env.DELEGATION_SIGNING_SECRET;
  if (!secret) {
    fail(
      'delegation_secret_unset',
      'The DELEGATION_SIGNING_SECRET environment variable is not set for the agentAuth component.'
    );
  }
  return secret;
}

/**
 * Issue an HMAC-signed scope delegation from a principal to an agent. The
 * signature is computed over the canonical fields with
 * DELEGATION_SIGNING_SECRET, so the delegation is later verifiable without any
 * external call.
 */
export const issue = mutation({
  args: {
    agentId: v.id('agents'),
    issuerSubject: v.string(),
    issuerKind: issuerKindValidator,
    scopes: v.array(v.string()),
    // Audit metadata only. Stored and covered by the delegation signature, but
    // NOT evaluated in any allow/deny decision today; do not rely on it for
    // ABAC or resource-scoping. Only `scopes` gate authorization.
    resources: v.optional(nullableStringArray),
    expiresAt: v.number()
  },
  returns: v.id('delegations'),
  handler: async (ctx, args) => {
    const now = Date.now();
    const secret = requireSigningSecret();
    const agent = await ctx.db.get('agents', args.agentId);
    if (agent === null) {
      fail('agent_not_found', 'No such agent.');
    }
    // Reject scopes the agent was never granted at issue time. authz.can already
    // intersects a delegation with agent.scopes so an over-broad grant cannot
    // widen authority, but storing scopes outside the agent's set pollutes the
    // audit trail and delegation UX with authority that can never take effect.
    // Fail closed here so a delegation always represents a real, usable subset.
    const exceeding = args.scopes.filter(
      (scope) => !agent.scopes.includes(scope)
    );
    if (exceeding.length > 0) {
      fail(
        'scopes_exceed_agent',
        `Requested scopes are not granted to this agent: ${exceeding.join(', ')}.`
      );
    }
    if (args.expiresAt <= now) {
      fail('invalid_expiry', 'expiresAt must be in the future.');
    }
    const resources = args.resources ?? null;
    const signature = await signDelegation(secret, {
      agentId: args.agentId,
      issuerSubject: args.issuerSubject,
      issuerKind: args.issuerKind,
      scopes: args.scopes,
      resources,
      expiresAt: args.expiresAt
    });
    const delegationId = await ctx.db.insert('delegations', {
      agentId: args.agentId,
      issuerSubject: args.issuerSubject,
      issuerKind: args.issuerKind,
      scopes: args.scopes,
      resources,
      expiresAt: args.expiresAt,
      revokedAt: null,
      signature
    });
    await writeAudit(ctx, {
      eventType: 'delegation.issued',
      agentId: args.agentId,
      orgCode: agent.orgCode,
      scopesUsed: args.scopes,
      detail: {
        issuerSubject: args.issuerSubject,
        issuerKind: args.issuerKind,
        expiresAt: args.expiresAt
      }
    });
    return delegationId;
  }
});

/**
 * Verify a stored delegation: recompute its HMAC and check expiry/revocation
 * (invariant I5). A missing delegation reports `not_found` rather than throwing
 * so callers can branch uniformly on the result.
 */
export const verify = query({
  args: {delegationId: v.id('delegations')},
  returns: verifyResultValidator,
  handler: async (ctx, args) => {
    const secret = requireSigningSecret();
    const delegation = await ctx.db.get('delegations', args.delegationId);
    if (delegation === null) {
      return {
        valid: false as const,
        code: 'not_found',
        reason: 'No such delegation.'
      };
    }
    return await verifyDelegation(secret, delegation, Date.now());
  }
});

/** Revoke a delegation. Idempotent: an already-revoked delegation is a no-op. */
export const revoke = mutation({
  args: {delegationId: v.id('delegations'), reason: v.optional(v.string())},
  returns: v.null(),
  handler: async (ctx, args) => {
    const delegation = await ctx.db.get('delegations', args.delegationId);
    if (delegation === null) {
      fail('delegation_not_found', 'No such delegation.');
    }
    if (delegation.revokedAt !== null) {
      return null;
    }
    await ctx.db.patch('delegations', args.delegationId, {
      revokedAt: Date.now()
    });
    await writeAudit(ctx, {
      eventType: 'delegation.revoked',
      agentId: delegation.agentId,
      scopesUsed: delegation.scopes,
      detail: {
        issuerSubject: delegation.issuerSubject,
        reason: args.reason ?? null
      }
    });
    return null;
  }
});

export const get = query({
  args: {delegationId: v.id('delegations')},
  returns: v.union(delegationDoc, v.null()),
  handler: async (ctx, args) => {
    return await ctx.db.get('delegations', args.delegationId);
  }
});

export const listForAgent = query({
  args: {agentId: v.id('agents'), limit: v.optional(v.number())},
  returns: v.array(delegationDoc),
  handler: async (ctx, args) => {
    const limit = Math.min(Math.max(args.limit ?? 100, 1), 200);
    return await ctx.db
      .query('delegations')
      .withIndex('by_agent', (q) => q.eq('agentId', args.agentId))
      .take(limit);
  }
});
