import {ConvexError} from 'convex/values';
import type {Infer} from 'convex/values';
import type {MutationCtx} from './_generated/server.js';
import type {Doc, Id} from './_generated/dataModel.js';
import type {
  decisionValidator,
  elevationStatusValidator,
  instanceStatusValidator,
  metadataValidator
} from './validators.js';

export type Metadata = Infer<typeof metadataValidator>;
export type Decision = Infer<typeof decisionValidator>;
export type InstanceStatus = Infer<typeof instanceStatusValidator>;
export type ElevationStatus = Infer<typeof elevationStatusValidator>;

/**
 * Throw a machine-readable error. `code` is a stable identifier callers can
 * branch on via `ConvexError.data.code`; `message` is for humans.
 */
export function fail(code: string, message: string): never {
  throw new ConvexError({code, message});
}

export interface AuditEvent {
  eventType: string;
  agentId?: Id<'agents'> | null;
  instanceId?: Id<'instances'> | null;
  actingFor?: string | null;
  orgCode?: string | null;
  scopesUsed?: string[] | null;
  decision?: Decision | null;
  correlationId?: string | null;
  detail?: Metadata;
}

/**
 * Append one row to the audit log. Returns the correlationId (generated if
 * not supplied) so related events can share one.
 */
export async function writeAudit(
  ctx: MutationCtx,
  event: AuditEvent
): Promise<string> {
  const correlationId = event.correlationId ?? crypto.randomUUID();
  await ctx.db.insert('auditLog', {
    at: Date.now(),
    eventType: event.eventType,
    agentId: event.agentId ?? null,
    instanceId: event.instanceId ?? null,
    actingFor: event.actingFor ?? null,
    orgCode: event.orgCode ?? null,
    scopesUsed: event.scopesUsed ?? null,
    decision: event.decision ?? null,
    correlationId,
    detail: event.detail ?? {}
  });
  return correlationId;
}

/**
 * The status an instance behaves as right now: a stored "running" status
 * past its expiry counts as "expired" (invariant I5), even if no mutation
 * has materialized that yet.
 */
export function effectiveInstanceStatus(
  instance: Pick<Doc<'instances'>, 'status' | 'expiresAt'>,
  now: number
): InstanceStatus {
  if (instance.status === 'running' && instance.expiresAt <= now) {
    return 'expired';
  }
  return instance.status;
}

/**
 * The status an elevation request behaves as right now. An approved grant past
 * its expiry reads as "expired" (invariant I6) without mutating the stored row,
 * exactly mirroring {@link effectiveInstanceStatus}. Pending/denied/expired
 * statuses are returned unchanged.
 */
export function effectiveElevationStatus(
  row: Pick<Doc<'elevationRequests'>, 'status' | 'expiresAt'>,
  now: number
): ElevationStatus {
  if (row.status === 'approved' && row.expiresAt <= now) {
    return 'expired';
  }
  return row.status;
}
