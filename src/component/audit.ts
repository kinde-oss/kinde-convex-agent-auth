import {v} from 'convex/values';
import {
  paginationOptsValidator,
  paginationResultValidator
} from 'convex/server';
import type {IndexRange} from 'convex/server';
import {paginator} from 'convex-helpers/server/pagination';
import {query as defineQuery} from './_generated/server.js';
import schema from './schema.js';

const auditDoc = schema.tables.auditLog.validator.extend({
  _id: v.id('auditLog'),
  _creationTime: v.number()
});

/**
 * The minimal shape of an index range builder positioned at the `at` field,
 * which is the trailing field of every auditLog index. Lets one helper apply
 * the optional time bounds regardless of which index was chosen.
 */
interface AtRangeBuilder extends IndexRange {
  gte(field: 'at', value: number): AtUpperBuilder;
  lte(field: 'at', value: number): IndexRange;
}
interface AtUpperBuilder extends IndexRange {
  lte(field: 'at', value: number): IndexRange;
}

/** Apply the inclusive `[startAt, endAt]` bounds on `at`, if supplied. */
function timeRange(
  q: AtRangeBuilder,
  startAt: number | undefined,
  endAt: number | undefined
): IndexRange {
  if (startAt !== undefined && endAt !== undefined) {
    return q.gte('at', startAt).lte('at', endAt);
  }
  if (startAt !== undefined) {
    return q.gte('at', startAt);
  }
  if (endAt !== undefined) {
    return q.lte('at', endAt);
  }
  return q;
}

/**
 * Read-only, paginated, filterable view over the audit log. NEVER writes —
 * the audit log is the source of truth (invariant I4).
 *
 * Filters are optional and combine with AND. The most selective available
 * index is chosen for the supplied equality filter, with the time range
 * applied on the trailing `at` field of that index:
 *   - agentId   → `by_agent`      (['agentId', 'at'])
 *   - orgCode   → `by_org_code`   (['orgCode', 'at'])
 *   - eventType → `by_event_type` (['eventType', 'at'])
 *   - otherwise → `by_at`         (['at'])
 * Any filters not covered by the chosen index are applied to the page in TS
 * (built-in `.paginate()` does not work in components, and `paginator` does
 * not support `.filter()`). `startAt`/`endAt` are both inclusive. Results are
 * returned newest-first.
 */
export const query = defineQuery({
  args: {
    paginationOpts: paginationOptsValidator,
    agentId: v.optional(v.id('agents')),
    orgCode: v.optional(v.string()),
    eventType: v.optional(v.string()),
    startAt: v.optional(v.number()),
    endAt: v.optional(v.number())
  },
  returns: paginationResultValidator(auditDoc),
  handler: async (ctx, args) => {
    const {agentId, orgCode, eventType, startAt, endAt} = args;
    const pager = paginator(ctx.db, schema).query('auditLog');

    const ordered =
      agentId !== undefined
        ? pager.withIndex('by_agent', (q) =>
            timeRange(q.eq('agentId', agentId), startAt, endAt)
          )
        : orgCode !== undefined
          ? pager.withIndex('by_org_code', (q) =>
              timeRange(q.eq('orgCode', orgCode), startAt, endAt)
            )
          : eventType !== undefined
            ? pager.withIndex('by_event_type', (q) =>
                timeRange(q.eq('eventType', eventType), startAt, endAt)
              )
            : pager.withIndex('by_at', (q) => timeRange(q, startAt, endAt));

    const result = await ordered.order('desc').paginate(args.paginationOpts);

    // Apply every supplied filter in TS so combined filters AND correctly even
    // when the chosen index only covers one of them. The index still provides
    // the selectivity; this is a defensive, read-only narrowing.
    const page = result.page.filter(
      (row) =>
        (agentId === undefined || row.agentId === agentId) &&
        (orgCode === undefined || row.orgCode === orgCode) &&
        (eventType === undefined || row.eventType === eventType) &&
        (startAt === undefined || row.at >= startAt) &&
        (endAt === undefined || row.at <= endAt)
    );

    return {...result, page};
  }
});
