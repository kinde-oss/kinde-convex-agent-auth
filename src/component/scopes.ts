/**
 * The effective scope set for an agent acting under a delegation, optionally
 * narrowed by a tenant policy's `allowedToolsOverride` and by the caller's live
 * Kinde token scopes.
 *
 * This is pure attenuation (invariant I1): the result is the intersection of
 * every input, so it is always a subset of each one and can never be wider
 * than any single input. A `null` (or omitted) override / `callerTokenScopes`
 * means "no such gate" and is skipped entirely (it never widens the result) —
 * so omitting `callerTokenScopes` leaves the result byte-for-byte identical to
 * the three-argument behavior.
 *
 * The output is de-duplicated and sorted so callers get a stable shape
 * regardless of input ordering. This function is consumed by `authz.can`, so it
 * is kept standalone and free of any Convex dependency.
 */
export function intersectScopes(
  agentScopes: readonly string[],
  delegationScopes: readonly string[],
  allowedToolsOverride: readonly string[] | null,
  callerTokenScopes?: readonly string[] | null
): string[] {
  const delegationSet = new Set(delegationScopes);
  const overrideSet =
    allowedToolsOverride === null ? null : new Set(allowedToolsOverride);
  const tokenSet =
    callerTokenScopes === null || callerTokenScopes === undefined
      ? null
      : new Set(callerTokenScopes);
  const effective = new Set<string>();
  // Iterating the agent's scopes guarantees the result is a subset of the
  // agent's grant; the membership gates do the same for the other inputs.
  for (const scope of agentScopes) {
    if (
      delegationSet.has(scope) &&
      (overrideSet === null || overrideSet.has(scope)) &&
      (tokenSet === null || tokenSet.has(scope))
    ) {
      effective.add(scope);
    }
  }
  return [...effective].sort();
}
