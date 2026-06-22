/**
 * The effective scope set for an agent acting under a delegation, optionally
 * narrowed by a tenant policy's `allowedToolsOverride`.
 *
 * This is pure attenuation (invariant I1): the result is the intersection of
 * every input, so it is always a subset of each one and can never be wider
 * than any single input. A `null` override means "no override" and is skipped
 * entirely (it never widens the result).
 *
 * The output is de-duplicated and sorted so callers get a stable shape
 * regardless of input ordering. This function is consumed by `authz.can` in
 * Phase 4, so it is kept standalone and free of any Convex dependency.
 */
export function intersectScopes(
  agentScopes: readonly string[],
  delegationScopes: readonly string[],
  allowedToolsOverride: readonly string[] | null
): string[] {
  const delegationSet = new Set(delegationScopes);
  const overrideSet =
    allowedToolsOverride === null ? null : new Set(allowedToolsOverride);
  const effective = new Set<string>();
  // Iterating the agent's scopes guarantees the result is a subset of the
  // agent's grant; the membership gates do the same for the other inputs.
  for (const scope of agentScopes) {
    if (
      delegationSet.has(scope) &&
      (overrideSet === null || overrideSet.has(scope))
    ) {
      effective.add(scope);
    }
  }
  return [...effective].sort();
}
