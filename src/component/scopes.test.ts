import {describe, expect, test} from 'vitest';
import {intersectScopes} from './scopes.js';

/** True if every element of `subset` is present in `superset`. */
function isSubsetOf(subset: readonly string[], superset: readonly string[]) {
  const set = new Set(superset);
  return subset.every((item) => set.has(item));
}

describe('intersectScopes', () => {
  test('identical sets return the full set (sorted, de-duplicated)', () => {
    expect(intersectScopes(['read', 'write'], ['read', 'write'], null)).toEqual(
      ['read', 'write']
    );
  });

  test('partial overlap returns only the common scopes', () => {
    expect(
      intersectScopes(
        ['read', 'write', 'admin'],
        ['write', 'admin', 'delete'],
        null
      )
    ).toEqual(['admin', 'write']);
  });

  test('disjoint sets return empty', () => {
    expect(intersectScopes(['read'], ['write'], null)).toEqual([]);
  });

  test('an empty input on any side collapses the result to empty', () => {
    expect(intersectScopes([], ['read'], null)).toEqual([]);
    expect(intersectScopes(['read'], [], null)).toEqual([]);
    expect(intersectScopes(['read'], ['read'], [])).toEqual([]);
  });

  test('a null override is skipped, never widening the result', () => {
    expect(intersectScopes(['read', 'write'], ['read', 'write'], null)).toEqual(
      ['read', 'write']
    );
  });

  test('an override narrows further but cannot introduce new scopes', () => {
    // "admin" is in the override but not in agent ∩ delegation, so it is absent.
    expect(
      intersectScopes(
        ['read', 'write', 'admin'],
        ['read', 'write', 'admin'],
        ['read', 'admin', 'superuser']
      )
    ).toEqual(['admin', 'read']);
  });

  test('duplicates within an input do not duplicate the output', () => {
    expect(
      intersectScopes(
        ['read', 'read', 'write'],
        ['read', 'write', 'write'],
        null
      )
    ).toEqual(['read', 'write']);
  });

  test('output ordering is stable regardless of input ordering', () => {
    expect(intersectScopes(['c', 'a', 'b'], ['b', 'c', 'a'], null)).toEqual([
      'a',
      'b',
      'c'
    ]);
  });

  test('I1: the result is a subset of every input and never wider', () => {
    const cases: Array<{
      agent: string[];
      delegation: string[];
      override: string[] | null;
    }> = [
      {agent: [], delegation: [], override: null},
      {agent: ['a', 'b', 'c'], delegation: ['b', 'c', 'd'], override: null},
      {agent: ['a', 'b'], delegation: ['x', 'y'], override: null},
      {
        agent: ['a', 'b', 'c'],
        delegation: ['a', 'b', 'c'],
        override: ['a', 'b']
      },
      {
        agent: ['read', 'write', 'admin'],
        delegation: ['write', 'admin'],
        override: ['admin', 'extra']
      },
      {agent: ['a'], delegation: ['a'], override: []}
    ];
    for (const {agent, delegation, override} of cases) {
      const result = intersectScopes(agent, delegation, override);
      // Subset of each input (attenuation only).
      expect(isSubsetOf(result, agent)).toBe(true);
      expect(isSubsetOf(result, delegation)).toBe(true);
      if (override !== null) {
        expect(isSubsetOf(result, override)).toBe(true);
      }
      // Never wider than the smallest constraining input.
      const bound = Math.min(
        new Set(agent).size,
        new Set(delegation).size,
        override === null ? Infinity : new Set(override).size
      );
      expect(result.length).toBeLessThanOrEqual(bound);
    }
  });
});
