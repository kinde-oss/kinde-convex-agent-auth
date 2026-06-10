/// <reference types="vite/client" />
import {expect, test} from 'vitest';
import {convexTest} from 'convex-test';
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import schema from './schema.js';

export const modules = import.meta.glob('./**/*.*s');

export function initConvexTest() {
  const t = convexTest(schema, modules);
  return t;
}

/**
 * Assert that a component call rejects with a machine-readable ConvexError
 * carrying the given `code`. convex-test re-serializes `ConvexError.data`
 * to a JSON string across the function boundary, so both forms are handled.
 */
export async function expectFail(
  promise: Promise<unknown>,
  code: string
): Promise<void> {
  let error: unknown;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  expect(error, `expected ConvexError with code "${code}"`).toBeInstanceOf(
    ConvexError
  );
  const raw = (error as ConvexError<Value>).data;
  const data = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
  expect((data as {code: string}).code).toBe(code);
}

test('setup', () => {});
