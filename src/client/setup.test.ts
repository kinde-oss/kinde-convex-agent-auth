/// <reference types="vite/client" />
import {expect, test} from 'vitest';
import {convexTest} from 'convex-test';
import type {TestConvex} from 'convex-test';
import {defineSchema} from 'convex/server';
import type {
  FunctionReference,
  FunctionVisibility,
  GenericSchema,
  SchemaDefinition
} from 'convex/server';
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import {register} from '../test.js';
import type {RunFullCtx} from './index.js';

const modules = import.meta.glob('./**/*.*s');

export function initConvexTest() {
  const t = convexTest(defineSchema({}), modules);
  register(t);
  return t;
}

type Args = Record<string, unknown>;

/**
 * Adapt a TestConvex instance to the ctx shape the client layer expects,
 * mirroring how an app action would call into the component.
 */
export function makeRunCtx(
  t: TestConvex<SchemaDefinition<GenericSchema, boolean>>
): RunFullCtx {
  const runQuery = async (
    ref: FunctionReference<'query', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.query(ref, args ?? {});
  const runMutation = async (
    ref: FunctionReference<'mutation', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.mutation(ref, args ?? {});
  const runAction = async (
    ref: FunctionReference<'action', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.action(ref, args ?? {});
  return {
    runQuery: runQuery as RunFullCtx['runQuery'],
    runMutation: runMutation as RunFullCtx['runMutation'],
    runAction: runAction as RunFullCtx['runAction']
  };
}

/**
 * Assert that a call rejects with a machine-readable ConvexError carrying
 * the given `code`. Handles both object data (errors thrown by the client
 * layer) and JSON-string data (errors re-serialized by convex-test).
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
