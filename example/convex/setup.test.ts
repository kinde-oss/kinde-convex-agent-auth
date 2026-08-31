/// <reference types="vite/client" />
import {test} from 'vitest';
import {convexTest} from 'convex-test';
import schema from './schema.js';
import component from '@kinde-oss/kinde-convex-agent-auth/test';

const modules = import.meta.glob('./**/*.*s');

// When users want to write tests that use the component, they need to
// explicitly register it with its schema and modules.
export function initConvexTest() {
  const t = convexTest(schema, modules);
  component.register(t);
  return t;
}

test('setup', () => {});
