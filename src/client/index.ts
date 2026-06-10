import type {ComponentApi} from '../component/_generated/component.js';

/**
 * Client for the Kinde agent auth component.
 *
 * Construct it with the component reference from your app's generated
 * `components` object:
 *
 * ```ts
 * import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
 * import {components} from './_generated/api.js';
 *
 * export const agentAuth = new AgentAuth(components.agentAuth);
 * ```
 *
 * Methods wrapping the component API are added in later phases.
 */
export class AgentAuth {
  constructor(public readonly component: ComponentApi) {}
}
