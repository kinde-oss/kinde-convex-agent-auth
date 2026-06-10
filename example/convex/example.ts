import {query} from './_generated/server.js';
import {components} from './_generated/api.js';
import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
import {v} from 'convex/values';

export const agentAuth = new AgentAuth(components.agentAuth);

export const health = query({
  args: {},
  returns: v.string(),
  handler: async () => 'ok'
});
