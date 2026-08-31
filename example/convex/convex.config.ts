import {defineApp} from 'convex/server';
import {v} from 'convex/values';
import agentAuth from '@kinde-oss/kinde-convex-agent-auth/convex.config.js';

const app = defineApp({
  env: {
    KINDE_DOMAIN: v.string(),
    KINDE_AUDIENCE: v.optional(v.string()),
    DELEGATION_SIGNING_SECRET: v.string()
  }
});

app.use(agentAuth, {
  env: {
    KINDE_DOMAIN: app.env.KINDE_DOMAIN,
    KINDE_AUDIENCE: app.env.KINDE_AUDIENCE,
    DELEGATION_SIGNING_SECRET: app.env.DELEGATION_SIGNING_SECRET
  }
});

export default app;
