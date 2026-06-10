import {defineApp} from 'convex/server';
import agentAuth from '@kinde-oss/kinde-convex-agent-auth/convex.config.js';

const app = defineApp();
app.use(agentAuth);

export default app;
