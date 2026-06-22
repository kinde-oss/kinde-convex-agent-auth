import {httpRouter} from 'convex/server';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-auth';
import {components} from './_generated/api.js';

const http = httpRouter();

// Default mount: `/agent/verify` and `/agent/elevation/respond`. With no
// authorizeApprover hook, the respond route takes approverSubject from the body
// and the app MUST protect the route by other means.
registerRoutes(http, components.agentAuth);

// A second mount demonstrating the documented step-up pattern: the app
// authenticates the human (here via an `X-Admin-Subject` header standing in for
// a real admin session) and supplies the approverSubject itself.
registerRoutes(http, components.agentAuth, {
  pathPrefix: '/agent-admin',
  authorizeApprover: async (request) => {
    const subject = request.headers.get('X-Admin-Subject');
    if (subject === null || subject.length === 0) {
      throw new Error('No authenticated admin.');
    }
    return subject;
  }
});

export default http;
