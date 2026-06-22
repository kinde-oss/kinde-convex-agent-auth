# Kinde Convex Agent Auth

The Kinde agent auth component for [Convex](https://convex.dev) — agent identity, delegation, authorization, human-in-the-loop elevation, reactive revocation, and audit, backed by Kinde M2M.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

This package is a Convex component plus a thin client. Day-to-day development:

- `npm run build:codegen` — regenerate component code and type-check the build.
- `npm test` — run the full `convex-test` + `vitest` suite (with type-checking).
- `npm run typecheck` — type-check the package and the example app.
- `npm run lint` — run ESLint.
- `npm run format` — run Prettier over the repo.

The `example/` directory is a runnable reference app that exercises the whole component end-to-end; `example/convex/example.ts` shows the intended usage of each function and `example/convex/e2e.test.ts` tells the full story as one test.

### Initial set up

1. Clone the repository to your machine:

   ```bash
   git clone https://github.com/kinde-oss/kinde-convex-agent-auth.git
   ```

2. Go into the project:

   ```bash
   cd kinde-convex-agent-auth
   ```

3. Install the dependencies:

   ```bash
   npm install
   ```

## Usage

This component gives a Convex app a complete authorization story for autonomous and supervised agents: it registers agents against their Kinde M2M `client_id`, verifies their Kinde-issued RS256 access tokens, issues HMAC-signed scope delegations, decides every tool call through a single `authz.can` pipeline, supports human-in-the-loop scope elevation, enforces per-tenant policy with a reactive revocation kill switch, and writes an append-only audit trail of every decision.

### Install and wire up

Install the package:

```bash
npm i @kinde-oss/kinde-convex-agent-auth
```

Add the component to your app's `convex/convex.config.ts` and pass through its environment variables:

```ts
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
```

The component reads these environment variables:

| Variable | Required | Purpose |
| --- | --- | --- |
| `KINDE_DOMAIN` | yes | Your Kinde domain, e.g. `myapp.kinde.com` (no protocol). |
| `KINDE_AUDIENCE` | no | Expected `aud` claim for M2M tokens; skipped if unset. |
| `DELEGATION_SIGNING_SECRET` | yes | Secret used to HMAC-sign delegations. |
| `MODE` | no | `test` relaxes external calls for local development. |

Set them with `npx convex env set KINDE_DOMAIN myapp.kinde.com`, and so on.

Construct the client once:

```ts
// convex/agentAuth.ts
import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
import {components} from './_generated/api.js';

export const agentAuth = new AgentAuth(components.agentAuth);
```

Mount the HTTP routes in your `convex/http.ts` (the routes run in your app's context, where auth and env are available):

```ts
import {httpRouter} from 'convex/server';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-auth';
import {components} from './_generated/api.js';

const http = httpRouter();
registerRoutes(http, components.agentAuth);
export default http;
```

This exposes `POST /agent/verify` (token introspection) and `POST /agent/elevation/respond` (the human-approval webhook). See `RegisterRoutesOptions` for `pathPrefix` and the `authorizeApprover` step-up hook.

### `verifyCaller` — the stable contract

`verifyCaller` is the stable verification seam. **Its signature and the `VerifiedAgent` shape are additive-only within a major version** — sibling Kinde Convex components (e.g. the upcoming `kinde-convex-agent-billing`) plug into exactly this seam, so fields are only ever added, never changed or removed.

```ts
function verifyCaller(
  ctx: RunActionCtx,
  component: ComponentApi,
  token: string,
  options?: VerifyCallerOptions
): Promise<VerifiedAgent>;

interface VerifiedAgent {
  subject: string; // the token's `sub`, falling back to `azp` (M2M client id)
  agentId: string | null; // the registered agent for that client id, or null
  orgCode: string | null; // the trusted `org_code` claim (the only tenant source)
  scopes: string[]; // `scp` array, or `scope` split on spaces
  claims: Record<string, unknown>; // the full verified JWT payload
}
```

It verifies the token's signature against Kinde's cached JWKS (refreshing on key rotation), enforces issuer/audience, then applies the component's registry, org-binding, and revocation checks. Call it from an action (or the mounted `/agent/verify` route).

### Capabilities

| Layer | What it does |
| --- | --- |
| Agent registry | Register, suspend, and configure M2M agents mapped to Kinde `client_id`s. |
| Authentication | `verifyCaller` verifies Kinde RS256 JWTs against a cached, rotation-aware JWKS. |
| Delegation | HMAC-signed, attenuation-only scope delegations from a principal to an agent. |
| Authorization | A single `authz.can` pipeline returns machine-readable allow/deny decisions. |
| Elevation | Human-in-the-loop scope elevation that augments a single instance's effective scopes. |
| Multi-tenancy & revocation | Org binding plus a reactive revocation overlay (global → org → agent → instance kill switch). |
| Audit | Append-only audit log of every decision, with a paginated, filterable query. |

### Composes with billing

Other Kinde Convex components compose with this one through the `verifyCaller` seam: a sibling such as `kinde-convex-agent-billing` calls `verifyCaller` to resolve the agent identity, then layers its own concerns on top of the returned `VerifiedAgent`. Keep that contract additive and these components interoperate without importing each other's internals.

## Documentation

For details on integrating Kinde into your project, head over to the [Kinde docs](https://kinde.com/docs/) and the [developer tools](https://kinde.com/docs/developer-tools/) section 👍🏼.

## Publishing

The core team handles publishing.

## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
