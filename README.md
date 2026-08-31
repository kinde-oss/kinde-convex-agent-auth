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

## Security model

Read this before exposing any of this component to the network. Its functions are raw machinery with **no authentication of their own** — the host app is the security boundary.

1. **Component mutations are not authenticated.** A Convex component cannot see the host app's auth context (`ctx.auth`), so every mutation and query here is callable by whatever surface the host app exposes. Nothing in the component checks _who_ is calling; that is the app's job. Treat each function as machinery to wrap, not an endpoint to expose.

2. **Admin-only functions — never expose these publicly.** Wrap each in an app-layer function that authenticates an admin first: `agents.register`, `agents.setPolicy`, `delegations.issue`, `elevation.approve`, `elevation.deny`, `revocations.revoke`, `revocations.clear`, `policies.setTenantPolicy`, and `instances.start`. For `delegations.issue` in particular, the app must verify that the signed-in Kinde user session matches `issuerSubject` before issuing — the HMAC proves the stored row was not tampered with after issue, **not** that the human actually consented to the delegation.

3. **Agent-facing endpoints must use `authorize()` exclusively.** Never call `authz.can` from a public surface with the caller args omitted: with no caller identity, `can` authorizes any valid path that can reach the `instanceId` without binding the decision to the JWT caller — the classic confused-deputy bug. The caller-binding guard (`caller_instance_mismatch`) only protects you when identity is threaded in, and `authorize()` always threads it in (the verified `agentId` / `orgCode` / `subject`). Agent tool checks go through `authorize()`, full stop.

4. **The elevation HTTP route fails closed.** `POST /agent/elevation/respond` returns **501** unless you mount it with an `authorizeApprover` hook. That hook must return an approver subject extracted from a **verified human session** (e.g. a Kinde user access token), never from the request body — the body is attacker-controlled and is never read for approver identity. The hook owns its own token verification, so it must check the `aud` claim as well as the signature and issuer — see [Elevation and the approval route](#elevation-and-the-approval-route). Verifying only signature and issuer accepts every token in your Kinde tenant, agent M2M tokens included, as an approver.

5. **`instances.start` runs only after token verification.** Start an instance only inside an action that has already verified the agent's token. `actingForSubject` asserts who the agent acts for and selects which delegation applies in `authz.can`; it must come from a delegation/consent flow, not from raw client input.

6. **Production checklist:**
   - [ ] `KINDE_AUDIENCE` is set (**required in live mode**) so a valid token minted for another API in the same Kinde tenant cannot be replayed here.
   - [ ] Org-scoped M2M applications run with `requireOrgCode: true`. Note the automatic enforcement for org-bound agents: an agent registered with an `orgCode` rejects an org-less token with `org_code_required_for_org_agent` even without this flag.
   - [ ] `enforceTokenScopes: true` so a shrunk Kinde M2M scope set and `agents.scopes` cannot drift apart silently.
   - [ ] `requireRegisteredAgent` left at its default `true` on any public verify surface. The `false` setting is for introspection tooling only — never for an endpoint that treats the result as a trusted agent.

## Integration

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
| `KINDE_AUDIENCE` | required in live mode | Expected `aud` claim for M2M tokens. Required when `MODE` is `live` (`config.get` fails with `kinde_audience_required_in_live` if unset); optional in `test` mode. Prevents cross-audience token replay within your Kinde tenant. |
| `DELEGATION_SIGNING_SECRET` | yes | Secret used to HMAC-sign delegations. |
| `MODE` | no | `test` relaxes external calls for local development; defaults to `live`. |

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

This exposes `POST /agent/verify` (token introspection) and `POST /agent/elevation/respond` (the human-approval webhook). `/agent/verify` works out of the box; **the elevation route returns 501 until you mount it with an `authorizeApprover` hook** (see [Elevation and the approval route](#elevation-and-the-approval-route)). See `RegisterRoutesOptions` for `pathPrefix` and the hook.

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

Pass `enforceTokenScopes: true` to `authorize()` (or `verifyCaller`) to feed the caller's live Kinde token scopes into the decision as an additional attenuating input, so an action outside the token's scopes is denied even if it is within `agents.scopes`. It is attenuation-only and defaults to off (byte-for-byte unchanged).

### Delegations

`delegations.issue` mints an HMAC-signed, **attenuation-only** grant from a principal (a Kinde user or org) to an agent:

- **Scope-subset rule.** Every requested scope must already be in the agent's `scopes`. Issuing a scope the agent was never granted is rejected with `scopes_exceed_agent` (the offending scopes are listed in the message). A delegation can only ever narrow authority, never widen it.
- **Ambiguous delegations.** When more than one signature-valid, unrevoked, unexpired delegation matches the same agent + `actingForSubject`, the one with the newest `expiresAt` wins. The choice is deterministic (it never depends on insertion order) and is still intersected with the agent's scopes, so it stays attenuation-safe.
- **Signatures are re-verified at decision time.** `authz.can` re-checks each delegation's HMAC before honoring it, so a tampered or directly-inserted row is skipped and audited as `delegation.signature_invalid` regardless of how it entered the table. The signature proves integrity, not human consent — see point 2 of the [security model](#security-model).

### Elevation and the approval route

When an agent hits a scope wall it files an `elevation.request`; a human approves or denies it, and an approved, unexpired elevation augments **that one instance's** effective scopes for the approved action (never beyond `approvedScopes`).

Approvals come through `POST /agent/elevation/respond`, which **returns 501 unless mounted with an `authorizeApprover` hook**. The hook returns the approver's subject from a verified human session (e.g. a Kinde user access token); the request body is never trusted for approver identity. See `example/convex/http.ts` for a hook that verifies a Kinde user token's **signature, issuer and audience** against the tenant JWKS.

The hook runs without a Convex ctx, so it cannot read the component's config — it reads `KINDE_DOMAIN` and `KINDE_AUDIENCE` from the app's own environment and applies the same audience rule the component applies in `config.get`: **`KINDE_AUDIENCE` is required in live mode** (the hook rejects with `kinde_audience_required_in_live` when it is unset), and a token whose `aud` is wrong — or absent — is rejected with `invalid_audience`. Without that check, any valid token from your Kinde tenant, including an agent's own M2M token, would authenticate an approver.

### API reference notes

| Field | Where | Status |
| --- | --- | --- |
| `resource` | `authz.can` / `authorize()` | **Audit metadata only.** Recorded on the decision's audit row but not evaluated in the allow/deny decision. Do not rely on it for ABAC or resource-scoping. |
| `resources` | `delegations.issue` | **Audit metadata only.** Stored and covered by the delegation signature but not evaluated in any decision. Do not rely on it for ABAC. |

**Limitations.** Authorization decisions are action/scope-based only today. Resource binding is **not** implemented: the `resource`/`resources` fields above are recorded for audit but never gate a decision, so do not assume resource-level enforcement exists.

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
