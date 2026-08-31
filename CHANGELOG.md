<!-- Ideally, this should get auto-generated via tools like [auto-changelog](https://github.com/CookPete/auto-changelog). Eventually, this will get set up as part of the repository template. -->

## 0.1.0

Initial release of the Kinde agent auth Convex component.

- **Agent registry & instances** — register, suspend, reactivate, and configure M2M agents mapped to Kinde `client_id`s, and start/track per-run instances with expiry.
- **Kinde JWKS verification & `verifyCaller`** — verify Kinde RS256 access tokens against a cached, rotation-aware JWKS; `verifyCaller` is the stable verification seam returning a `VerifiedAgent`.
- **Reactive revocation overlay** — a global → org → agent → instance kill switch that denies on the next call regardless of token expiry.
- **HMAC-signed delegations & scope intersection** — attenuation-only scope delegations, verifiable without external calls, with a standalone, exhaustively-tested scope intersection.
- **`authz.can` decision pipeline & tenant policies** — a single decision pipeline returning machine-readable allow/deny reasons, with per-tenant policy overrides.
- **Human-in-the-loop elevation** — request/approve/deny scope elevation that augments a single instance's effective scopes until expiry.
- **Audit query** — an append-only audit log of every decision with a paginated, filterable, read-only query.
- **App-mounted HTTP routes** — `registerRoutes` mounts token-introspection and human-approval webhook endpoints in the consuming app's `convex/http.ts`.
- **Example app** — a runnable reference app and end-to-end integration test covering the full agent lifecycle.
