/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    agents: {
      get: FunctionReference<
        "query",
        "internal",
        { agentId: string },
        {
          _creationTime: number;
          _id: string;
          allowedTools: Array<string>;
          kind: "autonomous" | "supervised";
          kindeClientId: string | null;
          metadata: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          name: string;
          orgCode: string | null;
          ownerId: string | null;
          ownerKind: "user" | "org" | "platform";
          scopes: Array<string>;
          slug: string;
          status: "active" | "suspended";
        } | null,
        Name
      >;
      list: FunctionReference<
        "query",
        "internal",
        {
          limit?: number;
          orgCode?: string | null;
          status?: "active" | "suspended";
        },
        Array<{
          _creationTime: number;
          _id: string;
          allowedTools: Array<string>;
          kind: "autonomous" | "supervised";
          kindeClientId: string | null;
          metadata: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          name: string;
          orgCode: string | null;
          ownerId: string | null;
          ownerKind: "user" | "org" | "platform";
          scopes: Array<string>;
          slug: string;
          status: "active" | "suspended";
        }>,
        Name
      >;
      reactivate: FunctionReference<
        "mutation",
        "internal",
        { agentId: string },
        null,
        Name
      >;
      register: FunctionReference<
        "mutation",
        "internal",
        {
          allowedTools: Array<string>;
          kind: "autonomous" | "supervised";
          kindeClientId?: string | null;
          metadata?: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          name: string;
          orgCode?: string | null;
          ownerId?: string | null;
          ownerKind: "user" | "org" | "platform";
          scopes: Array<string>;
          slug: string;
        },
        string,
        Name
      >;
      setPolicy: FunctionReference<
        "mutation",
        "internal",
        { agentId: string; allowedTools: Array<string>; scopes: Array<string> },
        null,
        Name
      >;
      suspend: FunctionReference<
        "mutation",
        "internal",
        { agentId: string; reason?: string },
        null,
        Name
      >;
    };
    config: {
      get: FunctionReference<
        "query",
        "internal",
        {},
        { audience: string | null; domain: string; mode: "test" | "live" },
        Name
      >;
    };
    instances: {
      complete: FunctionReference<
        "mutation",
        "internal",
        { instanceId: string },
        "running" | "completed" | "revoked" | "expired",
        Name
      >;
      get: FunctionReference<
        "query",
        "internal",
        { instanceId: string },
        {
          _creationTime: number;
          _id: string;
          actingForSubject: string | null;
          agentId: string;
          createdAt: number;
          expiresAt: number;
          orgCode: string | null;
          runId: string;
          status: "running" | "completed" | "revoked" | "expired";
        } | null,
        Name
      >;
      listActive: FunctionReference<
        "query",
        "internal",
        { agentId?: string; limit?: number; orgCode?: string | null },
        Array<{
          _creationTime: number;
          _id: string;
          actingForSubject: string | null;
          agentId: string;
          createdAt: number;
          expiresAt: number;
          orgCode: string | null;
          runId: string;
          status: "running" | "completed" | "revoked" | "expired";
        }>,
        Name
      >;
      start: FunctionReference<
        "mutation",
        "internal",
        {
          actingForSubject?: string | null;
          agentId: string;
          expiresAt: number;
          orgCode?: string | null;
          runId: string;
        },
        string,
        Name
      >;
    };
    jwks: {
      get: FunctionReference<
        "query",
        "internal",
        {},
        {
          _creationTime: number;
          _id: string;
          domain: string;
          fetchedAt: number;
          keys: Array<Record<string, string | Array<string>>>;
        } | null,
        Name
      >;
      refresh: FunctionReference<
        "action",
        "internal",
        {},
        Array<Record<string, string | Array<string>>>,
        Name
      >;
    };
    revocations: {
      check: FunctionReference<
        "query",
        "internal",
        { agentId?: string; instanceId?: string; orgCode?: string },
        {
          _creationTime: number;
          _id: string;
          createdAt: number;
          reason: string;
          targetId: string | null;
          targetKind: "instance" | "agent" | "org" | "global";
        } | null,
        Name
      >;
      clear: FunctionReference<
        "mutation",
        "internal",
        {
          targetId?: string | null;
          targetKind: "instance" | "agent" | "org" | "global";
        },
        number,
        Name
      >;
      revoke: FunctionReference<
        "mutation",
        "internal",
        {
          reason?: string;
          targetId?: string | null;
          targetKind: "instance" | "agent" | "org" | "global";
        },
        string,
        Name
      >;
    };
    verification: {
      check: FunctionReference<
        "mutation",
        "internal",
        {
          expectedOrgCode?: string;
          kindeClientId: string | null;
          orgCode: string | null;
          subject: string;
          tokenScopes: Array<string>;
        },
        | { agentId: string | null; allowed: true; correlationId: string }
        | {
            allowed: false;
            code: string;
            correlationId: string;
            reason: string;
          },
        Name
      >;
      recordRejection: FunctionReference<
        "mutation",
        "internal",
        { code: string; reason: string },
        string,
        Name
      >;
    };
  };
