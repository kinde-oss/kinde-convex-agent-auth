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
  };
