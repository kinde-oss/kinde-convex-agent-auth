/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as agents from "../agents.js";
import type * as audit from "../audit.js";
import type * as authz from "../authz.js";
import type * as config from "../config.js";
import type * as delegations from "../delegations.js";
import type * as elevation from "../elevation.js";
import type * as helpers from "../helpers.js";
import type * as instances from "../instances.js";
import type * as jwks from "../jwks.js";
import type * as policies from "../policies.js";
import type * as revocations from "../revocations.js";
import type * as scopes from "../scopes.js";
import type * as validators from "../validators.js";
import type * as verification from "../verification.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";
import { anyApi, componentsGeneric } from "convex/server";

const fullApi: ApiFromModules<{
  agents: typeof agents;
  audit: typeof audit;
  authz: typeof authz;
  config: typeof config;
  delegations: typeof delegations;
  elevation: typeof elevation;
  helpers: typeof helpers;
  instances: typeof instances;
  jwks: typeof jwks;
  policies: typeof policies;
  revocations: typeof revocations;
  scopes: typeof scopes;
  validators: typeof validators;
  verification: typeof verification;
}> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
> = anyApi as any;

export const components = componentsGeneric() as unknown as {};
