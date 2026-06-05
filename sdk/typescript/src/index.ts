/**
 * @agentauth/sdk — The open-source identity & authorization plane for AI agents.
 *
 * @packageDocumentation
 */

export { AgentAuthClient } from "./client.js";
export type {
  AgentAuthClientOptions,
  IssueIdentityRequest,
  IssueIdentityResponse,
  CreateEnvelopeRequest,
  EnvelopeResponse,
  MintTokenRequest,
  AccessTokenResponse,
  DelegateRequest,
  ToolScope,
  AgentAuthError,
} from "./client.js";

export { AgenticEnvelope, ToolPermission, EnvelopeVerifier } from "./envelope.js";
export type { EnvelopeClaims } from "./envelope.js";

export {
  agentAuthMiddleware,
  requireToolPermission,
  getEnvelopeFromRequest,
} from "./middleware.js";
export type {
  AgentAuthMiddlewareOptions,
  AgentAuthRequest,
} from "./middleware.js";

/** The library version. */
export const VERSION = "0.1.0";
