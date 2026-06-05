/**
 * AgentAuth middleware for Express, Hono, Fastify, and other Node.js frameworks.
 *
 * @example Express
 * ```typescript
 * import express from "express";
 * import { agentAuthMiddleware } from "@agentauth/sdk";
 *
 * const app = express();
 * app.use(agentAuthMiddleware({ publicKeyPem: process.env.AGENTAUTH_PUBLIC_KEY }));
 *
 * app.post("/tools/github/create_issue", (req, res) => {
 *   const envelope = req.agentEnvelope!;
 *   console.log(`Agent ${envelope.agentId} creating issue`);
 *   res.json({ ok: true });
 * });
 * ```
 *
 * @example Hono
 * ```typescript
 * import { Hono } from "hono";
 * import { agentAuthMiddleware } from "@agentauth/sdk";
 *
 * const app = new Hono();
 * app.use("*", agentAuthMiddleware({ publicKeyPem: process.env.AGENTAUTH_PUBLIC_KEY }));
 * ```
 */

import { AgenticEnvelope, EnvelopeVerifier } from "./envelope.js";

/** Paths that skip AgentAuth verification. */
const DEFAULT_SKIP_PATHS = ["/healthz", "/readyz", "/metrics", "/favicon.ico"];

/** Options for configuring the AgentAuth middleware. */
export interface AgentAuthMiddlewareOptions {
  /** ECDSA P-256 public key PEM for offline verification. */
  publicKeyPem?: string;
  /** AgentAuth server URL for online verification (used if publicKeyPem not set). */
  serverUrl?: string;
  /** API key for the AgentAuth server. */
  apiKey?: string;
  /** JWT issuer to expect. Default "agentauth". */
  issuer?: string;
  /**
   * If true (default), reject requests that don't have an X-Agent-Envelope header.
   * Set to false to allow unauthenticated requests (envelope added to context if present).
   */
  requireEnvelope?: boolean;
  /** URL path prefixes to skip. Default: ["/healthz", "/readyz", "/metrics"]. */
  skipPaths?: string[];
  /** Custom denial handler. */
  onDeny?: (req: AgentAuthRequest, res: AgentAuthResponse, reason: string) => void;
}

/** Minimal request interface compatible with Express, Hono, and custom servers. */
export interface AgentAuthRequest {
  headers: Record<string, string | string[] | undefined>;
  path?: string;
  url?: string;
  method?: string;
  /** Injected by middleware after successful verification. */
  agentEnvelope?: AgenticEnvelope;
  /** Injected by middleware — the verified agent's SPIFFE ID. */
  agentId?: string;
}

/** Minimal response interface for sending denial responses. */
export interface AgentAuthResponse {
  status(code: number): AgentAuthResponse;
  json(body: unknown): void;
  set?(header: string, value: string): AgentAuthResponse;
  header?(header: string, value: string): AgentAuthResponse;
}

type NextFunction = (err?: unknown) => void;

type ExpressMiddleware = (
  req: AgentAuthRequest,
  res: AgentAuthResponse,
  next: NextFunction,
) => void | Promise<void>;

/**
 * Returns Express/Connect-compatible middleware that enforces AgentAuth
 * identity verification on every request.
 *
 * Works with Express, Connect, Fastify (via express-compatibility), Hono, and others.
 */
export function agentAuthMiddleware(options: AgentAuthMiddlewareOptions = {}): ExpressMiddleware {
  const {
    requireEnvelope = true,
    skipPaths = DEFAULT_SKIP_PATHS,
    issuer = "agentauth",
    onDeny,
  } = options;

  const verifier = new EnvelopeVerifier({
    publicKeyPem: options.publicKeyPem,
    issuer,
  });

  return async function agentAuth(
    req: AgentAuthRequest,
    res: AgentAuthResponse,
    next: NextFunction,
  ): Promise<void> {
    const path = req.path ?? req.url ?? "";

    // Skip configured paths
    if (skipPaths.some((prefix) => path.startsWith(prefix))) {
      return next();
    }

    // Extract the envelope token
    const rawHeader = req.headers["x-agent-envelope"];
    const envelopeToken = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;

    if (!envelopeToken) {
      if (requireEnvelope) {
        return deny(res, onDeny, req, "missing X-Agent-Envelope header", "MISSING_ENVELOPE");
      }
      return next();
    }

    // Verify the envelope
    let envelope: AgenticEnvelope;
    try {
      envelope = await verifier.verify(envelopeToken);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "envelope verification failed";
      return deny(res, onDeny, req, reason, "INVALID_ENVELOPE");
    }

    // Inject into request
    req.agentEnvelope = envelope;
    req.agentId = envelope.agentId;

    return next();
  };
}

/**
 * Middleware factory that also enforces a specific tool permission.
 * Use this for route-level permission checks.
 *
 * @example
 * ```typescript
 * app.post(
 *   "/tools/database/query",
 *   requireToolPermission("database.query", "read"),
 *   (req, res) => { ... }
 * );
 * ```
 */
export function requireToolPermission(
  tool: string,
  operation: string,
): ExpressMiddleware {
  return function (req: AgentAuthRequest, res: AgentAuthResponse, next: NextFunction) {
    const envelope = req.agentEnvelope;
    if (!envelope) {
      return deny(res, undefined, req, "no agent envelope in request", "NO_ENVELOPE");
    }
    if (!envelope.hasToolPermission(tool, operation)) {
      return deny(
        res,
        undefined,
        req,
        `agent not permitted to ${operation} ${tool}`,
        "INSUFFICIENT_SCOPE",
      );
    }
    return next();
  };
}

/**
 * Extract the verified AgenticEnvelope from an Express/Hono/Fastify request.
 *
 * @example
 * ```typescript
 * app.post("/tools/github/issues", (req, res) => {
 *   const envelope = getEnvelopeFromRequest(req);
 *   console.log("Delegated by:", envelope?.delegatorId);
 * });
 * ```
 */
export function getEnvelopeFromRequest(
  req: AgentAuthRequest,
): AgenticEnvelope | undefined {
  return req.agentEnvelope;
}

function deny(
  res: AgentAuthResponse,
  onDeny: AgentAuthMiddlewareOptions["onDeny"] | undefined,
  req: AgentAuthRequest,
  reason: string,
  code: string,
): void {
  if (onDeny) {
    onDeny(req, res, reason);
    return;
  }
  setHeader(res, "Content-Type", "application/json");
  res.status(403).json({
    error: "forbidden",
    code,
    message: reason,
  });
}

function setHeader(res: AgentAuthResponse, key: string, value: string): void {
  if (typeof res.set === "function") {
    res.set(key, value);
  } else if (typeof res.header === "function") {
    res.header(key, value);
  }
}
