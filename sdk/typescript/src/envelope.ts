/**
 * AgentAuth Agentic Identity Envelope — TypeScript implementation.
 *
 * The AgenticEnvelope is the core authorization container for AI agents.
 * It is a signed JWT carrying the agent's identity, declared intent, and
 * tool scope, and must be passed with every MCP tool call.
 */

/** The claims inside a signed envelope JWT. */
export interface EnvelopeClaims {
  /** SPIFFE ID of the entity that spawned this agent. */
  delegator_id: string;
  /** SPIFFE SVID of the executing agent. */
  agent_id: string;
  /** Unique identifier for this task execution. */
  task_id: string;
  /** Organization/tenant scope. */
  tenant_id: string;
  /** Session scope grouping related envelopes. */
  session_id: string;
  /** Human-readable task description. */
  declared_intent: string;
  /** The tools this agent is authorized to use. */
  tool_scope: Array<{
    tool: string;
    operations: string[];
    constraints?: Record<string, string>;
  }>;
  /** Reference to recorded user consent. */
  consent_ref?: string;
  /** Signed parent envelopes forming the delegation chain. */
  delegation_chain?: string[];
  /** JWT issued-at timestamp. */
  iat: number;
  /** JWT expiry timestamp. */
  exp: number;
  /** JWT unique identifier for revocation. */
  jti: string;
  /** Envelope format version. */
  ver: string;
  /** JWT issuer. */
  iss?: string;
  /** JWT subject (= agent_id). */
  sub?: string;
}

/** A single tool permission entry. */
export class ToolPermission {
  constructor(
    /** MCP tool name or glob pattern. */
    public readonly tool: string,
    /** Allowed operations. */
    public readonly operations: string[],
    /** Optional constraints. */
    public readonly constraints: Record<string, string> = {},
  ) {}

  /**
   * Check if this permission allows the given tool and operation.
   */
  allows(tool: string, operation: string): boolean {
    if (!matchesPattern(this.tool, tool)) return false;
    return this.operations.some((op) => op === "*" || op === operation);
  }

  toJSON() {
    const obj: Record<string, unknown> = {
      tool: this.tool,
      operations: this.operations,
    };
    if (Object.keys(this.constraints).length > 0) {
      obj.constraints = this.constraints;
    }
    return obj;
  }
}

/**
 * The Agentic Identity Envelope — the core authorization container for AI agents.
 *
 * Parse and verify an envelope from the X-Agent-Envelope header:
 *
 * @example
 * ```typescript
 * import { EnvelopeVerifier } from "@agentauth/sdk";
 *
 * const verifier = new EnvelopeVerifier({ publicKeyPem: PUBLIC_KEY_PEM });
 * const envelope = await verifier.verify(request.headers["x-agent-envelope"]);
 *
 * if (!envelope.hasToolPermission("database.query", "read")) {
 *   throw new Error("Agent not permitted to query database");
 * }
 * ```
 */
export class AgenticEnvelope {
  /** SPIFFE ID of the entity that spawned this agent. */
  readonly delegatorId: string;
  /** SPIFFE SVID of the executing agent. */
  readonly agentId: string;
  /** Unique task identifier. */
  readonly taskId: string;
  /** Organization/tenant scope. */
  readonly tenantId: string;
  /** Session scope. */
  readonly sessionId: string;
  /** Human-readable description of what the agent will do. */
  readonly declaredIntent: string;
  /** The tools this agent is authorized to use. */
  readonly toolScope: ToolPermission[];
  /** Reference to user consent record. */
  readonly consentRef: string;
  /** Signed parent envelopes forming the delegation chain. */
  readonly delegationChain: string[];
  /** Issuance Unix timestamp. */
  readonly issuedAt: number;
  /** Expiry Unix timestamp. */
  readonly expiresAt: number;
  /** Unique JWT ID for revocation. */
  readonly jti: string;
  /** Envelope format version. */
  readonly version: string;

  constructor(claims: EnvelopeClaims) {
    this.delegatorId = claims.delegator_id ?? "";
    this.agentId = claims.agent_id ?? claims.sub ?? "";
    this.taskId = claims.task_id ?? "";
    this.tenantId = claims.tenant_id ?? "";
    this.sessionId = claims.session_id ?? "";
    this.declaredIntent = claims.declared_intent ?? "";
    this.toolScope = (claims.tool_scope ?? []).map(
      (ts) => new ToolPermission(ts.tool, ts.operations, ts.constraints ?? {}),
    );
    this.consentRef = claims.consent_ref ?? "";
    this.delegationChain = claims.delegation_chain ?? [];
    this.issuedAt = claims.iat;
    this.expiresAt = claims.exp;
    this.jti = claims.jti ?? "";
    this.version = claims.ver ?? "1";
  }

  /** Returns true if the envelope has passed its expiration time. */
  get isExpired(): boolean {
    return Date.now() / 1000 > this.expiresAt;
  }

  /** Returns the number of delegation hops in this envelope. */
  get delegationDepth(): number {
    return this.delegationChain.length;
  }

  /**
   * Check whether this envelope grants the specified operation on the given tool.
   *
   * @param tool - Tool name (e.g. "filesystem.read", "github.issues.create")
   * @param operation - Operation (e.g. "read", "write", "delete")
   */
  hasToolPermission(tool: string, operation: string): boolean {
    return this.toolScope.some((perm) => perm.allows(tool, operation));
  }

  /** Returns a plain object representation of the envelope. */
  toJSON(): Record<string, unknown> {
    return {
      delegator_id: this.delegatorId,
      agent_id: this.agentId,
      task_id: this.taskId,
      tenant_id: this.tenantId,
      session_id: this.sessionId,
      declared_intent: this.declaredIntent,
      tool_scope: this.toolScope.map((ts) => ts.toJSON()),
      consent_ref: this.consentRef,
      delegation_chain: this.delegationChain,
      iat: this.issuedAt,
      exp: this.expiresAt,
      jti: this.jti,
      ver: this.version,
    };
  }
}

/** Options for EnvelopeVerifier. */
export interface EnvelopeVerifierOptions {
  /** ECDSA P-256 public key in PEM format. Used for offline verification. */
  publicKeyPem?: string;
  /** Expected JWT issuer. Default "agentauth". */
  issuer?: string;
}

/**
 * Verifies signed Agentic Identity Envelope JWTs.
 *
 * Use this in your MCP server or A2A endpoint to verify incoming envelopes
 * without calling the AgentAuth server (offline verification).
 *
 * @example
 * ```typescript
 * import { EnvelopeVerifier } from "@agentauth/sdk";
 *
 * const verifier = new EnvelopeVerifier({ publicKeyPem: process.env.AGENTAUTH_PUBLIC_KEY });
 *
 * // In your Express/Hono/Fastify middleware:
 * const envelope = await verifier.verify(req.headers["x-agent-envelope"]);
 * if (!envelope.hasToolPermission("github.issues", "write")) {
 *   res.status(403).json({ error: "insufficient_scope" });
 *   return;
 * }
 * ```
 */
export class EnvelopeVerifier {
  private readonly publicKeyPem?: string;
  private readonly issuer: string;

  constructor(options: EnvelopeVerifierOptions = {}) {
    this.publicKeyPem = options.publicKeyPem;
    this.issuer = options.issuer ?? "agentauth";
  }

  /**
   * Verify a signed envelope JWT and return the parsed envelope.
   *
   * @param token - The signed JWT string from the X-Agent-Envelope header.
   * @throws Error if the token is invalid, expired, or has a bad signature.
   */
  async verify(token: string): Promise<AgenticEnvelope> {
    if (!token) {
      throw new Error("envelope token is empty");
    }

    if (this.publicKeyPem) {
      return this.verifyWithKey(token);
    }

    // Fallback: decode without verification (development only)
    console.warn(
      "[AgentAuth] SECURITY WARNING: envelope verification is disabled " +
        "(no publicKeyPem configured). Do not use in production.",
    );
    return this.decodeUnverified(token);
  }

  private async verifyWithKey(token: string): Promise<AgenticEnvelope> {
    // Use Web Crypto API (available in Node.js 18+, browsers, Deno, Bun)
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("malformed JWT: expected 3 parts");
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Decode header
      const headerJson = base64UrlDecode(headerB64);
      const header = JSON.parse(headerJson) as { alg?: string; typ?: string };

      if (header.alg !== "ES256") {
        throw new Error(`unsupported algorithm: ${header.alg}`);
      }

      // Import the public key
      const pemBody = this.publicKeyPem!
        .replace(/-----BEGIN PUBLIC KEY-----/, "")
        .replace(/-----END PUBLIC KEY-----/, "")
        .replace(/\s+/g, "");
      const keyBytes = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
      const cryptoKey = await crypto.subtle.importKey(
        "spki",
        keyBytes,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );

      // Verify signature
      const signingInput = `${headerB64}.${payloadB64}`;
      const signatureBytes = Uint8Array.from(atob(base64UrlToBase64(signatureB64)), (c) =>
        c.charCodeAt(0),
      );
      const dataBytes = new TextEncoder().encode(signingInput);

      // Convert DER/compact signature to Web Crypto format
      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        cryptoKey,
        signatureBytes,
        dataBytes,
      );

      if (!valid) {
        throw new Error("envelope signature verification failed");
      }

      // Parse claims
      const payloadJson = base64UrlDecode(payloadB64);
      const claims = JSON.parse(payloadJson) as EnvelopeClaims;

      // Validate expiry
      if (Date.now() / 1000 > claims.exp) {
        throw new Error("envelope token has expired");
      }

      // Validate issuer
      if (claims.iss && claims.iss !== this.issuer) {
        throw new Error(`unexpected issuer: ${claims.iss}`);
      }

      return new AgenticEnvelope(claims);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("envelope")) {
        throw err;
      }
      throw new Error(`envelope verification failed: ${err}`);
    }
  }

  private decodeUnverified(token: string): AgenticEnvelope {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("malformed JWT: expected 3 parts");
    }
    const payloadJson = base64UrlDecode(parts[1]);
    const claims = JSON.parse(payloadJson) as EnvelopeClaims;
    return new AgenticEnvelope(claims);
  }
}

// ---- Utility functions ----

function base64UrlDecode(b64url: string): string {
  const b64 = base64UrlToBase64(b64url);
  return atob(b64);
}

function base64UrlToBase64(b64url: string): string {
  return b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (b64url.length % 4)) % 4);
}

function matchesPattern(pattern: string, value: string): boolean {
  if (pattern === "*" || pattern === value) return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return value === prefix || value.startsWith(prefix + ".");
  }
  if (pattern.endsWith("*")) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return false;
}
