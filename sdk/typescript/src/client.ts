/**
 * AgentAuth TypeScript client — full client for the AgentAuth control plane API.
 */

/** Options for configuring the AgentAuthClient. */
export interface AgentAuthClientOptions {
  /** Base URL of the AgentAuth server (e.g. https://auth.example.com). */
  serverUrl: string;
  /** API key for authentication. */
  apiKey?: string;
  /** Request timeout in milliseconds. Default: 30000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or Node.js < 18). */
  fetch?: typeof globalThis.fetch;
}

/** Tool permission definition for envelope creation. */
export interface ToolScope {
  /** MCP tool name or glob pattern (e.g. "filesystem.read", "github.issues.*"). */
  tool: string;
  /** Allowed operations (e.g. ["read", "write"] or ["*"]). */
  operations: string[];
  /** Optional additional constraints. */
  constraints?: Record<string, string>;
}

/** Request to issue a new agent identity. */
export interface IssueIdentityRequest {
  /** Optional. If empty, a UUID is generated. */
  agentId?: string;
  /** The identity of the entity delegating to this agent. */
  delegatorId: string;
  /** The tenant/organization scope. */
  tenantId: string;
  /** Human-readable description of what the agent will do. */
  declaredIntent: string;
  /** Token lifetime (e.g. "1h", "30m"). Default "1h". */
  ttl?: string;
  /** Optional metadata labels. */
  labels?: Record<string, string>;
}

/** Response from issuing a new agent identity. */
export interface IssueIdentityResponse {
  id: string;
  spiffeId: string;
  tenantId: string;
  delegatorId: string;
  certificatePem: string;
  /** Only returned at issuance — store securely and never log. */
  privateKeyPem: string;
  issuedAt: string;
  expiresAt: string;
  labels: Record<string, string>;
}

/** Request to create an agentic identity envelope. */
export interface CreateEnvelopeRequest {
  /** The agent's SPIFFE ID or AgentAuth ID. */
  agentId: string;
  /** Who delegated this task. */
  delegatorId?: string;
  /** The tenant scope. */
  tenantId?: string;
  /** Groups all envelopes in a session. */
  sessionId?: string;
  /** Human-readable description of the task. */
  declaredIntent: string;
  /** The tools this agent may use. */
  toolScope: ToolScope[];
  /** Reference to a consent record. */
  consentRef?: string;
  /** Envelope lifetime (e.g. "15m", "1h"). Default "15m". Max "4h". */
  ttl?: string;
}

/** Response from creating an envelope. */
export interface EnvelopeResponse {
  /** The signed JWT envelope token. Pass this as X-Agent-Envelope header. */
  token: string;
  expiresAt: string;
}

/** Request to mint an access token. */
export interface MintTokenRequest {
  /** The signed envelope JWT. */
  envelopeToken: string;
  /** Target resource URI per RFC 8707. */
  resource: string;
  /** OAuth 2.0 scopes to request. */
  scopes: string[];
  /** Optional DPoP proof JWT for key binding (RFC 9449). */
  dpopProof?: string;
  /** Token lifetime (e.g. "5m"). Default "5m". Max "30m". */
  ttl?: string;
}

/** Response from minting an access token. */
export interface AccessTokenResponse {
  accessToken: string;
  tokenType: "Bearer" | "DPoP";
  expiresIn: number;
  expiresAt: string;
  resource: string;
  scopes: string[];
  dpopThumbprint?: string;
  jti: string;
}

/** Request to delegate to a sub-agent. */
export interface DelegateRequest {
  /** The parent agent's signed envelope JWT. */
  parentEnvelopeToken: string;
  /** The SPIFFE ID of the sub-agent. */
  subAgentId: string;
  /** The task description for the sub-agent. */
  declaredIntent: string;
  /** Subset of parent's tools the sub-agent may use. */
  toolScope: ToolScope[];
  /** Sub-agent envelope lifetime (must be <= parent's remaining TTL). */
  ttl?: string;
  consentRef?: string;
}

/** AgentAuth API error. */
export class AgentAuthError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(`AgentAuth API error ${statusCode}: [${code}] ${message}`);
    this.name = "AgentAuthError";
  }
}

/**
 * Full client for the AgentAuth control plane API.
 *
 * @example
 * ```typescript
 * import { AgentAuthClient } from "@agentauth/sdk";
 *
 * const client = new AgentAuthClient({
 *   serverUrl: "https://auth.example.com",
 *   apiKey: process.env.AGENTAUTH_API_KEY,
 * });
 *
 * // Issue a new agent identity
 * const identity = await client.issueIdentity({
 *   delegatorId: "user:alice@example.com",
 *   tenantId: "my-org",
 *   declaredIntent: "Process support tickets",
 * });
 *
 * // Create an envelope for the task
 * const envelope = await client.createEnvelope({
 *   agentId: identity.id,
 *   declaredIntent: "Process support tickets",
 *   toolScope: [
 *     { tool: "zendesk.tickets.*", operations: ["read", "write"] },
 *   ],
 * });
 *
 * // Mint a short-lived token
 * const token = await client.mintToken({
 *   envelopeToken: envelope.token,
 *   resource: "https://api.zendesk.com/v2/tickets",
 *   scopes: ["read", "write"],
 * });
 * ```
 */
export class AgentAuthClient {
  private readonly serverUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(options: AgentAuthClientOptions) {
    this.serverUrl = options.serverUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetchFn = options.fetch ?? globalThis.fetch;
  }

  /**
   * Issue a new SPIFFE SVID identity for an AI agent.
   */
  async issueIdentity(req: IssueIdentityRequest): Promise<IssueIdentityResponse> {
    const body: Record<string, unknown> = {
      delegator_id: req.delegatorId,
      tenant_id: req.tenantId,
      declared_intent: req.declaredIntent,
      ttl: req.ttl ?? "1h",
    };
    if (req.agentId) body.agent_id = req.agentId;
    if (req.labels) body.labels = req.labels;

    const data = await this.post<Record<string, unknown>>("/v1/identities", body);
    return this.mapIdentity(data);
  }

  /**
   * Retrieve an agent identity by ID.
   */
  async getIdentity(agentId: string): Promise<IssueIdentityResponse> {
    const data = await this.get<Record<string, unknown>>(`/v1/identities/${agentId}`);
    return this.mapIdentity(data);
  }

  /**
   * Revoke an agent identity immediately.
   */
  async revokeIdentity(agentId: string): Promise<void> {
    await this.post(`/v1/identities/${agentId}/revoke`, null);
  }

  /**
   * Rotate credentials for an existing agent identity.
   */
  async rotateCredentials(agentId: string): Promise<IssueIdentityResponse> {
    const data = await this.post<Record<string, unknown>>(
      `/v1/identities/${agentId}/rotate`,
      null,
    );
    return this.mapIdentity(data);
  }

  /**
   * Create a signed Agentic Identity Envelope for a task.
   *
   * The returned token must be passed as the ``X-Agent-Envelope`` header
   * on every MCP tool call.
   */
  async createEnvelope(req: CreateEnvelopeRequest): Promise<EnvelopeResponse> {
    const body: Record<string, unknown> = {
      agent_id: req.agentId,
      declared_intent: req.declaredIntent,
      tool_scope: req.toolScope,
      ttl: req.ttl ?? "15m",
    };
    if (req.delegatorId) body.delegator_id = req.delegatorId;
    if (req.tenantId) body.tenant_id = req.tenantId;
    if (req.sessionId) body.session_id = req.sessionId;
    if (req.consentRef) body.consent_ref = req.consentRef;

    const data = await this.post<{ token: string; expires_at: string }>(
      "/v1/envelopes",
      body,
    );
    return { token: data.token, expiresAt: data.expires_at };
  }

  /**
   * Verify a signed envelope token and return its claims.
   */
  async verifyEnvelope(token: string): Promise<Record<string, unknown>> {
    return this.post<Record<string, unknown>>("/v1/envelopes/verify", { token });
  }

  /**
   * Delegate authority from a parent envelope to a sub-agent.
   *
   * The sub-agent's tool scope must be a subset of the parent's scope.
   */
  async delegateToAgent(req: DelegateRequest): Promise<EnvelopeResponse> {
    const body: Record<string, unknown> = {
      parent_envelope_token: req.parentEnvelopeToken,
      sub_agent_id: req.subAgentId,
      declared_intent: req.declaredIntent,
      tool_scope: req.toolScope,
      ttl: req.ttl ?? "10m",
    };
    if (req.consentRef) body.consent_ref = req.consentRef;

    const data = await this.post<{ token: string; expires_at: string }>(
      "/v1/envelopes/delegate",
      body,
    );
    return { token: data.token, expiresAt: data.expires_at };
  }

  /**
   * Mint a short-lived, resource-scoped OAuth 2.1 access token.
   */
  async mintToken(req: MintTokenRequest): Promise<AccessTokenResponse> {
    const body: Record<string, unknown> = {
      envelope_token: req.envelopeToken,
      resource: req.resource,
      scopes: req.scopes,
      ttl: req.ttl ?? "5m",
    };
    if (req.dpopProof) body.dpop_proof = req.dpopProof;

    const data = await this.post<Record<string, unknown>>("/v1/tokens", body);
    return {
      accessToken: data.access_token as string,
      tokenType: (data.token_type as "Bearer" | "DPoP") ?? "Bearer",
      expiresIn: data.expires_in as number,
      expiresAt: data.expires_at as string,
      resource: data.resource as string,
      scopes: (data.scope as string[]) ?? [],
      dpopThumbprint: (data.dpop_thumbprint as string) ?? undefined,
      jti: data.jti as string,
    };
  }

  /**
   * Revoke an access token by JTI.
   */
  async revokeToken(jti: string): Promise<void> {
    await this.post(`/v1/tokens/${jti}/revoke`, null);
  }

  // ---- HTTP helpers ----

  private async post<T>(path: string, body: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(this.serverUrl + path, {
        method: "POST",
        headers: this.headers(),
        body: body !== null ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      return this.handleResponse<T>(response);
    } finally {
      clearTimeout(timer);
    }
  }

  private async get<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(this.serverUrl + path, {
        method: "GET",
        headers: this.headers(),
        signal: controller.signal,
      });
      return this.handleResponse<T>(response);
    } finally {
      clearTimeout(timer);
    }
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const text = await response.text();
    if (response.status >= 400) {
      let code = "UNKNOWN";
      let message = text;
      try {
        const err = JSON.parse(text);
        code = err.code ?? code;
        message = err.message ?? text;
      } catch {
        // ignore JSON parse error
      }
      throw new AgentAuthError(response.status, code, message);
    }
    if (!text) return {} as T;
    return JSON.parse(text) as T;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "@agentauth/sdk/0.1.0",
    };
    if (this.apiKey) {
      h["Authorization"] = `Bearer ${this.apiKey}`;
    }
    return h;
  }

  private mapIdentity(data: Record<string, unknown>): IssueIdentityResponse {
    return {
      id: data.id as string,
      spiffeId: (data.spiffe_id as string) ?? "",
      tenantId: (data.tenant_id as string) ?? "",
      delegatorId: (data.delegator_id as string) ?? "",
      certificatePem: (data.certificate_pem as string) ?? "",
      privateKeyPem: (data.private_key_pem as string) ?? "",
      issuedAt: (data.issued_at as string) ?? "",
      expiresAt: (data.expires_at as string) ?? "",
      labels: (data.labels as Record<string, string>) ?? {},
    };
  }
}
