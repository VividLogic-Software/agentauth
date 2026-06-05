import { describe, it, expect, vi } from "vitest";
import { AgentAuthClient, AgentAuthError } from "../client.js";

function makeFetch(status: number, body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => JSON.stringify(body),
  } as Response);
}

const BASE_URL = "http://localhost:8080";
const API_KEY = "dev-key";

describe("AgentAuthClient", () => {
  describe("issueIdentity", () => {
    it("posts to /v1/identities and maps snake_case response", async () => {
      const fetchFn = makeFetch(200, {
        id: "agent-1",
        spiffe_id: "spiffe://agentauth.io/agent/acme/agent-1",
        tenant_id: "acme",
        delegator_id: "user:alice@acme.com",
        certificate_pem: "cert",
        private_key_pem: "key",
        issued_at: "2024-01-01T00:00:00Z",
        expires_at: "2024-01-01T01:00:00Z",
        labels: {},
      });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      const res = await client.issueIdentity({
        delegatorId: "user:alice@acme.com",
        tenantId: "acme",
        declaredIntent: "testing",
      });
      expect(res.id).toBe("agent-1");
      expect(res.spiffeId).toBe("spiffe://agentauth.io/agent/acme/agent-1");
      expect(res.tenantId).toBe("acme");
      const call = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toBe(`${BASE_URL}/v1/identities`);
      const body = JSON.parse(call[1].body as string);
      expect(body.delegator_id).toBe("user:alice@acme.com");
      expect(body.tenant_id).toBe("acme");
    });

    it("includes Authorization header", async () => {
      const fetchFn = makeFetch(200, { id: "x", spiffe_id: "", tenant_id: "", delegator_id: "", certificate_pem: "", private_key_pem: "", issued_at: "", expires_at: "", labels: {} });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: "secret-key", fetch: fetchFn });
      await client.issueIdentity({ delegatorId: "u", tenantId: "t", declaredIntent: "i" });
      const headers = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][1].headers;
      expect(headers["Authorization"]).toBe("Bearer secret-key");
    });
  });

  describe("createEnvelope", () => {
    it("posts to /v1/envelopes and returns token", async () => {
      const fetchFn = makeFetch(200, { token: "jwt.token.here", expires_at: "2024-01-01T00:15:00Z" });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      const res = await client.createEnvelope({
        agentId: "agent-1",
        declaredIntent: "read tickets",
        toolScope: [{ tool: "zendesk.tickets.*", operations: ["read"] }],
      });
      expect(res.token).toBe("jwt.token.here");
      expect(res.expiresAt).toBe("2024-01-01T00:15:00Z");
      const body = JSON.parse((fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string);
      expect(body.agent_id).toBe("agent-1");
      expect(body.tool_scope).toHaveLength(1);
      expect(body.ttl).toBe("15m");
    });
  });

  describe("verifyEnvelope", () => {
    it("posts token to /v1/envelopes/verify", async () => {
      const claims = { agent_id: "agent-1", tenant_id: "acme" };
      const fetchFn = makeFetch(200, claims);
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      const res = await client.verifyEnvelope("my.jwt.token");
      expect(res.agent_id).toBe("agent-1");
      const body = JSON.parse((fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string);
      expect(body.token).toBe("my.jwt.token");
    });
  });

  describe("mintToken", () => {
    it("posts to /v1/tokens and maps response", async () => {
      const fetchFn = makeFetch(200, {
        access_token: "tok-abc",
        token_type: "Bearer",
        expires_in: 300,
        expires_at: "2024-01-01T00:05:00Z",
        resource: "https://api.example.com",
        scope: ["read"],
        jti: "jti-abc",
      });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      const res = await client.mintToken({
        envelopeToken: "env.jwt",
        resource: "https://api.example.com",
        scopes: ["read"],
      });
      expect(res.accessToken).toBe("tok-abc");
      expect(res.tokenType).toBe("Bearer");
      expect(res.jti).toBe("jti-abc");
    });
  });

  describe("revokeToken", () => {
    it("posts to /v1/tokens/{jti}/revoke", async () => {
      const fetchFn = makeFetch(200, {});
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      await client.revokeToken("jti-abc");
      const url = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
      expect(url).toBe(`${BASE_URL}/v1/tokens/jti-abc/revoke`);
    });
  });

  describe("error handling", () => {
    it("throws AgentAuthError on 401", async () => {
      const fetchFn = makeFetch(401, { code: "UNAUTHORIZED", message: "missing api key" });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: "", fetch: fetchFn });
      await expect(
        client.issueIdentity({ delegatorId: "u", tenantId: "t", declaredIntent: "i" }),
      ).rejects.toThrow(AgentAuthError);
    });

    it("AgentAuthError has correct statusCode and code", async () => {
      const fetchFn = makeFetch(403, { code: "FORBIDDEN", message: "scope too broad" });
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      let err: AgentAuthError | undefined;
      try {
        await client.createEnvelope({ agentId: "a", declaredIntent: "i", toolScope: [] });
      } catch (e) {
        err = e as AgentAuthError;
      }
      expect(err).toBeInstanceOf(AgentAuthError);
      expect(err?.statusCode).toBe(403);
      expect(err?.code).toBe("FORBIDDEN");
    });

    it("handles non-JSON error body", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        status: 500,
        text: async () => "Internal Server Error",
      } as Response);
      const client = new AgentAuthClient({ serverUrl: BASE_URL, apiKey: API_KEY, fetch: fetchFn });
      await expect(
        client.issueIdentity({ delegatorId: "u", tenantId: "t", declaredIntent: "i" }),
      ).rejects.toThrow(AgentAuthError);
    });
  });

  describe("trailing slash normalization", () => {
    it("strips trailing slash from serverUrl", async () => {
      const fetchFn = makeFetch(200, { token: "t", expires_at: "" });
      const client = new AgentAuthClient({
        serverUrl: "http://localhost:8080/",
        apiKey: API_KEY,
        fetch: fetchFn,
      });
      await client.createEnvelope({ agentId: "a", declaredIntent: "i", toolScope: [] });
      const url = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
      expect(url).toBe("http://localhost:8080/v1/envelopes");
    });
  });
});
