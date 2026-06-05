import { describe, it, expect } from "vitest";
import { AgenticEnvelope, EnvelopeVerifier, ToolPermission } from "../envelope.js";
import type { EnvelopeClaims } from "../envelope.js";

const now = Math.floor(Date.now() / 1000);

function makeClaims(overrides: Partial<EnvelopeClaims> = {}): EnvelopeClaims {
  return {
    delegator_id: "user:alice@acme.com",
    agent_id: "spiffe://agentauth.io/agent/acme/agent-1",
    task_id: "task-abc",
    tenant_id: "acme",
    session_id: "session-xyz",
    declared_intent: "Process support tickets",
    tool_scope: [
      { tool: "zendesk.tickets.*", operations: ["read", "write"] },
      { tool: "filesystem.read", operations: ["read"] },
    ],
    iat: now - 60,
    exp: now + 900,
    jti: "jti-123",
    ver: "1",
    ...overrides,
  };
}

describe("ToolPermission", () => {
  it("allows exact match", () => {
    const perm = new ToolPermission("filesystem.read", ["read"]);
    expect(perm.allows("filesystem.read", "read")).toBe(true);
  });

  it("denies wrong operation", () => {
    const perm = new ToolPermission("filesystem.read", ["read"]);
    expect(perm.allows("filesystem.read", "write")).toBe(false);
  });

  it("allows wildcard operation", () => {
    const perm = new ToolPermission("database.query", ["*"]);
    expect(perm.allows("database.query", "delete")).toBe(true);
  });

  it("allows glob tool pattern prefix.*", () => {
    const perm = new ToolPermission("github.issues.*", ["read"]);
    expect(perm.allows("github.issues.create", "read")).toBe(true);
    expect(perm.allows("github.issues", "read")).toBe(true);
  });

  it("denies tool outside glob prefix", () => {
    const perm = new ToolPermission("github.issues.*", ["read"]);
    expect(perm.allows("github.pulls.create", "read")).toBe(false);
  });

  it("allows wildcard tool *", () => {
    const perm = new ToolPermission("*", ["read"]);
    expect(perm.allows("anything.at.all", "read")).toBe(true);
  });

  it("serializes to JSON omitting empty constraints", () => {
    const perm = new ToolPermission("tool.x", ["read"]);
    const json = perm.toJSON();
    expect(json).toEqual({ tool: "tool.x", operations: ["read"] });
    expect(json).not.toHaveProperty("constraints");
  });

  it("serializes constraints when present", () => {
    const perm = new ToolPermission("db.*", ["read"], { max_rows: "100" });
    expect(perm.toJSON().constraints).toEqual({ max_rows: "100" });
  });
});

describe("AgenticEnvelope", () => {
  it("parses claims into typed fields", () => {
    const env = new AgenticEnvelope(makeClaims());
    expect(env.delegatorId).toBe("user:alice@acme.com");
    expect(env.agentId).toBe("spiffe://agentauth.io/agent/acme/agent-1");
    expect(env.tenantId).toBe("acme");
    expect(env.jti).toBe("jti-123");
    expect(env.version).toBe("1");
  });

  it("hasToolPermission returns true for allowed tool+op", () => {
    const env = new AgenticEnvelope(makeClaims());
    expect(env.hasToolPermission("zendesk.tickets.create", "write")).toBe(true);
    expect(env.hasToolPermission("filesystem.read", "read")).toBe(true);
  });

  it("hasToolPermission returns false for disallowed op", () => {
    const env = new AgenticEnvelope(makeClaims());
    expect(env.hasToolPermission("filesystem.read", "write")).toBe(false);
  });

  it("hasToolPermission returns false for unlisted tool", () => {
    const env = new AgenticEnvelope(makeClaims());
    expect(env.hasToolPermission("github.issues.create", "write")).toBe(false);
  });

  it("isExpired is false for future exp", () => {
    const env = new AgenticEnvelope(makeClaims({ exp: now + 3600 }));
    expect(env.isExpired).toBe(false);
  });

  it("isExpired is true for past exp", () => {
    const env = new AgenticEnvelope(makeClaims({ exp: now - 1 }));
    expect(env.isExpired).toBe(true);
  });

  it("delegationDepth is 0 for root envelope", () => {
    const env = new AgenticEnvelope(makeClaims());
    expect(env.delegationDepth).toBe(0);
  });

  it("delegationDepth reflects chain length", () => {
    const env = new AgenticEnvelope(
      makeClaims({ delegation_chain: ["parent-jwt-1", "parent-jwt-2"] }),
    );
    expect(env.delegationDepth).toBe(2);
  });

  it("toJSON round-trips core fields", () => {
    const env = new AgenticEnvelope(makeClaims());
    const json = env.toJSON();
    expect(json.agent_id).toBe("spiffe://agentauth.io/agent/acme/agent-1");
    expect(json.tenant_id).toBe("acme");
    expect(Array.isArray(json.tool_scope)).toBe(true);
  });

  it("handles missing optional fields gracefully", () => {
    const claims: EnvelopeClaims = {
      delegator_id: "",
      agent_id: "",
      task_id: "",
      tenant_id: "",
      session_id: "",
      declared_intent: "",
      tool_scope: [],
      iat: now,
      exp: now + 900,
      jti: "jti-min",
      ver: "1",
    };
    const env = new AgenticEnvelope(claims);
    expect(env.consentRef).toBe("");
    expect(env.delegationChain).toEqual([]);
    expect(env.toolScope).toHaveLength(0);
  });
});

describe("EnvelopeVerifier (development / no-key mode)", () => {
  function makeToken(claims: Partial<EnvelopeClaims> = {}): string {
    const header = btoa(JSON.stringify({ alg: "ES256", typ: "JWT" }));
    const payload = btoa(JSON.stringify(makeClaims(claims)));
    const signature = btoa("fake-sig");
    return `${header}.${payload}.${signature}`;
  }

  it("decodes an unverified token and returns envelope", async () => {
    const verifier = new EnvelopeVerifier();
    const token = makeToken();
    const env = await verifier.verify(token);
    expect(env.tenantId).toBe("acme");
    expect(env.jti).toBe("jti-123");
  });

  it("throws on empty token", async () => {
    const verifier = new EnvelopeVerifier();
    await expect(verifier.verify("")).rejects.toThrow("envelope token is empty");
  });

  it("throws on malformed JWT (wrong part count)", async () => {
    const verifier = new EnvelopeVerifier();
    await expect(verifier.verify("notajwt")).rejects.toThrow("malformed JWT");
  });
});
