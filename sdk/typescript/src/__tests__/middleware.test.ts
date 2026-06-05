import { describe, it, expect, vi } from "vitest";
import {
  agentAuthMiddleware,
  requireToolPermission,
  getEnvelopeFromRequest,
} from "../middleware.js";
import type { AgentAuthRequest, AgentAuthResponse } from "../middleware.js";

const now = Math.floor(Date.now() / 1000);

function makeToken(overrides: Record<string, unknown> = {}): string {
  const header = btoa(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const payload = btoa(
    JSON.stringify({
      delegator_id: "user:alice@acme.com",
      agent_id: "spiffe://agentauth.io/agent/acme/agent-1",
      task_id: "task-1",
      tenant_id: "acme",
      session_id: "sess-1",
      declared_intent: "test",
      tool_scope: [{ tool: "github.issues.*", operations: ["read", "write"] }],
      iat: now - 60,
      exp: now + 900,
      jti: "jti-1",
      ver: "1",
      ...overrides,
    }),
  );
  return `${header}.${payload}.${btoa("fake-sig")}`;
}

function makeReq(headers: Record<string, string> = {}, path = "/tools/x"): AgentAuthRequest {
  return { headers, path };
}

// Returns a response spy. statusTracker.statusCode is updated in-place when .status() is called.
function makeRes(): { res: AgentAuthResponse; statusTracker: { statusCode: number; body: unknown } } {
  const statusTracker = { statusCode: 0, body: undefined as unknown };
  const res: AgentAuthResponse = {
    status(code) {
      statusTracker.statusCode = code;
      return res;
    },
    json(body) {
      statusTracker.body = body;
    },
  };
  return { res, statusTracker };
}

describe("agentAuthMiddleware", () => {
  it("calls next() when X-Agent-Envelope is valid (unverified mode)", async () => {
    const middleware = agentAuthMiddleware({ requireEnvelope: true });
    const req = makeReq({ "x-agent-envelope": makeToken() });
    const { res } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.agentEnvelope).toBeDefined();
    expect(req.agentId).toBe("spiffe://agentauth.io/agent/acme/agent-1");
  });

  it("returns 403 when envelope header is missing and requireEnvelope=true", async () => {
    const middleware = agentAuthMiddleware({ requireEnvelope: true });
    const req = makeReq({});
    const { res, statusTracker } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(statusTracker.statusCode).toBe(403);
  });

  it("calls next() without envelope when requireEnvelope=false", async () => {
    const middleware = agentAuthMiddleware({ requireEnvelope: false });
    const req = makeReq({});
    const { res } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.agentEnvelope).toBeUndefined();
  });

  it("skips verification for /healthz path", async () => {
    const middleware = agentAuthMiddleware({ requireEnvelope: true });
    const req = makeReq({}, "/healthz");
    const { res } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("skips custom skipPaths", async () => {
    const middleware = agentAuthMiddleware({
      requireEnvelope: true,
      skipPaths: ["/public/"],
    });
    const req = makeReq({}, "/public/docs");
    const { res } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("accepts array header value", async () => {
    const middleware = agentAuthMiddleware();
    const req: AgentAuthRequest = {
      headers: { "x-agent-envelope": [makeToken(), "extra"] as unknown as string },
      path: "/tools/x",
    };
    const { res } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("calls onDeny callback when provided", async () => {
    const onDeny = vi.fn();
    const middleware = agentAuthMiddleware({ requireEnvelope: true, onDeny });
    const req = makeReq({});
    const { res } = makeRes();
    await middleware(req, res, vi.fn());
    expect(onDeny).toHaveBeenCalledOnce();
    expect(onDeny.mock.calls[0][2]).toContain("missing");
  });

  it("returns 403 on malformed envelope token", async () => {
    const middleware = agentAuthMiddleware({ requireEnvelope: true });
    const req = makeReq({ "x-agent-envelope": "not.a.jwt" });
    const { res, statusTracker } = makeRes();
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(statusTracker.statusCode).toBe(403);
  });
});

describe("requireToolPermission", () => {
  it("calls next when envelope has the required permission", () => {
    const guard = requireToolPermission("github.issues.create", "write");
    const req = makeReq({});
    req.agentEnvelope = {
      hasToolPermission: (tool: string, op: string) =>
        tool === "github.issues.create" && op === "write",
    } as never;
    const { res } = makeRes();
    const next = vi.fn();
    guard(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("returns 403 when tool permission is insufficient", () => {
    const guard = requireToolPermission("database.delete", "write");
    const req = makeReq({});
    req.agentEnvelope = {
      hasToolPermission: () => false,
    } as never;
    const { res, statusTracker } = makeRes();
    const next = vi.fn();
    guard(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(statusTracker.statusCode).toBe(403);
  });

  it("returns 403 when no envelope is attached to request", () => {
    const guard = requireToolPermission("any.tool", "read");
    const req = makeReq({});
    const { res, statusTracker } = makeRes();
    const next = vi.fn();
    guard(req, res, next);
    expect(statusTracker.statusCode).toBe(403);
  });
});

describe("getEnvelopeFromRequest", () => {
  it("returns undefined when no envelope attached", () => {
    expect(getEnvelopeFromRequest(makeReq({}))).toBeUndefined();
  });

  it("returns attached envelope", () => {
    const req = makeReq({});
    req.agentEnvelope = { agentId: "agent-1" } as never;
    expect(getEnvelopeFromRequest(req)?.agentId).toBe("agent-1");
  });
});
