# AgentAuth MCP Server Example

Shows how to build an MCP server protected by AgentAuth middleware. Every tool
call is gated by envelope verification and OPA policy evaluation.

## Prerequisites

- Go 1.22+
- A running AgentAuth server (see `docs/quickstart.md`)

## How to Run

```bash
go run ./examples/mcp-server
```

Server starts on `:3000`.

## How to Test

Without an envelope (expect 403):

```bash
curl http://localhost:3000/tools/filesystem/read
```

With a valid envelope (expect 200):

```bash
curl -H "X-Agent-Envelope: <token>" http://localhost:3000/tools/filesystem/read
```

The middleware:

1. Extracts the envelope from the `X-Agent-Envelope` header
2. Verifies the JWT signature and expiry
3. Evaluates OPA policy against the requested tool/operation
4. Records the decision in the audit log
5. Injects the verified envelope into the request context
