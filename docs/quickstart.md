# Quickstart

Get AgentAuth running in under 10 minutes.

## 1. Prerequisites

- Go 1.22+
- Docker and Docker Compose
- Python 3.11+ (optional, for Python SDK) or Node 20+ (optional, for TypeScript SDK)

## 2. Run with Docker Compose

```bash
git clone https://github.com/VividLogic-Software/agentauth
cd agentauth
cp .env.example .env
docker compose up -d
```

This starts four services:

| Service | Purpose |
|---------|---------|
| `agentauth-server` | Control plane API on `:8080` |
| `postgres` | Identity and audit log storage |
| `redis` | Token cache and revocation |
| `nats` | Event bus for revocation fan-out |

## 3. Issue your first agent identity

```bash
curl -X POST http://localhost:8080/v1/identities \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "delegator_id": "user:alice@acme.com",
    "tenant_id": "acme",
    "declared_intent": "Analyze Q3 sales data"
  }'
```

## 4. Create an envelope

```bash
curl -X POST http://localhost:8080/v1/envelopes \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "<agent_id from step 3>",
    "delegator_id": "user:alice@acme.com",
    "tenant_id": "acme",
    "declared_intent": "Analyze Q3 sales data",
    "tool_scope": [
      {"tool": "postgres.query", "operations": ["read"]}
    ]
  }'
```

## 5. Verify an envelope

```bash
curl -X POST http://localhost:8080/v1/envelopes/verify \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"token": "<envelope_token from step 4>"}'
```

## 6. Python SDK quickstart

```python
from agentauth import AgentAuthClient
client = AgentAuthClient(server_url="http://localhost:8080", api_key="dev-key")
identity = await client.issue_identity(
    delegator_id="user:alice@acme.com",
    tenant_id="acme",
    declared_intent="Analyze Q3 sales data",
)
```

## 7. TypeScript SDK quickstart

```typescript
import { AgentAuthClient } from '@agentauth/sdk';
const client = new AgentAuthClient({ serverUrl: 'http://localhost:8080', apiKey: 'dev-key' });
const identity = await client.issueIdentity({
    delegatorId: 'user:alice@acme.com',
    tenantId: 'acme',
    declaredIntent: 'Analyze Q3 sales data',
});
```

## 8. Protect an MCP server

```go
import "github.com/VividLogic-Software/agentauth/pkg/middleware"

router.Use(middleware.MCPMiddleware(middleware.MCPMiddlewareConfig{
    Verifier:     verifier,
    PolicyEngine: policyEngine,
    Auditor:      auditor,
}))
```

## 9. View the audit log

```bash
curl -H "Authorization: Bearer dev-key" "http://localhost:8080/v1/audit?tenant_id=acme"
```
