# AgentAuth Python SDK

## Install

```bash
pip install agentauth
```

## Compatibility

Python 3.11+, fully async (`asyncio`), no mandatory dependencies beyond stdlib.

## Quickstart

```python
from agentauth import AgentAuthClient

client = AgentAuthClient(server_url="http://localhost:8080", api_key="your-api-key")

identity = await client.issue_identity(
    delegator_id="user:alice@acme.com",
    tenant_id="acme",
    declared_intent="Analyze Q3 sales data",
)

envelope = await client.create_envelope(
    agent_id=identity.id,
    delegator_id="user:alice@acme.com",
    tenant_id="acme",
    declared_intent="Analyze Q3 sales data",
    tool_scope=[{"tool": "postgres.query", "operations": ["read"]}],
)

parsed = await client.verify_envelope(envelope.token)
```

## Key Classes

- `AgentAuthClient` — async HTTP client for the control plane API (`client.py`)
- `AgenticEnvelope` — dataclass representing a parsed envelope (`envelope.py`)
- `ToolScope` — permission entry: `tool`, `operations`, optional `constraints`
- `AgentAuthMiddleware` — ASGI middleware for FastAPI/Starlette (`middleware.py`)

## FastAPI Middleware

```python
from agentauth import AgentAuthClient
from agentauth.middleware import AgentAuthMiddleware

client = AgentAuthClient(server_url="http://localhost:8080", api_key="...")
app.add_middleware(AgentAuthMiddleware, client=client)
```

See `examples/langchain-agent/` for a full integration example.
API docs at `docs/api-reference.md`.
