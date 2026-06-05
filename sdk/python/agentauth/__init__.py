"""
AgentAuth — The open-source identity & authorization plane for AI agents.

AgentAuth provides cryptographically-verifiable agent identity, Just-In-Time
credential brokering, delegation chain management, and tamper-evident audit logs
for AI agents using MCP tools and A2A communication patterns.

Quick start:

    from agentauth import AgentAuthClient

    client = AgentAuthClient(server_url="https://auth.example.com", api_key="...")

    # Issue an identity for your agent
    identity = await client.issue_identity(
        delegator_id="user:alice@example.com",
        tenant_id="my-org",
        declared_intent="Summarize emails and draft replies",
    )

    # Create an agentic envelope for the task
    envelope = await client.create_envelope(
        agent_id=identity.id,
        declared_intent="Summarize emails and draft replies",
        tool_scope=[
            {"tool": "gmail.read", "operations": ["read"]},
            {"tool": "gmail.send", "operations": ["write"]},
        ],
    )

    # Mint a short-lived token for a specific resource
    token = await client.mint_token(
        envelope_token=envelope.token,
        resource="https://gmail.googleapis.com/gmail/v1/users/me/messages",
        scopes=["read"],
    )

For framework integrations, see:
    agentauth.middleware  — FastAPI/Starlette ASGI middleware
    agentauth.envelope   — Envelope creation and verification
    agentauth.client     — Full API client
"""

from agentauth.client import AgentAuthClient, AgentAuthError, AgentAuthAPIError
from agentauth.envelope import (
    AgenticEnvelope,
    ToolPermission,
    EnvelopeVerifier,
    EnvelopeSigner,
)
from agentauth.middleware import AgentAuthMiddleware

__version__ = "0.1.0"
__author__ = "AgentAuth Contributors"
__license__ = "Apache-2.0"

__all__ = [
    # Client
    "AgentAuthClient",
    "AgentAuthError",
    "AgentAuthAPIError",
    # Envelope
    "AgenticEnvelope",
    "ToolPermission",
    "EnvelopeVerifier",
    "EnvelopeSigner",
    # Middleware
    "AgentAuthMiddleware",
    # Version
    "__version__",
]
