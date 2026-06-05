"""
AgentAuth + LangChain Integration Example

This example shows how to protect a LangChain agent with AgentAuth:
- Issue an identity for the agent
- Create an Agentic Identity Envelope for the task
- Wrap all tool calls with authorization checks
- Mint JIT tokens for each resource the agent accesses

Requirements:
    pip install agentauth[all] langchain langchain-openai

Environment variables:
    AGENTAUTH_SERVER_URL  — AgentAuth server URL
    AGENTAUTH_API_KEY     — AgentAuth API key
    OPENAI_API_KEY        — OpenAI API key (for the LLM)
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

# AgentAuth
from agentauth import AgentAuthClient, ToolScope

# LangChain (install with: pip install langchain langchain-openai)
try:
    from langchain.tools import tool, BaseTool
    from langchain.agents import AgentExecutor, create_openai_functions_agent
    from langchain_openai import ChatOpenAI
    from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False


# ============================================================
# AgentAuth-protected tool wrapper
# ============================================================

class AgentAuthProtectedTool:
    """
    Wraps a LangChain tool with AgentAuth authorization checks.
    Before each invocation, it verifies the agent's envelope permits
    the requested tool and operation.
    """

    def __init__(
        self,
        tool_name: str,
        operation: str,
        envelope_token: str,
        agentauth_client: AgentAuthClient,
    ) -> None:
        self.tool_name = tool_name
        self.operation = operation
        self.envelope_token = envelope_token
        self.client = agentauth_client

    async def check_authorization(self) -> None:
        """Verify the envelope grants permission for this tool."""
        claims = await self.client.verify_envelope(self.envelope_token)
        if not claims.get("valid"):
            raise PermissionError(f"Envelope verification failed for tool {self.tool_name}")

        # Check tool scope
        tool_scope = claims.get("claims", {}).get("tool_scope", [])
        for scope in tool_scope:
            if _matches_tool(scope.get("tool", ""), self.tool_name):
                if any(
                    op in ("*", self.operation)
                    for op in scope.get("operations", [])
                ):
                    return

        raise PermissionError(
            f"Agent not authorized to {self.operation} {self.tool_name}. "
            f"Check the envelope's tool_scope."
        )


def _matches_tool(pattern: str, tool: str) -> bool:
    if pattern in ("*", tool):
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return tool == prefix or tool.startswith(prefix + ".")
    return False


# ============================================================
# Example tools (simulated)
# ============================================================

async def read_emails(envelope_token: str, client: AgentAuthClient, count: int = 10) -> list[dict]:
    """Read the most recent emails from Gmail."""
    guard = AgentAuthProtectedTool("gmail.read", "read", envelope_token, client)
    await guard.check_authorization()

    # In a real implementation, this would call the Gmail API
    # using a JIT token minted by AgentAuth
    print(f"[AgentAuth] Authorized: gmail.read/read for agent")
    return [
        {"id": "1", "subject": "Q4 Budget Review", "from": "cfo@example.com"},
        {"id": "2", "subject": "Team Standup Notes", "from": "pm@example.com"},
    ]


async def search_database(
    envelope_token: str,
    client: AgentAuthClient,
    query: str,
    limit: int = 100,
) -> list[dict]:
    """Search the customer database."""
    guard = AgentAuthProtectedTool("database.query", "read", envelope_token, client)
    await guard.check_authorization()

    print(f"[AgentAuth] Authorized: database.query/read for agent")
    return [{"id": "customer_123", "name": "Acme Corp", "mrr": 50000}]


async def send_email(
    envelope_token: str,
    client: AgentAuthClient,
    to: str,
    subject: str,
    body: str,
) -> dict:
    """Send an email via Gmail."""
    guard = AgentAuthProtectedTool("gmail.send", "write", envelope_token, client)
    await guard.check_authorization()

    # Mint a JIT token specifically for the Gmail send API
    token = await client.mint_token(
        envelope_token=envelope_token,
        resource="https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        scopes=["write"],
    )

    print(f"[AgentAuth] Authorized: gmail.send/write, JIT token minted (expires in {token.expires_in}s)")
    print(f"[AgentAuth] DPoP bound: {bool(token.dpop_thumbprint)}")

    # In a real implementation: call Gmail API with token.access_token
    return {"message_id": "msg_abc123", "status": "sent", "to": to}


# ============================================================
# Main: set up AgentAuth and run the agent
# ============================================================

async def main() -> None:
    server_url = os.environ.get("AGENTAUTH_SERVER_URL", "http://localhost:8080")
    api_key = os.environ.get("AGENTAUTH_API_KEY", "dev-key")

    print("=" * 60)
    print("AgentAuth + LangChain Example")
    print("=" * 60)

    async with AgentAuthClient(server_url=server_url, api_key=api_key) as client:

        # Step 1: Issue an identity for this agent
        print("\n[1] Issuing agent identity...")
        identity = await client.issue_identity(
            delegator_id="user:alice@example.com",
            tenant_id="acme-corp",
            declared_intent="Process customer emails and update CRM records",
            labels={"team": "sales-ops", "environment": "production"},
        )
        print(f"    Agent ID:  {identity.id}")
        print(f"    SPIFFE ID: {identity.spiffe_id}")
        print(f"    Expires:   {identity.expires_at}")

        # Step 2: Create an Agentic Identity Envelope for this specific task
        print("\n[2] Creating agentic envelope...")
        envelope = await client.create_envelope(
            agent_id=identity.id,
            delegator_id="user:alice@example.com",
            tenant_id="acme-corp",
            declared_intent="Summarize unread emails and create follow-up tasks in CRM",
            tool_scope=[
                ToolScope("gmail.read", ["read"]),
                ToolScope("gmail.send", ["write"], {"max_recipients": "10"}),
                ToolScope("database.query", ["read"], {"schema": "public", "max_rows": "1000"}),
            ],
            ttl="30m",
        )
        print(f"    Envelope token: {envelope.token[:40]}...")
        print(f"    Expires: {envelope.expires_at}")

        # Step 3: Run tool calls with authorization enforcement
        print("\n[3] Running authorized tool calls...")

        # Read emails (authorized)
        emails = await read_emails(envelope.token, client)
        print(f"    Read {len(emails)} emails")

        # Search database (authorized)
        customers = await search_database(envelope.token, client, "SELECT * FROM customers LIMIT 5")
        print(f"    Found {len(customers)} customers")

        # Send email (authorized + JIT token)
        result = await send_email(
            envelope.token,
            client,
            to="customer@acme.com",
            subject="Follow-up from our conversation",
            body="Hi, thank you for your time today...",
        )
        print(f"    Sent email: {result['message_id']}")

        # Step 4: Demonstrate delegation to a sub-agent
        print("\n[4] Delegating to a sub-agent (read-only scope subset)...")
        sub_envelope = await client.delegate_to_agent(
            parent_token=envelope.token,
            sub_agent_id=f"{identity.id}-summarizer",
            declared_intent="Summarize email content only",
            tool_scope=[
                ToolScope("gmail.read", ["read"]),  # Subset: no write, no database
            ],
            ttl="10m",
        )
        print(f"    Sub-agent envelope: {sub_envelope.token[:40]}...")

        # Verify sub-agent can only read emails
        sub_emails = await read_emails(sub_envelope.token, client)
        print(f"    Sub-agent read {len(sub_emails)} emails (authorized)")

        try:
            await send_email(sub_envelope.token, client, "test@test.com", "test", "body")
        except PermissionError as e:
            print(f"    Sub-agent blocked from sending (correct!): {e}")

        print("\n[5] Authorization complete. All actions recorded in tamper-evident audit log.")
        print("\nRun `agentauth audit list --tenant-id acme-corp` to view the audit trail.")


if __name__ == "__main__":
    asyncio.run(main())
