"""
AgentAuth Python client — full async client for the AgentAuth control plane API.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import urllib.request
import urllib.error
import urllib.parse


class AgentAuthError(Exception):
    """Base exception for AgentAuth client errors."""
    pass


class AgentAuthAPIError(AgentAuthError):
    """Raised when the AgentAuth API returns an error response."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(f"AgentAuth API error {status_code}: [{code}] {message}")


@dataclass
class AgentIdentity:
    """Represents a fully-issued agent identity."""
    id: str
    spiffe_id: str
    tenant_id: str
    delegator_id: str
    declared_intent: str
    certificate_pem: str
    private_key_pem: str
    issued_at: datetime
    expires_at: datetime
    labels: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentIdentity":
        return cls(
            id=data["id"],
            spiffe_id=data["spiffe_id"],
            tenant_id=data.get("tenant_id", ""),
            delegator_id=data.get("delegator_id", ""),
            declared_intent=data.get("declared_intent", ""),
            certificate_pem=data.get("certificate_pem", ""),
            private_key_pem=data.get("private_key_pem", ""),
            issued_at=_parse_datetime(data.get("issued_at", "")),
            expires_at=_parse_datetime(data.get("expires_at", "")),
            labels=data.get("labels") or {},
        )


@dataclass
class EnvelopeResponse:
    """A signed agentic envelope token and its expiry."""
    token: str
    expires_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnvelopeResponse":
        return cls(
            token=data["token"],
            expires_at=_parse_datetime(data.get("expires_at", "")),
        )


@dataclass
class AccessToken:
    """A minted short-lived access token."""
    access_token: str
    token_type: str
    expires_in: int
    expires_at: datetime
    resource: str
    scopes: list[str]
    dpop_thumbprint: str = ""
    jti: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccessToken":
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 0),
            expires_at=_parse_datetime(data.get("expires_at", "")),
            resource=data.get("resource", ""),
            scopes=data.get("scope") or [],
            dpop_thumbprint=data.get("dpop_thumbprint", ""),
            jti=data.get("jti", ""),
        )


@dataclass
class ToolScope:
    """Defines the tools and operations an agent is permitted to use."""
    tool: str
    operations: list[str]
    constraints: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"tool": self.tool, "operations": self.operations}
        if self.constraints:
            d["constraints"] = self.constraints
        return d


class AgentAuthClient:
    """
    Async client for the AgentAuth control plane API.

    All methods are async and should be called with ``await``.
    Supports both aiohttp (preferred) and stdlib urllib as a fallback.

    Example::

        import asyncio
        from agentauth import AgentAuthClient

        async def main():
            client = AgentAuthClient(
                server_url="https://auth.example.com",
                api_key="your-api-key",
            )
            identity = await client.issue_identity(
                delegator_id="user:alice@example.com",
                tenant_id="my-org",
                declared_intent="Process support tickets",
            )
            print(f"Issued identity: {identity.id}")
            print(f"SPIFFE ID: {identity.spiffe_id}")

        asyncio.run(main())
    """

    def __init__(
        self,
        server_url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the AgentAuth client.

        :param server_url: Base URL of the AgentAuth server (e.g. https://auth.example.com)
        :param api_key: API key for authentication. Can also be set via AGENTAUTH_API_KEY env var.
        :param timeout: Request timeout in seconds.
        """
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session: Any = None

    async def __aenter__(self) -> "AgentAuthClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    async def issue_identity(
        self,
        delegator_id: str,
        tenant_id: str,
        declared_intent: str,
        agent_id: str = "",
        ttl: str = "1h",
        labels: dict[str, str] | None = None,
    ) -> AgentIdentity:
        """
        Issue a new SPIFFE SVID identity for an AI agent.

        :param delegator_id: The identity of the entity delegating to this agent.
                             For human users: "user:alice@example.com"
                             For parent agents: their SPIFFE ID.
        :param tenant_id: The tenant/organization scope.
        :param declared_intent: Human-readable description of what the agent will do.
        :param agent_id: Optional. If empty, a UUID is generated.
        :param ttl: Token lifetime. Default "1h". Max "24h".
        :param labels: Optional metadata labels.
        :returns: AgentIdentity containing the certificate and SPIFFE ID.
        :raises AgentAuthAPIError: If the server returns an error.
        """
        payload: dict[str, Any] = {
            "delegator_id": delegator_id,
            "tenant_id": tenant_id,
            "declared_intent": declared_intent,
            "ttl": ttl,
        }
        if agent_id:
            payload["agent_id"] = agent_id
        if labels:
            payload["labels"] = labels

        data = await self._post("/v1/identities", payload)
        return AgentIdentity.from_dict(data)

    async def get_identity(self, agent_id: str) -> AgentIdentity:
        """
        Retrieve an agent identity by ID.

        :param agent_id: The agent's unique identifier.
        :returns: AgentIdentity record.
        """
        data = await self._get(f"/v1/identities/{agent_id}")
        return AgentIdentity.from_dict(data)

    async def revoke_identity(self, agent_id: str) -> None:
        """
        Revoke an agent identity. All future authorization checks for this
        identity will be denied immediately.

        :param agent_id: The agent's unique identifier.
        """
        await self._post(f"/v1/identities/{agent_id}/revoke", None)

    async def rotate_credentials(self, agent_id: str) -> AgentIdentity:
        """
        Rotate an agent's credentials, issuing a new certificate.

        :param agent_id: The agent's unique identifier.
        :returns: New AgentIdentity with fresh certificate.
        """
        data = await self._post(f"/v1/identities/{agent_id}/rotate", None)
        return AgentIdentity.from_dict(data)

    async def create_envelope(
        self,
        agent_id: str,
        declared_intent: str,
        tool_scope: list[ToolScope | dict[str, Any]],
        delegator_id: str = "",
        tenant_id: str = "",
        session_id: str = "",
        consent_ref: str = "",
        ttl: str = "15m",
    ) -> EnvelopeResponse:
        """
        Create a signed Agentic Identity Envelope for a task.

        The envelope is a signed JWT that carries the agent's identity, declared
        intent, and tool scope. It must be passed with every MCP tool call and
        A2A delegation via the ``X-Agent-Envelope`` header.

        :param agent_id: The SPIFFE ID or AgentAuth ID of the executing agent.
        :param declared_intent: Human-readable description of the task.
        :param tool_scope: List of tool permissions granted for this task.
        :param delegator_id: Who delegated this task. Optional.
        :param tenant_id: The tenant scope. Optional if set globally.
        :param session_id: Groups all envelopes in a session. Optional.
        :param consent_ref: Reference to a consent record. Optional.
        :param ttl: Envelope lifetime. Default "15m". Max "4h".
        :returns: EnvelopeResponse with the signed token.
        """
        normalized_scope: list[dict[str, Any]] = []
        for s in tool_scope:
            if isinstance(s, ToolScope):
                normalized_scope.append(s.to_dict())
            else:
                normalized_scope.append(s)

        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "declared_intent": declared_intent,
            "tool_scope": normalized_scope,
            "ttl": ttl,
        }
        if delegator_id:
            payload["delegator_id"] = delegator_id
        if tenant_id:
            payload["tenant_id"] = tenant_id
        if session_id:
            payload["session_id"] = session_id
        if consent_ref:
            payload["consent_ref"] = consent_ref

        data = await self._post("/v1/envelopes", payload)
        return EnvelopeResponse.from_dict(data)

    async def verify_envelope(self, token: str) -> dict[str, Any]:
        """
        Verify a signed envelope token and return its claims.

        :param token: The signed envelope JWT string.
        :returns: Dictionary of envelope claims.
        :raises AgentAuthAPIError: If the token is invalid or expired.
        """
        data = await self._post("/v1/envelopes/verify", {"token": token})
        return data

    async def delegate_to_agent(
        self,
        parent_token: str,
        sub_agent_id: str,
        declared_intent: str,
        tool_scope: list[ToolScope | dict[str, Any]],
        ttl: str = "10m",
        consent_ref: str = "",
    ) -> EnvelopeResponse:
        """
        Delegate authority from a parent envelope to a sub-agent.

        The sub-agent's scope must be a subset of the parent's scope.
        The delegation chain is automatically embedded in the new envelope.

        :param parent_token: The signed JWT of the delegating agent's envelope.
        :param sub_agent_id: The SPIFFE ID of the sub-agent being delegated to.
        :param declared_intent: The task description for the sub-agent.
        :param tool_scope: Subset of parent's tools the sub-agent may use.
        :param ttl: Sub-agent envelope lifetime (must be <= parent's remaining TTL).
        :param consent_ref: Reference to consent record.
        :returns: EnvelopeResponse with the sub-agent's signed token.
        """
        normalized_scope: list[dict[str, Any]] = []
        for s in tool_scope:
            if isinstance(s, ToolScope):
                normalized_scope.append(s.to_dict())
            else:
                normalized_scope.append(s)

        payload: dict[str, Any] = {
            "parent_envelope_token": parent_token,
            "sub_agent_id": sub_agent_id,
            "declared_intent": declared_intent,
            "tool_scope": normalized_scope,
            "ttl": ttl,
        }
        if consent_ref:
            payload["consent_ref"] = consent_ref

        data = await self._post("/v1/envelopes/delegate", payload)
        return EnvelopeResponse.from_dict(data)

    async def mint_token(
        self,
        envelope_token: str,
        resource: str,
        scopes: list[str],
        dpop_proof: str = "",
        ttl: str = "5m",
    ) -> AccessToken:
        """
        Mint a short-lived, resource-scoped OAuth 2.1 access token.

        If a DPoP proof is provided, the token is cryptographically bound to
        the agent's key per RFC 9449, preventing token theft.

        :param envelope_token: The signed agentic envelope JWT.
        :param resource: Target resource URI per RFC 8707.
        :param scopes: OAuth 2.0 scopes to request.
        :param dpop_proof: Optional DPoP proof JWT for key binding (RFC 9449).
        :param ttl: Token lifetime. Default "5m". Max "30m".
        :returns: AccessToken with the signed JWT.
        """
        payload: dict[str, Any] = {
            "envelope_token": envelope_token,
            "resource": resource,
            "scopes": scopes,
            "ttl": ttl,
        }
        if dpop_proof:
            payload["dpop_proof"] = dpop_proof

        data = await self._post("/v1/tokens", payload)
        return AccessToken.from_dict(data)

    async def revoke_token(self, jti: str) -> None:
        """
        Immediately revoke an access token by JTI.

        :param jti: The token's unique identifier (from the ``jti`` JWT claim).
        """
        await self._post(f"/v1/tokens/{jti}/revoke", None)

    async def _ensure_session(self) -> None:
        """Initialize the HTTP session (aiohttp preferred, falls back to stdlib)."""
        if self._session is None:
            try:
                import aiohttp  # type: ignore[import]
                connector = aiohttp.TCPConnector(ssl=True)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self._auth_headers(),
                )
            except ImportError:
                self._session = _StdlibSession(
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                )

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _post(self, path: str, payload: Any) -> dict[str, Any]:
        await self._ensure_session()
        url = self.server_url + path
        return await self._session.post(url, json=payload)

    async def _get(self, path: str) -> dict[str, Any]:
        await self._ensure_session()
        url = self.server_url + path
        return await self._session.get(url)


class _StdlibSession:
    """Minimal async HTTP session backed by urllib (no aiohttp dependency)."""

    def __init__(self, headers: dict[str, str], timeout: float) -> None:
        self.headers = headers
        self.timeout = timeout

    async def post(self, url: str, json: Any) -> dict[str, Any]:
        body = json_encode(json) if json is not None else b""
        return await self._request("POST", url, body)

    async def get(self, url: str) -> dict[str, Any]:
        return await self._request("GET", url, b"")

    async def close(self) -> None:
        pass

    async def _request(self, method: str, url: str, body: bytes) -> dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_request, method, url, body)

    def _sync_request(self, method: str, url: str, body: bytes) -> dict[str, Any]:
        req = urllib.request.Request(url, data=body or None, method=method)
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read().decode("utf-8")
                if not data:
                    return {}
                return json.loads(data)
        except urllib.error.HTTPError as e:
            body_bytes = e.read()
            try:
                err = json.loads(body_bytes)
                raise AgentAuthAPIError(
                    status_code=e.code,
                    code=err.get("code", "UNKNOWN"),
                    message=err.get("message", body_bytes.decode()),
                )
            except json.JSONDecodeError:
                raise AgentAuthAPIError(
                    status_code=e.code,
                    code="UNKNOWN",
                    message=body_bytes.decode(),
                )


def json_encode(obj: Any) -> bytes:
    return json.dumps(obj).encode("utf-8")


def _parse_datetime(s: str) -> datetime:
    if not s:
        return datetime.min
    # Handle various ISO 8601 formats
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return datetime.min
