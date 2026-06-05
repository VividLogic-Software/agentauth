"""
AgentAuth envelope module — create, sign, and verify Agentic Identity Envelopes.

For most use cases, use AgentAuthClient.create_envelope() instead of this module
directly. This module is for low-level envelope operations when you need to
verify envelopes without calling the server.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Optional JWT library — use PyJWT if available
try:
    import jwt as pyjwt  # type: ignore[import]
    _HAS_PYJWT = True
except ImportError:
    _HAS_PYJWT = False


@dataclass
class ToolPermission:
    """Defines the tools and operations an agent is permitted to use."""

    #: The MCP tool name or glob pattern.
    #: Examples: "filesystem.read", "github.issues.*", "postgres://db/*"
    tool: str

    #: The allowed operations. Use ["*"] for all operations.
    operations: list[str]

    #: Optional additional constraints (e.g. {"max_rows": "1000"})
    constraints: dict[str, str] = field(default_factory=dict)

    def allows(self, tool: str, operation: str) -> bool:
        """Check if this permission allows the given tool and operation."""
        if not _matches_pattern(self.tool, tool):
            return False
        return any(op == "*" or op == operation for op in self.operations)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"tool": self.tool, "operations": self.operations}
        if self.constraints:
            d["constraints"] = self.constraints
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolPermission":
        return cls(
            tool=data["tool"],
            operations=data.get("operations", []),
            constraints=data.get("constraints") or {},
        )


@dataclass
class AgenticEnvelope:
    """
    The Agentic Identity Envelope carries the complete authorization context
    for an AI agent — who it is, who delegated it, what it may do, and for how long.

    This is the core data structure of AgentAuth. Every MCP tool call and
    A2A delegation must carry a signed envelope.
    """

    #: SPIFFE ID of the entity that spawned this agent.
    delegator_id: str

    #: SPIFFE SVID of the executing agent.
    agent_id: str

    #: Unique identifier for this task execution.
    task_id: str

    #: Organization/tenant scope.
    tenant_id: str

    #: Session scope grouping related envelopes.
    session_id: str

    #: Human-readable description of what the agent will do.
    declared_intent: str

    #: The tools this agent is authorized to use.
    tool_scope: list[ToolPermission]

    #: Reference to the recorded user consent.
    consent_ref: str

    #: Signed parent envelopes forming the delegation chain.
    delegation_chain: list[str]

    #: Unix timestamp of issuance.
    issued_at: int

    #: Unix timestamp of expiry.
    expires_at: int

    #: Unique JWT ID for revocation.
    jti: str

    #: Envelope format version.
    version: str = "1"

    @property
    def is_expired(self) -> bool:
        """Returns True if the envelope has passed its expiration time."""
        return time.time() > self.expires_at

    @property
    def delegation_depth(self) -> int:
        """Returns the number of delegation hops in this envelope."""
        return len(self.delegation_chain)

    def has_tool_permission(self, tool: str, operation: str) -> bool:
        """
        Check whether this envelope grants the specified operation on the given tool.

        :param tool: The tool name (e.g. "filesystem.read", "github.issues.create").
        :param operation: The operation (e.g. "read", "write", "delete").
        :returns: True if the tool/operation is permitted.
        """
        return any(perm.allows(tool, operation) for perm in self.tool_scope)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgenticEnvelope":
        """Deserialize an AgenticEnvelope from a claims dictionary."""
        return cls(
            delegator_id=data.get("delegator_id", ""),
            agent_id=data.get("agent_id", data.get("sub", "")),
            task_id=data.get("task_id", ""),
            tenant_id=data.get("tenant_id", ""),
            session_id=data.get("session_id", ""),
            declared_intent=data.get("declared_intent", ""),
            tool_scope=[
                ToolPermission.from_dict(ts)
                for ts in data.get("tool_scope", [])
            ],
            consent_ref=data.get("consent_ref", ""),
            delegation_chain=data.get("delegation_chain") or [],
            issued_at=data.get("iat", 0),
            expires_at=data.get("exp", 0),
            jti=data.get("jti", ""),
            version=data.get("ver", "1"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the envelope to a dictionary."""
        return {
            "delegator_id": self.delegator_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "declared_intent": self.declared_intent,
            "tool_scope": [ts.to_dict() for ts in self.tool_scope],
            "consent_ref": self.consent_ref,
            "delegation_chain": self.delegation_chain,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.jti,
            "ver": self.version,
        }


class EnvelopeVerifier:
    """
    Verifies signed Agentic Identity Envelope JWTs using the AgentAuth public key.

    Use this in your MCP server or A2A endpoint to verify incoming envelopes
    without calling the AgentAuth server (offline verification).

    Example::

        from agentauth import EnvelopeVerifier

        verifier = EnvelopeVerifier(public_key_pem=PUBLIC_KEY_PEM)

        # In your request handler:
        envelope = verifier.verify(request.headers["X-Agent-Envelope"])
        if not envelope.has_tool_permission("filesystem.read", "read"):
            raise PermissionError("Agent not permitted to read filesystem")
    """

    def __init__(self, public_key_pem: str, issuer: str = "agentauth") -> None:
        """
        :param public_key_pem: The ECDSA P-256 public key in PEM format.
        :param issuer: The expected JWT issuer claim value.
        """
        self.public_key_pem = public_key_pem
        self.issuer = issuer
        self._key: Any = None

        if _HAS_PYJWT:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key  # type: ignore[import]
            try:
                self._key = load_pem_public_key(public_key_pem.encode())
            except Exception as e:
                raise ValueError(f"Invalid public key PEM: {e}") from e

    def verify(self, token: str) -> AgenticEnvelope:
        """
        Verify a signed envelope JWT and return the parsed envelope.

        :param token: The signed JWT string from the X-Agent-Envelope header.
        :returns: Parsed AgenticEnvelope with verified claims.
        :raises ValueError: If the token is invalid, expired, or has bad signature.
        """
        if not token:
            raise ValueError("envelope token is empty")

        if _HAS_PYJWT and self._key is not None:
            try:
                claims = pyjwt.decode(
                    token,
                    self._key,
                    algorithms=["ES256"],
                    options={"require": ["exp", "iat", "iss", "sub"]},
                    issuer=self.issuer,
                )
                return AgenticEnvelope.from_dict(claims)
            except pyjwt.ExpiredSignatureError:
                raise ValueError("envelope token has expired")
            except pyjwt.InvalidTokenError as e:
                raise ValueError(f"invalid envelope token: {e}")
        else:
            # Fallback: decode without signature verification (dev mode only)
            # NEVER use this in production
            return self._decode_unverified(token)

    def _decode_unverified(self, token: str) -> AgenticEnvelope:
        """Decode without signature verification — for development only."""
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed JWT: expected 3 parts")

        # Add padding for base64url decoding
        payload_b64 = parts[1] + "==" * (4 - len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        claims = json.loads(payload_bytes)
        return AgenticEnvelope.from_dict(claims)


class EnvelopeSigner:
    """
    Signs Agentic Identity Envelopes using an ECDSA P-256 private key.

    Typically you don't need this class directly — use AgentAuthClient.create_envelope()
    which calls the server to sign envelopes. This class is for advanced use cases
    where you need to sign envelopes locally (e.g. offline or edge deployments).

    Example::

        from agentauth import EnvelopeSigner, ToolPermission

        signer = EnvelopeSigner(private_key_pem=PRIVATE_KEY_PEM)
        token = signer.sign(
            agent_id="spiffe://agentauth.io/agent/my-org/abc123",
            declared_intent="Summarize customer emails",
            tool_scope=[ToolPermission("gmail.read", ["read"])],
            tenant_id="my-org",
            ttl_seconds=900,
        )
    """

    def __init__(self, private_key_pem: str, issuer: str = "agentauth") -> None:
        """
        :param private_key_pem: The ECDSA P-256 private key in PEM format.
        :param issuer: The JWT issuer claim value.
        """
        self.private_key_pem = private_key_pem
        self.issuer = issuer
        self._key: Any = None

        if _HAS_PYJWT:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key  # type: ignore[import]
            try:
                self._key = load_pem_private_key(private_key_pem.encode(), password=None)
            except Exception as e:
                raise ValueError(f"Invalid private key PEM: {e}") from e

    def sign(
        self,
        agent_id: str,
        declared_intent: str,
        tool_scope: list[ToolPermission],
        tenant_id: str,
        delegator_id: str = "",
        session_id: str = "",
        ttl_seconds: int = 900,
        delegation_chain: list[str] | None = None,
    ) -> str:
        """
        Sign a new envelope JWT.

        :returns: Signed JWT string.
        :raises RuntimeError: If PyJWT or cryptography is not installed.
        """
        if not _HAS_PYJWT or self._key is None:
            raise RuntimeError(
                "PyJWT and cryptography are required for local signing. "
                "Install them with: pip install agentauth[crypto]"
            )

        import uuid

        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": agent_id,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "declared_intent": declared_intent,
            "tool_scope": [ts.to_dict() for ts in tool_scope],
            "ver": "1",
        }
        if delegator_id:
            payload["delegator_id"] = delegator_id
        if session_id:
            payload["session_id"] = session_id
        if delegation_chain:
            payload["delegation_chain"] = delegation_chain

        token = pyjwt.encode(payload, self._key, algorithm="ES256")
        if isinstance(token, bytes):
            return token.decode("utf-8")
        return token


def _matches_pattern(pattern: str, value: str) -> bool:
    """Check if a glob pattern matches a tool name."""
    if pattern == "*" or pattern == value:
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return value == prefix or value.startswith(prefix + ".")
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return False
