"""
AgentAuth ASGI middleware for FastAPI and Starlette MCP servers.

Drop-in middleware that enforces agent identity verification on every request
to your MCP server. Rejects unauthenticated or unauthorized requests before
they reach your handler.

Usage with FastAPI::

    from fastapi import FastAPI
    from agentauth.middleware import AgentAuthMiddleware, get_current_envelope

    app = FastAPI()
    app.add_middleware(
        AgentAuthMiddleware,
        server_url="https://auth.example.com",
        api_key="your-api-key",
        require_envelope=True,
    )

    @app.post("/tools/filesystem/read")
    async def filesystem_read(request: Request):
        envelope = get_current_envelope(request)
        # envelope is guaranteed to be valid here
        print(f"Agent {envelope.agent_id} is reading filesystem")
        ...

Usage with raw ASGI::

    from agentauth.middleware import AgentAuthMiddleware

    app = AgentAuthMiddleware(
        app=your_asgi_app,
        server_url="https://auth.example.com",
        api_key="your-api-key",
    )
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Awaitable

from agentauth.envelope import AgenticEnvelope, EnvelopeVerifier

logger = logging.getLogger("agentauth.middleware")

# ASGI type aliases
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class AgentAuthMiddleware:
    """
    ASGI middleware that enforces AgentAuth agent identity on MCP requests.

    For every incoming request, this middleware:
    1. Extracts the ``X-Agent-Envelope`` header
    2. Verifies the signed JWT (signature, expiry, issuer)
    3. Injects the verified envelope into the request state
    4. Returns 403 if the envelope is missing or invalid

    The verified envelope is available in request handlers via:
    - ``request.state.agent_envelope`` (FastAPI/Starlette)
    - ``scope["agentauth.envelope"]`` (raw ASGI)
    """

    ENVELOPE_HEADER = "x-agent-envelope"
    DPOP_HEADER = "dpop"

    def __init__(
        self,
        app: ASGIApp,
        server_url: str = "",
        api_key: str = "",
        public_key_pem: str = "",
        issuer: str = "agentauth",
        require_envelope: bool = True,
        skip_paths: list[str] | None = None,
        on_deny: Callable[[Scope, Send, str], Awaitable[None]] | None = None,
    ) -> None:
        """
        :param app: The inner ASGI application.
        :param server_url: AgentAuth server URL (used for online verification).
        :param api_key: API key for AgentAuth server calls.
        :param public_key_pem: Public key for offline envelope verification.
                               If provided, skips server round-trip for verification.
        :param issuer: Expected JWT issuer. Default "agentauth".
        :param require_envelope: If True (default), reject requests without an envelope.
        :param skip_paths: URL path prefixes to skip (e.g. ["/healthz", "/metrics"]).
        :param on_deny: Optional async callback to customize denial responses.
        """
        self.app = app
        self.server_url = server_url
        self.api_key = api_key
        self.require_envelope = require_envelope
        self.skip_paths = skip_paths or ["/healthz", "/readyz", "/metrics"]

        if public_key_pem:
            self.verifier: EnvelopeVerifier | None = EnvelopeVerifier(
                public_key_pem=public_key_pem, issuer=issuer
            )
        else:
            self.verifier = None

        self._on_deny = on_deny or _default_deny_response

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self._should_skip(path):
            await self.app(scope, receive, send)
            return

        # Extract headers
        headers = dict(scope.get("headers", []))
        envelope_token = headers.get(self.ENVELOPE_HEADER.encode(), b"").decode()

        if not envelope_token:
            if self.require_envelope:
                logger.warning("request rejected: missing X-Agent-Envelope header",
                               extra={"path": path})
                await self._on_deny(
                    scope, send, "missing X-Agent-Envelope header"
                )
                return
            await self.app(scope, receive, send)
            return

        # Verify the envelope
        envelope = await self._verify_envelope(envelope_token)
        if envelope is None:
            await self._on_deny(scope, send, "invalid or expired envelope")
            return

        # Inject envelope into scope for downstream handlers
        scope["agentauth.envelope"] = envelope
        scope["agentauth.agent_id"] = envelope.agent_id

        logger.debug(
            "request authorized",
            extra={
                "agent_id": envelope.agent_id,
                "tenant_id": envelope.tenant_id,
                "declared_intent": envelope.declared_intent,
                "path": path,
            },
        )

        await self.app(scope, receive, send)

    async def _verify_envelope(self, token: str) -> AgenticEnvelope | None:
        """Verify the envelope token, using local verification if a key is set."""
        if self.verifier is not None:
            try:
                return self.verifier.verify(token)
            except ValueError as e:
                logger.warning("envelope verification failed: %s", e)
                return None

        # Online verification via AgentAuth server
        if self.server_url:
            return await self._verify_online(token)

        # No verification configured — decode without checking (dev mode only)
        logger.warning(
            "SECURITY WARNING: envelope verification is disabled (no public_key_pem or server_url set)"
        )
        try:
            verifier = EnvelopeVerifier(public_key_pem="", issuer="agentauth")
            return verifier._decode_unverified(token)
        except Exception as e:
            logger.warning("failed to decode envelope: %s", e)
            return None

    async def _verify_online(self, token: str) -> AgenticEnvelope | None:
        """Verify an envelope by calling the AgentAuth server."""
        try:
            from agentauth.client import AgentAuthClient
            async with AgentAuthClient(self.server_url, self.api_key) as client:
                claims = await client.verify_envelope(token)
                if claims.get("valid"):
                    from agentauth.envelope import AgenticEnvelope
                    return AgenticEnvelope.from_dict(claims.get("claims", {}))
                return None
        except Exception as e:
            logger.error("online envelope verification failed: %s", e)
            return None

    def _should_skip(self, path: str) -> bool:
        """Check if the request path should skip authentication."""
        return any(path.startswith(prefix) for prefix in self.skip_paths)


async def _default_deny_response(scope: Scope, send: Send, reason: str) -> None:
    """Send a standard 403 JSON response."""
    body = json.dumps({
        "error": "forbidden",
        "code": "AGENT_AUTH_DENIED",
        "message": reason,
    }).encode("utf-8")

    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-agentauth-denied", reason.encode()[:256]),
        ],
    })
    await send({
        "type": "http.response.body",
        "body": body,
        "more_body": False,
    })


def get_current_envelope(request: Any) -> AgenticEnvelope | None:
    """
    Extract the verified AgenticEnvelope from a FastAPI/Starlette request.

    :param request: A FastAPI or Starlette Request object.
    :returns: The verified envelope, or None if not set.

    Example::

        from fastapi import Request
        from agentauth.middleware import get_current_envelope

        @app.post("/tools/database/query")
        async def query(request: Request):
            envelope = get_current_envelope(request)
            if not envelope or not envelope.has_tool_permission("database.query", "read"):
                raise HTTPException(status_code=403, detail="Not permitted")
            ...
    """
    if hasattr(request, "state") and hasattr(request.state, "agent_envelope"):
        return request.state.agent_envelope
    if hasattr(request, "scope"):
        return request.scope.get("agentauth.envelope")
    return None


def require_tool_permission(tool: str, operation: str):
    """
    FastAPI dependency that enforces a specific tool permission.

    Usage::

        from fastapi import Depends
        from agentauth.middleware import require_tool_permission

        @app.post("/tools/database/query")
        async def query(
            request: Request,
            _=Depends(require_tool_permission("database.query", "read"))
        ):
            ...
    """
    async def _dependency(request: Any) -> AgenticEnvelope:
        from fastapi import HTTPException

        envelope = get_current_envelope(request)
        if envelope is None:
            raise HTTPException(status_code=403, detail="No agent envelope present")
        if not envelope.has_tool_permission(tool, operation):
            raise HTTPException(
                status_code=403,
                detail=f"Agent not permitted to {operation} {tool}",
            )
        return envelope

    return _dependency
