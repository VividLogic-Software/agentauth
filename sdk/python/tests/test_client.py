"""Tests for agentauth.client — AgentAuthClient, data classes, _StdlibSession."""
import asyncio
import json
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentauth.client import (
    AccessToken,
    AgentAuthAPIError,
    AgentAuthClient,
    AgentIdentity,
    EnvelopeResponse,
    ToolScope,
    _parse_datetime,
)


# ---------------------------------------------------------------------------
# _parse_datetime
# ---------------------------------------------------------------------------

class TestParseDatetime:
    def test_parses_z_suffix(self):
        dt = _parse_datetime("2024-01-15T10:30:00Z")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15

    def test_parses_fractional_z(self):
        dt = _parse_datetime("2024-06-01T12:00:00.000Z")
        assert dt.year == 2024

    def test_returns_min_on_empty(self):
        assert _parse_datetime("") == datetime.min

    def test_returns_min_on_garbage(self):
        assert _parse_datetime("not-a-date") == datetime.min


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class TestAgentIdentity:
    def test_from_dict(self):
        data = {
            "id": "agent-1",
            "spiffe_id": "spiffe://agentauth.io/agent/acme/agent-1",
            "tenant_id": "acme",
            "delegator_id": "user:alice@acme.com",
            "declared_intent": "testing",
            "certificate_pem": "cert",
            "private_key_pem": "key",
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-01T01:00:00Z",
            "labels": {"env": "prod"},
        }
        identity = AgentIdentity.from_dict(data)
        assert identity.id == "agent-1"
        assert identity.spiffe_id == "spiffe://agentauth.io/agent/acme/agent-1"
        assert identity.tenant_id == "acme"
        assert identity.labels == {"env": "prod"}
        assert isinstance(identity.issued_at, datetime)

    def test_from_dict_missing_labels_defaults_to_empty(self):
        data = {
            "id": "agent-2",
            "spiffe_id": "spiffe://agentauth.io/agent/acme/agent-2",
            "issued_at": "",
            "expires_at": "",
        }
        identity = AgentIdentity.from_dict(data)
        assert identity.labels == {}


class TestEnvelopeResponse:
    def test_from_dict(self):
        data = {"token": "signed.jwt.token", "expires_at": "2024-01-01T00:15:00Z"}
        resp = EnvelopeResponse.from_dict(data)
        assert resp.token == "signed.jwt.token"
        assert resp.expires_at.minute == 15


class TestAccessToken:
    def test_from_dict(self):
        data = {
            "access_token": "tok-abc",
            "token_type": "Bearer",
            "expires_in": 300,
            "expires_at": "2024-01-01T00:05:00Z",
            "resource": "https://api.example.com",
            "scope": ["read"],
            "jti": "jti-xyz",
        }
        tok = AccessToken.from_dict(data)
        assert tok.access_token == "tok-abc"
        assert tok.token_type == "Bearer"
        assert tok.jti == "jti-xyz"
        assert tok.scopes == ["read"]

    def test_from_dict_defaults(self):
        data = {"access_token": "tok"}
        tok = AccessToken.from_dict(data)
        assert tok.token_type == "Bearer"
        assert tok.scopes == []
        assert tok.jti == ""


class TestToolScope:
    def test_to_dict_no_constraints(self):
        ts = ToolScope(tool="github.*", operations=["read"])
        assert ts.to_dict() == {"tool": "github.*", "operations": ["read"]}

    def test_to_dict_with_constraints(self):
        ts = ToolScope(tool="db.*", operations=["read"], constraints={"max_rows": "100"})
        d = ts.to_dict()
        assert d["constraints"] == {"max_rows": "100"}


# ---------------------------------------------------------------------------
# AgentAuthClient — using mocked _post and _get
# ---------------------------------------------------------------------------

def make_client(**kwargs) -> AgentAuthClient:
    return AgentAuthClient(server_url="http://localhost:8080", api_key="dev-key", **kwargs)


IDENTITY_DICT = {
    "id": "agent-1",
    "spiffe_id": "spiffe://agentauth.io/agent/acme/agent-1",
    "tenant_id": "acme",
    "delegator_id": "user:alice@acme.com",
    "declared_intent": "test",
    "certificate_pem": "cert",
    "private_key_pem": "key",
    "issued_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-01-01T01:00:00Z",
    "labels": {},
}

ENVELOPE_DICT = {"token": "env.jwt.here", "expires_at": "2024-01-01T00:15:00Z"}

TOKEN_DICT = {
    "access_token": "tok-abc",
    "token_type": "Bearer",
    "expires_in": 300,
    "expires_at": "2024-01-01T00:05:00Z",
    "resource": "https://api.example.com",
    "scope": ["read"],
    "jti": "jti-xyz",
}


class TestAgentAuthClientIssueIdentity:
    @pytest.mark.asyncio
    async def test_issue_identity_posts_correct_fields(self):
        client = make_client()
        client._post = AsyncMock(return_value=IDENTITY_DICT)
        result = await client.issue_identity(
            delegator_id="user:alice@acme.com",
            tenant_id="acme",
            declared_intent="test",
        )
        assert result.id == "agent-1"
        call_args = client._post.call_args
        path, payload = call_args[0]
        assert path == "/v1/identities"
        assert payload["delegator_id"] == "user:alice@acme.com"
        assert payload["tenant_id"] == "acme"
        assert payload["ttl"] == "1h"

    @pytest.mark.asyncio
    async def test_issue_identity_includes_agent_id_when_set(self):
        client = make_client()
        client._post = AsyncMock(return_value=IDENTITY_DICT)
        await client.issue_identity(
            delegator_id="u",
            tenant_id="t",
            declared_intent="i",
            agent_id="my-agent",
        )
        payload = client._post.call_args[0][1]
        assert payload["agent_id"] == "my-agent"

    @pytest.mark.asyncio
    async def test_issue_identity_omits_empty_agent_id(self):
        client = make_client()
        client._post = AsyncMock(return_value=IDENTITY_DICT)
        await client.issue_identity(delegator_id="u", tenant_id="t", declared_intent="i")
        payload = client._post.call_args[0][1]
        assert "agent_id" not in payload


class TestAgentAuthClientCreateEnvelope:
    @pytest.mark.asyncio
    async def test_create_envelope_posts_correct_fields(self):
        client = make_client()
        client._post = AsyncMock(return_value=ENVELOPE_DICT)
        result = await client.create_envelope(
            agent_id="agent-1",
            declared_intent="read tickets",
            tool_scope=[ToolScope(tool="zendesk.*", operations=["read"])],
        )
        assert result.token == "env.jwt.here"
        path, payload = client._post.call_args[0]
        assert path == "/v1/envelopes"
        assert payload["agent_id"] == "agent-1"
        assert payload["ttl"] == "15m"
        assert payload["tool_scope"] == [{"tool": "zendesk.*", "operations": ["read"]}]

    @pytest.mark.asyncio
    async def test_create_envelope_accepts_raw_dict_scope(self):
        client = make_client()
        client._post = AsyncMock(return_value=ENVELOPE_DICT)
        await client.create_envelope(
            agent_id="a",
            declared_intent="i",
            tool_scope=[{"tool": "raw.*", "operations": ["read"]}],
        )
        payload = client._post.call_args[0][1]
        assert payload["tool_scope"][0]["tool"] == "raw.*"


class TestAgentAuthClientMintToken:
    @pytest.mark.asyncio
    async def test_mint_token_posts_correct_fields(self):
        client = make_client()
        client._post = AsyncMock(return_value=TOKEN_DICT)
        result = await client.mint_token(
            envelope_token="env.jwt",
            resource="https://api.example.com",
            scopes=["read"],
        )
        assert result.access_token == "tok-abc"
        path, payload = client._post.call_args[0]
        assert path == "/v1/tokens"
        assert payload["envelope_token"] == "env.jwt"
        assert payload["ttl"] == "5m"


class TestAgentAuthClientRevokeToken:
    @pytest.mark.asyncio
    async def test_revoke_token_calls_correct_path(self):
        client = make_client()
        client._post = AsyncMock(return_value={})
        await client.revoke_token("jti-xyz")
        path = client._post.call_args[0][0]
        assert path == "/v1/tokens/jti-xyz/revoke"


class TestAgentAuthClientVerifyEnvelope:
    @pytest.mark.asyncio
    async def test_verify_envelope_sends_token(self):
        client = make_client()
        client._post = AsyncMock(return_value={"agent_id": "agent-1"})
        result = await client.verify_envelope("my.jwt.token")
        assert result["agent_id"] == "agent-1"
        path, payload = client._post.call_args[0]
        assert path == "/v1/envelopes/verify"
        assert payload["token"] == "my.jwt.token"


class TestAgentAuthClientTrailingSlash:
    def test_strips_trailing_slash(self):
        client = AgentAuthClient(server_url="http://localhost:8080/")
        assert client.server_url == "http://localhost:8080"


class TestAgentAuthClientAuthHeaders:
    def test_includes_bearer_token(self):
        client = make_client()
        headers = client._auth_headers()
        assert headers["Authorization"] == "Bearer dev-key"

    def test_no_auth_header_when_no_key(self):
        client = AgentAuthClient(server_url="http://localhost:8080")
        headers = client._auth_headers()
        assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# AgentAuthAPIError
# ---------------------------------------------------------------------------

class TestAgentAuthAPIError:
    def test_str_representation(self):
        err = AgentAuthAPIError(status_code=403, code="FORBIDDEN", message="scope too broad")
        assert "403" in str(err)
        assert "FORBIDDEN" in str(err)
        assert "scope too broad" in str(err)

    def test_attributes(self):
        err = AgentAuthAPIError(401, "UNAUTHORIZED", "missing key")
        assert err.status_code == 401
        assert err.code == "UNAUTHORIZED"
        assert err.message == "missing key"
