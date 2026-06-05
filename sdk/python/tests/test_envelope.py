"""Tests for agentauth.envelope — ToolPermission, AgenticEnvelope, EnvelopeVerifier."""
import base64
import json
import time

import pytest

from agentauth.envelope import AgenticEnvelope, EnvelopeVerifier, ToolPermission, _matches_pattern


def _make_claims(**overrides):
    now = int(time.time())
    claims = {
        "delegator_id": "user:alice@acme.com",
        "agent_id": "spiffe://agentauth.io/agent/acme/agent-1",
        "task_id": "task-abc",
        "tenant_id": "acme",
        "session_id": "session-xyz",
        "declared_intent": "Process support tickets",
        "tool_scope": [
            {"tool": "zendesk.tickets.*", "operations": ["read", "write"]},
            {"tool": "filesystem.read", "operations": ["read"]},
        ],
        "iat": now - 60,
        "exp": now + 900,
        "jti": "jti-123",
        "ver": "1",
    }
    claims.update(overrides)
    return claims


def _make_token(claims=None):
    """Build a fake (unsigned) JWT from a claims dict."""
    if claims is None:
        claims = _make_claims()
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"fake-sig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"


# ---------------------------------------------------------------------------
# _matches_pattern
# ---------------------------------------------------------------------------

class TestMatchesPattern:
    def test_exact_match(self):
        assert _matches_pattern("filesystem.read", "filesystem.read")

    def test_wildcard_tool(self):
        assert _matches_pattern("*", "anything.at.all")

    def test_glob_prefix_sub_tool(self):
        assert _matches_pattern("github.issues.*", "github.issues.create")

    def test_glob_prefix_exact(self):
        assert _matches_pattern("github.issues.*", "github.issues")

    def test_glob_prefix_no_match(self):
        assert not _matches_pattern("github.issues.*", "github.pulls.create")

    def test_trailing_star(self):
        assert _matches_pattern("github.*", "github.issues")

    def test_no_match(self):
        assert not _matches_pattern("filesystem.read", "filesystem.write")


# ---------------------------------------------------------------------------
# ToolPermission
# ---------------------------------------------------------------------------

class TestToolPermission:
    def test_allows_exact(self):
        perm = ToolPermission(tool="filesystem.read", operations=["read"])
        assert perm.allows("filesystem.read", "read")

    def test_denies_wrong_operation(self):
        perm = ToolPermission(tool="filesystem.read", operations=["read"])
        assert not perm.allows("filesystem.read", "write")

    def test_wildcard_operation(self):
        perm = ToolPermission(tool="db.query", operations=["*"])
        assert perm.allows("db.query", "delete")

    def test_glob_tool_pattern(self):
        perm = ToolPermission(tool="zendesk.tickets.*", operations=["read", "write"])
        assert perm.allows("zendesk.tickets.list", "read")
        assert perm.allows("zendesk.tickets.update", "write")

    def test_glob_tool_no_match(self):
        perm = ToolPermission(tool="zendesk.tickets.*", operations=["read"])
        assert not perm.allows("zendesk.users.get", "read")

    def test_to_dict_no_constraints(self):
        perm = ToolPermission(tool="x.y", operations=["read"])
        d = perm.to_dict()
        assert d == {"tool": "x.y", "operations": ["read"]}
        assert "constraints" not in d

    def test_to_dict_with_constraints(self):
        perm = ToolPermission(tool="db.*", operations=["read"], constraints={"max_rows": "100"})
        assert perm.to_dict()["constraints"] == {"max_rows": "100"}

    def test_from_dict_round_trip(self):
        d = {"tool": "github.*", "operations": ["read"], "constraints": {"repo": "my-repo"}}
        perm = ToolPermission.from_dict(d)
        assert perm.tool == "github.*"
        assert perm.operations == ["read"]
        assert perm.constraints == {"repo": "my-repo"}


# ---------------------------------------------------------------------------
# AgenticEnvelope
# ---------------------------------------------------------------------------

class TestAgenticEnvelope:
    def test_from_dict_parses_fields(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert env.delegator_id == "user:alice@acme.com"
        assert env.agent_id == "spiffe://agentauth.io/agent/acme/agent-1"
        assert env.tenant_id == "acme"
        assert env.jti == "jti-123"
        assert env.version == "1"

    def test_has_tool_permission_allowed(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert env.has_tool_permission("zendesk.tickets.list", "read")
        assert env.has_tool_permission("zendesk.tickets.create", "write")
        assert env.has_tool_permission("filesystem.read", "read")

    def test_has_tool_permission_denied_op(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert not env.has_tool_permission("filesystem.read", "write")

    def test_has_tool_permission_denied_tool(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert not env.has_tool_permission("github.issues.create", "write")

    def test_is_expired_false(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert not env.is_expired

    def test_is_expired_true(self):
        env = AgenticEnvelope.from_dict(_make_claims(exp=int(time.time()) - 1))
        assert env.is_expired

    def test_delegation_depth_root(self):
        env = AgenticEnvelope.from_dict(_make_claims())
        assert env.delegation_depth == 0

    def test_delegation_depth_chain(self):
        env = AgenticEnvelope.from_dict(_make_claims(delegation_chain=["jwt-1", "jwt-2"]))
        assert env.delegation_depth == 2

    def test_to_dict_round_trip(self):
        claims = _make_claims()
        env = AgenticEnvelope.from_dict(claims)
        d = env.to_dict()
        assert d["agent_id"] == "spiffe://agentauth.io/agent/acme/agent-1"
        assert d["tenant_id"] == "acme"
        assert isinstance(d["tool_scope"], list)

    def test_missing_optional_fields_default(self):
        minimal = {
            "agent_id": "agent-1",
            "declared_intent": "test",
            "tool_scope": [],
            "iat": 0,
            "exp": int(time.time()) + 900,
            "jti": "jti-min",
        }
        env = AgenticEnvelope.from_dict(minimal)
        assert env.consent_ref == ""
        assert env.delegation_chain == []
        assert env.delegator_id == ""


# ---------------------------------------------------------------------------
# EnvelopeVerifier (development / no PyJWT mode)
# ---------------------------------------------------------------------------

class TestEnvelopeVerifier:
    def test_decode_unverified_returns_envelope(self):
        verifier = EnvelopeVerifier.__new__(EnvelopeVerifier)
        verifier.public_key_pem = "dummy"
        verifier.issuer = "agentauth"
        verifier._key = None  # force dev mode
        token = _make_token()
        env = verifier.verify(token)
        assert env.tenant_id == "acme"
        assert env.jti == "jti-123"

    def test_raises_on_empty_token(self):
        verifier = EnvelopeVerifier.__new__(EnvelopeVerifier)
        verifier.public_key_pem = ""
        verifier.issuer = "agentauth"
        verifier._key = None
        with pytest.raises(ValueError, match="empty"):
            verifier.verify("")

    def test_raises_on_malformed_jwt(self):
        verifier = EnvelopeVerifier.__new__(EnvelopeVerifier)
        verifier.public_key_pem = ""
        verifier.issuer = "agentauth"
        verifier._key = None
        with pytest.raises(ValueError, match="malformed"):
            verifier.verify("not.a.valid.jwt.here.extra")

    def test_decode_unverified_two_part_raises(self):
        verifier = EnvelopeVerifier.__new__(EnvelopeVerifier)
        verifier.public_key_pem = ""
        verifier.issuer = "agentauth"
        verifier._key = None
        with pytest.raises(ValueError, match="3 parts"):
            verifier._decode_unverified("header.payload")
