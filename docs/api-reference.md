# API Reference

All `/v1/*` routes require `Authorization: Bearer <api-key>` header.

## Health & Version

### `GET /healthz`

Liveness check. No auth required.

**Response:** `{"status":"ok"}`

### `GET /readyz`

Readiness check. No auth required.

**Response:** `{"status":"ready"}`

### `GET /version`

Returns server version. No auth required.

**Response:** `{"version":"0.1.0","go_version":"go1.22"}`

## Identities

### `POST /v1/identities`

Issue a new agent identity (SPIFFE SVID).

**Request:**
```json
{
  "agent_id": "optional-uuid",
  "delegator_id": "user:alice@acme.com",
  "tenant_id": "acme",
  "declared_intent": "Analyze Q3 sales data",
  "ttl": "1h",
  "attestation": {},
  "labels": {"team": "finance"}
}
```

**Response (201):**
```json
{
  "id": "uuid",
  "spiffe_id": "spiffe://agentauth.io/agent/acme/uuid",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----...",
  "issued_at": "2026-01-01T00:00:00Z",
  "expires_at": "2026-01-01T01:00:00Z",
  "labels": {}
}
```

### `GET /v1/identities/{agentID}`

Retrieve an identity record.

**Response:** Full identity record (no private key).

### `POST /v1/identities/{agentID}/revoke`

Revoke an identity immediately.

**Response (204):** No content.

### `POST /v1/identities/{agentID}/rotate`

Rotate credentials (issue new certificate).

**Response:** New identity with fresh certificate.

### `GET /v1/identities`

List identities for a tenant. Query params: `tenant_id`, `limit`, `offset`.

**Response:** `{"items":[],"total":0}`

## Envelopes

### `POST /v1/envelopes`

Create a signed Agentic Identity Envelope.

**Request:**
```json
{
  "agent_id": "spiffe://agentauth.io/agent/acme/uuid",
  "delegator_id": "user:alice@acme.com",
  "tenant_id": "acme",
  "declared_intent": "Analyze Q3 sales data",
  "tool_scope": [{"tool": "postgres.query", "operations": ["read"]}],
  "ttl": "15m"
}
```

**Response (201):** `{"token":"<signed-jwt>","expires_at":"..."}`

### `POST /v1/envelopes/verify`

Verify a signed envelope token.

**Request:** `{"token":"<signed-jwt>"}`

**Response:** `{"valid":true,"claims":{...}}`

### `POST /v1/envelopes/delegate`

Delegate authority to a sub-agent.

**Request:**
```json
{
  "parent_envelope_token": "<signed-jwt>",
  "sub_agent_id": "spiffe://...",
  "declared_intent": "Summarize emails",
  "tool_scope": [{"tool": "gmail.read", "operations": ["read"]}],
  "ttl": "10m"
}
```

**Response (201):** `{"token":"<sub-agent-jwt>","expires_at":"..."}`

## Tokens

### `POST /v1/tokens`

Mint a JIT access token.

**Request:**
```json
{
  "envelope_token": "<signed-jwt>",
  "resource": "https://api.example.com/resource",
  "scopes": ["read"],
  "dpop_proof": "optional-dpop-jwt",
  "ttl": "5m"
}
```

**Response (201):**
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### `POST /v1/tokens/{jti}/revoke`

Revoke a token by JTI.

**Response (204):** No content.

### `POST /v1/token`

RFC 8693 token exchange.

**Response:**
```json
{
  "access_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300
}
```

## Audit

### `GET /v1/audit`

List audit events.

**Response:** `{"items":[],"total":0}`

### `GET /v1/audit/verify`

Verify hash chain integrity.

**Response:** `{"verified":true,"entries_checked":0}`

## Policies

### `GET /v1/policies`

List policies.

**Response:** `{"items":[],"total":0}`

### `POST /v1/policies`

Create a policy.

**Response (201):** `{"id":"","package":"","version":""}`

### `DELETE /v1/policies/{policyID}`

Delete a policy.

**Response (204):** No content.
