# Core Concepts

## 1. Agent Identity (SPIFFE/SVID)

Every agent gets a cryptographically-bound X.509 certificate with a SPIFFE URI
in the format `spiffe://agentauth.io/agent/{tenant_id}/{agent_id}`. Unlike
static API keys, SVIDs are short-lived (default 1 hour, max 24 hours), rotate
automatically, and can be revoked instantly. Workload attestation proves the
agent is running in a trusted environment (Kubernetes service account, AWS IAM,
GCP workload identity). Code reference: `internal/identity/issuer.go`.

## 2. The Agentic Identity Envelope

A signed ES256 JWT that carries the full authorization context. Key fields:
`delegator_id` (who spawned the agent), `agent_id` (the executing agent),
`task_id`, `tenant_id`, `session_id`, `declared_intent` (human-readable task),
`tool_scope` (allowed tools and operations), and `delegation_chain` (parent
envelope tokens). Default TTL is 15 minutes (max 4 hours). Max delegation
depth is 8 hops. The envelope must be passed as the `X-Agent-Envelope` HTTP
header on every MCP tool call and A2A hop. Code reference:
`internal/envelope/agentic_envelope.go`.

## 3. Just-In-Time Credential Brokering

Tokens are minted per-call, scoped to one exact resource (RFC 8707 Resource
Indicators). Default TTL is 5 minutes (max 30), always capped by the envelope's
remaining TTL. DPoP binding (RFC 9449) cryptographically ties the token to the
agent's private key — a stolen token is useless because the attacker cannot
prove possession of the key. Code reference:
`internal/broker/credential_broker.go`.

## 4. Delegation Chains

Delegation follows a parent-to-child model: Human → Agent A → Agent B. Each
hop creates a child envelope with a subset of the parent's `tool_scope`
(attenuation-only — sub-agents can never exceed their parent's permissions).
Maximum delegation depth is 8 hops (configurable per tenant, default 4). The
full chain is embedded in `delegation_chain` as an array of parent JWT tokens,
enabling cryptographic verification at every hop. Code reference:
`internal/envelope/delegation.go`.

## 5. Tamper-Evident Audit Log

Every identity issuance, token mint, policy decision, and tool call is recorded
in a hash-chained append-only log. Each entry contains
`SHA-256(prev_entry_hash + event_data)`, forming an unbreakable chain. Chain
integrity can be verified at any time via `GET /v1/audit/verify`. Compliant
with SOC 2 Type II and EU AI Act high-risk audit requirements. Code references:
`internal/audit/log.go`, `internal/audit/chain.go`.
