# Changelog

All notable changes to AgentAuth are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SPIRE integration for production workload attestation
- gRPC API alongside REST
- Agent registry UI (web dashboard)
- Consent management API
- Rate limiting per agent/tenant
- WASM policy modules as alternative to OPA

---

## [0.1.0] — 2025-06-04

### Added

**Core Identity**
- SPIFFE/SVID identity issuance for AI agents with X.509 certificates
- SPIFFE URI format: `spiffe://agentauth.io/agent/{tenant_id}/{agent_id}`
- Workload attestation support: Kubernetes service account tokens, AWS IMDSv2, join tokens
- Identity rotation and revocation with immediate effect
- PostgreSQL-backed identity registry with SPIFFE ID index

**Agentic Identity Envelope**
- Signed JWT-based envelope carrying delegator ID, agent ID, task ID, tenant, session, declared intent, tool scope, consent ref, and delegation chain
- ES256 signing (ECDSA P-256)
- Configurable TTL with maximum 4h cap
- Tool permission matching with glob patterns (e.g. `github.issues.*`)
- Delegation depth tracking with configurable maximum (default 8)

**JIT Credential Brokering**
- Short-lived OAuth 2.1 access tokens scoped to specific resources (RFC 8707)
- DPoP proof validation (RFC 9449) for key-bound tokens
- RFC 8693 token exchange endpoint
- Token revocation with immediate Redis cache invalidation
- Envelope-to-token scope alignment validation

**Delegation Chain Management**
- Agent-to-agent delegation via `POST /v1/envelopes/delegate`
- Cryptographic delegation chain embedded in child envelopes
- Scope subset validation — sub-agents cannot escalate beyond parent scope
- Full chain verification including each link's signature

**Policy Engine**
- OPA/Rego-based policy evaluation
- Built-in policies: baseline authorization, filesystem safety, data exfil prevention
- Tenant-level tool allowlists and blocklists
- Runtime policy loading and hot reloading (planned)

**Tamper-Evident Audit Log**
- SHA-256 hash-chained append-only log
- Full chain integrity verification endpoint
- Fields: agent_id, action, resource, decision, envelope_ref, metadata, prev_hash, entry_hash

**HTTP Middleware**
- Go: `pkg/middleware/mcp.go` — chi/net/http compatible MCP middleware
- Go: `pkg/middleware/a2a.go` — A2A delegation middleware with chain verification
- Python: `AgentAuthMiddleware` — ASGI middleware for FastAPI/Starlette
- TypeScript: `agentAuthMiddleware` — Express/Connect middleware

**Client Libraries**
- Go: `pkg/client/client.go`
- Python: `sdk/python/agentauth` (PyPI: `agentauth`)
- TypeScript: `sdk/typescript/src` (npm: `@agentauth/sdk`)

**Infrastructure**
- Multi-stage Dockerfile with distroless final image (~15MB)
- docker-compose.yml with PostgreSQL 16, Redis 7, NATS
- Kubernetes manifests: namespace, deployment (3 replicas), service, configmap, RBAC
- Helm chart with full values.yaml
- GitHub Actions: CI (Go, Python, TypeScript, Docker), release (multi-arch), security (CodeQL, Trivy, govulncheck)

**Examples**
- LangChain agent with AgentAuth protection
- MCP server with per-tool authorization enforcement
- A2A delegation chain example

[Unreleased]: https://github.com/VividLogic-Software/agentauth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/VividLogic-Software/agentauth/releases/tag/v0.1.0
