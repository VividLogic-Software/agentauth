<div align="center">

```
    _                    _   _         _   _
   / \   __ _  ___ _ __ | |_/ \  _   _| |_| |__
  / _ \ / _` |/ _ \ '_ \| __/ _ \| | | | __| '_ \
 / ___ \ (_| |  __/ | | | || (_) | |_| | |_| | | |
/_/   \_\__, |\___|_| |_|\__\___/ \__,_|\__|_| |_|
         |___/
```

**The Open-Source Identity & Authorization Plane for AI Agents**

*SPIFFE + OAuth 2.x + OPA — fused, agent-native, production-ready.*

[![CI](https://github.com/VividLogic-Software/agentauth/actions/workflows/ci.yml/badge.svg)](https://github.com/VividLogic-Software/agentauth/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/VividLogic-Software/agentauth)](https://goreportcard.com/report/github.com/VividLogic-Software/agentauth)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](go.mod)
[![PyPI](https://img.shields.io/pypi/v/agentauth?color=blue&logo=python)](https://pypi.org/project/agentauth/)
[![npm](https://img.shields.io/npm/v/%40agentauth%2Fsdk?color=red&logo=npm)](https://www.npmjs.com/package/@agentauth/sdk)
[![Docker Pulls](https://img.shields.io/docker/pulls/agentauth/agentauth?logo=docker)](https://hub.docker.com/r/agentauth/agentauth)
[![Discord](https://img.shields.io/discord/1234567890?logo=discord&label=discord)](https://discord.gg/agentauth)
[![CNCF Landscape](https://img.shields.io/badge/CNCF%20Landscape-agentauth-blue)](https://landscape.cncf.io/)

</div>

---

## The Problem: Your Auth Stack Was Built for Humans

The authentication and authorization infrastructure underpinning every enterprise was designed for a single interaction model: a **human clicks "Allow."**

AI agents are something fundamentally different. They are:

- **Non-interactive** — they can't complete an OAuth consent screen
- **Continuously operating** — they run for hours, days, or indefinitely
- **Delegation-native** — they spawn sub-agents that spawn more sub-agents
- **Cross-boundary actors** — they call tools, APIs, and other agents across trust domains
- **Outnumbering humans 82:1** inside enterprises today (CyberArk, 2025)

The result is predictable and already measured:

| Metric | Reality |
|--------|---------|
| Agent projects using unscoped API keys | **93%** |
| Agents that end up over-permissioned | **74%** |
| Organizations with confirmed/suspected agent security incidents | **88%** |
| Organizations that tie verifiable identities to their agents | **22%** |

*Sources: 2026 practitioner survey; Okta AI Agents Report, Apr 2026; CyberArk Identity Security Landscape 2025*

**AgentAuth is the open-source answer.** A complete identity and authorization control plane purpose-built for the agent era: cryptographically-bound identities, signed delegation chains, just-in-time resource-scoped tokens, and a tamper-evident audit trail — shipped as one coherent platform instead of a build-it-yourself kit.

---

## How It Works

Every agent gets a **SPIFFE/SVID identity** and carries a signed **Agentic Identity Envelope** on every call. The envelope answers the four questions that matter at every trust boundary:

> *Who is this agent? Who delegated it? What is it allowed to do? Prove it.*

```
Human User ──delegates──▶ Agent A (SVID: spiffe://acme.com/agent/tenant-1/planner-7f3a)
                               │
                               │ spawns (delegates subset of permissions)
                               ▼
                          Agent B (SVID: spiffe://acme.com/agent/tenant-1/executor-2b9c)
                               │
                               │ calls MCP tool: "postgres.query"
                               ▼
                    ┌─ AgentAuth Middleware ──────────────────────────────────────────┐
                    │  1. Verify SVID signature + trust domain                       │
                    │  2. Parse Agentic Identity Envelope                            │
                    │  3. Verify delegation chain: Human → Agent A → Agent B         │
                    │  4. Check tool_scope: is "postgres.query" in envelope?         │
                    │  5. Evaluate OPA policy: is this op allowed at this time?      │
                    │  6. Mint JIT DPoP-bound token scoped to this exact resource    │
                    │  7. Record tamper-evident audit event                          │
                    └─────────────────────────────────────────────────────────────────┘
                               │
                         ✅ Allow (short-lived, scoped, DPoP-bound)
                            or
                         ❌ Deny (logged, alertable, kill-switch available)
```

---

## Quick Start

### Python (3 lines to protect your first agent)

```bash
pip install agentauth
```

```python
import asyncio
from agentauth import AgentAuthClient

client = AgentAuthClient(server_url="http://localhost:8080", api_key="your-api-key")

async def main():
    # Issue a cryptographically-bound identity for your agent
    identity = await client.issue_identity(
        delegator_id="user:alice@acme.com",
        tenant_id="acme",
        declared_intent="Analyze Q3 sales data and generate a summary report",
        labels={"team": "finance", "env": "production"},
    )
    print(f"Agent identity: {identity.spiffe_id}")
    print(f"Expires: {identity.expires_at}")

    # Create a signed envelope scoping exactly what this agent can do
    envelope_token = await client.create_envelope(
        agent_id=identity.id,
        delegator_id="user:alice@acme.com",
        tenant_id="acme",
        declared_intent="Analyze Q3 sales data and generate a summary report",
        tool_scope=[
            {"tool": "postgres.query", "operations": ["read"]},
            {"tool": "filesystem.write", "operations": ["write"],
             "constraints": {"path_prefix": "/reports/q3/"}},
        ],
    )

    # Verify an incoming envelope (in your MCP server or A2A handler)
    parsed = await client.verify_envelope(envelope_token)
    print(f"Delegated by: {parsed.delegator_id}")
    print(f"Depth: {parsed.delegation_depth} hops")
    print(f"Can query postgres? {parsed.has_tool_permission('postgres.query', 'read')}")

asyncio.run(main())
```

### TypeScript / Node.js

```bash
npm install @agentauth/sdk
```

```typescript
import { AgentAuthClient } from '@agentauth/sdk';

const client = new AgentAuthClient({
  serverUrl: 'http://localhost:8080',
  apiKey: process.env.AGENTAUTH_API_KEY,
});

// Issue identity
const identity = await client.issueIdentity({
  delegatorId: 'user:alice@acme.com',
  tenantId: 'acme',
  declaredIntent: 'Process customer support tickets and draft responses',
  labels: { team: 'support' },
});

// Create envelope with tool scope
const envelopeToken = await client.createEnvelope({
  agentId: identity.id,
  delegatorId: 'user:alice@acme.com',
  tenantId: 'acme',
  declaredIntent: 'Process customer support tickets and draft responses',
  toolScope: [
    { tool: 'zendesk.tickets.*', operations: ['read', 'write'] },
    { tool: 'email.send', operations: ['write'],
      constraints: { recipient_domain: 'customers.acme.com' } },
  ],
});

// Drop-in Express middleware for your MCP server
import { agentAuthMiddleware } from '@agentauth/sdk/middleware';
app.use('/tools', agentAuthMiddleware({ client, requiredTool: 'zendesk.tickets.*' }));
```

### Go

```bash
go get github.com/VividLogic-Software/agentauth/pkg/client
```

```go
import (
    "github.com/VividLogic-Software/agentauth/pkg/client"
    "github.com/VividLogic-Software/agentauth/pkg/middleware"
)

c := client.New("http://localhost:8080", client.WithAPIKey(os.Getenv("AGENTAUTH_API_KEY")))

// Drop-in chi/net-http middleware for MCP servers
r.Use(middleware.AgentAuth(c, middleware.RequireTool("filesystem.*")))
```

### Docker Compose (run AgentAuth in 60 seconds)

```bash
git clone https://github.com/VividLogic-Software/agentauth
cd agentauth
cp .env.example .env
docker compose up -d
# AgentAuth server at http://localhost:8080
# Dashboard at http://localhost:3000
```

---

## Core Features

### Identity Issuance
- **SPIFFE/SVID-compatible X.509 identities** — every agent gets a cryptographically-bound certificate with a `spiffe://` URI
- **Workload attestation** — automatically attest agents running in Kubernetes (service accounts), AWS (instance metadata/IRSA), GCP (workload identity), or any custom attestor
- **Automatic rotation** — credentials rotate before expiry; old certificates are revoked atomically
- **Kill switch** — revoke any agent identity instantly; revocation fans out via NATS in < 50ms

### Agentic Identity Envelope
- **Signed delegation chains** — every sub-agent carries a JWT envelope with a verifiable chain of custody from the root user/system
- **Declared intent** — human-readable description of the task, surfaced in audit logs and authorization UIs
- **Tool scope** — granular allowlist of MCP tools and operations with optional constraints
- **Delegation depth limits** — configurable maximum hop depth (default: 8) prevents unbounded delegation trees
- **Short-lived by design** — envelopes default to 15-minute TTL with configurable max of 4 hours

### Credential Broker
- **JIT token minting** — tokens are minted per-call, scoped to the exact resource being accessed (RFC 8707 Resource Indicators)
- **DPoP binding** (RFC 9449) — tokens are cryptographically bound to the agent's key pair; stolen tokens are useless
- **Token exchange** (RFC 8693) — structured delegation: exchange a parent envelope for a child-scoped token
- **Sender-constrained by default** — no bearer tokens; every token proves possession

### Policy Engine
- **OPA/Rego-compatible** — write policies in the language your team already knows
- **Built-in agent policies** — deny over-permissioned scopes, enforce delegation depth limits, block create/modify/delete/pay without step-up
- **Runtime guardrails** — check declared intent against allowed task types; flag prompt-injection patterns
- **Step-up authorization** — require explicit human approval for high-value or irreversible actions

### Tamper-Evident Audit Log
- **Hash-chained append-only log** — every identity issuance, token mint, policy decision, and revocation is recorded with a SHA-256 chain
- **OTel `gen_ai.*` spans** — every decision emits an OpenTelemetry trace; wire it to your existing observability stack
- **SIEM export** — structured JSON audit stream to any SIEM (Splunk, Elastic, Datadog)
- **SOC 2 / EU AI Act ready** — built-in audit export for high-risk AI Act obligations (Aug 2026)

### Framework Integrations
- **MCP middleware** — drop-in HTTP middleware for Model Context Protocol servers (Python/Go/TS)
- **A2A middleware** — per-hop envelope verification for Google Agent-to-Agent Protocol
- **LangChain/LangGraph** — native callback handler + tool wrapper
- **OpenAI Agents SDK** — compatible tool authorization hooks
- **CrewAI** — agent wrapper with identity envelope injection

---

## Architecture

```
                    ┌──────────────────────── GOVERNANCE LAYER ──────────────────────────┐
                    │  Policy authoring (OPA/Rego) · trust-domain config · audit export  │
                    └────────────────▲────────────────────────────────────▲──────────────┘
  AGENT LAYER                        │                                    │
  (LangGraph / CrewAI /              │ policy decisions                   │ audit events
   OpenAI SDK / custom)              │                                    │
        │ requests identity / token  │                                    │
        ▼                            │                                    │
  ┌─ API LAYER ──────────┐   ┌─ CONTROL PLANE ───────────────┐   ┌─ MONITORING LAYER ──┐
  │ gRPC + REST          │──▶│ Identity Issuer (attestation, │   │ OTel gen_ai.* spans │
  │ Python / TS / Go SDK │   │  SVID mint, rotation, revoke) │──▶│ tamper-evident log  │
  │ MCP / A2A middleware │   │ Credential Broker (JIT, DPoP, │   │ SIEM export         │
  └────────▲─────────────┘   │  RFC 8693/8707/9449)          │   └─────────────────────┘
           │                 │ Policy Decision Point (OPA)   │
           │ short-lived,    │ Delegation-chain Verifier     │
           │ scoped token    └────────────────▲──────────────┘
           ▼                                  │ state
  ┌─ DATA PLANE ──────────┐        ┌─ STORAGE LAYER ──────────────────┐  ┌─ SECURITY LAYER ──┐
  │ Per-call enforcement  │        │ PostgreSQL (registry, ownership,  │  │ HSM/KMS support   │
  │ at MCP server /       │        │  policy) · Redis (token cache,    │  │ TPM/enclave attest│
  │ A2A hop / tool gateway│        │  revocation) · Object store       │  │ key rotation      │
  └───────────────────────┘        │ (hash-chained audit log)          │  └───────────────────┘
                                   └─── EVENT LAYER: NATS (revocation + audit fan-out) ───────┘
```

---

## Envelope Anatomy

An Agentic Identity Envelope is a signed JWT carrying the full authorization context:

```json
{
  "delegator_id": "user:alice@acme.com",
  "agent_id": "spiffe://acme.com/agent/acme/planner-7f3a8b2c",
  "task_id": "01J4KX7M3Z-ANALYZE-Q3-SALES",
  "tenant_id": "acme",
  "session_id": "sess_2x9pqr",
  "declared_intent": "Analyze Q3 sales data and generate a summary report",
  "tool_scope": [
    {
      "tool": "postgres.query",
      "operations": ["read"],
      "constraints": { "schema": "public", "max_rows": "10000" }
    },
    {
      "tool": "filesystem.write",
      "operations": ["write"],
      "constraints": { "path_prefix": "/reports/q3/" }
    }
  ],
  "consent_ref": "consent_8f3a2b9c",
  "delegation_chain": ["<signed JWT of parent envelope>"],
  "iat": 1748995200,
  "exp": 1748996100,
  "jti": "env_01J4KX7M3Z",
  "ver": "1"
}
```

---

## Deployment

### Kubernetes (recommended for production)

```bash
# Install with Helm
helm repo add agentauth https://charts.agentauth.io
helm install agentauth agentauth/agentauth \
  --set postgres.external.url="postgresql://user:pass@db:5432/agentauth" \
  --set redis.external.url="redis://cache:6379" \
  --set config.trustDomain="my-company.com"
```

### Self-hosted (Docker Compose)

```bash
# Production-ready compose with TLS termination
docker compose -f docker-compose.yml up -d
```

### Managed Cloud

[AgentAuth Cloud](https://agentauth.io) — fully managed, SOC 2 Type II certified, with a generous free tier for open-source projects.

---

## Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v0.1** (MVP) | 🚀 Released | SPIFFE/SVID issuance · credential broker · agentic envelope · Python/TS/Go SDKs · MCP middleware · tamper-evident audit log |
| **v0.2** | 🔨 In Progress | A2A multi-hop delegation verification · OPA policy engine · agent registry with owner-of-record · NATS revocation fan-out · step-up auth |
| **v0.3** | 📋 Planned | WIMSE/Cross-App-Access integration · full K8s/AWS/GCP attestation · Helm chart · LangGraph/CrewAI/OpenAI SDK native integrations |
| **v1.0** | 🎯 Q4 2026 | Production hardened · HSM/KMS key storage · FedRAMP-ready · SOC 2 compliance pack · enterprise multi-tenancy |
| **v2.0** | 🔭 2027 | Hardware-attested (TPM/enclave) identities · cross-org federation · ERC-8004 reputation bridge · post-quantum credential agility |

---

## Why AgentAuth vs. Rolling Your Own

| Capability | DIY (SPIFFE alone) | DIY (OAuth alone) | AgentAuth |
|---|---|---|---|
| SPIFFE/SVID identity | ✅ | ❌ | ✅ |
| DPoP-bound JIT tokens | ❌ | Partial | ✅ |
| Signed delegation chains | ❌ | ❌ | ✅ |
| Declared-intent enforcement | ❌ | ❌ | ✅ |
| MCP middleware (drop-in) | ❌ | ❌ | ✅ |
| Tamper-evident audit log | ❌ | ❌ | ✅ |
| OPA policy engine | ❌ | ❌ | ✅ |
| Kill switch + revocation | Partial | Partial | ✅ |
| Time to first working agent | Days–weeks | Days–weeks | **Minutes** |

---

## Comparison with Proprietary Alternatives

AgentAuth is the only **credibly neutral, open-source** option. Proprietary alternatives (Oasis Security, Astrix, Descope, Okta for AI Agents) require you to trust a single vendor as the root of trust for your entire agent fleet — exactly the wrong architecture for infrastructure this critical.

| | AgentAuth | Proprietary SaaS | Build-your-own |
|---|---|---|---|
| License | Apache-2.0 | Proprietary | N/A |
| Self-host | ✅ | ❌ | ✅ |
| Vendor lock-in | ❌ | High | ❌ |
| Standards-based (SPIFFE, OAuth) | ✅ | Partial | Your choice |
| Time to production | Hours | Days | Months |
| Cost | Free + cloud option | $$$$ | Engineering time |

---

## Security

AgentAuth is security-critical infrastructure. We take disclosures seriously.

- **Report vulnerabilities:** security@agentauth.io (PGP key: [SECURITY.md](SECURITY.md))
- **Security advisories:** [GitHub Security Advisories](https://github.com/VividLogic-Software/agentauth/security/advisories)
- We follow a 90-day coordinated disclosure policy

See [SECURITY.md](SECURITY.md) for the full disclosure policy and supported versions.

---

## Contributing

AgentAuth is built in the open and welcomes contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- Architecture overview
- How to run the test suite
- Pull request process
- Code style guide

**Good first issues:** [`good-first-issue`](https://github.com/VividLogic-Software/agentauth/labels/good-first-issue)

---

## Community

- **Discord:** [discord.gg/agentauth](https://discord.gg/agentauth) — get help, share ideas, meet the team
- **GitHub Discussions:** [github.com/VividLogic-Software/agentauth/discussions](https://github.com/VividLogic-Software/agentauth/discussions)
- **Twitter/X:** [@agentauth_io](https://twitter.com/agentauth_io)
- **Newsletter:** [agentauth.io/newsletter](https://agentauth.io/newsletter)

---

## Acknowledgements

AgentAuth is built on the shoulders of giants:

- [SPIFFE/SPIRE](https://github.com/spiffe/spire) — the CNCF-graduated workload identity standard
- [Open Policy Agent](https://www.openpolicyagent.org/) — policy engine
- [go-spiffe](https://github.com/spiffe/go-spiffe) — Go SPIFFE SDK
- [golang-jwt](https://github.com/golang-jwt/jwt) — JWT library
- The IETF WIMSE and OAuth working groups for `draft-klrc-aiagent-auth` and related specs

---

## License

AgentAuth core is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

Enterprise features (multi-tenant governance UI, compliance modules, SSO/SCIM) are available under a commercial license. Contact [enterprise@agentauth.io](mailto:enterprise@agentauth.io).

---

<div align="center">

**AgentAuth** — *Because every agent deserves a cryptographic identity.*

[Website](https://agentauth.io) · [Docs](https://docs.agentauth.io) · [Discord](https://discord.gg/agentauth) · [Cloud](https://agentauth.io/cloud)

</div>
