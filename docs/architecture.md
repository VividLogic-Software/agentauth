# AgentAuth Architecture

## Overview

AgentAuth is an open-source identity and authorization control plane for AI
agents. It sits between agents and the tools they call, providing cryptographic
identity (SPIFFE/SVID), just-in-time credential brokering, OPA policy enforcement,
signed delegation chains, and a tamper-evident audit log.

## Component Map

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
  │ gRPC + REST          │──▶│ Identity Issuer (attestation,  │   │ OTel gen_ai.* spans │
  │ Python / TS / Go SDK │   │  SVID mint, rotation, revoke) │──▶│ tamper-evident log  │
  │ MCP / A2A middleware │   │ Credential Broker (JIT, DPoP,  │   │ SIEM export         │
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

## Request Lifecycle

1. Agent calls an MCP tool, sending its envelope as `X-Agent-Envelope` header
2. MCP middleware extracts the envelope and verifies the JWT signature + expiry
3. Policy engine evaluates the request against the envelope's tool scope and tenant rules
4. If allowed, the credential broker mints a JIT DPoP-bound token scoped to the resource
5. The audit event (allow or deny) is recorded in the hash-chained audit log
6. The request is forwarded to the tool handler with the verified envelope in context, or a 403 is returned

## Data Flow

- **PostgreSQL**: persistent store for agent identities, access token records, audit log entries, tenant policy config
- **Redis**: hot revocation cache and ephemeral token store; enables sub-50ms revocation checks
- **NATS**: event bus for revocation fan-out and audit event distribution; ensures all nodes see revocation events within milliseconds

## Key Packages

| Package | Purpose |
|---------|---------|
| `internal/identity` | SPIFFE/SVID issuance, attestation, rotation, revocation |
| `internal/broker` | JIT token minting with DPoP binding and RFC 8693 exchange |
| `internal/envelope` | Agentic Identity Envelope signing, verification, delegation chain management |
| `internal/policy` | OPA/Rego policy evaluation and built-in guardrails |
| `internal/audit` | Hash-chained append-only audit log |
| `internal/storage` | PostgreSQL and Redis persistence layer |
| `pkg/middleware` | Drop-in MCP and A2A HTTP middleware |
| `pkg/client` | Go client library for the control plane API |

## Deployment Topology

**Sidecar model**: deploy the AgentAuth middleware as a sidecar proxy next to each
MCP server. The agent talks to the sidecar, which validates the envelope and forwards
the request to the tool server.

**Centralized model**: agents and MCP servers call a centralized AgentAuth control
plane for identity issuance, envelope verification, and policy evaluation. The
control plane itself is stateless for verification paths; state lives in PostgreSQL
and Redis.
