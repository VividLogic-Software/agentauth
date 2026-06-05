# Contributing to AgentAuth

Thank you for contributing to AgentAuth. This is security-critical infrastructure — we value correctness, clarity, and careful review over speed.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Making a Contribution](#making-a-contribution)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Disclosures](#security-disclosures)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards. Report unacceptable behavior to conduct@agentauth.io.

---

## Development Setup

### Prerequisites

- Go 1.22+
- Docker + Docker Compose
- Python 3.11+ (for SDK development)
- Node.js 20+ / npm 10+ (for TypeScript SDK)
- `golangci-lint` v1.59+

### Start the development environment

```bash
git clone https://github.com/VividLogic-Software/agentauth
cd agentauth

# Start dependencies (Postgres, Redis, NATS)
docker compose -f docker-compose.dev.yml up -d

# Copy and configure environment
cp .env.example .env

# Install Go dependencies
go mod download

# Build the server
make build

# Run the server
make run
```

### Python SDK

```bash
cd sdk/python
pip install -e ".[dev]"
pytest
```

### TypeScript SDK

```bash
cd sdk/typescript
npm install
npm test
```

---

## Project Structure

```
agentauth/
├── cmd/                    # Main entry points
│   ├── agentauth-server/   # Control plane server
│   └── agentauth-cli/      # CLI tool
├── internal/               # Private packages (not importable externally)
│   ├── identity/           # SPIFFE/SVID identity issuance
│   ├── broker/             # JIT credential broker (DPoP, token exchange)
│   ├── envelope/           # Agentic Identity Envelope
│   ├── policy/             # OPA policy engine
│   ├── audit/              # Tamper-evident audit log
│   └── storage/            # PostgreSQL + Redis backends
├── pkg/                    # Public packages (stable API)
│   ├── middleware/         # MCP + A2A HTTP middleware
│   └── client/             # Go client library
├── sdk/
│   ├── python/             # Python SDK (agentauth package)
│   └── typescript/         # TypeScript SDK (@agentauth/sdk)
├── deploy/                 # Kubernetes + Helm
├── examples/               # Working usage examples
├── docs/                   # Extended documentation
└── test/                   # Integration + e2e tests
```

The `internal/` packages are the core of the system and where most security-sensitive code lives. Changes there require extra scrutiny and must include tests.

---

## Running Tests

```bash
# All Go tests
make test

# With race detector (required for PRs touching concurrency)
make test-race

# Integration tests (requires running dependencies)
make test-integration

# All SDKs
make test-all

# Linting
make lint
```

Tests must pass — including the race detector — before a PR will be merged. New features must include tests. Bug fixes must include a regression test.

---

## Making a Contribution

1. **Check existing issues** — search [GitHub Issues](https://github.com/VividLogic-Software/agentauth/issues) before opening a new one.
2. **For large changes, open an issue first** — discuss the approach before writing code. This saves everyone time.
3. **Fork and branch** — work from a feature branch (`feat/`, `fix/`, `chore/` prefix).
4. **Write tests** — see above.
5. **Run the full test suite** locally before pushing.
6. **Open a PR** against `main`.

### What makes a good PR

- One logical change per PR
- Clear description of what changed and why
- All tests pass (CI is a gate, not a suggestion)
- No unrelated formatting changes
- Updated documentation if behavior changed

---

## Code Style

### Go

- `gofmt` + `goimports` (enforced by CI)
- Follow [Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Error strings: lowercase, no punctuation (`"parsing token"` not `"Parsing token."`)
- Exported types and functions must have doc comments
- No `panic` in library code — return errors
- Security-sensitive code must include a comment explaining the invariant being maintained

### Python

- `ruff` for linting and formatting (enforced by CI)
- Type annotations required for public API
- `async`/`await` for all I/O

### TypeScript

- `eslint` + `prettier` (enforced by CI)
- Strict TypeScript — no `any` in public API
- Prefer `interface` over `type` for object shapes

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(identity): add K8s service-account attestor

fix(broker): reject DPoP proofs with iat drift > 60s

docs(readme): add TypeScript quick-start example

test(envelope): add delegation-depth overflow test
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`, `ci`

---

## Pull Request Process

1. CI must be green (tests, lint, security scan)
2. At least one maintainer review and approval
3. For changes to `internal/identity/`, `internal/broker/`, or `internal/audit/`: two maintainer approvals required
4. Squash-merge with a clean commit message

---

## Security Disclosures

**Do not open public GitHub issues for security vulnerabilities.**

Report to: security@agentauth.io

See [SECURITY.md](SECURITY.md) for the full coordinated disclosure policy, PGP key, and supported versions.
