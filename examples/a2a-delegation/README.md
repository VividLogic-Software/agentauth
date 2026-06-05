# AgentAuth A2A Delegation Example

Shows agent-to-agent delegation: a root agent spawns a data-fetcher sub-agent,
which spawns a transformer sub-sub-agent, each with a restricted scope and a
verifiable delegation chain.

## Prerequisites

- Go 1.22+
- A running AgentAuth server (see `docs/quickstart.md`)

## How to Run

```bash
go run ./examples/a2a-delegation
```

## What to Expect

The example creates a delegation chain:

```
user:alice@example.com
  └── orchestrator (1h TTL, database.* + storage.* + email.send)
        └── data-fetcher (30m TTL, database.query/read)
              └── transformer (20m TTL, database.query/read, 50k rows)
```

Each delegation hop:

- Has a cryptographically signed envelope
- Carries the full delegation chain in the JWT
- Is attenuated — sub-agents cannot exceed parent scope
- Is recorded in the tamper-evident audit log

The example also demonstrates scope escalation prevention (attempting to grant
write access to a read-only sub-agent is blocked) and JIT token minting.
