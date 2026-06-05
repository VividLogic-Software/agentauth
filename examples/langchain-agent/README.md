# AgentAuth + LangChain Example

Shows how to protect a LangChain agent with AgentAuth: issue identity, create
envelope, authorize tool calls, delegate to sub-agent, and mint JIT tokens.

## Prerequisites

```bash
pip install agentauth langchain langchain-openai
```

A running AgentAuth server (see `docs/quickstart.md`).

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENTAUTH_SERVER_URL` | AgentAuth server URL (default: `http://localhost:8080`) |
| `AGENTAUTH_API_KEY` | AgentAuth API key (default: `dev-key`) |
| `OPENAI_API_KEY` | OpenAI API key for the LLM |

## How to Run

```bash
python main.py
```

## What to Expect

The example demonstrates:

- Identity issuance for a sales-ops agent
- Envelope creation with tool scope (gmail.read, gmail.send, database.query)
- Authorized tool calls with envelope verification
- JIT token minting for resource access
- Sub-agent delegation with attenuated scope (read-only)
- Sub-agent blocked from write operations
