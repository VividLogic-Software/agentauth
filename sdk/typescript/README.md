# AgentAuth TypeScript SDK

## Install

```bash
npm install @agentauth/sdk
```

## Compatibility

Node.js 18+, Bun, browser (via `fetch`).

## Quickstart

```typescript
import { AgentAuthClient } from '@agentauth/sdk';

const client = new AgentAuthClient({
  serverUrl: 'http://localhost:8080',
  apiKey: process.env.AGENTAUTH_API_KEY,
});

const identity = await client.issueIdentity({
  delegatorId: 'user:alice@acme.com',
  tenantId: 'acme',
  declaredIntent: 'Analyze Q3 sales data',
});

const envelope = await client.createEnvelope({
  agentId: identity.id,
  declaredIntent: 'Analyze Q3 sales data',
  toolScope: [{ tool: 'postgres.query', operations: ['read'] }],
});

const parsed = await client.verifyEnvelope(envelope.token);
```

## Key Exports

- `AgentAuthClient` — typed HTTP client (`src/client.ts`)
- `agentAuthMiddleware` — Express/Hono middleware (`src/middleware.ts`)
- `verifyEnvelope` — standalone envelope verification function
- All types: `IssueIdentityRequest`, `CreateEnvelopeRequest`, `ToolScope`, etc.

## Express Middleware

```typescript
import { AgentAuthClient, agentAuthMiddleware } from '@agentauth/sdk';

const client = new AgentAuthClient({ serverUrl: 'http://localhost:8080' });
app.use('/tools', agentAuthMiddleware({ client }));
```

API docs at `docs/api-reference.md`.
