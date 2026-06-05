# Deploying AgentAuth

## Docker Compose (development / small teams)

```bash
git clone https://github.com/VividLogic-Software/agentauth
cd agentauth
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

This starts four services: `agentauth-server` on `:8080`, PostgreSQL 16 for
durable storage, Redis 7 for token caching and revocation, and NATS for the
event bus. Key env vars to set in `.env`:

- `AGENTAUTH_POSTGRES_DSN` — PostgreSQL connection string
- `AGENTAUTH_REDIS_ADDR` — Redis address
- `AGENTAUTH_TRUST_DOMAIN` — SPIFFE trust domain (e.g. `my-company.com`)
- `AGENTAUTH_JWT_SIGNING_KEY` — HS256 key for token signing
- `AGENTAUTH_CA_CERT_FILE` — CA certificate path
- `AGENTAUTH_SIGNING_KEY_FILE` — CA private key path

## Kubernetes with Helm (production)

```bash
helm repo add agentauth https://charts.agentauth.io
helm install agentauth agentauth/agentauth \
  --set postgres.external.url="postgresql://user:pass@db:5432/agentauth" \
  --set redis.external.url="redis://cache:6379" \
  --set config.trustDomain="my-company.com"
```

See `deploy/helm/values.yaml` for the full values reference.
Raw Kubernetes manifests are available in `deploy/kubernetes/`.

## Configuration Reference

All environment variables use the `AGENTAUTH_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTAUTH_HOST` | `0.0.0.0` | Bind address |
| `AGENTAUTH_PORT` | `8080` | HTTP port |
| `AGENTAUTH_POSTGRES_DSN` | `postgres://agentauth:agentauth@localhost:5432/agentauth?sslmode=disable` | PostgreSQL connection string |
| `AGENTAUTH_REDIS_ADDR` | `localhost:6379` | Redis address |
| `AGENTAUTH_NATS_URL` | `nats://localhost:4222` | NATS URL |
| `AGENTAUTH_TRUST_DOMAIN` | `agentauth.io` | SPIFFE trust domain |
| `AGENTAUTH_CA_CERT_FILE` | _(ephemeral)_ | Path to CA certificate PEM |
| `AGENTAUTH_SIGNING_KEY_FILE` | _(ephemeral)_ | Path to CA private key PEM |
| `AGENTAUTH_JWT_SIGNING_KEY` | _(ephemeral)_ | HS256 key for token signing |
| `AGENTAUTH_LOG_LEVEL` | `info` | Log level: debug/info/warn/error |

## Running Database Migrations

```bash
# Using golang-migrate
migrate -path db/migrations -database $AGENTAUTH_POSTGRES_DSN up

# Or apply directly
psql $AGENTAUTH_POSTGRES_DSN -f db/migrations/001_initial_schema.up.sql
```

## TLS

In production, the server should sit behind a TLS-terminating ingress or load
balancer. See the Kubernetes ingress example in `deploy/kubernetes/`.
