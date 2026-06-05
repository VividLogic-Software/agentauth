# syntax=docker/dockerfile:1.7
# Multi-stage build for the AgentAuth server
# Final image is minimal (~15MB) using distroless/static

# ============================================================
# Stage 1: Build
# ============================================================
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build tools
RUN apk add --no-cache git ca-certificates tzdata

# Cache dependencies first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .

ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X main.version=${VERSION} \
      -X main.buildTime=${BUILD_TIME} \
      -X main.gitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o /bin/agentauth-server \
    ./cmd/agentauth-server

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -trimpath \
    -o /bin/agentauth-cli \
    ./cmd/agentauth-cli

# ============================================================
# Stage 2: Final (distroless)
# ============================================================
FROM gcr.io/distroless/static-debian12:nonroot AS final

# Copy timezone data and CA certificates from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the built binaries
COPY --from=builder /bin/agentauth-server /bin/agentauth-server
COPY --from=builder /bin/agentauth-cli /bin/agentauth-cli

# Run as non-root
USER nonroot:nonroot

# Default configuration directory
VOLUME ["/etc/agentauth"]

# Expose control plane port
EXPOSE 8080

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/agentauth-cli", "health", "--server-url", "http://localhost:8080"]

ENTRYPOINT ["/bin/agentauth-server"]
