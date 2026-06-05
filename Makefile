# AgentAuth Makefile
# Usage: make <target>

.PHONY: all build test lint fmt vet docker-build docker-push \
        generate clean release-local help

# Build configuration
MODULE   := github.com/VividLogic-Software/agentauth
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS  := -s -w \
            -X main.version=$(VERSION) \
            -X main.gitCommit=$(GIT_COMMIT) \
            -X main.buildTime=$(BUILD_TIME)

# Docker configuration
REGISTRY := ghcr.io
ORG      := agentauth
IMAGE    := $(REGISTRY)/$(ORG)/agentauth
TAG      := $(VERSION)

# Go configuration
GOBIN    := $(shell go env GOPATH)/bin
GOLANGCI := $(GOBIN)/golangci-lint

##@ General

all: fmt vet lint test build ## Run all checks and build

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

fmt: ## Format Go code
	go fmt ./...
	@echo "Format complete"

vet: ## Run go vet
	go vet ./...
	@echo "Vet complete"

generate: ## Run go generate
	go generate ./...

tidy: ## Tidy go.mod and go.sum
	go mod tidy

##@ Testing

test: ## Run unit tests
	go test -v -race -count=1 ./...

test-cover: ## Run unit tests with coverage report
	go test -v -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: ## Run integration tests (requires running services)
	go test -v -tags integration -race ./test/integration/...

test-e2e: ## Run e2e tests (requires running AgentAuth server)
	go test -v -tags e2e ./test/e2e/...

##@ Linting

lint: ## Run golangci-lint
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run --timeout 5m ./...

lint-fix: ## Run golangci-lint with auto-fix
	golangci-lint run --fix --timeout 5m ./...

security: ## Run security checks (gosec + govulncheck)
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec ./...
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

##@ Building

build: ## Build server and CLI binaries
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath \
		-o bin/agentauth-server ./cmd/agentauth-server
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath \
		-o bin/agentauth-cli ./cmd/agentauth-cli
	@echo "Build complete: bin/agentauth-server, bin/agentauth-cli"

build-all: ## Build for all supported platforms
	@mkdir -p dist
	@for PLATFORM in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		GOOS=$$(echo $$PLATFORM | cut -d/ -f1); \
		GOARCH=$$(echo $$PLATFORM | cut -d/ -f2); \
		EXT=""; \
		[ "$$GOOS" = "windows" ] && EXT=".exe"; \
		echo "Building $$PLATFORM..."; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH \
			go build -ldflags="$(LDFLAGS)" -trimpath \
			-o dist/agentauth-server-$$GOOS-$$GOARCH$$EXT \
			./cmd/agentauth-server; \
	done
	@echo "Multi-platform build complete: dist/"

##@ Docker

docker-build: ## Build Docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(TAG) \
		-t $(IMAGE):latest \
		.
	@echo "Docker image built: $(IMAGE):$(TAG)"

docker-push: docker-build ## Build and push Docker image
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest
	@echo "Docker image pushed: $(IMAGE):$(TAG)"

docker-run: ## Run AgentAuth with docker compose
	docker compose up -d
	@echo "AgentAuth stack started. Server at http://localhost:8080"

docker-stop: ## Stop docker compose stack
	docker compose down

##@ SDKs

sdk-python-install: ## Install Python SDK in development mode
	cd sdk/python && pip install -e ".[all]"

sdk-python-test: ## Run Python SDK tests
	cd sdk/python && hatch run test

sdk-python-build: ## Build Python SDK package
	cd sdk/python && hatch build

sdk-typescript-install: ## Install TypeScript SDK dependencies
	cd sdk/typescript && npm ci

sdk-typescript-build: ## Build TypeScript SDK
	cd sdk/typescript && npm run build

sdk-typescript-test: ## Run TypeScript SDK tests
	cd sdk/typescript && npm test

##@ Release

release-local: build-all ## Build release artifacts locally
	@cd dist && for f in agentauth-*; do sha256sum $$f; done > checksums.txt
	@echo "Release artifacts: dist/"

##@ Cleanup

clean: ## Remove build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html
	go clean -cache
	@echo "Clean complete"
