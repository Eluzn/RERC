# RERC (Relay Encrypted Chat) Makefile

.PHONY: all build test clean run-node run-client docker-build docker-up docker-down lint fmt deps

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Binary names
NODE_BINARY=rerc-node
CLIENT_BINARY=rerc-client

# Build directory
BUILD_DIR=./build

# Default target
all: deps fmt lint test build

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	$(GOFMT) -s -w .

# Lint code (requires golangci-lint to be installed)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed. Installing..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.54.2; \
	}
	golangci-lint run

# Run tests
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Build binaries
build: build-node build-client

# Build relay node
build-node:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GOBUILD) -ldflags="-s -w" -o $(BUILD_DIR)/$(NODE_BINARY) ./cmd/node

# Build client
build-client:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GOBUILD) -ldflags="-s -w" -o $(BUILD_DIR)/$(CLIENT_BINARY) ./cmd/client

# Run relay node (development)
run-node:
	$(GOCMD) run ./cmd/node -addr :8080 -db relay.db

# Run client (development)
run-client:
	$(GOCMD) run ./cmd/client -node ws://localhost:8080/ws

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	rm -f *.db

# Docker targets
docker-build:
	docker build -t rerc:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Development targets
dev-network: docker-up
	@echo "Development network started with relay nodes:"
	@echo "- Bootstrap: http://localhost:8080"
	@echo "- Relay 1:   http://localhost:8081" 
	@echo "- Relay 2:   http://localhost:8082"
	@echo "- Relay 3:   http://localhost:8083"

# Benchmark tests
benchmark:
	$(GOTEST) -bench=. -benchmem ./...

# Security scan (requires gosec to be installed)
security:
	@command -v gosec >/dev/null 2>&1 || { \
		echo "gosec is not installed. Installing..."; \
		curl -sfL https://raw.githubusercontent.com/securecodewarrior/gosec/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v2.18.2; \
	}
	gosec ./...

# Install development tools
install-tools:
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) -u github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Generate mock files (if using mockery)
mocks:
	@command -v mockery >/dev/null 2>&1 || { \
		echo "mockery is not installed. Installing..."; \
		$(GOGET) -u github.com/vektra/mockery/v2/...@latest; \
	}
	mockery --all --output=./mocks

# Performance profiling
profile-cpu:
	$(GOCMD) test -cpuprofile=cpu.prof -bench=. ./internal/crypto
	$(GOCMD) tool pprof cpu.prof

profile-mem:
	$(GOCMD) test -memprofile=mem.prof -bench=. ./internal/crypto
	$(GOCMD) tool pprof mem.prof

# Generate test certificates for TLS (if needed)
certs:
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Run deps, fmt, lint, test, and build"
	@echo "  deps          - Install Go dependencies"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Run linter (golangci-lint)"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  build         - Build both binaries"
	@echo "  build-node    - Build relay node binary"
	@echo "  build-client  - Build client binary"
	@echo "  run-node      - Run relay node (development)"
	@echo "  run-client    - Run client (development)"
	@echo "  clean         - Clean build artifacts"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start Docker compose network"
	@echo "  docker-down   - Stop Docker compose network"
	@echo "  docker-logs   - Show Docker logs"
	@echo "  dev-network   - Start development network"
	@echo "  benchmark     - Run benchmark tests"
	@echo "  security      - Run security scan (gosec)"
	@echo "  install-tools - Install development tools"
	@echo "  mocks         - Generate mock files"
	@echo "  profile-cpu   - Run CPU profiling"
	@echo "  profile-mem   - Run memory profiling"
	@echo "  certs         - Generate test TLS certificates"
	@echo "  help          - Show this help"
