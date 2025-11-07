#!/usr/bin/env bash
# Pre-commit hook for Go formatting and basic checks

set -e

echo "Running pre-commit checks..."

# Format code
echo "→ Running gofmt..."
gofmt -w .

# Run go vet
echo "→ Running go vet..."
go vet ./...

# Build check
echo "→ Building internal packages..."
go build ./internal/...

echo "→ Building local server..."
go build ./cmd/server

echo "✓ All pre-commit checks passed!"

