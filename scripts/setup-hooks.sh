#!/usr/bin/env bash
# Setup git hooks

set -e

echo "Setting up git hooks..."

# Make pre-commit script executable
chmod +x scripts/pre-commit.sh

# Create symlink to git hooks
ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit

echo "✓ Git hooks installed successfully!"
echo "Pre-commit hook will run gofmt, go vet, and build checks before each commit."

