#!/bin/sh
# Run this once to set up dependencies, then build with Docker Compose.
set -e

cd "$(dirname "$0")"

echo "==> Downloading Go modules..."
go mod tidy

echo "==> Building (local test)..."
go build -o /dev/null . 2>&1 && echo "Build OK" || echo "Build FAILED"

echo ""
echo "To start with Docker Compose:"
echo "  cp .env.example .env   # edit .env with your secrets"
echo "  docker compose up -d --build"
