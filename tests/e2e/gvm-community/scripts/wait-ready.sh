#!/usr/bin/env bash
# Wait for gvmd readiness using the rust-gvm E2E binary.
# Phase 1 (bash): Wait for gvmd socket inside container
# Phase 2-3 (rust): Poll feeds + scan configs via GMP
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-tests/e2e/gvm-community/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"

echo "=== Waiting for gvmd socket ==="
for i in $(seq 1 300); do
  if docker compose -f "$COMPOSE_FILE" exec -T gvmd test -S "$SOCKET_PATH" 2>/dev/null; then
    echo "Socket detected after ${i}s"
    break
  fi
  if (( i % 30 == 0 )); then
    echo "Still waiting for socket... (${i}s)"
  fi
  sleep 1
done

if ! docker compose -f "$COMPOSE_FILE" exec -T gvmd test -S "$SOCKET_PATH" 2>/dev/null; then
  echo "gvmd did not start: socket not found after 300s" >&2
  docker compose -f "$COMPOSE_FILE" logs --tail=30 gvmd 2>&1 || true
  exit 1
fi

echo "=== Running GMP readiness check via rust-gvm ==="
docker compose -f "$COMPOSE_FILE" --profile runner run --rm -T \
  -e GVM_ADMIN_USER="${GVM_ADMIN_USER:-admin}" \
  -e GVM_ADMIN_PASS="${GVM_ADMIN_PASS:-admin}" \
  -e GVM_SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}" \
  rust-gvm-e2e \
  cargo run --example e2e_gvm_community -- --mode wait-ready

echo "=== gvmd is ready ==="
