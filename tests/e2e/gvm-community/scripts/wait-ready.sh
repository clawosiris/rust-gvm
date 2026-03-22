#!/usr/bin/env bash
# Wait for gvmd readiness using the rust-gvm E2E binary.
# Phase 1 (bash): Wait for gvmd to accept connections on socket
# Phase 2-3 (rust): Poll feeds + scan configs via GMP
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-tests/e2e/gvm-community/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"

echo "=== Waiting for gvmd to accept connections ==="
for i in $(seq 1 300); do
  # Check that gvmd is actually listening, not just that the socket file exists
  # (socket file may persist from previous run with persistent volumes)
  if docker compose -f "$COMPOSE_FILE" exec -T gvmd \
      bash -c "echo '<get_version/>' | socat - UNIX-CONNECT:${SOCKET_PATH} 2>/dev/null | grep -q 'get_version_response'" 2>/dev/null; then
    echo "gvmd responding on socket after ${i}s"
    break
  fi
  # Fallback: if socat isn't available, check logs for ready message
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "ready to accept GMP connections"; then
    # Verify socket actually works
    if docker compose -f "$COMPOSE_FILE" exec -T gvmd test -S "$SOCKET_PATH" 2>/dev/null; then
      echo "gvmd ready (from logs) after ${i}s"
      break
    fi
  fi
  if (( i % 30 == 0 )); then
    echo "Still waiting for gvmd... (${i}s)"
    docker compose -f "$COMPOSE_FILE" logs --tail=3 gvmd 2>&1 | tail -3 || true
  fi
  sleep 1
done

echo "=== Running GMP readiness check via rust-gvm ==="
docker compose -f "$COMPOSE_FILE" --profile runner run --rm -T \
  --entrypoint "" \
  -e GVM_ADMIN_USER="${GVM_ADMIN_USER:-admin}" \
  -e GVM_ADMIN_PASS="${GVM_ADMIN_PASS:-admin}" \
  -e GVM_SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}" \
  rust-gvm-e2e \
  bash -c 'export PATH="/usr/local/cargo/bin:$PATH" && cargo run --example e2e_gvm_community -- --mode wait-ready'

echo "=== gvmd is ready ==="
