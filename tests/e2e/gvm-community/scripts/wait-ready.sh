#!/usr/bin/env bash
# Wait for gvmd to be fully ready.
# With upstream healthchecks on feed containers, gvmd won't start until
# feed data is copied. We just need to wait for gvmd to finish its own
# initialization (socket + GMP ready + feed sync).
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-tests/e2e/gvm-community/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"

echo "=== Phase 1: Waiting for gvmd socket ==="
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

echo "=== Phase 2: Waiting for GMP readiness ==="
for i in $(seq 1 120); do
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "ready to accept GMP connections"; then
    echo "gvmd accepting GMP connections"
    break
  fi
  if (( i % 20 == 0 )); then
    echo "Waiting for GMP readiness... (${i}/120)"
  fi
  sleep 2
done

echo "=== Phase 3: Waiting for feed sync ==="
# Wait for VT update and scan config creation.
# On a fresh environment this takes ~15 min; with persistent volumes it's fast.
for i in $(seq 1 180); do
  # Check for scan config creation in logs (gvmd logs "Scan config ... has been created")
  # OR check for the sync completion markers
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -qE "scan_config.*created|Updating VTs in database.*done"; then
    echo "Feed sync indicators found after ${i} polls (~$((i * 5))s)"

    # If VTs are done but configs might still be syncing, wait a bit more
    if ! docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "scan_config.*created"; then
      echo "VTs synced but scan configs not yet visible. Waiting 60s for data-objects sync..."
      sleep 60
    fi
    break
  fi

  if (( i % 12 == 0 )); then
    echo "Waiting for feed sync... ($((i * 5))s elapsed)"
    docker compose -f "$COMPOSE_FILE" logs --tail=3 gvmd 2>&1 | tail -3 || true
  fi
  sleep 5
done

echo "=== gvmd readiness check complete ==="
