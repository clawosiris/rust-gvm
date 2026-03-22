#!/usr/bin/env bash
# Wait for gvmd to be fully ready (socket + GMP responsive + scan configs loaded)
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
  exit 1
fi

echo "=== Phase 2: Waiting for GMP readiness ==="
for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "ready to accept GMP connections"; then
    echo "gvmd accepting GMP connections"
    break
  fi
  echo "Waiting for GMP readiness... (${i}/60)"
  sleep 2
done

echo "=== Phase 3: Waiting for scan configs (feed sync) ==="
# gvmd needs time to process feed data and create default scan configs.
# We check by running gvm-cli get_configs or checking gvmd logs for config creation.
for i in $(seq 1 120); do
  # Check if scan configs exist by looking for config creation events in gvmd logs
  if docker compose -f "$COMPOSE_FILE" exec -T gvmd \
      gvmd --get-scanners 2>/dev/null | grep -q "Scanner"; then
    echo "Scanners available after ${i} polls"
    break
  fi
  # Alternative: check logs for scan config creation
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "scan_config.*has been created"; then
    echo "Scan configs detected in logs after ${i} polls"
    break
  fi
  if (( i % 10 == 0 )); then
    echo "Waiting for feed sync to create scan configs... (${i}/120)"
  fi
  sleep 5
done

# Final grace period — let the feed sync settle
echo "Allowing 30s grace period for remaining feed sync..."
sleep 30

echo "=== gvmd readiness check complete ==="
