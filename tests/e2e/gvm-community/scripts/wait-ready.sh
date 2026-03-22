#!/usr/bin/env bash
# Wait for gvmd to be ready by checking for the socket inside the gvmd container
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-tests/e2e/gvm-community/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"
MAX_WAIT=300  # 5 minutes

echo "Waiting for gvmd socket inside container..."
for i in $(seq 1 $MAX_WAIT); do
  if docker compose -f "$COMPOSE_FILE" exec -T gvmd test -S "$SOCKET_PATH" 2>/dev/null; then
    echo "Socket detected after ${i}s"
    break
  fi
  if (( i % 30 == 0 )); then
    echo "Still waiting... (${i}s)"
  fi
  sleep 1
done

# Verify socket exists
if ! docker compose -f "$COMPOSE_FILE" exec -T gvmd test -S "$SOCKET_PATH" 2>/dev/null; then
  echo "gvmd did not start: socket ${SOCKET_PATH} not found after ${MAX_WAIT} seconds" >&2
  exit 1
fi

# Check for "ready to accept" message in gvmd logs
echo "Checking gvmd logs for readiness message..."
for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" logs gvmd 2>&1 | grep -q "ready to accept GMP connections"; then
    echo "gvmd is ready to accept GMP connections"
    exit 0
  fi
  echo "Poll ${i}/60: waiting for ready message..."
  sleep 2
done

echo "Warning: ready message not found in logs, but socket exists. Proceeding anyway."
exit 0
