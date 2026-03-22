#!/usr/bin/env bash
# Wait for gvmd to be fully ready:
#   1. Socket exists inside container
#   2. GMP connection responds
#   3. Scan configs exist (feed sync complete)
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-tests/e2e/gvm-community/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"
GVM_USER="${GVM_ADMIN_USER:-admin}"
GVM_PASS="${GVM_ADMIN_PASS:-admin}"

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

echo "=== Phase 3: Waiting for scan configs ==="
# Query scan configs via GMP over the Unix socket using Python inside gvmd container
GMP_QUERY_SCRIPT=$(cat << 'PYEOF'
import socket, ssl, sys, time

sock_path = sys.argv[1]
user = sys.argv[2]
passwd = sys.argv[3]

auth_xml = f'<authenticate><credentials><username>{user}</username><password>{passwd}</password></credentials></authenticate>'
configs_xml = '<get_configs/>'

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall((auth_xml + configs_xml).encode())
    data = b''
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            # Check if we have complete response (ends with </get_configs_response>)
            if b'</get_configs_response>' in data:
                break
        except socket.timeout:
            break
    s.close()
    count = data.count(b'<config ')
    print(count)
except Exception as e:
    print(f'0', file=sys.stdout)
    print(f'Error: {e}', file=sys.stderr)
PYEOF
)

for i in $(seq 1 180); do
  RESULT=$(docker compose -f "$COMPOSE_FILE" exec -T gvmd \
    python3 -c "$GMP_QUERY_SCRIPT" "$SOCKET_PATH" "$GVM_USER" "$GVM_PASS" 2>/dev/null || echo "0")
  RESULT=$(echo "$RESULT" | tr -d '[:space:]')

  if [[ "$RESULT" =~ ^[0-9]+$ ]] && (( RESULT > 0 )); then
    echo "Found ${RESULT} scan config(s) after ${i} polls (~$((i * 5))s)"
    echo "=== gvmd readiness check complete ==="
    exit 0
  fi

  if (( i % 10 == 0 )); then
    echo "Waiting for scan configs... (poll ${i}/180, ~$((i * 5))s elapsed)"
    # Show recent gvmd feed sync activity
    docker compose -f "$COMPOSE_FILE" logs --tail=5 gvmd 2>&1 | tail -3 || true
  fi
  sleep 5
done

echo "WARNING: No scan configs found after 15 minutes."
echo "Last gvmd log lines:"
docker compose -f "$COMPOSE_FILE" logs --tail=10 gvmd 2>&1 | tail -10 || true
echo "=== gvmd readiness check complete (no configs) ==="
# Exit 0 to let the smoke test provide its own error message
exit 0
