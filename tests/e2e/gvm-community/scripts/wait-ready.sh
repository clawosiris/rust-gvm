#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/workspace"
SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}"

echo "Waiting for gvmd socket at ${SOCKET_PATH}"
for _ in $(seq 1 120); do
  if [[ -S "${SOCKET_PATH}" ]]; then
    break
  fi
  sleep 1
done

if [[ ! -S "${SOCKET_PATH}" ]]; then
  echo "gvmd did not start: socket ${SOCKET_PATH} not found after 120 seconds" >&2
  exit 1
fi

echo "Socket detected. Polling get_version response"
for _ in $(seq 1 60); do
  if cargo run --quiet --example e2e_gvm_community -- --mode wait-ready; then
    echo "gvmd is responsive"
    exit 0
  fi
  sleep 2
done

echo "gvmd not responsive after 60 polls" >&2
exit 1
