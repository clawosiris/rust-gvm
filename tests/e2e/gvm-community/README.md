# GVM Community E2E Harness

This harness runs the Rust GMP client against a real Greenbone Community container stack over the shared `gvmd.sock` Unix socket.

The compose file is based on the current Greenbone Community container docs at `https://greenbone.github.io/docs/latest/22.4/container/`, trimmed to the services needed for `gvmd`, feed data, `ospd-openvas`, and the optional `gsad` API frontend.

## Prerequisites

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Enough local resources for the Greenbone stack. Greenbone documents 4 GB RAM / 20 GB disk as a minimum and recommends more for smoother runs.

## First run expectations

The first `docker compose up -d` is slow. The feed containers download and unpack vulnerability tests, SCAP data, CERT data, and report formats before `gvmd` becomes responsive. Expect several minutes on a warm network and potentially 10+ minutes on a cold start.

Named volumes keep feed and database state between runs. Use `docker compose down` to preserve those caches, or `./scripts/reset.sh` to remove everything and force a clean bootstrap.

## Quick start

```bash
cd tests/e2e/gvm-community
cp .env.example .env

docker compose up -d
docker compose run --rm rust-gvm-e2e ./tests/e2e/gvm-community/scripts/wait-ready.sh
docker compose run --rm rust-gvm-e2e ./tests/e2e/gvm-community/scripts/run-smoke.sh

# Optional extended scan flow
E2E_RUN_SCAN=1 docker compose run --rm rust-gvm-e2e ./tests/e2e/gvm-community/scripts/run-smoke.sh
```

To stop the stack but keep cached feed data:

```bash
docker compose down
```

To stop the stack and drop all named volumes:

```bash
./scripts/reset.sh
```

## Environment variables

- `GVM_ADMIN_USER`: GMP username. Default `admin`.
- `GVM_ADMIN_PASS`: GMP password. Default `admin`.
- `GVM_SOCKET_PATH`: Socket path inside the runner container. Default `/run/gvmd/gvmd.sock`.
- `E2E_RUN_SCAN`: Set to `1` to run the slower scan lifecycle test in addition to the smoke checks.

## Rust binary

The harness uses the workspace-level example target:

```bash
cargo build --example e2e_gvm_community
cargo run --example e2e_gvm_community -- --mode smoke
cargo run --example e2e_gvm_community -- --mode wait-ready
```

## Troubleshooting

- If `wait-ready.sh` fails on socket detection, inspect the stack with `docker compose ps` and `docker compose logs gvmd pg-gvm ospd-openvas`.
- If the socket exists but `get_version` keeps failing, `gvmd` is usually still importing feed or waiting on PostgreSQL. Keep the data volumes and retry once the logs quiet down.
- If the extended scan flow fails quickly, confirm the container host permits raw socket capabilities for `ospd-openvas`.
- On harness failure, capture logs with:

```bash
docker compose logs gvmd ospd-openvas openvasd > e2e-failure.log
```
