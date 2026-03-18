# E2E Test Harness with GVM Community Containers — OpenSpec

**Issue**: #22  
**Status**: Draft  
**Date**: 2026-03-17

---

## 1. Overview

### Problem
All current rust-gvm tests run against `gvm-mock-server`. While this validates protocol correctness and framing, it cannot catch:
- Server-side field validation and object lifecycle constraints
- Real feed-backed data behaviors (scan configs, report formats, NVT metadata)
- Auth/session behavior differences in a production gvmd deployment

### Goal
Provide a **manual, opt-in** E2E test harness that spins up GVM Community Edition containers and runs the rust-gvm client against a real gvmd instance.

### Non-goals
- Running in CI (too heavy: large containers, feed downloads, long startup)
- Replacing mock-server tests (E2E is supplementary, not primary)
- Testing openvas-mcp-server (separate concern)

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  docker-compose (tests/e2e/gvm-community/)                  │
│                                                             │
│  ┌──────────────┐     shared volume      ┌───────────────┐ │
│  │  gvmd         │◄── /run/gvmd/ ──────►│  rust-gvm      │ │
│  │  + openvas    │    (gvmd.sock)         │  test runner   │ │
│  │  + redis      │                        │  (cargo test)  │ │
│  │  + postgres   │                        │                │ │
│  └──────────────┘                        └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Transport Strategy

| Phase | Transport | Mechanism |
|-------|-----------|-----------|
| **Phase 1** (this spec) | Unix socket | Shared Docker volume for `/run/gvmd/` |
| **Phase 2** (future) | SSH | Add SSH sidecar container |
| **Phase 3** (after #7) | TLS/TCP | Expose gvmd port 9390 directly |

Phase 1 uses a shared Docker volume so both the gvmd container and the test-runner container can access `gvmd.sock`. This exercises `UnixSocketConnection` against a real server.

### 2.3 Connection Flow

```
Test runner container:
  1. Wait for /run/gvmd/gvmd.sock to exist
  2. Poll get_version until success (gvmd still initializing feeds)
  3. Authenticate with default admin credentials
  4. Run test suite
  5. Cleanup created resources
```

---

## 3. Directory Structure

```
tests/e2e/gvm-community/
├── docker-compose.yml       # GVM stack + test runner
├── Dockerfile.runner        # Rust test runner image
├── scripts/
│   ├── wait-ready.sh        # Poll gvmd until responsive
│   ├── run-smoke.sh         # Execute smoke test binary
│   └── reset.sh             # Teardown + cleanup
├── README.md                # Developer instructions
└── .env.example             # Default credentials, socket path
```

---

## 4. Docker Compose Definition

### 4.1 Services

| Service | Image | Role | Volumes |
|---------|-------|------|---------|
| `gvmd` | GVM Community container (per Greenbone docs) | GMP server | `gvmd-socket:/run/gvmd` |
| `rust-gvm-e2e` | `Dockerfile.runner` (workspace build) | Test executor | `gvmd-socket:/run/gvmd:ro` |

### 4.2 Volumes

```yaml
volumes:
  gvmd-socket:    # Shared Unix socket
  gvmd-data:      # Persistent feed data (optional, speeds re-runs)
```

### 4.3 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GVM_ADMIN_USER` | `admin` | gvmd admin username |
| `GVM_ADMIN_PASS` | `admin` | gvmd admin password |
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Socket path inside containers |
| `E2E_RUN_SCAN` | `0` | Set to `1` to run extended scan test |

---

## 5. Test Suite

### 5.1 Smoke Test (fast, deterministic)

Must complete within ~60 seconds once gvmd is ready.

| # | Test | GMP Commands | Assertion |
|---|------|-------------|-----------|
| 1 | Version negotiation | `get_version` | Status 200, version ≥ 22.4 |
| 2 | Authentication | `authenticate` | Status 200 |
| 3 | List scan configs | `get_scan_configs` | Status 200, ≥ 1 config returned |
| 4 | List scanners | `get_scanners` | Status 200, ≥ 1 scanner returned |
| 5 | List report formats | `get_report_formats` | Status 200 |
| 6 | List port lists | `get_port_lists` | Status 200, ≥ 1 port list |
| 7 | Create target | `create_target(name, hosts=127.0.0.1)` | Status 201, returns UUID |
| 8 | Get target | `get_targets(target_id=<uuid>)` | Status 200, contains created name |
| 9 | Delete target | `delete_target(target_id=<uuid>)` | Status 200 |
| 10 | Verify cleanup | `get_targets(target_id=<uuid>)` | Status 404 |

### 5.2 Extended Scan Test (slow, opt-in via `E2E_RUN_SCAN=1`)

| # | Test | GMP Commands | Assertion |
|---|------|-------------|-----------|
| 1 | Create target | `create_target` | 201 |
| 2 | Create task | `create_task(target, config, scanner)` | 201 |
| 3 | Start task | `start_task` | 202, returns report_id |
| 4 | Poll task status | `get_tasks(task_id)` (loop, max 30s) | Status transitions |
| 5 | Stop task | `stop_task` | 200 |
| 6 | Get report | `get_reports(report_id)` | 200, contains results XML |
| 7 | Cleanup | Delete task, target | 200 |

### 5.3 Failure Handling

- If socket doesn't appear within 120 seconds: fail with "gvmd did not start"
- If `get_version` doesn't succeed within 60 polls: fail with "gvmd not responsive"
- All created resources tracked in a cleanup list; teardown runs even on test failure
- Container logs captured on failure: `docker compose logs gvmd > e2e-failure.log`

---

## 6. Rust Implementation

### 6.1 Test Binary

Located at `examples/e2e_gvm_community.rs` (not a standard test — requires Docker environment):

```rust
// Uses gvm-client + gvm-connection directly
// Reads socket path from GVM_SOCKET_PATH env
// Reads credentials from GVM_ADMIN_USER / GVM_ADMIN_PASS env
// Runs smoke tests, optionally extended scan test
```

### 6.2 Dependencies (dev-only)

No new dependencies beyond existing workspace crates. The test binary uses `gvm-client`, `gvm-connection`, `gvm-gmp`, `gvm-protocol`.

---

## 7. Developer Workflow

```bash
cd tests/e2e/gvm-community

# Start GVM stack (first run downloads feeds — can take 10+ minutes)
docker compose up -d

# Wait for gvmd to be ready
./scripts/wait-ready.sh

# Run smoke tests
docker compose run --rm rust-gvm-e2e ./scripts/run-smoke.sh

# Optional: run extended scan test
E2E_RUN_SCAN=1 docker compose run --rm rust-gvm-e2e ./scripts/run-smoke.sh

# Teardown
docker compose down -v

# Or keep data volume for faster re-runs
docker compose down  # (without -v)
```

---

## 8. Success Criteria

- [ ] A developer can run a single documented command sequence and get PASS/FAIL
- [ ] Smoke test completes within 60 seconds once gvmd is ready
- [ ] Cleanup is reliable (no orphan targets/tasks)
- [ ] Uses real GVM container stack with real feed data
- [ ] README documents first-run expectations (feed download time)
- [ ] Container logs are preserved on failure

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Feed download is large/slow on first run | Document; use persistent volume |
| GVM container versions change | Pin image tags in compose |
| Socket path length limits | Use standard `/run/gvmd/gvmd.sock` |
| gvmd initialization is non-deterministic | Robust polling in `wait-ready.sh` |
| Default admin credentials change | Make configurable via `.env` |
