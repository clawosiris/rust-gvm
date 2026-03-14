# gvm-mock-server Test Specification — OpenSpec

## 1. Overview

This document specifies the complete test suite for **gvm-mock-server**. It covers the mock server's own correctness (does it behave like a GMP server?) and its role as test infrastructure for rust-gvm and python-gvm.

Tests are organized by the mock server's components and modes. Each section lists concrete test cases with expected behavior.

### Test Tiers

| Tier | Scope | Runner | When |
|------|-------|--------|------|
| **Unit** | Individual functions, XML generation, state transitions | `cargo test` | Every commit |
| **Mode** | Each server mode end-to-end via loopback connection | `cargo test` | Every commit |
| **Integration** | rust-gvm client against mock server | `cargo test --features integration` | Every PR |
| **Cross-client** | python-gvm against mock server binary | CI job (Python + Rust) | Release / weekly |
| **Stress** | Concurrency, large payloads, resource exhaustion | `cargo test --features stress` | Release |

---

## 2. XML Protocol Tests

### 2.1 Command Parsing

The mock server must correctly parse incoming GMP XML commands.

| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| XML-001 | Parse simple command | `<get_version/>` | Recognized as `get_version`, no attributes |
| XML-002 | Parse command with attributes | `<get_tasks usage_type="scan" details="1"/>` | Attributes extracted: `usage_type=scan`, `details=1` |
| XML-003 | Parse command with ID attribute | `<get_tasks task_id="abc-123"/>` | `task_id` extracted |
| XML-004 | Parse command with child elements | `<create_task><name>foo</name><target id="t1"/></create_task>` | `name=foo`, `target.id=t1` |
| XML-005 | Parse command with nested children | Full `create_task` with preferences | All nested `preference/scanner_name/value` pairs extracted |
| XML-006 | Parse authenticate command | `<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>` | `username=admin`, `password=pass` |
| XML-007 | Reject malformed XML | `<get_tasks` (no closing) | Connection error or ignore, no crash |
| XML-008 | Reject empty input | Empty byte stream | No crash, connection stays open |
| XML-009 | Handle XML with whitespace/newlines | Pretty-printed multi-line XML | Same parse result as compact |
| XML-010 | Handle XML with unicode | `<create_task><name>Tëst Tàsk</name></create_task>` | UTF-8 name preserved |
| XML-011 | Handle unknown command | `<do_something_weird/>` | Return 400 status, don't crash |
| XML-012 | Parse command with filter attribute | `<get_tasks filter="name=foo"/>` | `filter=name=foo` extracted |
| XML-013 | Parse command with filt_id attribute | `<get_tasks filt_id="f1"/>` | `filt_id=f1` extracted |

### 2.2 Response Generation

| Test ID | Test Case | Expected Response |
|---------|-----------|-------------------|
| XML-020 | Well-formed response envelope | Every response has `status` and `status_text` attributes |
| XML-021 | Response tag matches command | `get_tasks` → `<get_tasks_response>`, `create_alert` → `<create_alert_response>` |
| XML-022 | Create response includes ID | `<create_task_response status="201" ... id="UUID"/>` |
| XML-023 | Get list response includes count | `<get_tasks_response>` contains `<task_count>` |
| XML-024 | Response is valid XML | Every response parses without error via quick-xml |
| XML-025 | Response preserves UTF-8 | Unicode in resource names roundtrips correctly |
| XML-026 | Large response is valid | Multi-MB report response is valid, well-formed XML |
| XML-027 | Empty list response | `<get_tasks_response status="200"><task_count>0</task_count></get_tasks_response>` |

---

## 3. Echo Mode Tests

| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| ECHO-001 | Any recognized command returns 200 | `<get_tasks/>` | `<get_tasks_response status="200" status_text="OK"/>` |
| ECHO-002 | Create commands return 201 | `<create_task>...</create_task>` | `status="201"`, includes `id` attribute |
| ECHO-003 | No auth required | `<get_tasks/>` without prior authenticate | 200 (not 401) |
| ECHO-004 | get_version works | `<get_version/>` | Returns configured version |
| ECHO-005 | Unknown command returns 400 | `<nonexistent_command/>` | `status="400"` |
| ECHO-006 | Multiple commands in sequence | 10 commands in a row | All get well-formed responses |
| ECHO-007 | Response tag matches command | `<delete_task task_id="x"/>` | `<delete_task_response .../>` |

---

## 4. Fixture Mode Tests

### 4.1 Fixture Loading

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| FIX-001 | Load common fixtures at startup | `get_version.xml`, `authenticate_success.xml` loaded |
| FIX-002 | Load version-specific fixtures | v22_5 fixtures load when version=22.5 |
| FIX-003 | Version fallback | v22_5 request falls back to v22_4 fixture if no v22_5-specific fixture exists |
| FIX-004 | Custom fixture directory | `--fixtures ./custom/` overrides built-in fixtures |
| FIX-005 | Missing fixture for command | Command without a fixture file → generic 200 response |
| FIX-006 | Fixture file is valid XML | All shipped fixture files parse without error |

### 4.2 Fixture Templating

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| FIX-010 | `{{uuid}}` substitution | Each invocation produces a different valid UUID v4 |
| FIX-011 | `{{now}}` substitution | ISO 8601 timestamp within 1s of current time |
| FIX-012 | `{{version}}` substitution | Matches configured server version |
| FIX-013 | `{{resource_id}}` substitution | Extracted from incoming request's ID attribute |
| FIX-014 | Multiple variables in one fixture | All substituted correctly in single response |
| FIX-015 | No variables in fixture | Returned verbatim, no mangling |

### 4.3 Fixture Responses

| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| FIX-020 | get_version returns version fixture | `<get_version/>` | Configured version in `<version>` element |
| FIX-021 | authenticate returns auth fixture | Valid credentials | `status="200"`, includes `<role>` and `<timezone>` |
| FIX-022 | get_tasks returns task list fixture | `<get_tasks usage_type="scan"/>` | Multiple `<task>` elements with UUIDs, names, statuses |
| FIX-023 | get_task returns single task fixture | `<get_tasks task_id="x"/>` | Single `<task>` with full detail (config, target, schedule refs) |
| FIX-024 | create_task returns created fixture | `<create_task>...</create_task>` | `status="201"`, `id` attribute present |
| FIX-025 | get_reports returns report fixture | `<get_reports/>` | Report with nested results, hosts, ports |
| FIX-026 | Large report fixture | `<get_reports report_id="large"/>` | Multi-MB response, streams without OOM |
| FIX-027 | Error template for 404 | `<get_tasks task_id="nonexistent"/>` (with override) | `status="404"`, descriptive `status_text` |

---

## 5. Stateful Mode Tests

### 5.1 Authentication State

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| STATE-001 | Command before auth returns 401 | `<get_tasks/>` before `<authenticate>` → `status="401"` |
| STATE-002 | get_version works without auth | `<get_version/>` → `status="200"` (always allowed) |
| STATE-003 | Valid credentials authenticate | Configured username/password → `status="200"` |
| STATE-004 | Invalid credentials rejected | Wrong password → `status="400"`, `status_text="Authentication failed"` |
| STATE-005 | Auth persists for session | Authenticate once, subsequent commands work |
| STATE-006 | Separate sessions have independent auth | Client A authenticated, client B still requires auth |
| STATE-007 | Default credentials | `admin`/`admin` works when no custom credentials configured |
| STATE-008 | Custom credentials | Only configured credentials work |

### 5.2 Resource CRUD — Tasks

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CRUD-T001 | Create task | `create_task` → 201, returns UUID |
| CRUD-T002 | Get created task by ID | `get_tasks task_id=<uuid>` → returns task with correct name, config, target |
| CRUD-T003 | List all tasks | `get_tasks` → includes all created tasks |
| CRUD-T004 | List tasks (empty) | No tasks created → empty list, count=0 |
| CRUD-T005 | Modify task name | `modify_task` with new name → 200, subsequent get shows new name |
| CRUD-T006 | Modify task config | `modify_task` with new config_id → updated reference |
| CRUD-T007 | Delete task (to trash) | `delete_task ultimate="0"` → 200, task no longer in get_tasks |
| CRUD-T008 | Delete task (ultimate) | `delete_task ultimate="1"` → 200, task permanently gone |
| CRUD-T009 | Delete nonexistent task | `delete_task` with bad UUID → 404 |
| CRUD-T010 | Get nonexistent task | `get_tasks task_id="bad"` → 404 |
| CRUD-T011 | Clone task | `create_task` with `<copy>uuid</copy>` → new UUID, same attributes |
| CRUD-T012 | Create container task | `create_task` with `target id="0"` → stored as container task |
| CRUD-T013 | Create task missing required fields | No name or no target → 400 |
| CRUD-T014 | Modify nonexistent task | `modify_task` with bad UUID → 404 |

### 5.3 Resource CRUD — Other Types

Each resource type must pass the same CRUD pattern. Test matrix:

| Resource Type | Create | Get One | Get List | Modify | Delete | Clone |
|--------------|--------|---------|----------|--------|--------|-------|
| Targets | CRUD-TG001 | CRUD-TG002 | CRUD-TG003 | CRUD-TG004 | CRUD-TG005 | CRUD-TG006 |
| Configs | CRUD-C001 | CRUD-C002 | CRUD-C003 | CRUD-C004 | CRUD-C005 | CRUD-C006 |
| Scanners | CRUD-SC001 | CRUD-SC002 | CRUD-SC003 | CRUD-SC004 | CRUD-SC005 | CRUD-SC006 |
| Alerts | CRUD-A001 | CRUD-A002 | CRUD-A003 | CRUD-A004 | CRUD-A005 | CRUD-A006 |
| Credentials | CRUD-CR001 | CRUD-CR002 | CRUD-CR003 | CRUD-CR004 | CRUD-CR005 | CRUD-CR006 |
| Filters | CRUD-F001 | CRUD-F002 | CRUD-F003 | CRUD-F004 | CRUD-F005 | CRUD-F006 |
| Groups | CRUD-G001 | CRUD-G002 | CRUD-G003 | CRUD-G004 | CRUD-G005 | CRUD-G006 |
| Notes | CRUD-N001 | CRUD-N002 | CRUD-N003 | CRUD-N004 | CRUD-N005 | CRUD-N006 |
| Overrides | CRUD-O001 | CRUD-O002 | CRUD-O003 | CRUD-O004 | CRUD-O005 | CRUD-O006 |
| Permissions | CRUD-P001 | CRUD-P002 | CRUD-P003 | CRUD-P004 | CRUD-P005 | CRUD-P006 |
| Port Lists | CRUD-PL001 | CRUD-PL002 | CRUD-PL003 | CRUD-PL004 | CRUD-PL005 | CRUD-PL006 |
| Reports | CRUD-R001 | CRUD-R002 | CRUD-R003 | — | CRUD-R005 | — |
| Report Formats | CRUD-RF001 | CRUD-RF002 | CRUD-RF003 | CRUD-RF004 | CRUD-RF005 | — |
| Roles | CRUD-RO001 | CRUD-RO002 | CRUD-RO003 | CRUD-RO004 | CRUD-RO005 | CRUD-RO006 |
| Schedules | CRUD-S001 | CRUD-S002 | CRUD-S003 | CRUD-S004 | CRUD-S005 | CRUD-S006 |
| Tags | CRUD-TAG001 | CRUD-TAG002 | CRUD-TAG003 | CRUD-TAG004 | CRUD-TAG005 | CRUD-TAG006 |
| Tickets | CRUD-TK001 | CRUD-TK002 | CRUD-TK003 | CRUD-TK004 | CRUD-TK005 | CRUD-TK006 |
| TLS Certs | CRUD-TLS001 | CRUD-TLS002 | CRUD-TLS003 | CRUD-TLS004 | CRUD-TLS005 | — |
| Users | CRUD-U001 | CRUD-U002 | CRUD-U003 | CRUD-U004 | CRUD-U005 | CRUD-U006 |

### 5.4 Task Lifecycle State Machine

| Test ID | Test Case | Initial State | Action | Expected State |
|---------|-----------|---------------|--------|----------------|
| TASK-001 | Start new task | New | `start_task` | Requested → Running |
| TASK-002 | Stop running task | Running | `stop_task` | Stop Requested → Stopped |
| TASK-003 | Resume stopped task | Stopped | `resume_task` | Requested → Running |
| TASK-004 | Start already running task | Running | `start_task` | Error 409 (conflict) |
| TASK-005 | Stop already stopped task | Stopped | `stop_task` | Error 409 |
| TASK-006 | Resume non-stopped task | Running | `resume_task` | Error 409 |
| TASK-007 | Get task shows current status | Running | `get_task` | `<status>Running</status>` |
| TASK-008 | Task completes after delay | Running | Wait configured duration | Done |
| TASK-009 | Start task returns report ID | New | `start_task` | Response includes `<report_id>` |
| TASK-010 | Container task can't be started | Container | `start_task` | Error 400 |

### 5.5 Trashcan

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| TRASH-001 | Deleted resource appears in trash | `delete_task ultimate="0"` → task retrievable with `trash="1"` |
| TRASH-002 | Restore from trash | `<restore id="uuid"/>` → resource back in normal listing |
| TRASH-003 | Empty trashcan | `<empty_trashcan/>` → all trashed resources permanently removed |
| TRASH-004 | Ultimate delete skips trash | `delete_task ultimate="1"` → not in trash either |

### 5.6 Pre-seeding

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| SEED-001 | Seeded resources appear in get | Pre-seed a task → `get_tasks` returns it |
| SEED-002 | Seeded resources have correct IDs | Pre-seed with specific UUID → retrievable by that UUID |
| SEED-003 | Seeded references are consistent | Task references target → both exist in store |
| SEED-004 | Empty seed is valid | No pre-seeding → all resource lists empty |
| SEED-005 | Multiple resource types seeded | Seed tasks + targets + configs → all retrievable |

### 5.7 Filtering (Basic)

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| FILT-001 | Filter by name equality | `filter="name=MyTask"` → only matching tasks |
| FILT-002 | Filter returns empty for no match | `filter="name=nonexistent"` → empty list, count=0 |
| FILT-003 | Filter with filt_id | `filt_id="stored-filter-uuid"` → applies stored filter |
| FILT-004 | No filter returns all | No filter attribute → all resources |
| FILT-005 | Trash filter | `trash="1"` → only trashed resources |

---

## 6. Error Injection Tests

### 6.1 Fault Types

| Test ID | Test Case | Fault | Expected Client Behavior |
|---------|-----------|-------|-------------------------|
| ERR-001 | Server error on specific command | `FaultKind::ServerError500` on `get_tasks` | `status="500"`, other commands unaffected |
| ERR-002 | Connection drop after auth | `FaultKind::Disconnect` after authenticate | Client gets connection reset |
| ERR-003 | Delayed response | `FaultKind::Delay(5s)` | Response arrives after 5s |
| ERR-004 | Malformed XML response | `FaultKind::MalformedXml` | Client receives invalid XML, handles gracefully |
| ERR-005 | Truncated response | `FaultKind::TruncatedResponse` on `get_reports` | Client receives partial XML, detects incomplete |
| ERR-006 | Error after N commands | `Fault::after_commands(3, ...)` | First 3 succeed, 4th fails |
| ERR-007 | Error once then recover | `Fault::once(...)` | First occurrence fails, subsequent succeed |
| ERR-008 | Multiple faults compose | Delay + error after 2 | Both behaviors apply correctly |
| ERR-009 | No faults by default | No inject_fault calls | All commands succeed normally |

### 6.2 Fault Targeting

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| ERR-020 | Fault on specific command name | Only `get_reports` affected, others work |
| ERR-021 | Fault on all commands | `Fault::always(...)` → every command affected |
| ERR-022 | Fault after auth only | `Fault::after_auth(...)` → triggers post-authenticate |
| ERR-023 | Fault per-session | Session A has fault, session B does not |

---

## 7. Scenario Playback Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| SCEN-001 | Exact sequence matches | Commands arrive in expected order → responses from script |
| SCEN-002 | Unexpected command in strict mode | Wrong command arrives → server returns 400 or disconnects |
| SCEN-003 | Unexpected command in lenient mode | Wrong command → default response, scenario continues |
| SCEN-004 | Scenario from file | Load `.yaml` scenario → plays correctly |
| SCEN-005 | Scenario with file-based responses | `respond_file:` loads XML from disk |
| SCEN-006 | Scenario with inline responses | `respond:` uses inline XML |
| SCEN-007 | Scenario exhausted | More commands than steps → default response or error |
| SCEN-008 | Empty scenario | No steps defined → all commands get default response |
| SCEN-009 | Scenario with variables | `{{uuid}}` in scenario responses → substituted |

---

## 8. Response Override Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| OVR-001 | Override single command | `override_response("get_tasks", custom_xml)` → returns custom XML |
| OVR-002 | Override with error | `override_response("create_alert", error(409, "..."))` → 409 |
| OVR-003 | Non-overridden commands normal | Override `get_tasks`, `get_targets` still returns default |
| OVR-004 | Override replaces fixture | In fixture mode, override takes precedence |
| OVR-005 | Override replaces stateful | In stateful mode, override bypasses store |

---

## 9. Connection & Transport Tests

### 9.1 Unix Socket

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CONN-001 | Connect to Unix socket | Client connects, sends get_version, gets response |
| CONN-002 | Auto socket path | `unix_socket_auto()` creates temp path, returned via `socket_path()` |
| CONN-003 | Socket cleanup on shutdown | After `server.shutdown()`, socket file removed |
| CONN-004 | Multiple clients on same socket | Two clients connect simultaneously, each gets independent session |
| CONN-005 | Client disconnect and reconnect | Client disconnects, reconnects, can authenticate again |
| CONN-006 | Server handles client crash | Client TCP reset mid-command → server stays up |

### 9.2 TCP

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CONN-010 | Connect to TCP port | Client connects to `127.0.0.1:PORT`, GMP works |
| CONN-011 | Random port assignment | `tcp("127.0.0.1:0")` → OS-assigned port, retrievable via `port()` |
| CONN-012 | Multiple TCP clients | Concurrent connections each get independent state |

### 9.3 TLS (Feature-Gated)

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CONN-020 | TLS handshake succeeds | Client with matching CA connects |
| CONN-021 | Self-signed cert works | Server generates self-signed cert, client trusts it |
| CONN-022 | GMP over TLS | Full auth + command flow over TLS connection |

### 9.4 Session Isolation

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CONN-030 | Auth state is per-session | Client A authenticated, client B needs own auth |
| CONN-031 | Resource store is shared (stateful) | Client A creates task, client B sees it |
| CONN-032 | Command history is per-session | `command_history()` distinguishes sessions |

---

## 10. Inspection API Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| INSP-001 | Command history records all commands | Send 5 commands → history length 5 |
| INSP-002 | History includes command name | `history[0].command_name() == "get_version"` |
| INSP-003 | History includes raw XML | `history[0].raw_xml()` matches what was sent |
| INSP-004 | History ordered chronologically | Commands appear in send order |
| INSP-005 | State store inspection | `server.state().tasks().count()` matches created tasks |
| INSP-006 | State store after delete | Delete task → `tasks().count()` decremented |
| INSP-007 | History survives across sessions | Client disconnects, history retained until server shutdown |

---

## 11. Version-Specific Tests

| Test ID | Test Case | Version | Expected |
|---------|-----------|---------|----------|
| VER-001 | get_version returns 22.4 | V22_4 | `<version>22.4</version>` |
| VER-002 | get_version returns 22.5 | V22_5 | `<version>22.5</version>` |
| VER-003 | get_version returns 22.6 | V22_6 | `<version>22.6</version>` |
| VER-004 | get_version returns 22.7 | V22_7 | `<version>22.7</version>` |
| VER-005 | v22.5 resource_names command | V22_5 | `get_resource_names` returns valid response |
| VER-006 | v22.6 report_configs command | V22_6 | `create_report_config` works |
| VER-007 | v22.4 rejects report_configs | V22_4 | `create_report_config` → 400 (unknown command) |
| VER-008 | Version-specific fixtures used | V22_5 | Loads `fixtures/v22_5/` overlays |

---

## 12. Standalone Binary Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| BIN-001 | Start with `--mode echo` | Server starts, accepts connections |
| BIN-002 | Start with `--mode fixture` | Fixture responses returned |
| BIN-003 | Start with `--mode stateful` | CRUD operations work |
| BIN-004 | `--version 22.5` flag | get_version returns 22.5 |
| BIN-005 | `--socket` flag | Listens on specified Unix socket path |
| BIN-006 | `--tcp` flag | Listens on specified TCP address:port |
| BIN-007 | `--credentials user:pass` | Only specified credentials accepted |
| BIN-008 | `--scenario script.yaml` | Scenario playback mode |
| BIN-009 | `--fixtures ./dir/` | Custom fixture directory used |
| BIN-010 | Graceful shutdown on SIGTERM | Server shuts down, cleans up socket |
| BIN-011 | `--tls` with cert/key | TLS listener active |
| BIN-012 | Missing required flags | Clear error message, non-zero exit |
| BIN-013 | `--help` flag | Usage information printed |

---

## 13. Stress & Edge Case Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| STRESS-001 | 100 concurrent clients | All get correct responses, no deadlocks |
| STRESS-002 | 10,000 sequential commands | No memory leak, consistent response times |
| STRESS-003 | Large XML command (1MB) | Parsed without OOM or crash |
| STRESS-004 | Rapid connect/disconnect | 1000 connection cycles → server stable |
| STRESS-005 | Create 10,000 resources | Store handles it, get_tasks returns all |
| STRESS-006 | Binary data in base64 fields | Report with large base64 content → valid response |
| STRESS-007 | Simultaneous reads and writes | Concurrent create + get → no data races |
| STRESS-008 | Zero-length command | Empty send → server handles gracefully |
| STRESS-009 | Command flood without reading | Client sends 100 commands without reading responses → no hang |
| STRESS-010 | Server restart cycle | Start → serve → shutdown → start again → works |

---

## 14. Cross-Client Validation Tests

These tests run the same operations against the mock server from both rust-gvm and python-gvm, verifying behavioral equivalence.

| Test ID | Test Case | Validation |
|---------|-----------|------------|
| XVAL-001 | Version negotiation | Both clients detect same version |
| XVAL-002 | Authentication | Both clients authenticate successfully |
| XVAL-003 | Create task | Both create a task, get it, see same fields |
| XVAL-004 | Get task list | Both see same task count and UUIDs |
| XVAL-005 | Error handling | Both handle 404 for nonexistent resource |
| XVAL-006 | Auth failure | Both handle 400 for bad credentials |
| XVAL-007 | Get reports | Both parse report response with results |

### Cross-Client Test Runner

```bash
#!/bin/bash
# Start mock server
gvm-mock-server --mode stateful --socket /tmp/gvmd-xval.sock --version 22.5 &
SERVER_PID=$!
sleep 1

# Rust tests
cargo test --features cross-validation -- --test-socket /tmp/gvmd-xval.sock

# Python tests
pytest tests/cross_validation/ --gvmd-socket /tmp/gvmd-xval.sock

# Cleanup
kill $SERVER_PID
```

---

## 15. Test Implementation Notes

### 15.1 Test Helpers

```rust
/// Spawn a mock server for a single test, auto-cleanup on drop
async fn test_server(mode: ServerMode) -> (MockGmpServer, PathBuf) {
    let server = MockGmpServer::builder()
        .mode(mode)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();
    let path = server.socket_path().to_owned();
    (server, path)
}

/// Connect a raw client for protocol-level tests (no rust-gvm dependency)
async fn raw_client(socket: &Path) -> UnixStream {
    UnixStream::connect(socket).await.unwrap()
}

/// Send raw XML and read response
async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Vec<u8> {
    stream.write_all(xml).await.unwrap();
    // read until root element closes
    // ...
}
```

### 15.2 Test Organization

```
gvm-mock-server/
├── tests/
│   ├── xml_parsing.rs         # XML-* tests
│   ├── echo_mode.rs           # ECHO-* tests
│   ├── fixture_mode.rs        # FIX-* tests
│   ├── stateful_mode.rs       # STATE-*, CRUD-*, TASK-*, TRASH-*, SEED-*, FILT-* tests
│   ├── error_injection.rs     # ERR-* tests
│   ├── scenario.rs            # SCEN-* tests
│   ├── overrides.rs           # OVR-* tests
│   ├── connections.rs         # CONN-* tests
│   ├── inspection.rs          # INSP-* tests
│   ├── versions.rs            # VER-* tests
│   ├── binary.rs              # BIN-* tests (spawns binary as subprocess)
│   └── stress.rs              # STRESS-* tests (feature-gated)
```

### 15.3 CI Configuration

```yaml
# Required checks on every PR
test-unit:
  - cargo test -p gvm-mock-server

# Integration tests on every PR
test-integration:
  - cargo test -p gvm-mock-server --features integration

# Stress tests on release branches
test-stress:
  - cargo test -p gvm-mock-server --features stress -- --ignored

# Cross-client validation weekly
test-cross-client:
  - cargo build --release -p gvm-mock-server
  - ./target/release/gvm-mock-server --mode stateful --socket /tmp/gvmd.sock &
  - cargo test --features cross-validation
  - pip install gvm-mock-server && pytest tests/cross_validation/
```

---

## 16. Test Coverage Targets

| Component | Target | Measured By |
|-----------|--------|-------------|
| XML parsing | 95% line coverage | `cargo llvm-cov` |
| Echo mode | 100% branch coverage | All ECHO-* tests pass |
| Fixture mode | 90% line coverage | All FIX-* tests pass |
| Stateful CRUD | 100% of resource types | CRUD matrix fully green |
| Task state machine | 100% transition coverage | All TASK-* tests pass |
| Error injection | All fault types tested | All ERR-* tests pass |
| Connection handling | All transports tested | All CONN-* tests pass |
| Standalone binary | All CLI flags tested | All BIN-* tests pass |

Total test case count: **~220 specified tests** across 14 categories.
