# gvm-mock-server — OpenSpec

## 1. Overview

**gvm-mock-server** is a lightweight, programmable mock implementation of the Greenbone Management Protocol (GMP) server. It accepts GMP XML commands over Unix sockets or TCP/TLS and returns configurable responses, enabling integration testing of GMP client libraries without requiring a real gvmd instance or PostgreSQL database.

### Motivation

Neither python-gvm nor gvmd provides a test-usable GMP server:

- **python-gvm tests** use a `MockConnection` that returns a static `<foo_response status="200"/>` for every command. They verify *outbound XML only* — never response parsing, error handling, multi-command sequences, or connection lifecycle.
- **gvmd tests** use cgreen with linker-level function mocking (`-Wl,-wrap`). They test internal C functions, not the protocol over the wire.
- **No mock server exists anywhere in the Greenbone ecosystem** that accepts GMP XML over a socket and returns realistic responses.

This means:
1. Client libraries can't test response parsing against realistic GMP XML
2. There's no way to test version negotiation flows end-to-end
3. Error handling paths (auth failures, invalid commands, server errors) are untested
4. Multi-command session sequences (authenticate → get_version → create_task → start_task) can't be validated
5. Connection lifecycle (connect, disconnect, reconnect) testing requires a real server

### Goals

- Drop-in test server for rust-gvm integration tests
- Usable by python-gvm and any other GMP client library
- Programmable response behavior (canned, dynamic, error injection)
- Protocol-accurate GMP XML responses based on the 22.4–22.8 spec
- Stateful session simulation (authentication state, resource CRUD)
- Zero external dependencies (no PostgreSQL, no OpenVAS, no NVT feeds)

### Non-Goals

- Full gvmd behavioral fidelity (scanning, NVT execution, report generation)
- Production use as a vulnerability manager
- Performance benchmarking tool (though it should handle concurrent clients)

### License

AGPL-3.0-or-later (matching the Greenbone ecosystem)

---

## 2. Architecture

### 2.1 Crate Position

```
rust-gvm/
├── crates/
│   ├── gvm-connection/
│   ├── gvm-protocol/
│   ├── gvm-gmp/
│   ├── gvm-client/
│   └── gvm-mock-server/    ← This crate
├── spec/
│   ├── openspec.md
│   └── mock-server-openspec.md
└── tests/
    └── integration/         ← Uses gvm-mock-server
```

### 2.2 Component Diagram

```
┌─────────────────────────────────────────────────┐
│              gvm-mock-server                     │
│                                                  │
│  ┌──────────┐  ┌─────────────┐  ┌────────────┐ │
│  │ Listener  │  │   Session   │  │  Response   │ │
│  │           │──│   Handler   │──│  Generator  │ │
│  │ Unix/TCP  │  │             │  │             │ │
│  └──────────┘  └──────┬──────┘  └──────┬──────┘ │
│                       │                │         │
│                ┌──────┴──────┐  ┌──────┴──────┐ │
│                │    State    │  │   Fixture    │ │
│                │    Store    │  │   Library    │ │
│                │             │  │             │  │
│                │ • auth      │  │ • tasks.xml │  │
│                │ • resources │  │ • targets.. │  │
│                │ • sessions  │  │ • errors..  │  │
│                └─────────────┘  └─────────────┘ │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │          Behavior Engine                  │   │
│  │  • Canned responses (fixture-based)       │   │
│  │  • Dynamic responses (state-aware CRUD)   │   │
│  │  • Error injection (programmable faults)  │   │
│  │  • Scenario playback (scripted sequences) │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

---

## 3. Core Design

### 3.1 Server Modes

The mock server operates in one of three modes, selectable at construction time:

#### Mode 1: Echo (Minimal)
Returns a well-formed `<command_response status="200" status_text="OK"/>` for any recognized command. Useful for basic connectivity and XML framing tests.

#### Mode 2: Fixture (Realistic Responses)
Returns pre-built GMP XML responses from a fixture library. Each command maps to a realistic response template with proper structure, nested elements, and UUIDs. Supports version-specific fixtures.

#### Mode 3: Stateful (Simulated CRUD)
Maintains an in-memory resource store. Create commands generate UUIDs and store resources. Get commands return stored resources. Modify/delete commands update/remove them. Authentication is validated. This mode enables testing of multi-step workflows.

### 3.3 Transport Listeners

The mock server supports three listener types, all routing to the same `handle_stream` pipeline:

| Transport | Builder Method | Feature Flag | Notes |
|-----------|---------------|-------------|-------|
| Unix socket | `.unix_socket(path)` / `.unix_socket_auto()` | — (always available) | Default for local testing |
| TCP | `.tcp("addr:port")` | — (always available) | For cross-language testing |
| SSH | `.ssh("addr:port")` | `ssh` | Embeds `russh` SSH server with ephemeral Ed25519 host key |

#### SSH Listener Details

The SSH listener (`ssh_listener.rs`) implements `russh::server::Handler`:
- Generates an ephemeral Ed25519 host key at server start (no disk key required)
- Accepts password authentication (checks against configured credentials in Stateful mode, accepts all in other modes)
- Handles `direct-streamlocal@openssh.com` channel requests (used by `SshConnection`)
- Each SSH channel gets its own `SessionHandler` (same isolation as TCP/Unix connections)
- Respects server shutdown signal for graceful termination

This enables full end-to-end testing: `SshConnection` → mock SSH server → GMP handler → response, without needing a real SSH server or gvmd.

### 3.2 GMP Protocol Compliance

#### Status Codes

The mock server uses the GMP status code vocabulary:

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful get/modify/delete/action |
| 201 | Created | Successful create (returns `id` attribute) |
| 202 | Accepted | Async operations (start_task, resume_task) |
| 400 | Bad Request | Malformed XML, missing required elements |
| 401 | Unauthorized | Not authenticated, bad credentials |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource ID doesn't exist |
| 409 | Conflict | Resource in use, can't delete |
| 500 | Internal Error | Simulated server errors |
| 503 | Service Unavailable | Simulated overload/maintenance |

#### Response Format

All responses follow the GMP pattern:
```xml
<command_response status="CODE" status_text="TEXT">
  <!-- response body -->
</command_response>
```

For `create_*` commands:
```xml
<create_TYPE_response status="201" status_text="OK, resource created"
                      id="UUID-OF-NEW-RESOURCE"/>
```

For `get_*` commands (list):
```xml
<get_TYPEs_response status="200" status_text="OK">
  <TYPE id="uuid-1">
    <name>Resource Name</name>
    <comment>...</comment>
    <creation_time>2024-01-01T00:00:00Z</creation_time>
    <modification_time>2024-01-01T00:00:00Z</modification_time>
    <!-- type-specific fields -->
  </TYPE>
  <filters>...</filters>
  <sort>...</sort>
  <TYPE_count>...</TYPE_count>
</get_TYPEs_response>
```

#### Authentication Flow

1. `get_version` is always permitted (pre-auth)
2. All other commands require prior `authenticate` (except in `Echo` mode)
3. Default credentials: `admin` / `admin` (configurable)
4. Auth failure returns `<authenticate_response status="400" status_text="Authentication failed"/>`
5. Successful auth returns role and timezone:
```xml
<authenticate_response status="200" status_text="OK">
  <role>Admin</role>
  <timezone>UTC</timezone>
</authenticate_response>
```

#### Version Negotiation

`get_version` returns the configured GMP version:
```xml
<get_version_response status="200" status_text="OK">
  <version>22.5</version>
</get_version_response>
```

The version is configurable at server construction to test version negotiation in clients.

---

## 4. API Design

### 4.1 Builder API

```rust
use gvm_mock_server::{MockGmpServer, ServerMode, GmpVersion};

// Minimal echo server
let server = MockGmpServer::builder()
    .mode(ServerMode::Echo)
    .unix_socket("/tmp/gvmd-test.sock")
    .build()
    .await?;

// Realistic fixture server
let server = MockGmpServer::builder()
    .mode(ServerMode::Fixture)
    .version(GmpVersion::V22_5)
    .tcp("127.0.0.1:9390")
    .build()
    .await?;

// Stateful CRUD server
let server = MockGmpServer::builder()
    .mode(ServerMode::Stateful)
    .version(GmpVersion::V22_5)
    .credentials("testuser", "testpass")
    .unix_socket_auto()  // random temp path
    .build()
    .await?;

let socket_path = server.socket_path();  // for client connection
// ... run tests ...
server.shutdown().await?;
```

### 4.2 Programmatic Response Override

Override responses for specific commands:

```rust
use gvm_mock_server::{MockGmpServer, ResponseOverride};

let server = MockGmpServer::builder()
    .mode(ServerMode::Fixture)
    .override_response("get_tasks", ResponseOverride::xml(r#"
        <get_tasks_response status="200" status_text="OK">
            <task id="test-uuid-1">
                <name>My Custom Task</name>
                <status>Running</status>
            </task>
            <task_count>1<filtered>1</filtered></task_count>
        </get_tasks_response>
    "#))
    .override_response("create_alert", ResponseOverride::error(409, "Resource in use"))
    .build()
    .await?;
```

### 4.3 Error Injection

```rust
use gvm_mock_server::{MockGmpServer, Fault};

let server = MockGmpServer::builder()
    .mode(ServerMode::Fixture)
    // Fail the 3rd command in each session
    .inject_fault(Fault::after_commands(2, FaultKind::ServerError500))
    // Drop connection after auth
    .inject_fault(Fault::after_auth(FaultKind::Disconnect))
    // Delay responses by 5s (timeout testing)
    .inject_fault(Fault::always(FaultKind::Delay(Duration::from_secs(5))))
    // Return malformed XML once
    .inject_fault(Fault::once(FaultKind::MalformedXml))
    // Truncate response mid-stream
    .inject_fault(Fault::on_command("get_reports", FaultKind::TruncatedResponse))
    .build()
    .await?;
```

### 4.4 Scenario Playback

Script exact request→response sequences for deterministic testing:

```rust
use gvm_mock_server::{MockGmpServer, Scenario};

let scenario = Scenario::new()
    .expect_command("get_version")
    .respond_with_file("fixtures/get_version_22_5.xml")
    .expect_command("authenticate")
    .respond_with_file("fixtures/auth_success.xml")
    .expect_command("get_tasks")
    .respond_with_file("fixtures/get_tasks_empty.xml")
    .expect_command("create_task")
    .respond_with_file("fixtures/create_task_success.xml")
    .strict();  // fail if unexpected commands arrive

let server = MockGmpServer::builder()
    .mode(ServerMode::Scenario(scenario))
    .unix_socket_auto()
    .build()
    .await?;
```

### 4.5 Inspection API

After tests, inspect what the server received:

```rust
let history = server.command_history();
assert_eq!(history.len(), 4);
assert_eq!(history[0].command_name(), "get_version");
assert_eq!(history[1].command_name(), "authenticate");

// Access raw XML
let auth_xml = history[1].raw_xml();

// Check stateful store contents
let store = server.state();
assert_eq!(store.tasks().count(), 1);
assert_eq!(store.tasks().first().unwrap().name(), "My Task");
```

---

## 5. Fixture Library

### 5.1 Structure

```
gvm-mock-server/
└── fixtures/
    ├── common/
    │   ├── get_version.xml
    │   ├── authenticate_success.xml
    │   ├── authenticate_failure.xml
    │   ├── help.xml
    │   └── error_templates/
    │       ├── 400_bad_request.xml
    │       ├── 401_unauthorized.xml
    │       ├── 404_not_found.xml
    │       ├── 409_conflict.xml
    │       └── 500_internal.xml
    ├── v22_4/
    │   ├── tasks/
    │   │   ├── get_tasks_empty.xml
    │   │   ├── get_tasks_multiple.xml
    │   │   ├── get_task_single.xml
    │   │   ├── create_task_success.xml
    │   │   └── start_task_success.xml
    │   ├── targets/
    │   ├── configs/
    │   ├── scanners/
    │   ├── alerts/
    │   ├── credentials/
    │   ├── filters/
    │   ├── reports/
    │   │   ├── get_reports_empty.xml
    │   │   ├── get_report_with_results.xml
    │   │   └── get_report_large.xml      # Realistic multi-MB report
    │   ├── notes/
    │   ├── overrides/
    │   ├── port_lists/
    │   ├── schedules/
    │   ├── tags/
    │   ├── tickets/
    │   └── users/
    ├── v22_5/                              # Delta fixtures
    │   └── resource_names/
    ├── v22_6/
    │   └── report_configs/
    └── v22_7/
        └── scanners/
```

### 5.2 Fixture Content Guidelines

Fixtures should be:
- **Structurally complete** — include all elements the GMP spec defines for each response type (names, comments, creation_time, modification_time, permissions, tags, etc.)
- **Referentially consistent** — UUIDs used in tasks reference targets/configs/scanners that exist in other fixture files
- **Realistically sized** — the "large report" fixture should contain hundreds of results to test streaming/memory behavior
- **Version-accurate** — follow the RNC grammar from the GMP spec for each version

### 5.3 Fixture Templating

Fixtures support variable substitution for dynamic values:

```xml
<create_task_response status="201"
                      status_text="OK, resource created"
                      id="{{uuid}}"/>
```

Built-in variables:
- `{{uuid}}` — fresh UUID v4
- `{{now}}` — current ISO 8601 timestamp
- `{{version}}` — configured GMP version string
- `{{resource_id}}` — ID extracted from the incoming request

---

## 6. Stateful Store

### 6.1 Resource Model

In `Stateful` mode, the mock server maintains an in-memory store of GMP resources.

```rust
pub struct ResourceStore {
    tasks: HashMap<Uuid, TaskResource>,
    targets: HashMap<Uuid, TargetResource>,
    configs: HashMap<Uuid, ConfigResource>,
    scanners: HashMap<Uuid, ScannerResource>,
    alerts: HashMap<Uuid, AlertResource>,
    credentials: HashMap<Uuid, CredentialResource>,
    filters: HashMap<Uuid, FilterResource>,
    groups: HashMap<Uuid, GroupResource>,
    notes: HashMap<Uuid, NoteResource>,
    overrides: HashMap<Uuid, OverrideResource>,
    permissions: HashMap<Uuid, PermissionResource>,
    port_lists: HashMap<Uuid, PortListResource>,
    reports: HashMap<Uuid, ReportResource>,
    report_formats: HashMap<Uuid, ReportFormatResource>,
    roles: HashMap<Uuid, RoleResource>,
    schedules: HashMap<Uuid, ScheduleResource>,
    tags: HashMap<Uuid, TagResource>,
    tickets: HashMap<Uuid, TicketResource>,
    tls_certificates: HashMap<Uuid, TlsCertificateResource>,
    users: HashMap<Uuid, UserResource>,
    trashcan: Vec<TrashedResource>,
}
```

### 6.2 CRUD Behavior

| Command Pattern | Behavior |
|----------------|----------|
| `create_*` | Generate UUID, store resource, return 201 with ID |
| `get_*s` | Return all resources of type, apply filter if present |
| `get_* (with id)` | Return single resource or 404 |
| `modify_*` | Update stored resource or 404 |
| `delete_*` | Move to trashcan (or remove if `ultimate="1"`), or 404 |
| `clone (create with copy)` | Duplicate resource with new UUID |

### 6.3 Task State Machine

Tasks in stateful mode simulate the lifecycle:

```
New → Requested → Running → Done
                ↗           ↓
         Stopped ←── Stop Request
                ↗
         Resumed
```

- `start_task` → sets status to "Requested", then "Running" after configurable delay
- `stop_task` → sets status to "Stop Requested", then "Stopped"
- `resume_task` → sets status to "Requested" (from "Stopped" only)
- `get_task` → returns current status

### 6.4 Pre-seeding

Populate the store before tests:

```rust
let server = MockGmpServer::builder()
    .mode(ServerMode::Stateful)
    .seed(|store| {
        store.add_target("target-1", "Test Target", "192.168.1.0/24");
        store.add_config("config-1", "Full and fast");
        store.add_scanner("scanner-1", "OpenVAS Scanner", ScannerType::OpenVas);
        store.add_task("task-1", "Nightly Scan", "target-1", "config-1", "scanner-1");
    })
    .build()
    .await?;
```

---

## 7. Python Compatibility Layer

### 7.1 Standalone Binary

The crate also builds as a standalone binary for use by python-gvm tests and other non-Rust clients:

```bash
# Start mock server on a Unix socket
gvm-mock-server --mode stateful --socket /tmp/gvmd.sock --version 22.5

# Start on TCP
gvm-mock-server --mode fixture --tcp 127.0.0.1:9390 --version 22.4

# With TLS
gvm-mock-server --mode fixture --tls --cert server.pem --key server.key --tcp 0.0.0.0:9390

# Load custom fixtures
gvm-mock-server --mode fixture --fixtures ./my-fixtures/ --socket /tmp/gvmd.sock

# Scenario mode from a YAML script
gvm-mock-server --mode scenario --script test-flow.yaml --socket /tmp/gvmd.sock
```

### 7.2 Scenario YAML Format

For the standalone binary, scenarios can be defined in YAML:

```yaml
version: "22.5"
credentials:
  username: admin
  password: secret

steps:
  - expect: get_version
    respond: |
      <get_version_response status="200" status_text="OK">
        <version>22.5</version>
      </get_version_response>

  - expect: authenticate
    respond: |
      <authenticate_response status="200" status_text="OK">
        <role>Admin</role>
        <timezone>UTC</timezone>
      </authenticate_response>

  - expect: get_tasks
    respond_file: fixtures/v22_5/tasks/get_tasks_multiple.xml

  - expect: create_task
    respond: |
      <create_task_response status="201"
                            status_text="OK, resource created"
                            id="a1234567-89ab-cdef-0123-456789abcdef"/>
```

### 7.3 python-gvm Integration

A Python wrapper package `gvm-mock-server` (published to PyPI) that:
1. Downloads the platform-appropriate binary
2. Provides a pytest fixture:

```python
import pytest
from gvm_mock_server import mock_gvmd

@pytest.fixture
def gvmd():
    with mock_gvmd(mode="stateful", version="22.5") as server:
        yield server

def test_get_tasks(gvmd):
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import GMP

    conn = UnixSocketConnection(path=gvmd.socket_path)
    with GMP(conn) as gmp:
        # This now tests ACTUAL response parsing, not just XML generation
        tasks = gmp.get_tasks()
        assert tasks  # tests response parsing!
```

This would let python-gvm move from "verify we send correct XML" to "verify the full round-trip works" — a significant testing upgrade.

---

## 8. Testing Strategy

### 8.1 Self-Tests (gvm-mock-server crate)

- **Protocol compliance**: Verify all fixture responses parse as valid GMP XML against the RNC grammar
- **State machine**: Test task lifecycle transitions
- **Error injection**: Verify faults fire at correct times
- **Scenario playback**: Verify strict ordering enforcement
- **Concurrent clients**: Multiple simultaneous connections with independent state

### 8.2 Integration Tests (rust-gvm)

The mock server enables these previously-impossible test categories:

| Test Category | What It Validates |
|--------------|-------------------|
| Version negotiation | `get_version` → version-specific client selection |
| Auth flow | Connect → authenticate → commands → disconnect |
| CRUD round-trip | Create resource → get it back → verify fields |
| Error recovery | Server returns 404/500 → client handles gracefully |
| Connection lifecycle | Connect, disconnect, reconnect, timeout |
| Large responses | Multi-MB report parsing, streaming behavior |
| Malformed responses | Client handles truncated/invalid XML |
| Multi-version | Same test suite against 22.4, 22.5, 22.6, 22.7 |

### 8.3 Cross-Client Validation

Run the same mock server instance against both rust-gvm and python-gvm to verify behavioral equivalence:

```bash
# Start shared mock server
gvm-mock-server --mode stateful --socket /tmp/gvmd-test.sock --version 22.5

# Run rust-gvm tests
cargo test --features integration-tests

# Run python-gvm tests (with mock server pytest plugin)
pytest tests/ --gvmd-socket /tmp/gvmd-test.sock
```

---

## 9. Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime, socket listeners |
| `quick-xml` | XML parsing (incoming commands) and generation (responses) |
| `uuid` | UUID generation for resource IDs |
| `tracing` | Structured logging of received commands |
| `clap` | CLI argument parsing (standalone binary) |
| `serde` + `serde_yaml` | Scenario YAML parsing (standalone binary) |
| `tokio-rustls` | TLS support (feature-gated) |
| `russh` | SSH listener (feature-gated) |

Dev: `tempfile` (auto-cleanup socket paths), `gvm-connection` (integration tests)

---

## 10. Implementation Phases

### Phase 1: Echo + Fixture Modes ✅
1. TCP and Unix socket listeners
2. GMP XML command parser (extract command name + attributes)
3. Echo mode (well-formed generic responses)
4. Fixture mode with core resource type fixtures (tasks, targets, configs)
5. Builder API
6. Integration with rust-gvm test suite

**Exit criteria:** rust-gvm integration tests pass against mock server for version negotiation, authentication, and basic get/create commands.

### Phase 2: Stateful Mode ✅
1. In-memory resource store
2. CRUD operations for all resource types
3. Task state machine
4. Pre-seeding API
5. Filter string parsing (basic: name, id matching)
6. Command history / inspection API

**Exit criteria:** Full CRUD round-trip tests pass. Task lifecycle tests pass.

### Phase 3: Error Injection + Scenarios ✅
1. Fault injection engine
2. Scenario playback mode
3. Concurrent client support
4. Response override API

**Exit criteria:** Error handling tests pass. Scenario playback works.

### Phase 4: Python Ecosystem (Partial)
1. ✅ Standalone binary with CLI (`--mode`, `--version`, `--socket`, `--tcp`)
2. ⬜ Scenario YAML format — deferred
3. ⬜ TLS support — deferred
4. ⬜ Python wrapper package with pytest fixture — deferred
5. ✅ python-gvm integration test in CI (`tests/integration/test_python_gvm.py`)

**Exit criteria:** python-gvm can run tests against the mock server. ~~PyPI package published.~~

### Phase 4 Additions (Not in Original Spec)
- ✅ SSH listener (`ssh_listener.rs`) for E2E testing of SSH transport
- ✅ `util.rs` — shared `now_iso()` (Rata Die), `xml_escape()`, `xml_escape_attr()`
- ✅ Cross-platform binary builds (5 targets) in CI
- ✅ SBOM generation (CycloneDX) attached to releases
- ✅ Makefile with `test-integration` target
- ✅ Comprehensive test suite (198 mock-server tests)

---

## 11. Design Decisions

### D1: Separate Crate, Not Embedded in gvm-client
**Decision:** Standalone crate in the workspace.
**Rationale:** The mock server is useful to non-Rust clients (python-gvm, Go clients, shell scripts). Embedding it in gvm-client would force those consumers to depend on the full Rust client stack.

### D2: Three Modes Rather Than One Complex Server
**Decision:** Echo, Fixture, and Stateful as distinct modes.
**Rationale:** Different testing needs require different fidelity levels. Echo mode is fast for connection/framing tests. Fixture mode gives realistic XML without state complexity. Stateful mode enables workflow tests. Users pick the simplest mode that satisfies their test.

### D3: Fixture Files Over Programmatic XML Construction
**Decision:** Ship pre-built XML fixture files rather than generating all responses in code.
**Rationale:** Fixture files can be validated against the GMP RNC grammar independently. They're readable, auditable, and can be extracted from real gvmd captures. Code-generated XML risks encoding the same bugs the tests are trying to catch.

### D4: Standalone Binary for Cross-Language Use
**Decision:** Build both a Rust library crate and a standalone binary.
**Rationale:** The testing gap exists across all GMP client languages. A binary with a simple CLI makes the mock server accessible to Python, Go, and shell-based test suites. The pytest fixture wrapper makes adoption by python-gvm nearly zero-effort.

### D5: AGPL-3.0-or-later License
**Decision:** Match the Greenbone ecosystem licensing direction.
**Rationale:** Changed from GPL-3.0-or-later to AGPL-3.0-or-later. The mock server is part of the rust-gvm workspace. All source files carry SPDX headers.

---

## 12. Open Questions

1. **Fixture sourcing** — Should we capture fixtures from a real gvmd instance, or hand-craft them from the RNC grammar? Real captures are more realistic but harder to maintain. Possibly both: hand-crafted for structure, real captures for the "large report" fixture.

2. **Filter string parsing depth** — GMP filters are complex (`name=foo and type=task sort=name`). How much of the filter language should stateful mode implement? Suggest: basic equality matching in Phase 2, defer complex filters.

3. **TLS client certificate auth** — gvmd supports TLS client cert authentication. Should the mock server validate certs, or just accept any TLS connection? Suggest: accept any, with an option to require specific certs.

4. **WebSocket / HTTP transport** — Newer Greenbone components (OpenVAS daemon) use HTTP. Should the mock server support HTTP alongside GMP-over-socket? Suggest: out of scope for v1, separate mock for OpenVAS HTTP API if needed.

5. **Record-and-replay** — Should the mock server support recording traffic from a real gvmd and replaying it? This would be valuable for regression testing. Suggest: Phase 4+ stretch goal.
