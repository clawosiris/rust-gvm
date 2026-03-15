# Implementation Status

Last updated: 2026-03-15

## Crate Status

| Crate | Status | Lines | Tests | Description |
|-------|--------|-------|-------|-------------|
| `gvm-protocol` | ✅ Implemented | ~860 | 37 | XML command builder, response parser, streaming reader |
| `gvm-mock-server` | ✅ Implemented | ~3,600 | 198 | Programmable mock GMP server |
| `gvm-connection` | 🔧 Unix socket done | ~230 | 11 | Async transport layer (Unix socket implemented) |
| `gvm-gmp` | ✅ Implemented | ~4,430 | 480 | Typed GMP command builders (29 modules, 23 enums, full rustdoc) |
| `gvm-client` | ✅ Implemented | ~390 | 7 | High-level async client with version negotiation |

**Total: ~9,550 lines of Rust, 620+ tests**

---

## gvm-protocol

### XmlCommand Builder

| Feature | Status | Notes |
|---------|--------|-------|
| Command with attributes | ✅ | `XmlCommand::new("get_tasks").attr("task_id", "...")` |
| Child elements with text | ✅ | `.add_element("name").text("My Task")` |
| Child elements with attributes | ✅ | `.add_element("target").attr("id", "...")` |
| Nested children | ✅ | Arbitrary depth |
| XML escaping | ✅ | `&`, `<`, `>`, `"` in text and attributes |
| Filter string helper | ✅ | `.filter_string("name=foo")` |
| Serialization to bytes | ✅ | `.to_bytes()` |

### Response Parser

| Feature | Status | Notes |
|---------|--------|-------|
| Status code extraction | ✅ | `response.status_code()` → `Option<u16>` |
| Status text extraction | ✅ | `response.status_text()` → `Option<String>` |
| Success check | ✅ | `response.is_success()` → 2xx range |
| Resource ID extraction | ✅ | `response.id()` for create responses |
| Child text extraction | ✅ | `response.child_text("version")` |
| Root element name | ✅ | `response.root_element_name()` |
| Raw bytes access | ✅ | `response.data()` / `response.as_str()` |
| Raise for status | ✅ | `response.raise_for_status()` → Result |

### XmlReader (Streaming Framing)

| Feature | Status | Notes |
|---------|--------|-------|
| Self-closing elements | ✅ | `<get_version/>` |
| Elements with children | ✅ | `<get_tasks_response>...</get_tasks_response>` |
| Chunked delivery | ✅ | Feed partial data, detect completion |
| Nested same-name elements | ✅ | `<report><report>...</report></report>` |
| Reset for reuse | ✅ | `reader.reset()` |

---

## gvm-mock-server

### Server Modes

| Mode | Status | Description |
|------|--------|-------------|
| Echo | ✅ | Generic well-formed responses |
| Fixture | ✅ | Realistic pre-built XML responses |
| Stateful | ✅ | In-memory CRUD with auth |
| Scenario | ✅ | Scripted request→response playback |

### Builder API

| Feature | Status | Notes |
|---------|--------|-------|
| Mode selection | ✅ | `.mode(ServerMode::Stateful)` |
| Version configuration | ✅ | `.version(GmpVersion::V22_5)` — supports 22.4–22.7 |
| Unix socket (path) | ✅ | `.unix_socket("/tmp/gvmd.sock")` |
| Unix socket (auto temp) | ✅ | `.unix_socket_auto()` |
| TCP listener | ✅ | `.tcp("127.0.0.1:9390")` |
| Credentials | ✅ | `.credentials("admin", "admin")` |
| Fixture overrides | ✅ | `.override_response("get_tasks", xml)` |
| Pre-seeding | ✅ | `.seed(\|store\| { ... })` |
| Fault injection | ✅ | `.inject_fault(Fault::once(FaultKind::Disconnect))` |
| Scenario steps | ✅ | `.scenario_step(ScenarioStep { ... })` |

### Stateful CRUD

| Resource Type | Create | Get (single) | Get (list) | Modify | Delete | Clone |
|---------------|--------|-------------|-----------|--------|--------|-------|
| task | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| target | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| config | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| scanner | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alert | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| credential | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| filter | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| note | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| override | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| port_list | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| report | ✅ | ✅ (nested) | ✅ | ✅ | ✅ | ✅ |
| schedule | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| tag | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ticket | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| user | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| role | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| asset | ✅ | ✅ | ✅ (by type) | ✅ | ✅ | ✅ |
| result | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| nvt | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Task Lifecycle

| Transition | Status |
|-----------|--------|
| New → Running (start_task) | ✅ |
| Running → Stopped (stop_task) | ✅ |
| Stopped → Running (resume_task) | ✅ |
| Start creates report resource | ✅ |
| Start returns report_id | ✅ |
| Conflict detection (already running, etc.) | ✅ |

### Special Handlers

| Feature | Status | Notes |
|---------|--------|-------|
| get_version (pre-auth) | ✅ | Always allowed without authentication |
| authenticate (credential validation) | ✅ | Per-session state |
| get_assets (asset_type filtering) | ✅ | MCP server compatible |
| get_report (nested results XML) | ✅ | Proper `<report><report><results>` nesting |
| create_note/override (text + nvt_oid) | ✅ | Non-standard element parsing |
| create_ticket (result_id + comment) | ✅ | Non-standard element parsing |
| modify_ticket (status attribute) | ✅ | Ticket-specific handling |
| Trash/restore/empty_trashcan | ✅ | Full trashcan lifecycle |

### Fault Injection

| Fault Type | Status |
|-----------|--------|
| Server error (500) | ✅ |
| Custom error status + message | ✅ |
| Connection disconnect | ✅ |
| Response delay | ✅ |
| Malformed XML | ✅ |
| Truncated response | ✅ |

| Trigger | Status |
|---------|--------|
| Always | ✅ |
| Once | ✅ |
| After N commands | ✅ |
| On specific command | ✅ |
| Per-session isolation | ✅ |
| Multiple fault composition | ✅ |

### Fixture Library

| Category | Commands Covered |
|----------|-----------------|
| System | get_version, authenticate, help |
| Tasks | get_tasks, create_task, modify_task, delete_task, start_task, stop_task |
| Targets | get_targets |
| Reports | get_reports (with nested results) |
| Configs | get_scan_configs |
| Scanners | get_scanners |
| Alerts | get_alerts |
| Credentials | get_credentials |
| Filters | get_filters |
| Notes | get_notes |
| Overrides | get_overrides |
| Port Lists | get_port_lists |
| Schedules | get_schedules |
| Tags | get_tags |
| Tickets | get_tickets |
| Users | get_users |
| Roles | get_roles |
| Error templates | 400, 401, 404, 409, 500 |

### CLI (Standalone Binary)

| Feature | Status |
|---------|--------|
| `--mode echo\|fixture\|stateful` | ✅ |
| `--version 22.4\|22.5\|22.6\|22.7` | ✅ |
| `--socket <path>` | ✅ |
| `--tcp <addr:port>` | ✅ |
| Cross-platform binaries | ✅ (5 targets in CI) |

---

## gvm-connection

### GvmConnection Trait

| Method | Status | Notes |
|--------|--------|-------|
| `connect()` | ✅ | Async, with timeout |
| `disconnect()` | ✅ | Graceful shutdown |
| `send(&[u8])` | ✅ | Write bytes to transport |
| `read() -> Vec<u8>` | ✅ | Uses `XmlReader` for frame detection |
| `is_connected()` | ✅ | Synchronous check |

### Transports

| Transport | Status | Feature Flag | Notes |
|-----------|--------|-------------|-------|
| Unix socket | ✅ | `unix` (default) | `UnixSocketConnection` with configurable path, timeout, buffer size |
| TLS (TCP) | 📋 Planned | `tls` | Via `tokio-rustls` |
| SSH tunnel | 📋 Planned | `ssh` | Via `russh` |

### UnixSocketConfig

| Field | Default | Notes |
|-------|---------|-------|
| `path` | `/run/gvmd/gvmd.sock` | Configurable |
| `timeout` | 60s | Connect + read timeout |
| `read_buffer_size` | 64 KB | Per-read allocation |

### Error Types

| Variant | Description |
|---------|-------------|
| `NotConnected` | Operation requires active connection |
| `AlreadyConnected` | Double-connect attempt |
| `ConnectFailed` | Transport-level connection error |
| `SendFailed` | Write error |
| `ReadFailed` | Read error or unexpected EOF |
| `Timeout` | Operation exceeded configured timeout |
| `SocketNotFound` | Unix socket path does not exist |

### Integration Tests (against gvm-mock-server)

| Test | Status |
|------|--------|
| Connect + get_version | ✅ |
| Auth + create_target | ✅ |
| Reconnect flow (python-gvm pattern) | ✅ |
| Not-connected error paths | ✅ |
| Double-connect error | ✅ |

## gvm-gmp

Typed GMP command builders covering all entity types, system commands, and enums. Full rustdoc coverage.

### Command Modules (29)

alerts, authentication, credentials, filters, groups, hosts, notes, nvts, overrides, permissions, port_lists, report_formats, reports, resource_names, results, roles, scan_configs, scanners, schedules, system, tags, targets, tasks, tickets, tls_certificates, trashcan, users, version

### Enums (23)

AlertEvent, AlertCondition, AlertMethod, AliveTest, AggregateStatistic, CredentialFormat, CredentialType, EntityType (34 variants), FeedType, FilterType (25 variants), HelpFormat, HostsOrdering, InfoType, PermissionSubjectType, PortRangeType, ReportFormatType, ScannerType, SeverityLevel, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, SortOrder, TicketStatus, UserAuthType

### Tests

| Category | Count |
|----------|-------|
| Inline unit tests (command XML) | 80 |
| External command tests | 53 |
| Enum exhaustive tests | 347 |
| EntityId/type tests | 6 |
| **Total gvm-gmp** | **480** |

## gvm-client

High-level async `GmpClient<C>` and `GmpVersioned<C>` that combines `gvm-connection`, `gvm-protocol`, and `gvm-gmp`. Connects, negotiates GMP version (22.4–22.7), and provides typed `send`/`call` methods.

### Features

| Feature | Status |
|---------|--------|
| Auto version negotiation | ✅ |
| `GmpVersioned` enum (V224–VNext) | ✅ |
| `GvmError` with server/connection/parse/timeout/unsupported | ✅ |
| Version parsing from XML | ✅ |
| Full CRUD lifecycle tests | ✅ |
| Disconnect + error path tests | ✅ |

---

## Test Coverage

**Line coverage: 92.2%** (via `cargo-llvm-cov`)

| Test Category | Count | Notes |
|---------------|-------|-------|
| Unit tests (protocol) | 37 | XML builder, response parser, reader, request trait |
| Unit tests (mock server) | 73 | Store, parser, fixtures, faults, scenarios, history, version, util |
| Integration tests (mock server) | 137 | All modes, CRUD, lifecycle, faults, MCP compat (feature-gated) |
| Integration tests (connection) | 5 | Unix socket transport against mock server (feature-gated) |
| Unit tests (connection) | 6 | Config, error display, construction |
| Unit tests (gvm-gmp inline) | 80 | Command builder XML verification |
| External tests (gvm-gmp) | 53 | Per-module command XML tests |
| Enum exhaustive tests | 347 | Every variant as_gmp_str + FromStr + invalid |
| Type tests (EntityId) | 6 | Validation, Display, Hash, FromStr |
| Unit tests (gvm-client) | 7 | Version parsing and negotiation |
| Integration tests (gvm-client) | 6 | Version negotiation, CRUD lifecycle, error paths (feature-gated) |
| Python integration tests | 15 steps | python-gvm full lifecycle against mock server |
| **Total** | **620+ tests** | |

### Per-File Coverage

| File | Coverage |
|------|----------|
| `history.rs` | 100% |
| `version.rs` | 100% |
| `request.rs` | 100% |
| `xml_command.rs` | 99.6% |
| `handler.rs` | 88.3% |
| `builder.rs` | 80.8% |

## CI Pipelines

| Pipeline | Status | Jobs |
|----------|--------|------|
| CI (push/PR) | ✅ | fmt, clippy, test, test-all-features, doc, deny, coverage, MSRV, python-gvm |
| Nightly | ✅ | Full CI + 5-target cross-platform builds |
| Release | ✅ | Full test → 5-target builds → GitHub Release |
