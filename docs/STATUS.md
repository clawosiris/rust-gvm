# Implementation Status

Last updated: 2026-03-15

## Crate Status

| Crate | Status | Lines | Tests | Description |
|-------|--------|-------|-------|-------------|
| `gvm-protocol` | ✅ Implemented | ~860 | 23 | XML command builder, response parser, streaming reader |
| `gvm-mock-server` | ✅ Implemented | ~3,600 | 198 | Programmable mock GMP server |
| `gvm-connection` | 📋 Spec'd | ~6 | 0 | Transport layer (placeholder) |
| `gvm-gmp` | 📋 Spec'd | ~5 | 0 | Typed GMP command builders (placeholder) |
| `gvm-client` | 📋 Spec'd | ~5 | 0 | High-level async client (placeholder) |

**Total: ~4,500 lines of Rust, 221 tests (61 unit + 160 integration)**

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

## gvm-connection (Not Yet Implemented)

Spec'd in [openspec.md](../spec/openspec.md). Planned transports:

| Transport | Priority | Notes |
|-----------|----------|-------|
| Unix socket | High | Most common for local gvmd |
| TLS (TCP) | High | Remote connections |
| SSH tunnel | Medium | Via russh |
| Sync wrappers | Low | For non-async consumers |

## gvm-gmp (Not Yet Implemented)

Spec'd in [openspec.md](../spec/openspec.md). Will provide typed command builders for each GMP version.

Target GMP versions: 22.4, 22.5, 22.6, 22.7, 22.8+

## gvm-client (Not Yet Implemented)

Spec'd in [openspec.md](../spec/openspec.md). High-level client combining all layers with automatic version negotiation.

---

## Test Coverage

| Test Category | Count | Notes |
|---------------|-------|-------|
| Unit tests (protocol) | 23 | XML builder, response parser, reader |
| Unit tests (mock server) | 61 | Store, parser, fixtures, faults, scenarios, util |
| Integration tests (mock server) | 137 | All modes, CRUD, lifecycle, faults, MCP compat |
| Python integration tests | 15 steps | python-gvm full lifecycle against mock server |
| **Total** | **221+ tests** | |

## CI Pipelines

| Pipeline | Status | Jobs |
|----------|--------|------|
| CI (push/PR) | ✅ | fmt, clippy, test, test-all-features, doc, deny, coverage, MSRV, python-gvm |
| Nightly | ✅ | Full CI + 5-target cross-platform builds |
| Release | ✅ | Full test → 5-target builds → GitHub Release |
