# rust-gvm Library Test Specification — OpenSpec

## 1. Overview

This document specifies the complete test suite for the **rust-gvm** client library itself — the four crates (`gvm-connection`, `gvm-protocol`, `gvm-gmp`, `gvm-client`) that together implement a Rust GMP client.

All integration tests assume the **gvm-mock-server** is available as test infrastructure. Unit tests are self-contained.

### Relationship to Mock Server Tests

| Spec | Tests What |
|------|-----------|
| `mock-server-tests-openspec.md` | Does the mock server behave correctly? |
| **This spec** | Does the rust-gvm library behave correctly against a correct server? |

### Test Tiers

| Tier | Scope | Runner | When |
|------|-------|--------|------|
| **Unit** | Pure functions, XML builders, enum conversions, type validation | `cargo test` | Every commit |
| **Protocol** | Sans-I/O state machine against raw byte sequences | `cargo test` | Every commit |
| **Integration** | Full client against mock server (all modes) | `cargo test --features integration` | Every PR |
| **Compatibility** | Output byte-comparison with python-gvm | `cargo test --features compat` | Every PR |
| **Stress** | Large responses, many requests, timeout behavior | `cargo test --features stress` | Release |

---

## 2. `gvm-protocol` — Sans-I/O State Machine Tests

### 2.1 State Transitions

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| PROTO-001 | Initial state allows send | `Connection::new()` → `send(req)` succeeds, returns bytes |
| PROTO-002 | Send transitions to AwaitingResponse | After `send()`, second `send()` returns `InvalidState` |
| PROTO-003 | Receive data in AwaitingResponse | `receive_data()` after `send()` → transitions to ReceivingData |
| PROTO-004 | Complete response returns Some | Feed complete XML → `receive_data()` returns `Some(Response)` |
| PROTO-005 | Partial response returns None | Feed half of XML → `receive_data()` returns `None` |
| PROTO-006 | Multi-chunk response assembly | Feed XML in 3 chunks → first two return `None`, last returns `Some` |
| PROTO-007 | Response resets to Initial | After complete response, `send()` works again |
| PROTO-008 | Close resets state | From any state, `close()` → back to Initial |
| PROTO-009 | Receive in Initial is error | `receive_data()` without prior `send()` → `InvalidState` |
| PROTO-010 | Malformed XML enters Error state | Feed invalid XML → `GvmError::XmlParse` |
| PROTO-011 | Error state rejects send and receive | In Error state → both `send()` and `receive_data()` → `InvalidState` |
| PROTO-012 | Close from Error resets to Initial | `close()` → can `send()` again |
| PROTO-013 | Send returns correct bytes | `send(request)` → returned bytes equal `request.to_bytes()` |

### 2.2 XmlReader (Streaming End Detection)

| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| XMLR-001 | Simple self-closing element | `<get_version_response status="200"/>` | End detected |
| XMLR-002 | Element with children | `<get_tasks_response>...<task>...</task>...</get_tasks_response>` | End at closing root |
| XMLR-003 | Nested same-name elements | `<a><a>inner</a></a>` | End at outer `</a>` |
| XMLR-004 | Chunked delivery | Root element split across 5 chunks | End detected on final chunk |
| XMLR-005 | Large payload (5MB) | Multi-MB XML | End detected, no OOM |
| XMLR-006 | XML with CDATA | `<![CDATA[...]]>` inside element | Correctly handled |
| XMLR-007 | XML with comments | `<!-- comment -->` inside response | Ignored, end detection works |
| XMLR-008 | XML with processing instructions | `<?xml version="1.0"?>` prefix | Handled correctly |
| XMLR-009 | Empty root element | `<response></response>` | End detected |
| XMLR-010 | Huge text node (base64 report) | 10MB of base64 text in single element | Streams without OOM |

### 2.3 XmlCommand Builder

| Test ID | Test Case | Expected Bytes |
|---------|-----------|---------------|
| CMD-001 | Simple command | `XmlCommand::new("get_version")` → `<get_version/>` |
| CMD-002 | Command with attribute | `.set_attribute("task_id", "a1")` → `<cmd task_id="a1"/>` |
| CMD-003 | Command with child element | `.add_element_with_text("name", "foo")` → `<cmd><name>foo</name></cmd>` |
| CMD-004 | Command with empty child | `.add_element("target").set_attribute("id", "0")` → `<cmd><target id="0"/></cmd>` |
| CMD-005 | Command with multiple attributes | Two `set_attribute` calls → both present |
| CMD-006 | Command with nested children | Preferences with scanner_name/value pairs → correct nesting |
| CMD-007 | Command with filter | `.add_filter(Some("name=foo"), None)` → `filter="name=foo"` attribute |
| CMD-008 | Command with filter ID | `.add_filter(None, Some("f1"))` → `filt_id="f1"` attribute |
| CMD-009 | Implements Request trait | `XmlCommand` → `.to_bytes()` returns valid XML |
| CMD-010 | Special characters escaped | Name with `<>&"` → properly XML-escaped |
| CMD-011 | UTF-8 preserved | Unicode characters in text elements → correct encoding |
| CMD-012 | Boolean attribute | `to_bool(true)` → `"1"`, `to_bool(false)` → `"0"` |

---

## 3. `gvm-connection` — Transport Layer Tests

### 3.1 Unix Socket Connection

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| UNIX-001 | Connect to mock server | `UnixSocketConnection::connect()` succeeds |
| UNIX-002 | Send and receive bytes | Send XML bytes → receive response bytes |
| UNIX-003 | Default socket path | Default is `/run/gvmd/gvmd.sock` |
| UNIX-004 | Custom socket path | Configured path used |
| UNIX-005 | Disconnect closes socket | After `disconnect()`, socket is released |
| UNIX-006 | Reconnect after disconnect | `disconnect()` then `connect()` → works |
| UNIX-007 | Timeout on no response | Server delays > timeout → `GvmError::Timeout` |
| UNIX-008 | Connect to nonexistent socket | Path doesn't exist → `GvmError::Connection` |
| UNIX-009 | Send after disconnect | `send()` without `connect()` → error |
| UNIX-010 | is_connected reflects state | `false` before connect, `true` after, `false` after disconnect |
| UNIX-011 | Large payload round-trip | Send/receive multi-MB data → no truncation |
| UNIX-012 | Concurrent usage from single client | Sequential send/receive pairs → all correct |

### 3.2 TLS Connection (Feature-Gated)

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| TLS-001 | TLS handshake with mock server | Connect over TLS → GMP commands work |
| TLS-002 | Default port | Default is 9390 |
| TLS-003 | Custom hostname and port | Configured values used |
| TLS-004 | Certificate verification | Platform/custom roots and DNS/IP SAN are always verified |
| TLS-005 | Client certificate auth | Certfile + keyfile → presented during handshake |
| TLS-006 | TLS timeout | Handshake hang → timeout error |
| TLS-007 | Invalid cert → error | Expired/wrong cert → `GvmError::Connection` |
| TLS-008 | Send/receive over TLS | Full GMP command round-trip encrypted |

### 3.3 SSH Connection (Feature-Gated)

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| SSH-001 | SSH connection with password | Connect with username/password → GMP works |
| SSH-002 | Default SSH settings | Port 22, username "gmp" |
| SSH-003 | Custom SSH settings | Configured host/port/username |
| SSH-004 | SSH timeout | Connection hang → timeout error |
| SSH-005 | Known hosts validation | Known hosts file checked |
| SSH-006 | Send/receive over SSH | Full GMP command round-trip |

### 3.4 GvmConnection Trait

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| TRAIT-001 | All implementations satisfy trait | `UnixSocketConnection: GvmConnection` compiles |
| TRAIT-002 | All implementations are Send + Sync | Trait bound `Send + Sync` satisfied |
| TRAIT-003 | Implementations work with GmpClient | Each connection type plugs into `GmpClient<C>` |

---

## 4. `gvm-gmp` — Command Builder Tests

### 4.1 Type Safety

#### EntityId

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| TYPE-001 | Valid UUID accepted | `EntityId::new("550e8400-...")` → Ok |
| TYPE-002 | Empty string rejected | `EntityId::new("")` → Err |
| TYPE-003 | as_str round-trips | `id.as_str()` returns original string |
| TYPE-004 | Display/Debug implemented | Format string works |
| TYPE-005 | Eq and Hash work | Can be HashMap key |

#### Enums

For each enum type, test:

| Test ID Pattern | Test Case | Expected |
|----------------|-----------|----------|
| ENUM-{type}-001 | All variants exist | Compile-time check — variants match python-gvm |
| ENUM-{type}-002 | Conversion to GMP string | `.value()` returns the GMP wire string |
| ENUM-{type}-003 | Parse from string | `Type::from_str("wire_value")` → correct variant |
| ENUM-{type}-004 | Invalid string → error | `Type::from_str("garbage")` → Err |

**Enum types to test** (22 types):
AlertEvent, AlertCondition, AlertMethod, AliveTest, AggregateStatistic, CredentialFormat, CredentialType, EntityType, FeedType, FilterType, HelpFormat, HostsOrdering, InfoType, PermissionSubjectType, PortRangeType, ReportFormatType, ScannerType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, SortOrder, SeverityLevel, TicketStatus, UserAuthType

Total: ~88 enum tests (4 per type × 22 types)

### 4.2 Command Builder — Output Verification

Each command builder must produce XML bytes that **exactly match** what python-gvm produces for the same inputs. These are the core correctness tests.

#### Authentication

| Test ID | Test Case | Expected XML |
|---------|-----------|-------------|
| BUILD-AUTH-001 | authenticate | `<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>` |

#### Tasks (Representative — Full CRUD)

| Test ID | Test Case | Expected XML |
|---------|-----------|-------------|
| BUILD-TASK-001 | clone_task | `<create_task><copy>a1</copy></create_task>` |
| BUILD-TASK-002 | create_container_task | `<create_task><name>foo</name><target id="0"/></create_task>` |
| BUILD-TASK-003 | create_container_task with comment | Includes `<comment>bar</comment>` |
| BUILD-TASK-004 | create_task (minimal) | `<create_task><name>foo</name><usage_type>scan</usage_type><config id="c1"/><target id="t1"/><scanner id="s1"/></create_task>` |
| BUILD-TASK-005 | create_task with all options | Includes alterable, hosts_ordering, schedule, alerts, observers, preferences |
| BUILD-TASK-006 | create_task with multiple alerts | Multiple `<alert id="..."/>` elements |
| BUILD-TASK-007 | create_task with preferences | `<preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences>` |
| BUILD-TASK-008 | delete_task (soft) | `<delete_task task_id="a1" ultimate="0"/>` |
| BUILD-TASK-009 | delete_task (ultimate) | `<delete_task task_id="a1" ultimate="1"/>` |
| BUILD-TASK-010 | get_tasks (no args) | `<get_tasks usage_type="scan"/>` |
| BUILD-TASK-011 | get_tasks with filter_string | `<get_tasks usage_type="scan" filter="name=foo"/>` |
| BUILD-TASK-012 | get_tasks with filter_id | `<get_tasks usage_type="scan" filt_id="f1"/>` |
| BUILD-TASK-013 | get_tasks with trash | `<get_tasks usage_type="scan" trash="1"/>` |
| BUILD-TASK-014 | get_tasks with details | `<get_tasks usage_type="scan" details="1"/>` |
| BUILD-TASK-015 | get_tasks with schedules_only | `<get_tasks usage_type="scan" schedules_only="1"/>` |
| BUILD-TASK-016 | get_tasks with ignore_pagination | `<get_tasks usage_type="scan" ignore_pagination="1"/>` |
| BUILD-TASK-017 | get_task (single) | `<get_tasks task_id="a1" usage_type="scan" details="1"/>` |
| BUILD-TASK-018 | modify_task (id only) | `<modify_task task_id="t1"/>` |
| BUILD-TASK-019 | modify_task with name | `<modify_task task_id="t1"><name>foo</name></modify_task>` |
| BUILD-TASK-020 | modify_task with all options | All optional fields present |
| BUILD-TASK-021 | modify_task clear alerts | `<alert id="0"/>` when empty alert_ids |
| BUILD-TASK-022 | move_task | `<move_task task_id="a1"/>` |
| BUILD-TASK-023 | move_task with slave_id | `<move_task task_id="a1" slave_id="s1"/>` |
| BUILD-TASK-024 | start_task | `<start_task task_id="a1"/>` |
| BUILD-TASK-025 | resume_task | `<resume_task task_id="a1"/>` |
| BUILD-TASK-026 | stop_task | `<stop_task task_id="a1"/>` |

#### Required Argument Validation

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| BUILD-TASK-030 | clone_task(None) | `RequiredArgument` error |
| BUILD-TASK-031 | clone_task("") | `RequiredArgument` error |
| BUILD-TASK-032 | create_task missing name | `RequiredArgument` error |
| BUILD-TASK-033 | create_task missing config_id | `RequiredArgument` error |
| BUILD-TASK-034 | create_task missing target_id | `RequiredArgument` error |
| BUILD-TASK-035 | create_task missing scanner_id | `RequiredArgument` error |
| BUILD-TASK-036 | create_task with target_id="0" | `InvalidArgument` error (use create_container_task) |
| BUILD-TASK-037 | create_task negative schedule_periods | `InvalidArgument` error |
| BUILD-TASK-038 | delete_task(None) | `RequiredArgument` error |
| BUILD-TASK-039 | get_task(None) | `RequiredArgument` error |
| BUILD-TASK-040 | modify_task(None) | `RequiredArgument` error |
| BUILD-TASK-041 | start_task(None) | `RequiredArgument` error |

### 4.3 Command Builder — All Resource Types

Each resource type follows the same test pattern as Tasks above. Below is the test matrix — each cell is a group of tests following the BUILD-TASK pattern.

| Resource | Create | Get One | Get List | Modify | Delete | Clone | Actions | Validation |
|----------|--------|---------|----------|--------|--------|-------|---------|------------|
| Tasks | 7 | 1 | 7 | 4 | 2 | 1 | 4 (start/stop/resume/move) | 12 |
| Targets | 4 | 1 | 4 | 3 | 2 | 1 | — | 8 |
| Configs | 4 | 1 | 4 | 3 | 2 | 1 | — | 6 |
| Scanners | 3 | 1 | 4 | 3 | 2 | 1 | 1 (verify) | 6 |
| Alerts | 5 | 1 | 4 | 4 | 2 | 1 | 1 (test) | 8 |
| Credentials | 6 | 1 | 4 | 5 | 2 | 1 | — | 10 |
| Filters | 3 | 1 | 4 | 2 | 2 | 1 | — | 6 |
| Groups | 3 | 1 | 4 | 2 | 2 | 1 | — | 6 |
| Notes | 4 | 1 | 4 | 3 | 2 | 1 | — | 8 |
| Overrides | 4 | 1 | 4 | 3 | 2 | 1 | — | 8 |
| Permissions | 3 | 1 | 4 | 3 | 2 | 1 | — | 6 |
| Port Lists | 4 | 1 | 4 | 2 | 2 | 1 | — | 6 |
| Port Ranges | 2 | — | — | — | 1 | — | — | 4 |
| Reports | 2 | 1 | 4 | — | 1 | — | — | 4 |
| Report Formats | 3 | 1 | 4 | 2 | 2 | — | 1 (verify) | 6 |
| Roles | 3 | 1 | 4 | 2 | 2 | 1 | — | 6 |
| Schedules | 3 | 1 | 4 | 3 | 2 | 1 | — | 6 |
| Tags | 4 | 1 | 4 | 3 | 2 | 1 | — | 8 |
| Tickets | 3 | 1 | 4 | 2 | 2 | 1 | — | 6 |
| TLS Certificates | 3 | 1 | 4 | 2 | 2 | — | — | 6 |
| Users | 4 | 1 | 4 | 3 | 2 | 1 | — | 8 |
| Assets | 2 | 1 | 4 | 1 | 2 | — | — | 4 |

**Plus standalone commands:**

| Command | Tests |
|---------|-------|
| get_version | 1 (BUILD-VER-001) |
| help | 2 (default format + specific format) |
| get_aggregates | 4 (various type/group/sort combinations) |
| get_feeds | 2 (all + specific type) |
| get_info | 3 (by type, with filter, specific ID) |
| get_nvts | 3 (all, with details, specific) |
| get_nvt_families | 1 |
| get_preferences | 2 (all + specific) |
| get_resource_names | 3 (by type, with filter, specific) |
| get_results | 3 (all, with filter, specific) |
| get_settings | 2 (all + specific) |
| get_system_reports | 2 (all + specific) |
| get_vulns | 2 (all + with filter) |
| get_license | 1 |
| describe_auth | 1 |
| modify_auth | 2 |
| modify_license | 1 |
| modify_setting | 2 |
| empty_trashcan | 1 |
| restore | 2 (valid + missing ID) |
| run_wizard | 2 |
| sync_config | 1 |

**Estimated total command builder tests: ~450**

---

## 5. `gvm-gmp` — Response Parsing Tests

These tests verify that `Response` objects are correctly parsed from GMP XML returned by the mock server.

### 5.1 Response Basics

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| RESP-001 | Parse status code | `status="200"` → `response.status_code() == Some(200)` |
| RESP-002 | Parse status 201 | Created → `Some(201)` |
| RESP-003 | Parse status 400 | Bad request → `Some(400)` |
| RESP-004 | Parse status 401 | Unauthorized → `Some(401)` |
| RESP-005 | Parse status 404 | Not found → `Some(404)` |
| RESP-006 | Parse status 500 | Server error → `Some(500)` |
| RESP-007 | is_success for 2xx | 200, 201, 202 → `true` |
| RESP-008 | is_success for non-2xx | 400, 401, 404, 500 → `false` |
| RESP-009 | raise_for_status on success | 200 → returns `Ok(&self)` |
| RESP-010 | raise_for_status on error | 400 → returns `Err(StatusError)` |
| RESP-011 | StatusError contains response | Error has `.response` and `.request` |
| RESP-012 | data() returns raw bytes | Byte-for-byte match of received data |
| RESP-013 | xml() parses to element | Valid XML → `Ok(XmlElement)` |
| RESP-014 | xml() on invalid data | Corrupted bytes → `Err(XmlParse)` |
| RESP-015 | Missing status attribute | Response without `status` → `status_code() == None` |

### 5.2 Typed Response Parsing (Phase 2+)

When typed response structs are implemented, each type needs:

| Test ID Pattern | Test Case | Expected |
|----------------|-----------|----------|
| TRESP-{type}-001 | Parse from realistic fixture XML | All fields populated correctly |
| TRESP-{type}-002 | Parse from minimal XML | Required fields present, optional fields are None |
| TRESP-{type}-003 | Missing required field | Parse error, not panic |
| TRESP-{type}-004 | Unknown extra elements ignored | Forward-compatible parsing |
| TRESP-{type}-005 | Unicode in text fields | Correctly decoded |

**Types to test:** Task, Target, Config, Scanner, Alert, Credential, Filter, Group, Note, Override, Permission, PortList, Report, ReportFormat, Role, Schedule, Tag, Ticket, TlsCertificate, User, Result, Nvt, Feed

Estimated: ~115 typed response tests (5 per type × 23 types)

---

## 6. `gvm-client` — High-Level Client Tests

All tests in this section run against the mock server.

### 6.1 Version Negotiation

| Test ID | Test Case | Mock Config | Expected |
|---------|-----------|-------------|----------|
| CLIENT-VER-001 | Negotiate v22.4 | Mock returns `<version>22.4</version>` | `GmpVersioned::V224` |
| CLIENT-VER-002 | Negotiate v22.5 | Mock returns 22.5 | `GmpVersioned::V225` |
| CLIENT-VER-003 | Negotiate v22.6 | Mock returns 22.6 | `GmpVersioned::V226` |
| CLIENT-VER-004 | Negotiate v22.7 | Mock returns 22.7 | `GmpVersioned::V227` |
| CLIENT-VER-005 | Negotiate v22.8+ | Mock returns 22.8 | `GmpVersioned::Next` |
| CLIENT-VER-006 | Unsupported version | Mock returns 21.0 | `GvmError::UnsupportedVersion` |
| CLIENT-VER-007 | Malformed version response | Mock returns garbage | `GvmError` |
| CLIENT-VER-008 | Version with extra minor | Mock returns 22.9 | `GmpVersioned::Next` with warning |
| CLIENT-VER-009 | version() accessor | After connect | Returns correct `GmpVersion` tuple |

### 6.2 Connection Lifecycle

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CLIENT-CONN-001 | Connect establishes connection | `GmpVersioned::connect()` succeeds |
| CLIENT-CONN-002 | Auto-authentication | After connect, can send commands |
| CLIENT-CONN-003 | Disconnect closes cleanly | `disconnect()` succeeds, server sees close |
| CLIENT-CONN-004 | Double connect is idempotent | `connect(); connect();` → no error |
| CLIENT-CONN-005 | Send after disconnect → error | `disconnect(); send(...)` → error |
| CLIENT-CONN-006 | Context manager pattern | `{ let client = connect(); ... } // auto-disconnect on drop` |
| CLIENT-CONN-007 | Connect to unreachable server | Timeout or connection refused → `GvmError::Connection` |
| CLIENT-CONN-008 | Reconnect after server restart | Server stops and restarts → client reconnects |

### 6.3 Send & Call

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| CLIENT-SEND-001 | send() returns raw Response | Response with data bytes |
| CLIENT-SEND-002 | call() returns parsed XML | XmlElement with status checked |
| CLIENT-SEND-003 | call() on error status | Server returns 404 → `GvmError::Server` |
| CLIENT-SEND-004 | send() preserves full response | Large response data not truncated |
| CLIENT-SEND-005 | Sequential commands work | get_version → get_tasks → get_targets → all succeed |
| CLIENT-SEND-006 | 100 commands in sequence | No connection degradation |

### 6.4 Authentication

| Test ID | Test Case | Mock Config | Expected |
|---------|-----------|-------------|----------|
| CLIENT-AUTH-001 | Auto-auth on connect | Stateful mock | Client is authenticated after `connect()` |
| CLIENT-AUTH-002 | Auth with custom credentials | Custom user/pass mock | Succeeds when matching |
| CLIENT-AUTH-003 | Auth failure | Wrong credentials mock | `GvmError` during connect |
| CLIENT-AUTH-004 | Auth status in response | Successful auth → role and timezone available |

### 6.5 CRUD Round-Trips (Against Stateful Mock)

These test the full flow: build request → send → receive → parse response.

#### Tasks

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| RT-TASK-001 | Create task → returns UUID | UUID is valid, non-empty |
| RT-TASK-002 | Create task → get by UUID | Returned task has same name, config, target |
| RT-TASK-003 | Create task → list includes it | `get_tasks()` includes the created task |
| RT-TASK-004 | Create → modify → get | Modified fields reflected |
| RT-TASK-005 | Create → delete → get → 404 | Deleted task not retrievable |
| RT-TASK-006 | Create → clone → get both | Both exist with different UUIDs |
| RT-TASK-007 | Start task → get status | Status is "Running" or "Requested" |
| RT-TASK-008 | Start → stop → get status | Status is "Stopped" |
| RT-TASK-009 | Start → stop → resume | Status returns to "Running" |
| RT-TASK-010 | Empty task list | No tasks → count 0, no crash |

#### Other Resources (Pattern)

Each resource type follows RT-TASK pattern with relevant variations:

| Resource | Create → Get | Create → List | Modify → Get | Delete → 404 | Clone |
|----------|-------------|---------------|-------------|---------------|-------|
| Targets | RT-TG-001 | RT-TG-002 | RT-TG-003 | RT-TG-004 | RT-TG-005 |
| Configs | RT-C-001 | RT-C-002 | RT-C-003 | RT-C-004 | RT-C-005 |
| Scanners | RT-SC-001 | RT-SC-002 | RT-SC-003 | RT-SC-004 | RT-SC-005 |
| Alerts | RT-A-001 | RT-A-002 | RT-A-003 | RT-A-004 | RT-A-005 |
| Credentials | RT-CR-001 | RT-CR-002 | RT-CR-003 | RT-CR-004 | RT-CR-005 |
| Filters | RT-F-001 | RT-F-002 | RT-F-003 | RT-F-004 | RT-F-005 |
| Notes | RT-N-001 | RT-N-002 | RT-N-003 | RT-N-004 | RT-N-005 |
| Overrides | RT-O-001 | RT-O-002 | RT-O-003 | RT-O-004 | RT-O-005 |
| Schedules | RT-S-001 | RT-S-002 | RT-S-003 | RT-S-004 | RT-S-005 |
| Tags | RT-TAG-001 | RT-TAG-002 | RT-TAG-003 | RT-TAG-004 | RT-TAG-005 |
| Tickets | RT-TK-001 | RT-TK-002 | RT-TK-003 | RT-TK-004 | RT-TK-005 |
| Users | RT-U-001 | RT-U-002 | RT-U-003 | RT-U-004 | RT-U-005 |

**Estimated CRUD round-trip tests: ~70**

---

## 7. Error Handling Tests (Against Mock with Fault Injection)

| Test ID | Test Case | Mock Fault | Expected Client Behavior |
|---------|-----------|-----------|--------------------------|
| ERR-CLIENT-001 | Server returns 400 | `override_response("get_tasks", error(400))` | `GvmError::Server { status: 400 }` |
| ERR-CLIENT-002 | Server returns 401 | Stateful, no auth | `GvmError::Server { status: 401 }` |
| ERR-CLIENT-003 | Server returns 404 | Get nonexistent resource | `GvmError::Server { status: 404 }` |
| ERR-CLIENT-004 | Server returns 409 | Delete resource in use | `GvmError::Server { status: 409 }` |
| ERR-CLIENT-005 | Server returns 500 | Injected ServerError500 | `GvmError::Server { status: 500 }` |
| ERR-CLIENT-006 | Connection dropped | Injected Disconnect | `GvmError::Connection` |
| ERR-CLIENT-007 | Response timeout | Injected Delay > client timeout | `GvmError::Timeout` |
| ERR-CLIENT-008 | Malformed XML response | Injected MalformedXml | `GvmError::XmlParse` |
| ERR-CLIENT-009 | Truncated response | Injected TruncatedResponse | `GvmError::XmlParse` or `Connection` |
| ERR-CLIENT-010 | Auth failure recovery | Bad credentials → fix → retry | Second attempt succeeds |
| ERR-CLIENT-011 | Error doesn't poison client | One 500 → next command still works |
| ERR-CLIENT-012 | RequiredArgument before send | Missing required arg → error without network call |
| ERR-CLIENT-013 | InvalidArgument before send | Invalid enum value → error without network call |

---

## 8. Version-Specific Feature Tests

| Test ID | Test Case | Version | Expected |
|---------|-----------|---------|----------|
| VFEAT-001 | get_resource_names with ResourceType | V22_5 | Compiles and works |
| VFEAT-002 | get_resource_names not on V22_4 | V22_4 | Method not available (compile-time) |
| VFEAT-003 | Report configs CRUD | V22_6 | All operations work |
| VFEAT-004 | Report configs not on V22_5 | V22_5 | Methods not available |
| VFEAT-005 | Modified scanners | V22_7 | Version-specific scanner fields |
| VFEAT-006 | Agent commands | Next | Agents, AgentGroups, etc. available |
| VFEAT-007 | Agent commands not on V22_7 | V22_7 | Methods not available |
| VFEAT-008 | Version downgrades cleanly | V22_4 mock | Only V22_4 features accessible |

---

## 9. python-gvm Compatibility Tests

These tests verify that rust-gvm produces **byte-identical XML** to python-gvm for the same inputs. This is the gold standard for correctness.

### 9.1 Methodology

1. For each python-gvm test case that asserts `self.connection.send.has_been_called_with(b'...')`, extract the expected bytes
2. Build the same command in rust-gvm
3. Assert byte equality

### 9.2 Test Generation

```rust
/// Macro to generate compatibility tests from python-gvm expectations
macro_rules! compat_test {
    ($name:ident, $rust_expr:expr, $expected_bytes:expr) => {
        #[test]
        fn $name() {
            let request = $rust_expr;
            assert_eq!(request.to_bytes(), $expected_bytes);
        }
    };
}

compat_test!(
    compat_get_tasks_simple,
    Tasks::get_tasks(Default::default()),
    b"<get_tasks usage_type=\"scan\"/>"
);

compat_test!(
    compat_create_task,
    Tasks::create_task("foo", &id("c1"), &id("t1"), &id("s1"), Default::default()),
    b"<create_task><name>foo</name><usage_type>scan</usage_type><config id=\"c1\"/><target id=\"t1\"/><scanner id=\"s1\"/></create_task>"
);
```

### 9.3 Coverage

Port **every** `has_been_called_with` assertion from python-gvm's test suite. Based on the python-gvm test files analyzed:

- `tests/protocols/gmpv224/entities/` — ~40 test files, ~400 test methods
- Version overlays (v225, v226, v227, next) — ~50 additional tests

**Target: ~450 compatibility tests** matching python-gvm byte-for-byte.

---

## 10. Sync Wrapper Tests

| Test ID | Test Case | Expected |
|---------|-----------|----------|
| SYNC-001 | Sync connect works | `block_on(connect())` succeeds |
| SYNC-002 | Sync send/receive | Full command round-trip in sync mode |
| SYNC-003 | Sync CRUD round-trip | Create → get → verify in sync |
| SYNC-004 | Sync error handling | Server error → proper Rust error type |
| SYNC-005 | Sync with Unix socket | Sync wrapper over Unix connection |
| SYNC-006 | Sync with TLS | Sync wrapper over TLS connection |
| SYNC-007 | No tokio runtime required | Sync API creates its own runtime internally |

---

## 11. Property-Based Tests

Using `proptest` or `quickcheck`:

| Test ID | Test Case | Property |
|---------|-----------|----------|
| PROP-001 | XmlCommand round-trip | Any command → `to_bytes()` → parse XML → same structure |
| PROP-002 | EntityId validation | Random strings → either valid UUID or error, never panic |
| PROP-003 | Enum conversion round-trip | Any variant → `.value()` → `from_str()` → same variant |
| PROP-004 | Response status parsing | Any u16 → `status_code()` never panics |
| PROP-005 | XmlReader never panics | Arbitrary bytes → `feed_xml()` → either Ok or error, no panic |
| PROP-006 | Connection state machine | Random send/receive/close sequences → never panics, always valid state |
| PROP-007 | Large random XML | 10MB random valid XML → XmlReader detects end correctly |

---

## 12. Test Organization

```
rust-gvm/
├── crates/
│   ├── gvm-protocol/
│   │   └── tests/
│   │       ├── state_machine.rs        # PROTO-* tests
│   │       ├── xml_reader.rs           # XMLR-* tests
│   │       └── xml_command.rs          # CMD-* tests
│   ├── gvm-connection/
│   │   └── tests/
│   │       ├── unix.rs                 # UNIX-* tests
│   │       ├── tls.rs                  # TLS-* tests (feature-gated)
│   │       └── ssh.rs                  # SSH-* tests (feature-gated)
│   ├── gvm-gmp/
│   │   └── tests/
│   │       ├── types.rs                # TYPE-* tests
│   │       ├── enums.rs                # ENUM-* tests
│   │       ├── builders/               # BUILD-* tests (one file per resource type)
│   │       │   ├── tasks.rs
│   │       │   ├── targets.rs
│   │       │   ├── configs.rs
│   │       │   ├── ...
│   │       │   └── standalone.rs       # Non-CRUD commands
│   │       ├── responses.rs            # RESP-* tests
│   │       ├── typed_responses/        # TRESP-* tests (one file per type)
│   │       └── compat/                 # python-gvm compatibility tests
│   │           ├── v224.rs
│   │           ├── v225.rs
│   │           ├── v226.rs
│   │           ├── v227.rs
│   │           └── next.rs
│   └── gvm-client/
│       └── tests/
│           ├── version_negotiation.rs  # CLIENT-VER-* tests
│           ├── connection.rs           # CLIENT-CONN-* tests
│           ├── auth.rs                 # CLIENT-AUTH-* tests
│           ├── round_trips/            # RT-* tests (one file per resource type)
│           │   ├── tasks.rs
│           │   ├── targets.rs
│           │   └── ...
│           ├── error_handling.rs       # ERR-CLIENT-* tests
│           ├── version_features.rs     # VFEAT-* tests
│           ├── sync_wrapper.rs         # SYNC-* tests
│           └── properties.rs           # PROP-* tests
└── tests/
    └── integration/
        └── full_workflow.rs            # End-to-end multi-step scenarios
```

---

## 13. CI Configuration

```yaml
# Unit tests — every commit
test-unit:
  steps:
    - cargo test -p gvm-protocol
    - cargo test -p gvm-gmp

# Integration tests — every PR
test-integration:
  steps:
    - cargo test -p gvm-connection --features integration
    - cargo test -p gvm-client --features integration

# Compatibility tests — every PR
test-compat:
  steps:
    - cargo test -p gvm-gmp --features compat

# Full suite — release
test-release:
  steps:
    - cargo test --workspace --features integration,compat,stress
```

---

## 14. Coverage Targets

| Crate | Line Coverage | Branch Coverage | Measured By |
|-------|-------------|-----------------|-------------|
| gvm-protocol | 95% | 90% | State machine + XML reader |
| gvm-connection | 85% | 80% | Transport tests (some paths need real servers) |
| gvm-gmp | 95% | 95% | Builder output + response parsing |
| gvm-client | 90% | 85% | Round-trip + error handling |

---

## 15. Test Count Summary

| Category | Estimated Tests |
|----------|----------------|
| Protocol state machine (PROTO) | 13 |
| XML reader (XMLR) | 10 |
| XML command builder (CMD) | 12 |
| Connection transports (UNIX/TLS/SSH/TRAIT) | 23 |
| Type safety (TYPE) | 5 |
| Enum tests (ENUM) | 88 |
| Command builder output (BUILD) | ~450 |
| Response parsing (RESP) | 15 |
| Typed responses (TRESP) | ~115 |
| Client version negotiation (CLIENT-VER) | 9 |
| Client connection (CLIENT-CONN) | 8 |
| Client auth (CLIENT-AUTH) | 4 |
| Client send/call (CLIENT-SEND) | 6 |
| CRUD round-trips (RT) | ~70 |
| Error handling (ERR-CLIENT) | 13 |
| Version features (VFEAT) | 8 |
| python-gvm compatibility (compat) | ~450 |
| Sync wrapper (SYNC) | 7 |
| Property-based (PROP) | 7 |
| **Total** | **~1,300** |
