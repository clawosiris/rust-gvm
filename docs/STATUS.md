# Implementation Status

Last updated: 2026-08-31

## Support Direction

rust-gvm is intended to track current GMP/GVMD behavior directly. python-gvm compatibility remains useful for migration, interoperability, and validation, but it is a secondary target rather than the project's product boundary.

See [ROADMAP.md](ROADMAP.md) for the version support stance, compatibility policy, known coverage gaps, and follow-up work.

## Crate Status

The `next` Technology Preview lane now includes the first statically associated
typed-execution slice. `GmpRequest` binds a semantic request to one
`GmpResponse`, and `GmpClient::execute` preserves existing command gates,
redacted tracing, parsing, and compatibility APIs. Version/authentication,
target list/get/create/modify/delete, and asynchronous report export prove the
contract before family-by-family migration. See
[ADR 0001](adr/0001-typed-request-response-execution.md) and the
[typed-execution guide](typed-execution.md).

| Crate | Status | Lines | Tests | Description |
|-------|--------|-------|-------|-------------|
| `gvm-protocol` | ✅ Implemented | ~2,330 | 67 | XML command builder, response parser, streaming reader |
| `gvm-mock-server` | ✅ Implemented | ~5,850 | 266 | Programmable mock GMP server |
| `gvm-connection` | ✅ Implemented | ~1,500 | 45+ | Async Unix socket, verified TLS/mTLS, and SSH transports |
| `gvm-gmp` | ✅ Implemented | ~19,800 | 838 | Typed GMP command builders and response models |
| `gvm-client` | ✅ Implemented | ~3,590 | 62 | High-level async client with version negotiation and typed methods |

**Total: ~32,640 lines of Rust, 1,278 tests**

Schedule create/modify supports typed first-run input and once, hourly, daily,
weekly, and yearly recurrence. Schedule observations expose normalized typed
first-run/next-run timestamps reported by gvmd and distinguish floating or
`TZID`-qualified starts, recurrence dates, exclusions, and unsupported recurrence
rules from one-time schedules; raw iCalendar remains available for compatibility.
Raw create follows gvmd's default-timezone behavior, and raw modify requires an
iCalendar payload.

Target create and modify inputs use validated `TargetHost` values inside a
non-empty `TargetHosts` aggregate. The aggregate de-duplicates canonical values
across alternate address/network/range spellings and makes included/excluded
modify updates atomic. It can test whether exclusions cover every included
specification without expanding networks, using gvmd's usable-address treatment
for CIDRs; trailing-dot hostnames remain distinct from undotted hostnames.
IPv4 and IPv6 addresses, CIDR networks, address ranges, and ASCII hostnames are
rejected locally when malformed; IPv4 leading zeroes are normalized like gvmd,
and CIDR prefixes follow gvmd's `/1` through `/30` restriction. Unicode hostname
case-fold lookalikes are intentionally outside the typed API's accepted hostname
policy. DNS resolution and deployment policy, including gvmd's configured maximum
IP count, remain server-side. Typed creation models manual hosts; the stateful raw
mock also resolves gvmd-style `asset_hosts` filters, with filter precedence over a
supplied manual host list.
The same strict filter evaluator drives `get_assets` and target resolution,
including quoted values, relations, sorting, and pagination. Raw mock target
storage applies gvmd-style trimming, separator cleanup, and exact textual
de-duplication without rewriting otherwise valid host spellings.

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
| Exact frame boundaries | ✅ | Preserve coalesced bytes for the next response |
| Input size limit | ✅ | 64 MiB per frame by default; configurable |
| Nesting limit | ✅ | 256 elements per frame by default; configurable |
| Strict XML 1.0 checks | ✅ | Reject malformed declarations, names, references, and forbidden literals |
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
| Version configuration | ✅ | Defaults to `V22_7`; explicit 22.4–22.8 emulation remains available |
| Unix socket (path) | ✅ | `.unix_socket("/tmp/gvmd.sock")` |
| Unix socket (auto temp) | ✅ | `.unix_socket_auto()` |
| TCP listener | ✅ | `.tcp("127.0.0.1:9390")` |
| TLS listener | ✅ | `.tls("127.0.0.1:9390")`; generated certificate exposed for pinning |
| Mutual TLS | ✅ | `.require_client_cert("client-ca.pem")` |
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
| direct-host asset lifecycle and canonical `get_assets` | ✅ | Strict gvmd behavior by default; legacy flat inputs are explicit opt-in; report-import/bulk-delete paths are not modeled |
| get_report (nested results XML) | ✅ | Proper `<report><report><results>` nesting |
| structured audit reports (22.7+) | ✅ | Typed summaries and hosts with compliance filtering, pagination, details, and lean output |
| create_note/override (text + nvt_oid) | ✅ | Non-standard element parsing |
| create_ticket (result_id + comment) | ✅ | Non-standard element parsing |
| modify_ticket (status attribute) | ✅ | Ticket-specific handling |
| Trash/restore/empty_trashcan | ✅ | Full trashcan lifecycle |
| Task schedule relationships | ✅ | Stateful create/get persistence, schedule-period round trips, omit/set/clear modify semantics, reference validation, and dependency-safe deletion |

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
| System | get_version, authenticate, help, get_timezones |
| Tasks | get_tasks, create_task, modify_task, delete_task, start_task, stop_task |
| Targets | get_targets |
| Reports | get_reports (with nested results), get_report_vulns, get_report_tls_certificates, get_report_errors, get_report_closed_cves |
| Configs | get_scan_configs |
| Scanners | get_scanners |
| Alerts | get_alerts |
| Credentials | get_credentials, get_credential_stores |
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

### Version Gating

| Feature | Status | Notes |
|---------|--------|-------|
| Version-specific command rejection | ✅ | Returns 400 for commands unavailable in configured version |
| `report_config` commands (22.6+) | ✅ | create, get, modify, delete |
| `features` command (22.6+) | ✅ | get_features |
| structured audit-report commands (22.7+) | ✅ | get_audit_report and get_audit_report_hosts |
| REST-support GMP helpers (22.8+) | ✅ | raw structured scan report, report drill-downs, get_timezones, get_credential_stores |
| Version range metadata in responses | ✅ | Status text includes version requirement |

### CLI (Standalone Binary)

| Feature | Status |
|---------|--------|
| `--mode echo\|fixture\|stateful` | ✅ |
| `--version 22.4\|22.5\|22.6\|22.7\|22.8` | ✅ (22.7 default) |
| `--socket <path>` | ✅ |
| `--tcp <addr:port>` | ✅ |
| `--max-request-bytes <bytes>` | ✅ (64 MiB default) |
| XML nesting limit | ✅ (256 elements per frame; enforced across protocol, client, and mock readers) |
| `--tls <addr:port>` | ✅ (`tls` feature) |
| `--tls-client-ca <path>` | ✅ (`tls` feature) |
| `--tls-cert-out <path>` | ✅ (`tls` feature) |
| Cross-platform binaries | ✅ (5 targets in CI) |
| GHCR release image | ✅ `ghcr.io/clawosiris/gvm-mock-server:<tag>` |

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
| SSH tunnel | ✅ | `ssh` | `SshConnection` via `russh` — `direct-streamlocal` to remote gvmd socket |
| TLS (TCP) | ✅ | `tls` | `TlsConnection` via `tokio-rustls`, verified server SAN/roots, optional client identity |

### UnixSocketConfig

| Field | Default | Notes |
|-------|---------|-------|
| `path` | `/run/gvmd/gvmd.sock` | Configurable |
| `timeout` | 60s | Connect, request write/flush, and response-read timeout |
| `read_buffer_size` | 64 KB | Per-read allocation |

### SshConfig

| Field | Default | Notes |
|-------|---------|-------|
| `hostname` | `localhost` | SSH server address |
| `port` | 22 | SSH port |
| `username` | `root` | SSH user |
| `auth` | `Agent` | `Password`, `PrivateKey { key_path, passphrase }`, or `Agent` |
| `remote_socket` | `/run/gvmd/gvmd.sock` | Path to gvmd socket on remote host |
| `timeout` | 60s | Connect/auth/channel, request write/flush, and response-read timeout |
| `read_buffer_size` | 64 KB | Per-read allocation |
| `host_key_policy` | `KnownHosts` | Standard or custom `known_hosts`, pinned SHA-256 fingerprint, or explicit insecure opt-out |

### TlsConfig

| Field | Default | Notes |
|-------|---------|-------|
| `hostname` | `127.0.0.1` | TCP destination |
| `port` | 9390 | gvmd TLS port |
| `server_name` | Same as hostname | Required DNS/IP certificate SAN |
| `use_native_roots` | `true` | Platform trust store; disabling does not disable verification |
| custom roots | None | PEM roots can be supplied in memory or from a file |
| client identity | None | Optional PEM certificate chain plus unencrypted private key for mTLS |
| `timeout` | 60s | TCP connect, TLS handshake, request write/flush, and response-read timeout |
| `max_response_bytes` | 64 MiB | Bounded XML response size |

### Error Types

| Variant | Description |
|---------|-------------|
| `NotConnected` | Operation requires active connection |
| `AlreadyConnected` | Double-connect attempt |
| `ConnectFailed` | Transport-level connection error |
| `SendFailed` | Write error |
| `ReadFailed` | Read error or unexpected EOF |
| `Timeout` | Operation exceeded configured timeout |
| `InvalidConfiguration` | Trust roots, server name, or certificate/key material is unusable |
| `SocketNotFound` | Unix socket path does not exist |

### Integration Tests (against gvm-mock-server)

| Test | Status |
|------|--------|
| Connect + get_version | ✅ |
| Auth + create_target | ✅ |
| Reconnect flow (python-gvm pattern) | ✅ |
| Timeout invalidation and clean reconnect | ✅ |
| Not-connected error paths | ✅ |
| Double-connect error | ✅ |

Once an active transport returns a send or read error, it is invalidated. Callers
must reconnect before issuing another request; this prevents partial writes or
late responses from being associated with a later GMP command.

## gvm-gmp

Typed GMP command builders covering all entity types, system commands, and enums. Full rustdoc coverage.

### Target Port-List Updates

`ModifyTargetOpts::port_list_id` models omission and replacement with
`ScalarUpdate<EntityId>`. Current gvmd accepts a real port-list UUID when
replacing the relationship, but it does not define a sentinel or other wire
representation for detaching an existing port list. Consequently,
`ScalarUpdate::Clear` is rejected locally with
`ModifyTargetError::UnsupportedPortListClear`; no GMP request is sent.

`CreateTargetOpts` requires a `TargetPortSelection`, enforcing a typed one-of
choice between an existing `<port_list>` and a validated direct `<port_range>`.
Raw GMP also permits both, with gvmd validating the range before giving the port
list precedence. Direct ranges support gvmd's implicit TCP and protocol
carry-forward grammar, and validate the `1..=65535` port domain and ascending
range bounds before canonical serialization.

### Target Credential Service Ports

`CreateTargetOpts` and `ModifyTargetOpts` expose the SSH service port next to
the credential relationship. `ServicePort` validates the gvmd-supported
range `1..=65535`; typed target observations reject zero, nonnumeric, and
out-of-range backend values instead of losing malformed data. Both list and
single-target client reads preserve effective default and custom ports.

This is an intentional pre-1.0 API break: create ports use
`Option<ServicePort>`, modify ports use `ScalarUpdate<ServicePort>`, and the
low-level `create_target` builder now returns `Result` so a port without an SSH
credential ID fails explicitly. The high-level client exposes the same failure
as `GvmError::CreateTarget` before any request is sent.

Modify requests distinguish leaving the binding untouched, setting or replacing
the port, resetting it to gvmd's default port 22, and detaching the credential.
The reset operation keeps gvmd's numeric sentinel internal to the command
builder. The stateful mock mirrors these defaults and round trips SSH and SMB
credential identifiers, but rejects SMB service ports because current GMP/gvmd
only defines a nested port for the SSH credential. It also rejects create-time
detach sentinels and credential types that gvmd does not allow for SSH or SMB
target bindings.

The stateful mock also preserves target alive-test values. Stateful responses
and create/modify requests use gvmd's plural `alive_tests` field. The typed
request option remains named `alive_test` for source compatibility. Target
responses without an explicit alive-test value report `Scan Config Default`,
matching gvmd's observation behavior.

### Command Modules (29)

alerts, authentication, credentials, filters, groups, hosts, notes, nvts, overrides, permissions, port_lists, report_formats, reports, resource_names, results, roles, scan_configs, scanners, schedules, system, tags, targets, tasks, tickets, tls_certificates, trashcan, users, version

### Enums (23)

AlertEvent, AlertCondition, AlertMethod, AliveTest, AggregateStatistic, CredentialFormat, CredentialType, EntityType (34 variants), FeedType, FilterType (25 variants), HelpFormat, HostsOrdering, InfoType, PermissionSubjectType, PortRangeType, ReportFormatType, ScannerType, SeverityLevel, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, SortOrder, TicketStatus, UserAuthType

### Tests

`cargo test -p gvm-gmp --all-features -- --list` currently discovers 650 tests.
The categories below are a tracked subset of that complete inventory.

| Tracked category | Count |
|------------------|-------|
| Inline unit tests (command XML) | 80 |
| External command tests | 54 |
| Enum exhaustive tests | 347 |
| EntityId/type tests | 6 |
| **Tracked subset** | **487** |

## gvm-client

High-level async `GmpClient<C>` and `GmpVersioned<C>` that combines `gvm-connection`, `gvm-protocol`, and `gvm-gmp`. Connects, negotiates GMP version (22.4–22.7+), and provides typed `send`/`call` methods.

### GmpClient API

| Method | Description |
|--------|-------------|
| `GmpClient::connect(connection)` | Connect, get_version, negotiate — returns ready client |
| `client.version()` | Returns negotiated `GmpVersion` |
| `client.send(request)` | Send request, return raw `Response` |
| `client.call(request)` | Send request, raise `GvmError::Server` on non-2xx |
| `client.disconnect()` | Graceful transport shutdown |
| `client.connection()` / `connection_mut()` | Borrow underlying transport |
| `client.into_inner()` | Consume client, return transport |

### GmpVersioned API

| Method | Description |
|--------|-------------|
| `GmpVersioned::connect(connection)` | Connect and wrap as version-specific variant |
| `send` / `call` / `disconnect` / `version` | Delegated to inner `GmpClient` |

### Version Negotiation

| Server Version | Client Variant |
|---------------|----------------|
| 22.4 | `GmpVersioned::V224` |
| 22.5 | `GmpVersioned::V225` |
| 22.6 | `GmpVersioned::V226` |
| 22.7 | `GmpVersioned::V227` |
| 22.8+ | `GmpVersioned::Next` |
| < 22.4 | `GvmError::UnsupportedVersion` |

### GvmError

| Variant | Description |
|---------|-------------|
| `Connection(ConnectionError)` | Transport failure (preserves source chain) |
| `Server { status, message }` | Non-2xx GMP response |
| `XmlParse(String)` | Malformed version/response XML |
| `Parse(ParseError)` | Typed response model parsing failure |
| `UnsupportedVersion(major, minor)` | Server GMP version too old |
| `Timeout(Duration)` | Operation timeout |
| `InvalidState(String)` | Client state error |

### Typed Client Methods

Convenience methods on `GmpClient<C>` that combine `send()` + `XxxResponse::from_response()` into a single typed call. Implemented in `crates/gvm-client/src/typed.rs`.

| Domain | Get | Create | Notes |
|--------|-----|--------|-------|
| version | ✅ | — | `get_version()` |
| auth | — | — | `authenticate()` |
| target | ✅ | ✅ | |
| scan_config | ✅ | ✅ | Also: `get_scan_config()`, `modify_scan_config()`, `delete_scan_config()`, `clone_scan_config()`, global `sync_config()`; deprecated `sync_scan_config(id)` remains source-compatible |
| scanner | ✅ | ✅ | Also: `get_scanner()`, `modify_scanner()`, `delete_scanner()`, `verify_scanner()`, `clone_scanner()` |
| port_list | ✅ | ✅ | |
| task | ✅ | ✅ | Also: `start_task()` |
| report | ✅ | — | Also: typed report drill-down helpers for vulns, TLS certificates, errors, closed CVEs |
| result | ✅ | — | |
| feed | ✅ | — | |
| nvt | ✅ | — | Also: `get_nvt_families()` |
| secinfo | ✅ | — | CVE, CPE, CERT-Bund, DFN-CERT |
| alert | ✅ | ✅ | |
| credential | ✅ | ✅ | Also: `get_credential_stores()` |
| filter | ✅ | ✅ | |
| note | ✅ | ✅ | |
| override | ✅ | ✅ | |
| schedule | ✅ | ✅ | |
| tag | ✅ | ✅ | |
| ticket | ✅ | ✅ | |
| user | ✅ | ✅ | |
| group | ✅ | ✅ | |
| role | ✅ | ✅ | |
| permission | ✅ | ✅ | |
| host | ✅ | ✅ | |
| tls_certificate | ✅ | ✅ | |
| report_format | ✅ | ✅ | |
| report_config | ✅ | — | `get_report_configs_parsed()` |
| system | ✅ | — | `get_settings()`, `get_help()`, `describe_auth()`, `get_timezones()` |

### Features

| Feature | Status |
|---------|--------|
| Auto version negotiation | ✅ |
| `GmpVersioned` enum (V224–VNext) | ✅ |
| `GvmError` with server/connection/parse/timeout/unsupported | ✅ |
| Typed convenience methods (50+ methods, all GMP domains) | ✅ |
| Version parsing from XML | ✅ |
| Full CRUD lifecycle tests | ✅ |
| Disconnect + error path tests | ✅ |
| Works with Unix socket transport | ✅ |
| Works with SSH transport | ✅ |
| Works with verified TLS and mTLS transports | ✅ |

---

## Test Coverage

**Line coverage: 92.2%** (via `cargo-llvm-cov`)

| Test Category | Count | Notes |
|---------------|-------|-------|
| Unit tests (protocol) | 37 | XML builder, response parser, reader, request trait |
| Unit tests (mock server) | 73 | Store, parser, fixtures, faults, scenarios, history, version, util |
| Integration tests (mock server) | 137 | All modes, CRUD, lifecycle, faults, MCP compat (feature-gated) |
| Integration tests (connection) | — | Unix socket + SSH + verified TLS/mTLS transport tests (feature-gated) |
| Unit tests (connection) | — | Config, error display, and construction coverage |
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
| Security | ✅ | cargo-audit, cargo-machete |
| Nightly | ✅ | Full CI + 5-target cross-platform builds + SBOM generation + sbomqs quality gate |
| Release | ✅ | Full test → 5-target builds → SBOM + sbomqs → GitHub Release |

## SBOM Quality

SBOMs are generated by `cargo-cyclonedx` (CycloneDX 1.5 JSON + XML) and post-processed via `scripts/sbom_postprocess.py`:
- CC0-1.0 data license in document metadata
- Build lifecycle phase (`build`)
- Supplier hints: workspace crates → `clawosiris`, crates.io deps → `crates.io`

Quality gate: **sbomqs ≥ 7.0** enforced in CI (nightly + release).

## Security

- **SECURITY.md** — vulnerability reporting via GitHub Private Security Advisories
- **cargo-audit** — RustSec advisory database checks (weekly + on push)
- **cargo-deny** — license compliance, bans, source restrictions
- **Dependabot** — automated dependency updates (Cargo, pip, GitHub Actions)
- **cargo-machete** — unused dependency detection
