# rust-gvm — OpenSpec

## 1. Overview

**rust-gvm** is a Rust client library for the **Greenbone Management Protocol (GMP)**, a reimplementation of [python-gvm](https://github.com/greenbone/python-gvm). It provides a type-safe, async-first interface for communicating with Greenbone Vulnerability Manager (gvmd) over Unix sockets, TLS, or SSH.

### Goals

- Full coverage of GMP 22.4–22.8+ commands
- Strong type safety via Rust enums and newtypes
- Sans-I/O protocol core (transport-agnostic)
- Async-first with sync wrapper
- Version negotiation matching python-gvm behavior
- Zero `unsafe` in library code

### Non-Goals

- GUI or CLI (this is a library)
- OSP (Open Scanner Protocol) — separate crate if needed
- HTTP/OpenVAS daemon client — separate crate if needed

### License

AGPL-3.0-or-later (matching the Greenbone ecosystem)

> **Note:** Originally GPL-3.0-or-later; changed to AGPL-3.0-or-later to align with Greenbone's licensing direction. All source files carry SPDX headers:
> ```
> // SPDX-License-Identifier: AGPL-3.0-or-later
> // SPDX-FileCopyrightText: 2026 Greenbone AG
> ```

---

## 2. Architecture

### 2.1 Crate Structure

```
rust-gvm/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── gvm-connection/     # Transport layer (Unix, TLS, SSH)
│   ├── gvm-protocol/       # Sans-I/O protocol core (XML framing, state machine)
│   ├── gvm-gmp/            # GMP command builders + response types
│   └── gvm-client/         # High-level async client (combines all layers)
├── spec/                   # This spec
├── examples/
└── tests/                  # Integration tests
```

**Rationale:** Mirroring python-gvm's separation of connections, protocol core, and GMP commands — but as separate crates for Rust's compilation model and optional dependency trees.

### 2.2 Layer Diagram

```
┌─────────────────────────────────┐
│         gvm-client              │  High-level API, version negotiation
│  GmpClient::connect(conn)       │  Context manager equivalent
├─────────────────────────────────┤
│         gvm-gmp                 │  Command builders (Request → XML bytes)
│  Tasks::create_task(...)        │  Response parsing (XML → typed structs)
│  Enums: AlertEvent, ScannerType │  Per-version modules
├─────────────────────────────────┤
│       gvm-protocol              │  Sans-I/O state machine
│  Connection::send(req) → bytes  │  XmlReader (streaming XML end detection)
│  Connection::receive(data) →    │  State: Initial → AwaitingResponse →
│       Option<Response>          │         ReceivingData → Initial
├─────────────────────────────────┤
│      gvm-connection             │  Transport I/O
│  UnixSocket / Tls / Ssh         │  async read/write + sync wrappers
└─────────────────────────────────┘
```

---

## 3. Crate Specifications

### 3.1 `gvm-connection` — Transport Layer

**Purpose:** Provide async byte-stream connections to gvmd.

#### Trait Definition

```rust
#[async_trait]
pub trait GvmConnection: Send + Sync {
    async fn connect(&mut self) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn read(&mut self) -> Result<Vec<u8>>;
    fn is_connected(&self) -> bool;
}
```

#### Implementations

| Type | Transport | Default Address | Dependencies |
|------|-----------|-----------------|--------------|
| `UnixSocketConnection` | Unix domain socket | `/run/gvmd/gvmd.sock` | `tokio` |
| `TlsConnection` | TLS over TCP | `127.0.0.1:9390` | `tokio`, `tokio-rustls` or `tokio-native-tls` |
| `SshConnection` | SSH tunnel via `direct-streamlocal` | `localhost:22` (user: `root`) | `tokio`, `russh` |

#### Configuration

```rust
pub struct UnixSocketConfig {
    pub path: PathBuf,           // default: /run/gvmd/gvmd.sock
    pub timeout: Duration,       // default: 60s
}

pub struct TlsConfig {
    pub hostname: String,        // default: 127.0.0.1
    pub port: u16,               // default: 9390
    pub certfile: Option<PathBuf>,
    pub cafile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub password: Option<String>,
    pub timeout: Duration,
}

pub struct SshConfig {
    pub hostname: String,        // default: "localhost"
    pub port: u16,               // default: 22
    pub username: String,        // default: "root"
    pub auth: SshAuth,           // default: Agent
    pub remote_socket: String,   // default: "/run/gvmd/gvmd.sock"
    pub timeout: Duration,       // default: 60s
    pub read_buffer_size: usize, // default: 64KB
}

pub enum SshAuth {
    Password(String),
    PrivateKey { key_path: PathBuf, passphrase: Option<String> },
    Agent,
}
```

#### Feature Flags

- `unix` (default) — Unix socket support
- `tls` — TLS support
- `ssh` — SSH support

---

### 3.2 `gvm-protocol` — Sans-I/O Protocol Core

**Purpose:** XML framing state machine, decoupled from I/O. Direct port of python-gvm's `Connection` class.

#### State Machine

```
Initial ──send(req)──→ AwaitingResponse ──receive_data()──→ ReceivingData
   ↑                                                            │
   └──────────────── close() / response complete ───────────────┘
```

States:
- **Initial**: Ready to send a request
- **AwaitingResponse**: Request sent, waiting for first data byte
- **ReceivingData**: Accumulating XML data, streaming through `XmlReader`
- **Error**: Parse failure; must `close()` to reset

#### Core Types

```rust
/// A GMP request that can be serialized to XML bytes
pub trait Request: Send {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A GMP response
pub struct Response {
    data: Vec<u8>,
    // Lazy-parsed XML
}

impl Response {
    pub fn data(&self) -> &[u8];
    pub fn xml(&self) -> Result<XmlElement>;
    pub fn status_code(&self) -> Option<u16>;
    pub fn is_success(&self) -> bool;
    pub fn raise_for_status(&self) -> Result<&Self>;
}

/// Sans-I/O connection (state machine)
pub struct Connection { /* state enum internally */ }

impl Connection {
    pub fn new() -> Self;
    pub fn send(&mut self, request: &dyn Request) -> Result<Vec<u8>>;
    pub fn receive_data(&mut self, data: &[u8]) -> Result<Option<Response>>;
    pub fn close(&mut self);
}
```

#### XML Utilities

- `XmlReader` — streaming XML parser that detects when the root element closes
- `XmlCommand` — builder for GMP XML commands (mirrors python-gvm's `XmlCommand`)

```rust
pub struct XmlCommand { /* element tree */ }

impl XmlCommand {
    pub fn new(name: &str) -> Self;
    pub fn set_attribute(&mut self, key: &str, value: &str) -> &mut Self;
    pub fn add_element(&mut self, name: &str) -> &mut XmlElement;
    pub fn add_element_with_text(&mut self, name: &str, text: &str) -> &mut Self;
    pub fn add_filter(&mut self, filter_string: Option<&str>, filter_id: Option<&str>) -> &mut Self;
}

impl Request for XmlCommand {
    fn to_bytes(&self) -> Vec<u8>;
}
```

**XML crate choice:** `quick-xml` (fast, streaming, no `unsafe`).

---

### 3.3 `gvm-gmp` — GMP Command Builders

**Purpose:** Type-safe command construction and response parsing for each GMP version.

#### Module Layout

```
gvm-gmp/
├── src/
│   ├── lib.rs
│   ├── types.rs          # EntityId, shared newtypes
│   ├── enums.rs          # All GMP enums
│   ├── commands/         # Command builder modules
│   │   ├── mod.rs
│   │   ├── alerts.rs
│   │   ├── audits.rs
│   │   ├── credentials.rs
│   │   ├── filters.rs
│   │   ├── groups.rs
│   │   ├── hosts.rs
│   │   ├── notes.rs
│   │   ├── nvts.rs
│   │   ├── overrides.rs
│   │   ├── permissions.rs
│   │   ├── port_lists.rs
│   │   ├── reports.rs
│   │   ├── report_formats.rs
│   │   ├── resource_names.rs
│   │   ├── results.rs
│   │   ├── roles.rs
│   │   ├── scan_configs.rs
│   │   ├── scanners.rs
│   │   ├── schedules.rs
│   │   ├── tags.rs
│   │   ├── targets.rs
│   │   ├── tasks.rs
│   │   ├── tickets.rs
│   │   ├── tls_certificates.rs
│   │   ├── trashcan.rs
│   │   ├── users.rs
│   │   └── version.rs
│   ├── versions/         # Per-version deltas
│   │   ├── mod.rs
│   │   ├── v22_4.rs      # Base version (re-exports commands/)
│   │   ├── v22_5.rs      # Adds ResourceNames.get_resource_names with ResourceType
│   │   ├── v22_6.rs      # Adds ReportConfigs, modified Filters/Reports
│   │   ├── v22_7.rs      # Modified Scanners
│   │   └── next.rs       # Adds Agents, AgentGroups, CredentialStores, OciImageTargets
│   └── responses/        # Typed response structs (deserialized from XML)
│       ├── mod.rs
│       ├── task.rs
│       ├── target.rs
│       └── ...
```

#### Key Types

```rust
/// Newtype for GMP entity UUIDs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(id: impl Into<String>) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}

/// GMP protocol version tuple
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GmpVersion(pub u16, pub u16);
```

#### Enums (Complete List from python-gvm)

```rust
pub enum AlertEvent { TaskRunStatusChanged, UpdatedSecInfo, NewSecInfo }
pub enum AlertCondition { Always, FilterCountAtLeast, FilterCountChanged, SeverityAtLeast, SeverityChanged }
pub enum AlertMethod { Email, HttpGet, Scp, SendEmail, Smb, Snmp, SourcefireConnector, StartTask, SysLog, TippingPoint, VeriniceCe, VeninceNet, Alemba }
pub enum AliveTest { ScanConfigDefault, IcmpPing, TcpAckServicePing, TcpSynServicePing, ArpPing, IcmpAndTcpAckServicePing, IcmpAndArpPing, TcpAckServiceAndArpPing, IcmpTcpAckServiceAndArpPing, ConsiderAlive }
pub enum AggregateStatistic { Count, CMax, CSum, Max, Mean, Min, Sum, Text, Value, WordCounts }
pub enum CredentialFormat { Exe, Pem, Pgp, Rpm }
pub enum CredentialType { ClientCertificate, PasswordOnly, SnmpV1Or2c, SnmpV3, UsernamePassword, UsernameSshKey }
pub enum EntityType { Alert, Asset, AuditReport, CertBundAdv, Config, Cpe, Credential, Cve, DfnCertAdv, Filter, Group, Host, Note, Nvt, OperatingSystem, Override, Permission, Policy, PortList, Report, ReportConfig, ReportFormat, ResourceName, Result, Role, Scanner, Schedule, Tag, Target, Task, Ticket, TlsCertificate, User, Vulnerability }
pub enum FeedType { Nvt, Cert, Scap, Gvmd }
pub enum FilterType { Alert, Asset, Config, Credential, Filter, Group, Host, Note, Override, Permission, PortList, Report, ReportFormat, Result, Role, Scanner, Schedule, Setting, Tag, Target, Task, Ticket, TlsCertificate, User, Vulnerability }
pub enum HelpFormat { Html, Rnc, Text, Xml }
pub enum HostsOrdering { Sequential, Random, Reverse }
pub enum InfoType { CertBundAdv, Cpe, Cve, DfnCertAdv, Nvt, Ovaldef }
pub enum PermissionSubjectType { Group, Role, User }
pub enum PortRangeType { Tcp, Udp }
pub enum ReportFormatType { Anonymous, Csv, Itg, LaTexPdf, Nbr, Pdf, Svg, TxtReport, Verinice, Xml }
pub enum ScannerType { OpenVasScanner, CveScannerType, GreenBoneSensorType }
pub enum SnmpAuthAlgorithm { Md5, Sha1 }
pub enum SnmpPrivacyAlgorithm { Aes, Des }
pub enum SortOrder { Ascending, Descending }
pub enum SeverityLevel { High, Medium, Low, Log, Alarm }
pub enum TicketStatus { Open, Fixed, Closed }
pub enum UserAuthType { File, LdapConnect, RadiusConnect }
```

#### Command Builder Pattern (Example: Tasks)

```rust
pub struct Tasks;

impl Tasks {
    pub fn clone_task(task_id: &EntityId) -> impl Request;

    pub fn create_container_task(
        name: &str,
        comment: Option<&str>,
    ) -> impl Request;

    pub fn create_task(
        name: &str,
        config_id: &EntityId,
        target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateTaskOpts,
    ) -> impl Request;

    pub fn delete_task(
        task_id: &EntityId,
        ultimate: bool,
    ) -> impl Request;

    pub fn get_tasks(opts: GetTasksOpts) -> impl Request;
    pub fn get_task(task_id: &EntityId) -> impl Request;
    pub fn modify_task(task_id: &EntityId, opts: ModifyTaskOpts) -> impl Request;
    pub fn move_task(task_id: &EntityId, slave_id: Option<&EntityId>) -> impl Request;
    pub fn start_task(task_id: &EntityId) -> impl Request;
    pub fn resume_task(task_id: &EntityId) -> impl Request;
    pub fn stop_task(task_id: &EntityId) -> impl Request;
}

#[derive(Default)]
pub struct CreateTaskOpts {
    pub alterable: Option<bool>,
    pub hosts_ordering: Option<HostsOrdering>,
    pub schedule_id: Option<EntityId>,
    pub alert_ids: Vec<EntityId>,
    pub comment: Option<String>,
    pub schedule_periods: Option<u32>,
    pub observers: Vec<String>,
    pub preferences: HashMap<String, String>,
}

#[derive(Default)]
pub struct GetTasksOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
    pub schedules_only: Option<bool>,
    pub ignore_pagination: Option<bool>,
}
```

#### Full GMP Command Coverage

The following commands map 1:1 from GMP 22.5 (base = v22.4, extended by later versions):

**Authentication:**
- `authenticate(username, password)`

**CRUD Resources** (each has `create_*`, `get_*`/`get_*s`, `modify_*`, `delete_*`):
- Alerts, Assets, Configs (Scan Configs), Credentials, Filters, Groups, Notes, Overrides, Permissions, Port Lists, Port Ranges (create/delete only), Report Formats, Roles, Scanners, Schedules, Tags, Targets, Tasks, Tickets, TLS Certificates, Users

**Reports:**
- `create_report`, `get_reports`, `get_report`, `delete_report`

**Read-Only:**
- `get_aggregates`, `get_feeds`, `get_info`, `get_nvts`, `get_nvt_families`, `get_preferences`, `get_resource_names`, `get_results`, `get_settings`, `get_system_reports`, `get_version`, `get_vulns`, `get_license`

**Actions:**
- `start_task`, `stop_task`, `resume_task`, `move_task`
- `test_alert`, `verify_scanner`, `verify_report_format`
- `run_wizard`, `sync_config`
- `empty_trashcan`, `restore`
- `describe_auth`, `modify_auth`, `modify_license`, `modify_setting`
- `help`

#### Version Deltas

| Version | Additions/Changes |
|---------|-------------------|
| 22.4 | Base — all commands above |
| 22.5 | `ResourceNames` adds `ResourceType` enum with expanded types |
| 22.6 | Adds `ReportConfigs` (create/get/modify/delete), `AuditReports`, modified `Filters` and `Reports` |
| 22.7 | Modified `Scanners` |
| next (22.8+) | Adds `Agents`, `AgentGroups`, `AgentInstallers`, `CredentialStores`, `OciImageTargets`, report drill-down helpers (`get_report_vulns`, `get_report_tls_certificates`, `get_report_errors`, `get_report_closed_cves`), `get_timezones`, modified `Tasks`/`Credentials` |

---

### 3.4 `gvm-client` — High-Level Client

**Purpose:** Async client that combines connection + protocol + commands, with version negotiation.

#### API Design

```rust
pub struct GmpClient<C: GvmConnection> {
    connection: C,
    protocol: Connection,
    version: GmpVersion,
}

impl<C: GvmConnection> GmpClient<C> {
    /// Connect and negotiate GMP version
    pub async fn connect(connection: C) -> Result<Self>;

    /// Get the negotiated protocol version
    pub fn version(&self) -> GmpVersion;

    /// Send a request and get a typed response
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response>;

    /// Send a request, check status, return parsed XML
    pub async fn call<R: Request>(&mut self, request: R) -> Result<XmlElement>;

    pub async fn disconnect(&mut self) -> Result<()>;
}
```

#### Version-Aware API

```rust
/// Type-state pattern for version-specific methods
pub struct Gmp224<C: GvmConnection>(GmpClient<C>);
pub struct Gmp225<C: GvmConnection>(GmpClient<C>);
pub struct Gmp226<C: GvmConnection>(GmpClient<C>);
pub struct Gmp227<C: GvmConnection>(GmpClient<C>);
pub struct GmpNext<C: GvmConnection>(GmpClient<C>);

/// Version negotiation returns an enum
pub enum GmpVersioned<C: GvmConnection> {
    V224(Gmp224<C>),
    V225(Gmp225<C>),
    V226(Gmp226<C>),
    V227(Gmp227<C>),
    Next(GmpNext<C>),
}

impl<C: GvmConnection> GmpVersioned<C> {
    pub async fn connect(connection: C) -> Result<Self>;
}
```

#### Usage Example

```rust
use gvm_client::GmpVersioned;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::tasks::Tasks;

#[tokio::main]
async fn main() -> Result<()> {
    let conn = UnixSocketConnection::default();
    let mut gmp = GmpVersioned::connect(conn).await?;

    // Common operations work on any version via a shared trait
    let response = gmp.call(Tasks::get_tasks(Default::default())).await?;

    // Version-specific:
    match &mut gmp {
        GmpVersioned::V226(client) => {
            // report_configs only available in 22.6+
        }
        _ => {}
    }

    Ok(())
}
```

---

## 4. Error Handling

#### `gvm-client::GvmError` (high-level client)
```rust
#[derive(Debug, thiserror::Error)]
pub enum GvmError {
    #[error("connection error: {0}")]
    Connection(#[source] ConnectionError),

    #[error("XML parse error: {0}")]
    XmlParse(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("server error (status {status}): {message}")]
    Server { status: u16, message: String },

    #[error("unsupported GMP version: {0}.{1}")]
    UnsupportedVersion(u16, u16),

    #[error("timeout after {0:?}")]
    Timeout(Duration),
}
```

#### `gvm-connection::ConnectionError` (transport-level)
```rust
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    NotConnected,
    AlreadyConnected,
    ConnectFailed(#[source] std::io::Error),
    SendFailed(#[source] std::io::Error),
    ReadFailed(#[source] std::io::Error),
    Timeout(Duration),
    SocketNotFound(PathBuf),
}
```

`GvmError::Connection` preserves the full `ConnectionError` source chain. `ConnectionError::Timeout` is automatically promoted to `GvmError::Timeout`.

---

## 5. Dependencies

| Crate | Purpose | Feature-gated |
|-------|---------|---------------|
| `tokio` | Async runtime, Unix sockets, TCP | — |
| `quick-xml` | XML parsing and writing | — |
| `thiserror` | Error derive macros | — |
| `tracing` | Structured logging | — |
| `tokio-rustls` | TLS connections | `tls` |
| `russh` | SSH connections | `ssh` |
| `uuid` | UUID validation for EntityId | — |

Dev dependencies: `tokio-test`, `pretty_assertions`, `rstest`

---

## 6. Testing Strategy

### Unit Tests
- Command builders: verify XML output matches expected GMP XML
- State machine: verify state transitions, error states
- Response parsing: verify typed extraction from XML
- Enum exhaustive tests: every variant tested for `as_gmp_str()`, `FromStr`, and invalid input

### Integration Tests
- Against `gvm-mock-server` (all modes: Echo, Fixture, Stateful, Scenario)
- Feature-gated: `unix-socket-tests` for socket-based tests
- Feature-gated: `ssh` for SSH transport E2E tests
- `gvm-client` integration: version negotiation, CRUD lifecycle, error paths
- `gvm-connection` integration: Unix socket + SSH transport against mock server

### python-gvm Cross-Validation
- CI job runs `python-gvm` against `gvm-mock-server` (standalone binary)
- Full lifecycle: version negotiation → auth → target/task CRUD → notes CRUD → cleanup
- Test harness: `tests/integration/test_python_gvm.py`
- Validates protocol compatibility, not just XML generation

### Property-Based Tests
- Round-trip: `Request → bytes → parse → equivalent structure`
- Fuzz XML reader with arbitrary byte sequences

### Test Coverage
- Line coverage tracked via `cargo-llvm-cov` (target: ≥90%)
- Coverage report: `make coverage`

### Current Test Count: 630+
| Category | Count |
|----------|-------|
| gvm-protocol unit | 38 |
| gvm-mock-server unit | 73 |
| gvm-mock-server integration | 137 |
| gvm-connection unit + integration | 20 |
| gvm-gmp unit (inline) | 80 |
| gvm-gmp external command tests | 53 |
| gvm-gmp enum exhaustive tests | 347 |
| gvm-gmp type tests | 6 |
| gvm-client unit + integration | 13 |
| python-gvm integration | 15 steps |

---

## 7. CI/CD & Build Infrastructure

### CI Workflows (`.github/workflows/`)

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push/PR to main | Format, Clippy, Test (stable + MSRV 1.85), Test (all features), Documentation, Cargo Deny, Coverage, python-gvm integration |
| `nightly.yml` | Daily 04:00 UTC + manual | Full CI + 5-target cross-platform binary builds |
| `release.yml` | `v*` tag push | Test → 5-target builds → SBOM generation → GitHub Release with checksums |

### Cross-Platform Binaries

Built for 5 targets:
- `x86_64-unknown-linux-gnu` (Linux amd64)
- `aarch64-unknown-linux-gnu` (Linux arm64, via `cross`)
- `x86_64-unknown-linux-musl` (Linux amd64 static)
- `x86_64-apple-darwin` (macOS amd64)
- `aarch64-apple-darwin` (macOS arm64)

### SBOM (Software Bill of Materials)

Generated in release and nightly workflows using `cargo-cyclonedx`:
- CycloneDX 1.5 format (JSON + XML) for each workspace crate
- JSON SBOMs are post-processed to add CC0 document data licensing, build lifecycle metadata, and supplier names using deterministic heuristics
- CPEs are intentionally left unchanged unless a reliable package mapping is available
- Post-processed JSON SBOMs are scored with `sbomqs` before packaging
- Packaged as `rust-gvm-sbom.tar.gz` with SHA256 checksum
- Attached to GitHub releases alongside platform binaries

### Dependency Management

- **Dependabot** (`.github/dependabot.yml`):
  - Cargo: weekly, Monday, grouped minor/patch
  - GitHub Actions: weekly, grouped
  - pip: monthly
- **cargo-deny** (`deny.toml`): license allowlist, advisory database, v2 schema
  - Ignored advisories: RUSTSEC-2023-0071 (rsa Marvin Attack, transitive via russh), RUSTSEC-2025-0134 (rustls-pemfile unmaintained)

### Makefile

Development commands available via `make`:
- `make all` — fmt + clippy + test + doc
- `make test` / `make test-all` — workspace tests (default / all features)
- `make test-integration` — python-gvm integration tests
- `make clippy` / `make fmt` — lint and format
- `make doc` / `make doc-open` — build/open rustdoc
- `make deny` / `make audit` / `make outdated` / `make machete` — dependency checks
- `make coverage` / `make coverage-lcov` — line coverage reports
- `make ci` — full local CI simulation
- `make setup-tools` — install dev tools (cargo-deny, cargo-llvm-cov, etc.)

---

## 8. Implementation Phases (Status)

### Phase 1: Core Foundation ✅
1. `gvm-protocol` — Sans-I/O state machine + `XmlCommand` builder
2. `gvm-connection` — Unix socket only
3. Basic `gvm-gmp` — `Version`, `authenticate`, `Tasks` (as proof of concept)
4. `gvm-client` — Connect + version negotiation

**Exit criteria:** Can connect to gvmd, authenticate, and list tasks.

### Phase 2: Full GMP 22.4 Coverage ✅
1. All command builders for GMP 22.4
2. All enums
3. Response parsing for core types
4. TLS connection support
5. Comprehensive unit tests ported from python-gvm

**Exit criteria:** Feature parity with python-gvm for GMP 22.4.

### Phase 3: Version Variants + Polish (Mostly Complete)
1. ✅ Version deltas (22.5, 22.6, 22.7, next) — `GmpVersioned` enum
2. ✅ SSH connection support — `russh`-based `SshConnection`
3. ⬜ Sync wrapper API — deferred
4. ✅ Documentation (rustdoc, examples, README)
5. ✅ CI/CD pipeline (CI, nightly, release workflows)
6. ⬜ Publish to crates.io — deferred pending v0.2.0

**Exit criteria:** Full feature parity with python-gvm, published crate.

### Phase 3 Additions (Not in Original Spec)
- ✅ SBOM generation (CycloneDX) in release/nightly pipelines
- ✅ Dependabot configuration (cargo + actions + pip)
- ✅ cargo-deny license/advisory checking
- ✅ Makefile with full development workflow commands
- ✅ python-gvm integration test CI job
- ✅ Cross-platform binary builds (5 targets)
- ✅ AGPL-3.0-or-later license (changed from GPL)
- ✅ SPDX headers on all source files
- ✅ SSH listener in mock server (for E2E testing)

---

## 8. Supervisor Rules

### RULE: Project Journal (MANDATORY)

The supervisor agent **must** maintain a project journal at `journal/` in the repository root. This is a strict, non-negotiable requirement for every development session.

#### Purpose

1. **Document human creative input** — Every human instruction, design direction, correction, or decision must be captured verbatim or in faithful paraphrase. The human is the architect; the journal preserves their authorship.
2. **Document agent actions** — What each agent did, what it produced, what failed, what was retried.
3. **Enable blog generation** — The journal serves as raw material for writing blog posts about the human-AI collaborative development process.

#### Format

Each session produces a dated entry in `journal/YYYY-MM-DD.md`:

```markdown
# Project Journal — YYYY-MM-DD

## Session Summary
One-paragraph overview of what was accomplished.

## Human Directives
Chronological log of human instructions and decisions.
- **HH:MM** — [verbatim or faithful paraphrase of instruction]
- **HH:MM** — [decision/correction/redirect]

## Agent Actions
Chronological log of what agents did in response.
- **HH:MM** — [Agent: Supervisor/Coder/Reviewer] Action taken, outcome
- **HH:MM** — [Agent: Coder] Files created/modified, tests run, results

## Design Decisions
Decisions made during this session with rationale.
- **Decision:** [what]
  **Context:** [why it came up]
  **Rationale:** [why this choice]
  **Human input:** [what the human said that shaped this]

## Challenges & Retries
What went wrong, what was tried, what ultimately worked.

## Artifacts Produced
- Files created/modified (with brief description)
- PRs opened
- Tests added

## Open Threads
What's unfinished, blocked, or needs human input next session.
```

#### Rules

1. **Write-through, not batch.** Update the journal as work happens, not at the end. If the session crashes, the journal should still reflect what occurred up to that point.
2. **Human words are primary source.** When a human gives an instruction, capture it with enough fidelity that a reader can understand the human's intent and creative contribution. Do not reduce human input to mere "approved" or "requested."
3. **No sanitizing failure.** If an agent produced bad code, went down a wrong path, or needed correction — log it. This is valuable for blog content and process improvement.
4. **Commit the journal.** Journal entries must be committed to the repo alongside code changes. They are first-class project artifacts, not ephemeral notes.
5. **Blog-ready voice.** Write journal entries in a clear, narrative-friendly style. Assume a technical reader who wants to understand how human-AI collaboration actually works in practice.

---

## 9. Design Decisions

### D1: Sans-I/O Protocol Core
**Decision:** Port python-gvm's state machine pattern directly.
**Rationale:** Proven design. Enables testing without network I/O. Allows different async runtimes.

### D2: Separate Crates vs Monolith
**Decision:** Workspace with 4 crates.
**Rationale:** Users who only need command building (e.g., for testing) don't need transport deps. Feature flags alone would still compile unused connection code.

### D3: `quick-xml` over `xml-rs` or `roxmltree`
**Decision:** Use `quick-xml`.
**Rationale:** Fast, streaming, handles large responses (reports can be huge), active maintenance. `roxmltree` is read-only (can't build XML). `xml-rs` is slower.

### D4: Builder Pattern with Options Structs
**Decision:** Required args as positional, optional as `Opts` structs with `Default`.
**Rationale:** Matches python-gvm's keyword-argument API. Builder pattern would be more Rust-idiomatic but creates many small types. Options structs are simpler for this domain.

### D5: Async-First
**Decision:** Async by default with optional sync wrappers.
**Rationale:** GMP operations are inherently I/O bound. Most Rust networking code is async. Sync users can use `block_on` wrappers.

### D6: GPL-3.0-or-later License
**Decision:** Match python-gvm license exactly.
**Rationale:** User requirement. Maintains compatibility with the Greenbone ecosystem.

---

## 10. Open Questions

1. **Typed response structs vs raw XML?** — Phase 1 returns `Response` with raw XML access. Typed structs are Phase 2+ scope. Consider `serde` with custom XML deserializer vs manual extraction.

2. **`lxml` equivalence in Rust?** — python-gvm uses `lxml.etree`. Rust's `quick-xml` handles streaming but doesn't provide XPath. Consider `roxmltree` for read-side response parsing (it does support basic queries).

3. **Feature detection vs version enum?** — python-gvm uses class inheritance for versions. Rust could use trait-based feature detection instead. Current spec uses type-state + enum, evaluate during Phase 2.

4. **Streaming large reports?** — GMP report responses can be very large. Consider `AsyncRead`-based streaming response parsing for `get_reports`.
