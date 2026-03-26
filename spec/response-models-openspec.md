# OpenSpec: Response Models for rust-gvm

**Version:** 1.0  
**Author:** Thoth  
**Date:** 2026-03-26  
**Status:** Implementation In Progress (Phase 1 complete)  
**RFC:** [PR #65](https://github.com/clawosiris/rust-gvm/pull/65)  
**Phase 1 PR:** [PR #67](https://github.com/clawosiris/rust-gvm/pull/67)

---

## 1. Problem Statement

rust-gvm currently returns raw `gvm_protocol::Response` objects (opaque XML byte buffers) from all GMP commands. Every consumer — gvm-rools, rust-gvm-api, E2E tests, openvas-mcp-server — must independently:

1. Parse XML using `quick_xml`
2. Extract elements, attributes, and text values
3. Convert strings to typed values (IDs, booleans, integers)
4. Handle missing/optional fields
5. Manage error responses

This leads to duplicated, inconsistent, error-prone parsing across the ecosystem.

**Goal:** Encapsulate all XML parsing inside `gvm-gmp` and expose strongly-typed response models that consumers can use directly.

---

## 2. Architecture

### 2.1 Module Location

All response models live in `crates/gvm-gmp/src/responses/`, alongside the existing `commands/` module. This is **purely additive** — no existing API is modified or removed.

```
crates/gvm-gmp/src/
├── commands/               # EXISTING — request builders (unchanged)
├── common.rs               # EXISTING — request-side helpers (unchanged)
├── responses/              # NEW — response models
│   ├── mod.rs              # Re-exports all domain modules
│   ├── common.rs           # Shared types, ParseError, XmlNode parser
│   ├── version.rs          # Phase 1
│   ├── auth.rs             # Phase 1
│   ├── target.rs           # Phase 1
│   ├── scan_config.rs      # Phase 1
│   ├── scanner.rs          # Phase 1
│   ├── port_list.rs        # Phase 1
│   ├── task.rs             # Phase 2
│   ├── report.rs           # Phase 2
│   ├── result.rs           # Phase 2
│   ├── feed.rs             # Phase 3
│   ├── nvt.rs              # Phase 3
│   ├── secinfo.rs          # Phase 3 (CVE, CPE, CERT advisories)
│   ├── alert.rs            # Phase 4
│   ├── credential.rs       # Phase 4
│   ├── filter.rs           # Phase 4
│   ├── note.rs             # Phase 4
│   ├── override_.rs        # Phase 4 (underscore to avoid keyword)
│   ├── schedule.rs         # Phase 4
│   ├── tag.rs              # Phase 4
│   ├── ticket.rs           # Phase 4
│   ├── user.rs             # Phase 4
│   ├── group.rs            # Phase 4
│   ├── role.rs             # Phase 4
│   ├── permission.rs       # Phase 4
│   ├── host.rs             # Phase 4
│   ├── tls_certificate.rs  # Phase 4
│   └── system.rs           # Phase 4 (settings, trashcan, etc.)
├── enums.rs                # EXISTING (unchanged)
├── types.rs                # EXISTING (serde derives added)
└── lib.rs                  # `pub mod responses;` added
```

### 2.2 Dependency Changes

```toml
# crates/gvm-gmp/Cargo.toml

[features]
default = []
serde = ["dep:serde"]

[dependencies]
gvm-protocol = { workspace = true }
thiserror = { workspace = true }
serde = { version = "1", features = ["derive"], optional = true }
quick-xml = { workspace = true }
```

### 2.3 Backward Compatibility

- All changes are **additive** — new modules, new types
- Existing `commands::*` imports continue to work unchanged
- `EntityId` and `GmpVersion` gain conditional `serde` derives (non-breaking)
- Future phases may deprecate direct XML parsing in consumers, but never remove existing APIs without a major version bump

---

## 3. Core Design

### 3.1 Shared Types (`responses/common.rs`)

#### ParseError

```rust
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("missing required element: {0}")]
    MissingElement(String),
    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
    #[error("server error {status}: {message}")]
    ServerError { status: u16, message: String },
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}
```

#### EntityMeta

Common metadata present on all GMP entities:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntityMeta {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub creation_time: Option<String>,     // ISO 8601
    pub modification_time: Option<String>, // ISO 8601
    pub owner: Option<Owner>,
    pub in_use: bool,
    pub writable: bool,
}
```

#### Supporting Types

| Type | Purpose |
|------|---------|
| `Owner` | `{ name: String }` — resource owner |
| `NamedEntity` | `{ id: EntityId, name: String }` — reference to related entity (e.g., port_list inside target) |
| `CountInfo` | `{ total, filtered, page: Option<u32> }` — pagination metadata from `*_count` elements |
| `ActionResponse` | `{ status: u16, status_text: String }` — generic modify/delete response |

### 3.2 Response Pattern

Every domain follows the same pattern:

#### Entity Struct
Domain-specific fields plus `EntityMeta`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target {
    pub meta: EntityMeta,
    pub hosts: Option<String>,
    pub exclude_hosts: Option<String>,
    // ... domain-specific fields
}
```

#### List Response

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTargetsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Target>,
    pub counts: CountInfo,
}

impl GetTargetsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> { ... }
}
```

#### Create Response

```rust
pub struct CreateTargetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: EntityId,
}
```

#### Action Aliases

```rust
pub type ModifyTargetResponse = ActionResponse;
pub type DeleteTargetResponse = ActionResponse;
```

### 3.3 XML Parsing Infrastructure

The `XmlNode` tree parser (internal to `responses/common.rs`) converts raw XML bytes into a navigable tree structure:

```rust
pub(crate) struct XmlNode {
    pub name: String,
    pub attributes: HashMap<String, String>,
    pub text: String,
    pub children: Vec<XmlNode>,
}
```

Key parsing helpers:
- `parse_document(data: &[u8]) -> Result<XmlNode, ParseError>` — full document parse
- `status_from_response(response) -> Result<(u16, String), ParseError>` — extract + validate status
- `parse_entity_meta(node) -> Result<EntityMeta, ParseError>` — standard metadata extraction
- `parse_named_entity(node, field) -> Result<Option<NamedEntity>, ParseError>` — ref entity with id attr
- `count_info(node, count_name) -> Result<CountInfo, ParseError>` — pagination counts
- `parse_bool`, `parse_u16`, `parse_u32` — type conversion helpers

### 3.4 Design Rules

1. **`#[non_exhaustive]`** on all public structs — allows adding fields in minor versions
2. **Timestamps as `String`** — ISO 8601 format, no chrono/time dependency; parsed types may come later behind a feature flag
3. **Optional serde** — `#[cfg_attr(feature = "serde", derive(...))]` on all public types
4. **Status-first validation** — every `from_response()` checks for 2xx before parsing body; non-success returns `ParseError::ServerError`
5. **Graceful optionals** — missing XML elements produce `None`, not errors, for optional fields
6. **`"1"`/`"0"` booleans** — GMP uses string booleans; parser accepts `"1"`/`"true"` as true, `"0"`/`"false"` as false

---

## 4. Phase Plan

### Phase 1: Core Commands ✅ (Complete — PR #67)

| Domain | Entity | List Response | Create Response | Action Types | Tests |
|--------|--------|---------------|-----------------|--------------|-------|
| `version` | — | `GetVersionResponse` | — | — | 3 |
| `auth` | — | — | — | `AuthenticateResponse` | 3 |
| `target` | `Target` | `GetTargetsResponse` | `CreateTargetResponse` | `Modify`, `Delete` | 5 |
| `scan_config` | `ScanConfig` | `GetScanConfigsResponse` | `CreateScanConfigResponse` | `Modify`, `Delete`, `Sync` | 5 |
| `scanner` | `Scanner` | `GetScannersResponse` | `CreateScannerResponse` | `Modify`, `Delete`, `Verify` | 5 |
| `port_list` | `PortList` | `GetPortListsResponse` | `CreatePortListResponse` | `Modify`, `Delete` | 5 |

**Totals:** 6 modules, 4 entity structs, 14 response types, 26 tests, ~1,290 lines added.

### Phase 2: Tasks & Reports ✅ (Complete — PR #68)

| Domain | Entity | List Response | Create Response | Action/Other Types | Tests |
|--------|--------|---------------|-----------------|-------------------|-------|
| `task` | `Task`, `LastReport` | `GetTasksResponse` | `CreateTaskResponse` | `StartTaskResponse`, `Stop`, `Resume`, `Modify`, `Delete`, `Move` | 6 |
| `report` | `Report`, `ResultCount`, `Severity` | `GetReportsResponse` | — | `DeleteReportResponse` | 5 |
| `result` | `ScanResult`, `NvtRef`, `QodInfo` | `GetResultsResponse` | — | — | 5 |

**Totals:** 3 modules, 7 entity/helper structs, 11 response types, 16 tests, ~811 lines added.

**Implementation highlights:**
- `Task.progress` uses `i32` (-1 = not started, 0-100 = percent)
- `Task.alerts` is `Vec<NamedEntity>` (multiple alerts per task)
- `LastReport` contains `id: EntityId` + `timestamp: Option<String>` from nested `<last_report><report id="...">` XML
- `StartTaskResponse` extracts `report_id` from the 202 response body
- `Report` handles GMP's double-`<report>` nesting (outer = entity metadata, inner = scan details with result_count, severity, hosts)
- `ScanResult.nvt` parses `oid` from XML attribute, name/family/cvss_base from child elements
- `QodInfo` has `value: Option<u32>` + `type_: Option<String>`
- All severity values stored as `String` (not f64) per design rules

### Phase 3: Security Info

| Domain | Entity | Responses | Notes |
|--------|--------|-----------|-------|
| `feed` | `Feed` | `GetFeedsResponse` | Feed type, version, status |
| `nvt` | `Nvt`, `NvtFamily` | `GetNvtsResponse`, `GetNvtFamiliesResponse` | OID-keyed; refs, tags, solution |
| `secinfo` | `Cve`, `Cpe`, `CertBundAdvisory`, `DfnCertAdvisory` | `GetSecInfoResponse<T>` | Generic over info type; parsed from `get_info` |

**Feed entity fields:**
- `type_: String` (NVT, SCAP, CERT, GVMD_DATA)
- `name: String`
- `version: Option<String>`
- `description: Option<String>`
- `currently_syncing: Option<String>`

**NVT entity fields:**
- `oid: String`
- `name: String`
- `family: Option<String>`
- `cvss_base: Option<String>`
- `severity: Option<String>`
- `tags: Option<String>` (pipe-separated key=value)
- `solution_type: Option<String>`
- `refs: Vec<NvtRef>` (type + id, e.g., CVE, BID, URL)

### Phase 4: Remaining Entities

| Domain | Entity | Responses | Notes |
|--------|--------|-----------|-------|
| `alert` | `Alert` | CRUD responses | Condition, event, method sub-structures |
| `credential` | `Credential` | CRUD responses | Type-specific fields (username, cert, SNMP) |
| `filter` | `Filter` | CRUD responses | Term, type |
| `note` | `Note` | CRUD responses | NVT OID, text, hosts, port |
| `override_` | `Override` | CRUD responses | NVT OID, new_severity, hosts |
| `schedule` | `Schedule` | CRUD responses | iCalendar data, timezone |
| `tag` | `Tag` | CRUD responses | Resource type/id, value |
| `ticket` | `Ticket` | CRUD responses | Status, assigned_to, result |
| `user` | `User` | CRUD responses | Roles, groups, hosts access |
| `group` | `Group` | CRUD responses | Users list |
| `role` | `Role` | CRUD responses | Users list |
| `permission` | `Permission` | CRUD responses | Subject type/id, resource type/id |
| `host` | `Host` | CRUD responses | IP, OS, severities |
| `tls_certificate` | `TlsCertificate` | CRUD responses | Issuer, activation/expiry, md5/sha256 |
| `system` | — | `HelpResponse`, `DescribeAuthResponse`, `GetSettingsResponse` | Miscellaneous system commands |
| `report_format` | `ReportFormat` | CRUD responses | Content type, extension, trust |
| `report_config` | `ReportConfig` | CRUD responses | Report format ref, params |

---

## 5. Consumer Migration Guide

### Before (manual parsing)

```rust
let response = client.call(get_targets(GetTargetsOpts::default())).await?;
let xml = response.as_str()?;
// 20+ lines of quick_xml parsing...
let target_name = /* extract from XML */;
```

### After (typed response)

```rust
use gvm_gmp::responses::target::{GetTargetsResponse, Target};

let response = client.call(get_targets(GetTargetsOpts::default())).await?;
let parsed = GetTargetsResponse::from_response(&response)?;
for target in &parsed.items {
    println!("{}: {}", target.meta.id, target.meta.name);
}
```

### Migration per consumer

| Consumer | Phase | Effort |
|----------|-------|--------|
| **gvm-rools** (CLI) | After Phase 2 | Replace XML parsing in display/output formatting |
| **rust-gvm-api** (REST) | After Phase 2 | Replace manual XML→JSON conversion |
| **E2E tests** | After Phase 1 | Replace assertion helpers with typed field access |
| **openvas-mcp-server** | After Phase 4 | Full typed interface |

---

## 6. Testing Strategy

### Per-Domain Test Matrix

Each domain module includes these standard test categories:

| Category | Test Name Pattern | Description |
|----------|-------------------|-------------|
| Multi-item | `parses_multiple_*` | List response with 2+ items, all fields populated; validates counts, entity fields, nested refs |
| Empty list | `parses_empty_*` | Empty list (0 items, counts at 0); verifies no panic on missing items |
| Create | `parses_create_*_response` | Create response (201) with `id` extraction from root attribute |
| Error | `rejects_server_error` | Non-2xx status returns `ParseError::ServerError` with correct status + message |
| Optional fields | `parses_missing_optional_*_fields` | Entity with only required fields (name, id); all optionals are `None`/defaults |

### Complete Test Inventory

#### Phase 1 Tests (26 total)

**`version.rs`** (3 tests):
| Test | Validates |
|------|-----------|
| `parses_version_response` | Status 200, status_text, version string extraction |
| `rejects_server_error` | Status 500 → `ParseError::ServerError` |
| `rejects_missing_version` | Missing `<version>` element → `ParseError::MissingElement` |

**`auth.rs`** (3 tests):
| Test | Validates |
|------|-----------|
| `parses_authenticate_response` | Status 200 with child elements |
| `parses_self_closing_authenticate_response` | Self-closing `<authenticate_response ... />` (no body) |
| `rejects_server_error` | Status 400 → `ParseError::ServerError` |

**`target.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_targets` | 2 targets with owner, hosts, exclude_hosts, alive_tests, reverse_lookup flags, port_list ref (NamedEntity), max_hosts, counts with page |
| `parses_empty_targets` | 0 items, total count = 0 |
| `parses_create_target_response` | Status 201, id from root attribute |
| `rejects_server_error` | Status 400 → error |
| `parses_missing_optional_target_fields` | Only name+id present; comment, hosts, port_list all None; in_use/writable false |

**`scan_config.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_scan_configs` | 2 configs with usage_type (scan/policy), counts |
| `parses_empty_scan_configs` | 0 items |
| `parses_create_scan_config_response` | Status 201, id extraction |
| `rejects_server_error` | Status 404 → error |
| `parses_missing_optional_scan_config_fields` | comment=None, usage_type=None, in_use=false |

**`scanner.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_scanners` | 2 scanners with type, host, port (u16), credential ref (NamedEntity) |
| `parses_empty_scanners` | 0 items |
| `parses_create_scanner_response` | Status 201, id extraction |
| `rejects_server_error` | Status 503 → error |
| `parses_missing_optional_scanner_fields` | host=None, port=None, credential=None |

**`port_list.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_port_lists` | 2 port lists with port_count (u32), port_range string, page count |
| `parses_empty_port_lists` | 0 items |
| `parses_create_port_list_response` | Status 201, id extraction |
| `rejects_server_error` | Status 500 → error |
| `parses_missing_optional_port_list_fields` | comment=None, port_count=None, port_range=None |

#### Phase 2 Tests (16 total)

**`task.rs`** (6 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_tasks` | 2 tasks with status, progress (i32), target/config/scanner/schedule refs, 2 alerts (Vec\<NamedEntity\>), last_report (nested report id+timestamp), report_count, trend, usage_type, hosts_ordering |
| `parses_empty_tasks` | 0 items |
| `parses_create_task_response` | Status 201, id extraction |
| `parses_start_task_response` | **Status 202** (not 200), report_id extraction from `<report_id>` child |
| `rejects_server_error` | Status 400 → error |
| `parses_missing_optional_task_fields` | All optional fields None/empty; alerts vec empty |

**`report.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_reports` | 2 reports; first has nested inner `<report>` with scan_start, scan_end, result_count (full+filtered), severity (full+filtered), host_count; second has no inner report |
| `parses_empty_reports` | 0 items |
| `parses_nested_report_details` | **Double-report nesting**: outer entity metadata + inner scan details; validates scan_end, result_count.filtered, severity.full, host_count |
| `rejects_server_error` | Status 500 → error |
| `parses_missing_optional_report_fields` | task=None, scan_start=None, result_count=None, severity=None, host_count=None |

**`result.rs`** (5 tests):
| Test | Validates |
|------|-----------|
| `parses_multiple_results` | 2 results with host, port, NvtRef (oid from attribute, name, family, cvss_base), threat, severity (String), QodInfo (value u32, type_), description |
| `parses_empty_results` | 0 items |
| `parses_nvt_with_oid_attribute` | **NVT oid from XML attribute** (not child element); validates oid + nested name |
| `rejects_server_error` | Status 503 → error |
| `parses_missing_optional_result_fields` | host=None, nvt=None, qod=None, description=None |

### Planned Tests (Phase 3-4)

Each new domain module will follow the same 5-test minimum pattern. Domain-specific tests will be added for:
- **feed**: No entity id (feeds use type as key, not UUID)
- **nvt**: OID-keyed entities (not UUID), tags parsing
- **secinfo**: Generic response over multiple info types
- **alert**: Condition/event/method sub-structures
- **schedule**: iCalendar data parsing

### Integration Testing

After Phase 2, integration tests in `rust-gvm-e2e-tests` should:
1. Call GMP commands against live gvmd
2. Parse responses using typed models
3. Validate field contents against known test data

---

## 7. Future Extensions

### 7.1 Typed Timestamps (post-Phase 4)

Add optional `chrono` or `time` feature:
```toml
[features]
chrono = ["dep:chrono"]
```

```rust
#[cfg(feature = "chrono")]
pub fn creation_time_parsed(&self) -> Option<chrono::DateTime<chrono::Utc>> { ... }
```

### 7.2 Domain-Based Restructuring (v0.5+)

Consolidate request + response into domain folders:
```
target/
├── mod.rs
├── request.rs   # CreateTargetOpts, GetTargetsOpts (moved from commands/)
├── response.rs  # Target, GetTargetsResponse
└── handler.rs   # Typed client methods
```

This is the eventual RFC v2 structure but requires a breaking change cycle.

### 7.3 Typed Client Methods (v0.5+)

Add convenience methods to `GmpClient`:
```rust
impl<C: GvmConnection> GmpClient<C> {
    pub async fn get_targets_typed(&mut self, opts: GetTargetsOpts) 
        -> Result<GetTargetsResponse, ClientError> {
        let response = self.call(get_targets(opts)).await?;
        GetTargetsResponse::from_response(&response).map_err(ClientError::Parse)
    }
}
```

---

## 8. Open Questions (Resolved)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Timestamp type? | `String` (ISO 8601) | No external dep; parse later behind feature flag |
| `#[non_exhaustive]`? | Yes, all public structs | Semver-safe field additions |
| Separate get vs get_all? | Unified via opts | `get_targets(opts)` handles both single and list |
| Location? | `responses/` in gvm-gmp | Keeps command/response symmetry, single crate |
| Serde? | Optional feature flag | Zero overhead when unused |

---

## 9. Success Criteria

- [ ] All 4 phases implemented with full test coverage
- [ ] Zero breaking changes to existing `commands::*` API
- [ ] All consumers migrated to typed responses
- [ ] `cargo clippy --all-features` clean
- [ ] Documentation on public types
- [ ] Benchmark showing no regression from typed parsing vs. raw access

---

*This spec is a living document. Updated as phases complete and design evolves.*

*Last updated: 2026-03-26 (Phase 2 complete)*
