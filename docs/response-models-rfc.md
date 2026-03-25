# RFC: Response Models for rust-gvm

## Problem Statement

Currently, rust-gvm returns raw `gvm_protocol::Response` objects from all GMP commands. Consumers must:

1. Parse XML manually using `quick_xml`
2. Handle element extraction, attribute parsing, type conversion
3. Duplicate parsing logic across projects (E2E tests, gvm-rools, rust-gvm-api, openvas-mcp-server)

**Goal:** Encapsulate XML parsing inside rust-gvm and expose typed response models.

---

## Current Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           CONSUMERS                                  │
│  (gvm-rools, rust-gvm-api, E2E tests, openvas-mcp-server)           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Manual XML parsing with quick_xml                            │   │
│  │  - Duplicated across all consumers                            │   │
│  │  - Error-prone, inconsistent                                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  gvm-client                                                          │
│  ├── GmpClient<C: GvmConnection>                                     │
│  │   └── send/call → Response (raw XML bytes)                       │
│  └── GmpVersioned<C> (version-gated wrappers)                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  gvm-gmp                                                             │
│  ├── commands/*.rs  → XmlCommand builders (request side only)       │
│  ├── enums.rs       → AliveTest, AlertCondition, etc.               │
│  └── types.rs       → EntityId, GmpVersion                          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  gvm-protocol                                                        │
│  ├── Response       → status_code(), child_text(), as_str()         │
│  ├── Request trait  → to_bytes()                                    │
│  └── XmlCommand     → builds XML                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Proposed Architecture Options

### Option A: Response Models in `gvm-gmp` (Recommended)

Add a new `responses` module alongside `commands`:

```
crates/gvm-gmp/
├── src/
│   ├── commands/       # Existing request builders
│   │   ├── targets.rs
│   │   └── ...
│   ├── responses/      # NEW: Response models + parsing
│   │   ├── mod.rs
│   │   ├── targets.rs  # Target, GetTargetsResponse
│   │   ├── tasks.rs    # Task, GetTasksResponse
│   │   ├── common.rs   # Shared types (Timestamp, Permissions, etc.)
│   │   └── ...
│   ├── enums.rs
│   ├── types.rs
│   └── lib.rs
```

**Pros:**
- Keeps request/response logic together per command
- Natural pairing: `commands::targets::create_target()` ↔ `responses::targets::CreateTargetResponse`
- Single crate for all GMP protocol knowledge
- gvm-mock-server can use same models for fixture generation

**Cons:**
- Makes gvm-gmp larger
- Parsing logic mixed with command building

---

### Option B: New `gvm-models` Crate

Create a dedicated models crate:

```
crates/
├── gvm-gmp/         # Request builders only
├── gvm-protocol/    # Wire format
├── gvm-models/      # NEW: Response models
│   ├── src/
│   │   ├── lib.rs
│   │   ├── target.rs
│   │   ├── task.rs
│   │   ├── scanner.rs
│   │   └── ...
│   └── Cargo.toml
└── gvm-client/      # Adds typed methods
```

**Pros:**
- Clean separation: models are purely data structures
- Can be versioned independently
- Smaller, focused crate

**Cons:**
- Another crate to maintain
- Dependency chain: gvm-client → gvm-models + gvm-gmp
- Models divorced from command context

---

### Option C: Response Models in `gvm-protocol`

Extend gvm-protocol with typed parsing:

```
crates/gvm-protocol/
├── src/
│   ├── response.rs    # Existing Response
│   ├── models/        # NEW
│   │   ├── mod.rs
│   │   ├── target.rs
│   │   └── ...
│   └── lib.rs
```

**Pros:**
- Protocol-level concern (parsing belongs with protocol)
- Minimal crate count

**Cons:**
- gvm-protocol is meant to be "sans-I/O" and low-level
- Would need to depend on gvm-gmp for enums/types (circular risk)
- Mixes concerns: wire framing vs. domain models

---

## Recommendation: Option A (`gvm-gmp/responses`)

Option A is the cleanest fit because:

1. **Command ↔ Response symmetry:** Each command module gets a matching response module
2. **Single source of truth:** All GMP protocol knowledge in one crate
3. **Mock server reuse:** gvm-mock-server can import response models for fixture generation
4. **No new dependencies:** Uses existing quick_xml, thiserror, etc.

---

## Model Design

### Base Entity Pattern

```rust
// responses/common.rs

/// Common entity metadata present on all GMP resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityMeta {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
    pub modification_time: Option<DateTime<Utc>>,
    pub owner: Option<Owner>,
    pub permissions: Option<Permissions>,
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    pub permission: Vec<Permission>,
}
```

### Response Envelope Pattern

```rust
// responses/targets.rs

use crate::enums::AliveTest;
use crate::types::EntityId;
use super::common::{EntityMeta, parse_response};

/// A GMP target resource.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub meta: EntityMeta,
    pub hosts: Vec<String>,
    pub exclude_hosts: Vec<String>,
    pub alive_test: AliveTest,
    pub port_list: Option<PortListRef>,
    pub reverse_lookup_only: bool,
    pub reverse_lookup_unify: bool,
    pub max_hosts: Option<u32>,
}

/// Reference to a port list (id + name only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortListRef {
    pub id: EntityId,
    pub name: String,
}

/// Response from get_targets command.
#[derive(Debug, Clone, PartialEq)]
pub struct GetTargetsResponse {
    pub status: u16,
    pub status_text: String,
    pub targets: Vec<Target>,
    pub target_count: TargetCount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCount {
    pub total: u32,
    pub filtered: u32,
    pub page: u32,
}

/// Response from create_target command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTargetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: EntityId,
}

impl GetTargetsResponse {
    /// Parse from raw Response.
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        // Implementation
    }
}
```

### Parsing Approach

```rust
// responses/parse.rs

use gvm_protocol::Response;
use quick_xml::Reader;
use quick_xml::events::Event;

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
}

/// Parse helper for common patterns.
pub(crate) struct XmlParser<'a> {
    reader: Reader<&'a [u8]>,
}

impl<'a> XmlParser<'a> {
    pub fn new(response: &'a Response) -> Result<Self, ParseError> {
        // ...
    }
    
    pub fn text_content(&mut self, element: &str) -> Result<Option<String>, ParseError> {
        // ...
    }
    
    pub fn attribute(&mut self, attr: &str) -> Result<Option<String>, ParseError> {
        // ...
    }
}
```

---

## Integration with Existing Code

### gvm-client Changes

Add typed methods alongside raw `send`/`call`:

```rust
// gvm-client/src/lib.rs

impl<C: GvmConnection> GmpClient<C> {
    // Existing raw methods
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError>;
    pub async fn call<R: Request>(&mut self, request: R) -> Result<Response, GvmError>;
    
    // NEW: Typed methods
    pub async fn get_targets(
        &mut self, 
        opts: GetTargetsOpts
    ) -> Result<GetTargetsResponse, GvmError> {
        let response = self.call(gvm_gmp::commands::targets::get_targets(opts)).await?;
        GetTargetsResponse::from_response(&response)
            .map_err(|e| GvmError::Parse(e.to_string()))
    }
    
    pub async fn create_target(
        &mut self,
        name: &str,
        opts: CreateTargetOpts,
    ) -> Result<CreateTargetResponse, GvmError> {
        let response = self.call(gvm_gmp::commands::targets::create_target(name, opts)).await?;
        CreateTargetResponse::from_response(&response)
            .map_err(|e| GvmError::Parse(e.to_string()))
    }
}
```

### gvm-mock-server Integration

Use response models for fixture generation:

```rust
// gvm-mock-server/src/fixtures.rs

use gvm_gmp::responses::targets::{Target, GetTargetsResponse};

impl GetTargetsResponse {
    /// Generate fixture XML from model.
    pub fn to_xml(&self) -> String {
        // Serialize back to GMP XML
    }
}

// Or keep as separate trait:
pub trait ToGmpXml {
    fn to_gmp_xml(&self) -> String;
}
```

---

## Commands to Model (Priority Order)

### Phase 1: Core Commands (Week 1)
| Command | Response Model |
|---------|----------------|
| `get_version` | `GetVersionResponse` |
| `authenticate` | `AuthenticateResponse` |
| `get_targets` | `GetTargetsResponse`, `Target` |
| `create_target` | `CreateTargetResponse` |
| `get_scan_configs` | `GetScanConfigsResponse`, `ScanConfig` |
| `get_scanners` | `GetScannersResponse`, `Scanner` |
| `get_port_lists` | `GetPortListsResponse`, `PortList` |

### Phase 2: Tasks & Scans (Week 2)
| Command | Response Model |
|---------|----------------|
| `get_tasks` | `GetTasksResponse`, `Task` |
| `create_task` | `CreateTaskResponse` |
| `start_task` | `StartTaskResponse` |
| `get_reports` | `GetReportsResponse`, `Report` |
| `get_results` | `GetResultsResponse`, `Result` |

### Phase 3: Security Info (Week 3)
| Command | Response Model |
|---------|----------------|
| `get_nvts` | `GetNvtsResponse`, `Nvt` |
| `get_cves` | `GetCvesResponse`, `Cve` |
| `get_cpes` | `GetCpesResponse`, `Cpe` |
| `get_feeds` | `GetFeedsResponse`, `Feed` |

### Phase 4: Remaining Commands (Week 4)
- Alerts, Credentials, Filters, Notes, Overrides
- Users, Groups, Roles, Permissions
- Tags, Tickets, Schedules

---

## Serde Support

Add optional serde feature for JSON serialization:

```toml
# crates/gvm-gmp/Cargo.toml
[features]
default = []
serde = ["dep:serde"]

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```

```rust
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target {
    // ...
}
```

---

## Migration Path

1. **Non-breaking:** New `responses` module is additive
2. **Existing code continues to work:** `send()`/`call()` still return `Response`
3. **Gradual adoption:** Consumers migrate one command at a time
4. **Deprecation (future):** Eventually deprecate raw `Response` methods

---

## Open Questions for Decision

1. **Should we use `derive` macros for XML parsing?**
   - Options: Hand-written parsing vs. `serde-xml-rs` vs. custom derive
   - Recommendation: Hand-written for control, consider macro later

2. **Should response models be `#[non_exhaustive]`?**
   - Allows adding fields without breaking changes
   - Recommendation: Yes

3. **Should we include raw XML alongside parsed data?**
   - Useful for debugging, extensions
   - Recommendation: No (can call `as_str()` on original Response if needed)

4. **Timestamp handling: `chrono` or `time`?**
   - `chrono` is more common but has had security issues
   - `time` is lighter but less mature
   - Recommendation: Start with String, add parsed timestamp later

---

## Files to Create

```
crates/gvm-gmp/src/responses/
├── mod.rs              # Module exports
├── common.rs           # EntityMeta, Owner, Permissions, parsing utilities
├── error.rs            # ParseError
├── parse.rs            # XmlParser helper
├── version.rs          # GetVersionResponse
├── authentication.rs   # AuthenticateResponse
├── targets.rs          # Target, GetTargetsResponse, CreateTargetResponse
├── scan_configs.rs     # ScanConfig, GetScanConfigsResponse
├── scanners.rs         # Scanner, GetScannersResponse
├── port_lists.rs       # PortList, GetPortListsResponse
├── tasks.rs            # Task, GetTasksResponse, CreateTaskResponse
├── reports.rs          # Report, GetReportsResponse
├── results.rs          # Result, GetResultsResponse
├── feeds.rs            # Feed, GetFeedsResponse
└── ... (remaining commands)
```

---

## Summary

| Aspect | Decision |
|--------|----------|
| **Location** | `gvm-gmp/src/responses/` (Option A) |
| **Pattern** | Struct per entity + struct per response envelope |
| **Parsing** | Hand-written with quick_xml |
| **Serde** | Optional feature flag |
| **Breaking changes** | None (additive) |
| **Timeline** | 4 weeks for full coverage |

---

*Author: Thoth*  
*Date: 2026-03-25*  
*Status: RFC — Awaiting Review*
