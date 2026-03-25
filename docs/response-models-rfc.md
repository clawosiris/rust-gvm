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

## Proposed Architecture: Domain-Based Structure

Reorganize `gvm-gmp` around **domains** (entities), with each domain containing its request, response, and handler logic:

```
crates/gvm-gmp/src/
├── scanner/
│   ├── mod.rs          # Re-exports
│   ├── request.rs      # GetScannersOpts, CreateScannerOpts, ModifyScannerOpts
│   ├── response.rs     # Scanner, GetScannersResponse, CreateScannerResponse
│   └── handler.rs      # get_scanners(), create_scanner(), delete_scanner()
│
├── target/
│   ├── mod.rs
│   ├── request.rs      # CreateTargetOpts, GetTargetsOpts, ModifyTargetOpts
│   ├── response.rs     # Target, PortListRef, GetTargetsResponse, CreateTargetResponse
│   └── handler.rs      # create_target(), get_targets(), modify_target(), delete_target()
│
├── task/
│   ├── mod.rs
│   ├── request.rs      # CreateTaskOpts, GetTasksOpts, StartTaskOpts
│   ├── response.rs     # Task, GetTasksResponse, CreateTaskResponse, StartTaskResponse
│   └── handler.rs      # create_task(), get_tasks(), start_task(), stop_task()
│
├── scan_config/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── port_list/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── report/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── result/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── feed/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── nvt/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── alert/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── credential/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── filter/
│   ├── mod.rs
│   ├── request.rs
│   ├── response.rs
│   └── handler.rs
│
├── ... (remaining domains)
│
├── common/
│   ├── mod.rs
│   ├── entity.rs       # EntityMeta, Owner, Permissions (shared)
│   ├── error.rs        # ParseError
│   └── parse.rs        # XmlParser utilities
│
├── enums.rs            # AliveTest, AlertCondition, etc. (keep existing)
├── types.rs            # EntityId, GmpVersion (keep existing)
└── lib.rs              # Top-level re-exports
```

---

## Design Pattern

Each domain follows a consistent structure:

### request.rs — Input Types
```rust
// target/request.rs

use crate::enums::AliveTest;
use crate::types::EntityId;

/// Options for creating a target.
#[derive(Debug, Clone, Default)]
pub struct CreateTargetOpts {
    pub comment: Option<String>,
    pub hosts: Vec<String>,
    pub exclude_hosts: Vec<String>,
    pub alive_test: Option<AliveTest>,
    pub port_list_id: Option<EntityId>,
    pub reverse_lookup_only: Option<bool>,
    pub reverse_lookup_unify: Option<bool>,
}

/// Options for listing targets.
#[derive(Debug, Clone, Default)]
pub struct GetTargetsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

/// Options for modifying a target.
#[derive(Debug, Clone, Default)]
pub struct ModifyTargetOpts {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub hosts: Vec<String>,
    pub exclude_hosts: Vec<String>,
    pub alive_test: Option<AliveTest>,
    pub port_list_id: Option<EntityId>,
}
```

### response.rs — Output Types
```rust
// target/response.rs

use crate::common::{EntityMeta, ParseError};
use crate::enums::AliveTest;
use crate::types::EntityId;
use gvm_protocol::Response;

/// A GMP target entity.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct GetTargetsResponse {
    pub status: u16,
    pub status_text: String,
    pub targets: Vec<Target>,
    pub target_count: TargetCount,
}

/// Response from create_target command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTargetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: EntityId,
}

/// Response from modify_target / delete_target commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetActionResponse {
    pub status: u16,
    pub status_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCount {
    pub total: u32,
    pub filtered: u32,
    pub page: u32,
}

impl GetTargetsResponse {
    /// Parse from raw GMP response.
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        // XML parsing implementation
    }
}

impl CreateTargetResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        // XML parsing implementation
    }
}
```

### handler.rs — Command Builders
```rust
// target/handler.rs

use gvm_protocol::{Request, XmlCommand};
use crate::types::EntityId;
use super::request::{CreateTargetOpts, GetTargetsOpts, ModifyTargetOpts};

/// Build a create_target request.
#[must_use]
pub fn create_target(name: &str, opts: CreateTargetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_target");
    cmd.add_element_with_text("name", name);
    // ... build XML
    cmd
}

/// Build a get_targets request.
#[must_use]
pub fn get_targets(opts: GetTargetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_targets");
    // ... build XML
    cmd
}

/// Build a get_target request (single target by ID).
#[must_use]
pub fn get_target(target_id: &EntityId) -> impl Request {
    XmlCommand::new("get_targets")
        .attribute("target_id", target_id.as_str())
        .attribute("details", "1")
}

/// Build a modify_target request.
#[must_use]
pub fn modify_target(target_id: &EntityId, opts: ModifyTargetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_target")
        .attribute("target_id", target_id.as_str());
    // ... build XML
    cmd
}

/// Build a delete_target request.
#[must_use]
pub fn delete_target(target_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_target")
        .attribute("target_id", target_id.as_str())
        .attribute("ultimate", if ultimate { "1" } else { "0" })
}
```

### mod.rs — Re-exports
```rust
// target/mod.rs

mod request;
mod response;
mod handler;

pub use request::*;
pub use response::*;
pub use handler::*;
```

---

## Common Types

### common/entity.rs — Shared Entity Metadata
```rust
use crate::types::EntityId;

/// Common metadata present on all GMP entities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntityMeta {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub creation_time: Option<String>,  // ISO 8601 string
    pub modification_time: Option<String>,
    pub owner: Option<Owner>,
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub name: String,
}
```

### common/error.rs — Parse Errors
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
}
```

---

## Usage Examples

### Consumer Code (After)
```rust
use gvm_gmp::target::{CreateTargetOpts, create_target, CreateTargetResponse};
use gvm_gmp::scanner::{get_scanners, GetScannersOpts, Scanner};
use gvm_gmp::task::{Task, get_tasks, GetTasksOpts};

// Create a target
let opts = CreateTargetOpts {
    hosts: vec!["192.168.1.0/24".to_string()],
    port_list_id: Some(port_list_id),
    ..Default::default()
};
let response = client.call(create_target("My Target", opts)).await?;
let result = CreateTargetResponse::from_response(&response)?;
println!("Created target: {}", result.id);

// List scanners
let response = client.call(get_scanners(GetScannersOpts::default())).await?;
let scanners = GetScannersResponse::from_response(&response)?;
for scanner in &scanners.scanners {
    println!("Scanner: {} ({})", scanner.meta.name, scanner.meta.id);
}
```

---

## Migration Strategy

### Phase 1: Create New Structure (Non-Breaking)

1. Add domain folders alongside existing `commands/` module
2. Implement request/response/handler for core domains
3. Re-export from top-level `lib.rs` for new API
4. Existing `commands::*` paths continue to work

### Phase 2: Migrate Consumers

1. Update gvm-rools to use new domain imports
2. Update rust-gvm-api to use new domain imports
3. Update E2E tests to use typed responses

### Phase 3: Deprecate Old Structure

1. Mark `commands::*` as `#[deprecated]`
2. Point users to new domain-based imports
3. Remove in next major version

---

## Domains to Implement

### Phase 1: Core (Week 1)
| Domain | Operations |
|--------|------------|
| `version` | get_version |
| `auth` | authenticate |
| `target` | create, get, get_all, modify, delete, clone |
| `scan_config` | create, get, get_all, modify, delete, clone |
| `scanner` | create, get, get_all, modify, delete |
| `port_list` | create, get, get_all, modify, delete, clone |

### Phase 2: Tasks & Reports (Week 2)
| Domain | Operations |
|--------|------------|
| `task` | create, get, get_all, modify, delete, clone, start, stop, resume |
| `report` | get, get_all, delete |
| `result` | get, get_all |

### Phase 3: Security Info (Week 3)
| Domain | Operations |
|--------|------------|
| `feed` | get_all |
| `nvt` | get, get_all |
| `cve` | get, get_all |
| `cpe` | get, get_all |
| `cert_bund` | get, get_all |
| `dfn_cert` | get, get_all |

### Phase 4: Remaining (Week 4)
| Domain | Operations |
|--------|------------|
| `alert` | CRUD |
| `credential` | CRUD |
| `filter` | CRUD |
| `note` | CRUD |
| `override` | CRUD |
| `schedule` | CRUD |
| `tag` | CRUD |
| `ticket` | CRUD |
| `user` | CRUD |
| `group` | CRUD |
| `role` | CRUD |
| `permission` | CRUD |

---

## Feature Flags

```toml
# crates/gvm-gmp/Cargo.toml

[features]
default = []
serde = ["dep:serde"]  # Enable JSON serialization

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```

```rust
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Target {
    // ...
}
```

---

## Open Questions

1. **Timestamp handling:** Start with `String` (ISO 8601), add parsed `DateTime` later?
   - Recommendation: Yes, keep it simple initially

2. **`#[non_exhaustive]` on all structs?**
   - Recommendation: Yes, allows adding fields without breaking changes

3. **Separate `get` vs `get_all` handlers, or unified with options?**
   - Recommendation: Unified — `get_targets(opts)` handles both via `target_id` option

---

## Summary

| Aspect | Decision |
|--------|----------|
| **Structure** | Domain-based (`target/`, `scanner/`, `task/`) |
| **Files per domain** | `mod.rs`, `request.rs`, `response.rs`, `handler.rs` |
| **Shared types** | `common/` module |
| **Parsing** | Hand-written with quick_xml |
| **Serde** | Optional feature flag |
| **Non-exhaustive** | Yes, on all public structs |
| **Breaking changes** | None (additive, deprecate later) |
| **Timeline** | 4 weeks for full coverage |

---

*Author: Thoth*  
*Date: 2026-03-25*  
*Revised: Domain-based structure per @recepkizilarslan feedback*  
*Status: RFC v2 — Awaiting Final Review*
