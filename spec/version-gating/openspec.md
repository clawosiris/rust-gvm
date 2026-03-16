# OpenSpec: Version-Specific GMP Behavior

**Issue:** [#16](https://github.com/clawosiris/rust-gvm/issues/16)
**Status:** Draft
**Author:** Thoth (Architect)
**Date:** 2026-03-16

---

## 1. Overview

### Problem Statement

The rust-gvm workspace treats all GMP versions (22.4–22.7) identically. The mock server accepts any command regardless of configured version, the client exposes the same API for all versions, and the command builder is missing 22.6+ commands. This means:

- Tests cannot validate version-specific behavior
- The mock server cannot simulate real gvmd version constraints
- Clients cannot get compile-time safety for version-appropriate command usage

### Goals

1. Mock server rejects commands not available in its configured GMP version
2. New 22.6+ commands (report_config CRUD, get_features) implemented across all crates
3. Client version wrappers expose version-appropriate method sets
4. Comprehensive cross-version test coverage

### Non-Goals

- Backward compatibility with GMP versions before 22.4
- Full audit/compliance response rendering (complex XML, defer to later)
- Deprecation warnings for deprecated-but-still-accepted elements (e.g., `first`/`last` filter keywords)

---

## 2. Architecture

### Version Model

GMP versions collapse into two protocol generations:

```
Generation 1: 22.4, 22.5  (119 commands)
Generation 2: 22.6, 22.7  (124 commands = Gen1 + 5 new)
```

The 5 new commands in Generation 2:
- `create_report_config`
- `delete_report_config`
- `get_report_configs`
- `modify_report_config`
- `get_features`

### Command Availability Matrix

```
Command                  | 22.4 | 22.5 | 22.6 | 22.7 |
-------------------------|------|------|------|------|
(all 119 base commands)  |  ✅  |  ✅  |  ✅  |  ✅  |
create_report_config     |  ❌  |  ❌  |  ✅  |  ✅  |
delete_report_config     |  ❌  |  ❌  |  ✅  |  ✅  |
get_report_configs       |  ❌  |  ❌  |  ✅  |  ✅  |
modify_report_config     |  ❌  |  ❌  |  ✅  |  ✅  |
get_features             |  ❌  |  ❌  |  ✅  |  ✅  |
```

### Data Flow (Version Gating in Mock Server)

```
Client Request
  │
  ▼
Handler::handle_stateful()
  │
  ├── get_version → always allowed (pre-auth)
  ├── authenticate → always allowed (pre-auth)
  │
  ├── version_check(cmd.name, self.version)
  │     ├── Ok → proceed to CRUD handler
  │     └── Err → return error_response(400, "Command not available in GMP {version}")
  │
  └── handle_create / handle_get / handle_modify / handle_delete
```

---

## 3. Interface Definitions

### 3.1 `gvm-mock-server` — Version Gating

#### New: `version::command_available()`

```rust
/// Check if a command is available in the given GMP version.
///
/// Returns `true` for all base commands (available in all versions).
/// Returns `false` for 22.6+ commands when version is 22.4 or 22.5.
pub fn command_available(command_name: &str, version: GmpVersion) -> bool
```

Commands gated to 22.6+:
- `create_report_config`
- `delete_report_config`
- `get_report_configs`
- `modify_report_config`
- `get_features`

#### New: Handler integration

In `Handler::handle_stateful()`, after auth check but before command dispatch:

```rust
if !command_available(&cmd.name, self.version) {
    return error_response(
        &cmd.name,
        400,
        &format!(
            "Command '{}' is not available in GMP {}",
            cmd.name,
            self.version
        ),
    );
}
```

#### New: `get_features` handler

In stateful mode, `get_features` returns a response listing enabled features. For the mock server, return a minimal set:

```xml
<get_features_response status="200" status_text="OK">
  <!-- Empty or with mock features depending on mode -->
</get_features_response>
```

#### New: Report Config Resource

Add `report_config` to the resource store with standard CRUD operations:
- `create_report_config` — name, report_format_id, params
- `get_report_configs` — list with optional filter
- `modify_report_config` — name, comment, params
- `delete_report_config` — by ID

The `ResourceStore` already handles generic resource types; report_config follows the same pattern as existing resources (target, task, etc.).

### 3.2 `gvm-gmp` — New Command Modules

#### `commands::report_configs`

```rust
pub fn create_report_config(name: &str, report_format_id: &str) -> impl Request
pub fn create_report_config_opts(name: &str, report_format_id: &str, opts: CreateReportConfigOpts) -> impl Request
pub fn delete_report_config(id: &str) -> impl Request
pub fn get_report_configs() -> impl Request
pub fn get_report_configs_opts(opts: GetReportConfigsOpts) -> impl Request
pub fn get_report_config(id: &str) -> impl Request
pub fn modify_report_config(id: &str, opts: ModifyReportConfigOpts) -> impl Request

pub struct CreateReportConfigOpts {
    pub comment: Option<String>,
    pub params: Vec<ReportConfigParam>,
}

pub struct GetReportConfigsOpts {
    pub filter: Option<String>,
    pub first: Option<u32>,
    pub rows: Option<u32>,
}

pub struct ModifyReportConfigOpts {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub params: Vec<ReportConfigParam>,
}

pub struct ReportConfigParam {
    pub name: String,
    pub value: String,
}
```

#### `commands::features`

```rust
pub fn get_features() -> impl Request
```

### 3.3 `gvm-client` — Version-Specific Methods

The `Gmp226`, `Gmp227`, and `GmpNext` wrappers gain additional methods:

```rust
impl<C: GvmConnection> Gmp226<C> {
    // All base GmpClient methods via Deref/delegation, PLUS:
    pub async fn create_report_config(&mut self, ...) -> Result<Response, GvmError>;
    pub async fn get_report_configs(&mut self, ...) -> Result<Response, GvmError>;
    pub async fn modify_report_config(&mut self, ...) -> Result<Response, GvmError>;
    pub async fn delete_report_config(&mut self, ...) -> Result<Response, GvmError>;
    pub async fn get_features(&mut self) -> Result<Response, GvmError>;
}
// Same for Gmp227 and GmpNext
```

`Gmp224` and `Gmp225` do **not** get these methods → compile-time error if you try to use report_config commands on a 22.4/22.5 client.

**Implementation approach:** Use a shared trait for the 22.6+ methods:

```rust
/// Commands available in GMP 22.6+.
pub trait Gmp226Commands {
    async fn create_report_config(&mut self, name: &str, report_format_id: &str) -> Result<Response, GvmError>;
    async fn get_report_configs(&mut self) -> Result<Response, GvmError>;
    async fn modify_report_config(&mut self, id: &str, opts: ModifyReportConfigOpts) -> Result<Response, GvmError>;
    async fn delete_report_config(&mut self, id: &str) -> Result<Response, GvmError>;
    async fn get_features(&mut self) -> Result<Response, GvmError>;
}

impl<C: GvmConnection> Gmp226Commands for Gmp226<C> { ... }
impl<C: GvmConnection> Gmp226Commands for Gmp227<C> { ... }
impl<C: GvmConnection> Gmp226Commands for GmpNext<C> { ... }
// NOT implemented for Gmp224 or Gmp225
```

---

## 4. Error Handling

### Mock Server Version Rejection

When a command is not available for the configured version:

```xml
<{command}_response status="400" status_text="Command '{command}' is not available in GMP {version}"/>
```

Status 400 chosen because the command is syntactically valid but not supported in this version context. This matches how gvmd handles unknown commands.

### Client Version Mismatch

Compile-time enforcement: calling a 22.6 method on a `Gmp224` is a type error.

For `GmpVersioned` (dynamic dispatch), callers pattern-match on the variant:

```rust
match client {
    GmpVersioned::V226(c) | GmpVersioned::V227(c) => {
        c.get_features().await?;
    }
    _ => { /* not available */ }
}
```

---

## 5. Dependencies

No new external dependencies. Uses existing:
- `quick-xml` (XML generation in gvm-gmp)
- `gvm-protocol` (Request/Response traits)
- `async-trait` (for `Gmp226Commands` trait with async methods)

---

## 6. Testing Strategy

### 6.1 Unit Tests

**`gvm-mock-server::version`**
- `command_available("get_version", V22_4)` → true
- `command_available("create_report_config", V22_4)` → false
- `command_available("create_report_config", V22_6)` → true
- `command_available("get_features", V22_5)` → false
- `command_available("get_features", V22_7)` → true
- All 119 base commands → true for all versions

**`gvm-gmp::commands::report_configs`**
- `create_report_config` XML output matches GMP schema
- `create_report_config_opts` with all optional fields
- `get_report_configs` / `get_report_config` XML output
- `modify_report_config` with various opt combinations
- `delete_report_config` XML output

**`gvm-gmp::commands::features`**
- `get_features` XML output

### 6.2 Integration Tests

**Version rejection (mock server + connection)**

Parameterized across V22_4 and V22_5:
- Connect to mock server configured with version
- Authenticate
- Send `create_report_config` → expect 400 error
- Send `get_features` → expect 400 error
- Send `get_report_configs` → expect 400 error
- Send `create_target` → expect success (base command)

**Version acceptance (mock server + connection)**

Parameterized across V22_6 and V22_7:
- Connect to mock server configured with version
- Authenticate
- Send `create_report_config` → expect success
- Send `get_features` → expect success
- Send `get_report_configs` → expect success
- Full report_config CRUD lifecycle

**Cross-version CRUD parity**

Parameterized across all 4 versions:
- Target CRUD → identical behavior
- Task CRUD → identical behavior
- Note CRUD → identical behavior
- Verify response XML structure is version-consistent for shared commands

### 6.3 Client Tests

- `GmpVersioned::connect()` with 22.4 → V224 variant
- `GmpVersioned::connect()` with 22.6 → V226 variant
- V226 client: `get_features()` succeeds
- V224 client: `get_features()` is not available (compile-time check documented in test comment)

### 6.4 Test Infrastructure

```rust
/// Helper: spawn mock servers for all versions
async fn servers_all_versions() -> Vec<(GmpVersion, MockGmpServer)> {
    vec![
        (GmpVersion::V22_4, server_with_version(GmpVersion::V22_4).await),
        (GmpVersion::V22_5, server_with_version(GmpVersion::V22_5).await),
        (GmpVersion::V22_6, server_with_version(GmpVersion::V22_6).await),
        (GmpVersion::V22_7, server_with_version(GmpVersion::V22_7).await),
    ]
}
```

Use `rstest` `#[case]` for parameterized version testing.

---

## 7. Implementation Phases

### Phase 1: Version Gating in Mock Server ⬜
**Estimated LOC:** ~80
**Files:**
- `crates/gvm-mock-server/src/version.rs` — add `command_available()`
- `crates/gvm-mock-server/src/handler.rs` — add version check before dispatch
- `crates/gvm-mock-server/src/version.rs` — unit tests

### Phase 2: New Commands in gvm-gmp ⬜
**Estimated LOC:** ~200
**Files:**
- `crates/gvm-gmp/src/commands/report_configs.rs` — new module
- `crates/gvm-gmp/src/commands/features.rs` — new module
- `crates/gvm-gmp/src/commands/mod.rs` — re-export
- `crates/gvm-gmp/tests/test_report_configs.rs` — command XML tests
- `crates/gvm-gmp/tests/test_features.rs` — command XML tests

### Phase 3: Mock Server Report Config CRUD ⬜
**Estimated LOC:** ~60
**Files:**
- `crates/gvm-mock-server/src/handler.rs` — `get_features` handling
- `crates/gvm-mock-server/src/store.rs` — report_config follows existing resource pattern (no changes needed if generic)

### Phase 4: Client Version Wrappers ⬜
**Estimated LOC:** ~150
**Files:**
- `crates/gvm-client/src/lib.rs` — `Gmp226Commands` trait + impls
- `crates/gvm-client/src/lib.rs` — version-specific method delegation

### Phase 5: Cross-Version Tests ⬜
**Estimated LOC:** ~250
**Files:**
- `crates/gvm-mock-server/tests/version_gating.rs` — rejection/acceptance tests
- `crates/gvm-mock-server/tests/cross_version_parity.rs` — parameterized CRUD across versions
- `crates/gvm-client/tests/versioned_client.rs` — client wrapper tests

**Total estimated:** ~740 LOC across 5 phases

---

## 8. Design Decisions

### DD-1: Two-generation model, not per-version
**Decision:** Treat 22.4/22.5 as identical and 22.6/22.7 as identical.
**Rationale:** The GMP docs confirm 22.5 has no changes over 22.4, and 22.7 has no changes over 22.6. Greenbone's own docs redirect 22.4→22.5 and 22.6→22.7. Modeling per-version differences that don't exist would add complexity with no value.

### DD-2: 400 status for version-rejected commands
**Decision:** Return status 400 ("bad request") for commands not available in the configured version.
**Rationale:** Consistent with how gvmd handles unknown/unsupported commands. Alternatives considered: 404 (not a resource), 501 (not implemented) — but 400 is the GMP convention for invalid commands.

### DD-3: Compile-time version safety via trait
**Decision:** Use a `Gmp226Commands` trait implemented only on 22.6+ wrapper types.
**Rationale:** Provides compile-time safety — calling `get_features()` on a `Gmp224` is a type error, not a runtime error. This is the Rust-idiomatic approach. Alternative considered: runtime version check in each method — rejected because it moves errors from compile-time to runtime.

### DD-4: `command_available()` as a simple function, not registry
**Decision:** Implement version gating as a match on a small set of gated commands, not a full command registry.
**Rationale:** Only 5 commands differ between generations. A full registry would be over-engineered. If future GMP versions add more divergence, we can migrate to a registry then.

---

## 9. Open Questions

1. **Audit/compliance response rendering:** GET_REPORTS with `usage_type=audit` returns different XML (compliance_count/compliance instead of result_count/severity). Should the mock server support this in this phase, or defer?
   - **Recommendation:** Defer. The audit response format is complex and not required by openvas-mcp-server. File a separate issue.

2. **GET_INFO type changes (CPE/CVE):** The 22.6 changes to CPE/CVE elements in GET_INFO responses affect response XML structure. Should the mock server render version-appropriate GET_INFO responses?
   - **Recommendation:** Defer. GET_INFO is not in the current mock server's stateful handler scope. File a separate issue when GET_INFO support is added.

3. **Deprecated elements:** Should the mock server emit deprecated elements (e.g., `first`/`last` on GET_TASKS) for 22.4 and omit them for later versions?
   - **Recommendation:** No. Deprecated elements are still valid in all versions; they're just not recommended. Omitting them would break clients that still use them.
