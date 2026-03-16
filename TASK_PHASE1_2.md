# Task: GMP Version Gating — Phases 1 & 2

Implement version-specific GMP behavior per `spec/version-gating/openspec.md`.

## Phase 1: Mock Server Version Gating

### 1a. Add `command_available()` to `crates/gvm-mock-server/src/version.rs`

```rust
/// Commands only available in GMP 22.6+
const GMP_22_6_COMMANDS: &[&str] = &[
    "create_report_config",
    "delete_report_config",
    "get_report_configs",
    "modify_report_config",
    "get_features",
];

/// Check if a command is available in the given GMP version.
pub fn command_available(command_name: &str, version: GmpVersion) -> bool {
    if GMP_22_6_COMMANDS.contains(&command_name) {
        return matches!(version, GmpVersion::V22_6 | GmpVersion::V22_7);
    }
    true // all base commands available in all versions
}
```

Add unit tests in the same file:
- `command_available("get_version", V22_4)` → true
- `command_available("authenticate", V22_5)` → true
- `command_available("create_target", V22_4)` → true (base command)
- `command_available("create_report_config", V22_4)` → false
- `command_available("create_report_config", V22_5)` → false
- `command_available("create_report_config", V22_6)` → true
- `command_available("create_report_config", V22_7)` → true
- `command_available("get_features", V22_5)` → false
- `command_available("get_features", V22_6)` → true
- `command_available("get_features", V22_7)` → true
- `command_available("delete_report_config", V22_4)` → false
- `command_available("modify_report_config", V22_7)` → true

### 1b. Integrate version check into `crates/gvm-mock-server/src/handler.rs`

In `Handler::handle_stateful()`, after the `get_version` and `authenticate` checks but BEFORE the command dispatch match, add:

```rust
use crate::version::command_available;

// Version gating: reject commands not available in configured version
if !command_available(&cmd.name, self.version) {
    return crate::response_gen::error_response(
        &cmd.name,
        400,
        &format!(
            "Command '{}' is not available in GMP {}",
            cmd.name, self.version
        ),
    );
}
```

### 1c. Add `get_features` handling in the stateful handler

In the command dispatch match in `handle_stateful()`, add before the `_ =>` catch-all:

```rust
"get_features" => {
    format!(
        "<get_features_response status=\"200\" status_text=\"OK\">\
         </get_features_response>"
    ).into_bytes()
}
```

Make sure `command_available` is public (it already will be from 1a).

## Phase 2: New Commands in gvm-gmp

### 2a. Create `crates/gvm-gmp/src/commands/report_configs.rs`

Follow the pattern of existing command modules (e.g., `targets.rs`, `tasks.rs`). Each command function returns an `XmlCommand` implementing `Request`.

Commands to implement:
- `create_report_config(name: &str, report_format_id: &str) -> XmlCommand`
- `create_report_config_opts(name: &str, report_format_id: &str, opts: CreateReportConfigOpts) -> XmlCommand`
- `delete_report_config(id: &str) -> XmlCommand`
- `delete_report_config_opts(id: &str, opts: DeleteReportConfigOpts) -> XmlCommand`  
- `get_report_configs() -> XmlCommand`
- `get_report_configs_opts(opts: GetReportConfigsOpts) -> XmlCommand`
- `get_report_config(id: &str) -> XmlCommand`
- `modify_report_config(id: &str, opts: ModifyReportConfigOpts) -> XmlCommand`

Opts structs (all fields Optional, derive Default):
```rust
#[derive(Debug, Default)]
pub struct CreateReportConfigOpts {
    pub comment: Option<String>,
}

#[derive(Debug, Default)]
pub struct DeleteReportConfigOpts {
    pub ultimate: Option<bool>,
}

#[derive(Debug, Default)]
pub struct GetReportConfigsOpts {
    pub filter: Option<String>,
    pub first: Option<u32>,
    pub rows: Option<u32>,
}

#[derive(Debug, Default)]
pub struct ModifyReportConfigOpts {
    pub name: Option<String>,
    pub comment: Option<String>,
}
```

XML structure examples:
- `<create_report_config><name>N</name><report_format_id>ID</report_format_id></create_report_config>`
- `<delete_report_config report_config_id="ID"/>`  
- `<get_report_configs/>` or `<get_report_configs filter="name=foo"/>`
- `<get_report_configs report_config_id="ID"/>`
- `<modify_report_config report_config_id="ID"><name>N</name></modify_report_config>`

Add SPDX header: `// SPDX-License-Identifier: AGPL-3.0-or-later` and `// SPDX-FileCopyrightText: 2026 Greenbone AG`

Add doc comments on every public item (the crate has `#![warn(missing_docs)]`).

### 2b. Create `crates/gvm-gmp/src/commands/features.rs`

```rust
pub fn get_features() -> XmlCommand {
    XmlCommand::new("get_features")
}
```

Add SPDX header and doc comments.

### 2c. Register modules in `crates/gvm-gmp/src/commands/mod.rs`

Add `pub mod report_configs;` and `pub mod features;` to the module declarations.

### 2d. Create tests

Create `crates/gvm-gmp/tests/test_report_configs.rs`:
- Test each command function produces correct XML
- Test opts variants (with and without optional fields)
- Test delete with `ultimate: true`
- Follow the pattern of existing test files (e.g., `test_targets.rs`)

Create `crates/gvm-gmp/tests/test_features.rs`:
- Test `get_features()` produces `<get_features/>`

## Validation

After completing all changes, run:
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace`
4. `cargo doc --workspace --all-features --no-deps`

All must pass with zero warnings and zero errors.

When completely finished, run this command to notify me:
openclaw system event --text "Done: Phase 1+2 complete — version gating in mock server + new gvm-gmp commands" --mode now
