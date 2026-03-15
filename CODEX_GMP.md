# CODEX TASK: Implement gvm-gmp crate

## Context

You are implementing `crates/gvm-gmp/` — the typed GMP command builder crate for the rust-gvm workspace. The full spec is in `spec/openspec.md` section 3.3.

The crate depends on `gvm-protocol` (same workspace) which provides `XmlCommand`, `Request` trait, and `Response`.

## What Already Exists

- `crates/gvm-gmp/Cargo.toml` — placeholder with workspace deps
- `crates/gvm-gmp/src/lib.rs` — empty placeholder
- `gvm-protocol` provides: `XmlCommand`, `Request` (trait), `Response`, `XmlReader`

## Architecture

```
crates/gvm-gmp/src/
├── lib.rs              # Re-exports, top-level docs
├── types.rs            # EntityId newtype, GmpVersion
├── enums.rs            # All GMP enums (AlertEvent, CredentialType, etc.)
├── commands/
│   ├── mod.rs          # Re-exports all command modules
│   ├── authentication.rs  # authenticate()
│   ├── version.rs      # get_version()
│   ├── tasks.rs        # create/get/modify/delete/start/stop/resume task
│   ├── targets.rs      # create/get/modify/delete target
│   ├── notes.rs        # create/get/modify/delete note
│   ├── overrides.rs    # create/get/modify/delete override
│   ├── alerts.rs       # create/get/modify/delete/test alert
│   ├── credentials.rs  # create/get/modify/delete credential
│   ├── filters.rs      # create/get/modify/delete filter
│   ├── scan_configs.rs # create/get/modify/delete/sync config
│   ├── scanners.rs     # create/get/modify/delete/verify scanner
│   ├── schedules.rs    # create/get/modify/delete schedule
│   ├── port_lists.rs   # create/get/modify/delete port_list
│   ├── reports.rs      # create/get/delete report
│   ├── results.rs      # get_results, get_result
│   ├── tickets.rs      # create/get/modify/delete ticket
│   ├── tags.rs         # create/get/modify/delete tag
│   ├── users.rs        # create/get/modify/delete user
│   ├── roles.rs        # create/get/modify/delete role
│   ├── groups.rs       # create/get/modify/delete group
│   ├── permissions.rs  # create/get/modify/delete permission
│   ├── hosts.rs        # create/get/modify/delete host asset
│   ├── nvts.rs         # get_nvts, get_nvt_families
│   ├── trashcan.rs     # empty_trashcan, restore
│   └── system.rs       # help, get_feeds, get_settings, get_aggregates, get_system_reports
└── tests/              # (integration tests go in crates/gvm-gmp/tests/)
```

## Implementation Rules

1. **Every command builder returns `impl Request`** by building an `XmlCommand` internally.
2. **Use the builder/opts pattern** for commands with many optional parameters:
   ```rust
   pub struct CreateTaskOpts {
       pub comment: Option<String>,
       pub alterable: Option<bool>,
       // ...
   }
   impl Default for CreateTaskOpts { ... }
   ```
3. **`EntityId`** is a newtype around `String` with validation (non-empty, UUID-like).
4. **Enums** use `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` and implement a `as_gmp_str()` method returning the GMP XML string value.
5. **No I/O** — this crate only builds XML commands. It depends on `gvm-protocol` for `XmlCommand` and `Request`.
6. **Tests**: Write unit tests for each command module verifying the generated XML is correct. Use `cmd.to_bytes()` and check the output contains expected XML elements/attributes.

## Priority Order

Implement in this order (most used by openvas-mcp-server first):
1. `types.rs` + `enums.rs` (foundations)
2. `authentication.rs` + `version.rs` (basics)
3. `tasks.rs` + `targets.rs` (core workflow)
4. `notes.rs` + `overrides.rs` + `tickets.rs` (annotations)
5. `scan_configs.rs` + `scanners.rs` + `schedules.rs` + `port_lists.rs` (configuration)
6. `alerts.rs` + `credentials.rs` + `filters.rs` (supporting)
7. `reports.rs` + `results.rs` + `nvts.rs` (read-heavy)
8. `users.rs` + `roles.rs` + `groups.rs` + `permissions.rs` (access control)
9. `hosts.rs` + `tags.rs` + `trashcan.rs` + `system.rs` (remaining)

## Example Implementation (tasks.rs)

```rust
use gvm_protocol::{Request, XmlCommand};
use crate::types::EntityId;
use crate::enums::HostsOrdering;

pub fn create_task(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("config", "").set_attribute("id", config_id.as_str());
    cmd.add_element_with_text("target", "").set_attribute("id", target_id.as_str());
    cmd.add_element_with_text("scanner", "").set_attribute("id", scanner_id.as_str());
    if let Some(comment) = &opts.comment {
        cmd.add_element_with_text("comment", comment);
    }
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", if alterable { "1" } else { "0" });
    }
    if let Some(ordering) = &opts.hosts_ordering {
        cmd.add_element_with_text("hosts_ordering", ordering.as_gmp_str());
    }
    for alert_id in &opts.alert_ids {
        let elem = cmd.add_element("alert");
        elem.set_attribute("id", alert_id.as_str());
    }
    if let Some(schedule_id) = &opts.schedule_id {
        let elem = cmd.add_element("schedule");
        elem.set_attribute("id", schedule_id.as_str());
    }
    cmd
}

#[derive(Debug, Default)]
pub struct CreateTaskOpts {
    pub comment: Option<String>,
    pub alterable: Option<bool>,
    pub hosts_ordering: Option<HostsOrdering>,
    pub schedule_id: Option<EntityId>,
    pub alert_ids: Vec<EntityId>,
    pub schedule_periods: Option<u32>,
    pub observers: Vec<String>,
    pub preferences: Vec<(String, String)>,
}

pub fn get_tasks(opts: GetTasksOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tasks");
    cmd.add_filter(opts.filter_string.as_deref(), opts.filter_id.as_ref().map(|id| id.as_str()));
    if let Some(trash) = opts.trash {
        cmd.set_attribute("trash", if trash { "1" } else { "0" });
    }
    if let Some(details) = opts.details {
        cmd.set_attribute("details", if details { "1" } else { "0" });
    }
    cmd
}

pub fn get_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks").attribute("task_id", task_id.as_str())
}

pub fn start_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("start_task").attribute("task_id", task_id.as_str())
}

pub fn stop_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("stop_task").attribute("task_id", task_id.as_str())
}

pub fn resume_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("resume_task").attribute("task_id", task_id.as_str())
}

pub fn delete_task(task_id: &EntityId, ultimate: bool) -> impl Request {
    let mut cmd = XmlCommand::new("delete_task").attribute("task_id", task_id.as_str());
    if ultimate {
        cmd = cmd.attribute("ultimate", "1");
    }
    cmd
}
```

## Checklist

- [ ] `types.rs` — `EntityId`, `GmpVersion`
- [ ] `enums.rs` — All GMP enums with `as_gmp_str()`
- [ ] `commands/` — All command modules (see list above)
- [ ] `lib.rs` — Re-export everything cleanly
- [ ] Unit tests for every command module
- [ ] `Cargo.toml` — ensure gvm-protocol dependency is correct
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` clean (no warnings)

When completely finished, run this command to notify me:
openclaw system event --text "Done: Implemented gvm-gmp typed command builder crate with full GMP 22.5 coverage" --mode now
