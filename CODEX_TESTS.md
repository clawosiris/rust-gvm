# CODEX TASK: Comprehensive test suite matching python-gvm coverage

## Context

Python-gvm has ~1,300 test methods. We have ~218. The biggest gap is in command XML verification and error-path testing.

Reference: `/tmp/python-gvm-src/tests/protocols/gmpv224/entities/` contains the authoritative test patterns.

## Scope

Add tests to these crates, in priority order:

### 1. gvm-gmp command tests (BIGGEST GAP — ~900 tests needed)

For EACH command module in `crates/gvm-gmp/src/commands/`, create a corresponding test file in `crates/gvm-gmp/tests/` (external integration tests, not inline):

```
crates/gvm-gmp/tests/
├── test_tasks.rs
├── test_targets.rs  
├── test_notes.rs
├── test_overrides.rs
├── test_alerts.rs
├── test_credentials.rs
├── test_filters.rs
├── test_scan_configs.rs
├── test_scanners.rs
├── test_schedules.rs
├── test_port_lists.rs
├── test_reports.rs
├── test_report_formats.rs
├── test_results.rs
├── test_tickets.rs
├── test_tags.rs
├── test_users.rs
├── test_roles.rs
├── test_groups.rs
├── test_permissions.rs
├── test_hosts.rs
├── test_tls_certificates.rs
├── test_trashcan.rs
├── test_system.rs
├── test_authentication.rs
├── test_version.rs
├── test_nvts.rs
├── test_resource_names.rs
└── test_enums.rs
```

#### Test pattern (follow python-gvm exactly)

Each test verifies the EXACT XML bytes output. Use this helper:

```rust
fn xml(request: impl gvm_protocol::Request) -> String {
    String::from_utf8(request.to_bytes()).expect("valid utf8")
}
fn id(s: &str) -> gvm_gmp::EntityId {
    gvm_gmp::EntityId::new(s).unwrap()
}
```

**For each command function, test:**

1. **Basic call** — verify exact XML output matches python-gvm's expected bytes
2. **Each optional parameter** — verify it appears in XML when set
3. **Default/empty optionals** — verify they're omitted from XML
4. **Multiple values** (e.g., alert_ids) — verify correct XML for 0, 1, and multiple items
5. **Boolean parameters** — verify "1" for true, "0" for false

**Example — test_tasks.rs should include (matching python-gvm):**

```rust
#[test]
fn test_create_task_basic() {
    assert_eq!(xml(create_task("foo", &id("c1"), &id("t1"), &id("s1"), Default::default())),
        "<create_task><name>foo</name><usage_type>scan</usage_type><config id=\"c1\"/><target id=\"t1\"/><scanner id=\"s1\"/></create_task>");
}

#[test]
fn test_create_task_with_comment() { ... }

#[test]
fn test_create_task_single_alert() { ... }

#[test]
fn test_create_task_multiple_alerts() { ... }

#[test]
fn test_create_task_empty_alerts() { ... }

#[test]
fn test_create_task_with_alterable_true() { ... }

#[test]
fn test_create_task_with_alterable_false() { ... }

#[test]
fn test_create_task_with_hosts_ordering() { ... }

#[test]
fn test_create_task_with_schedule() { ... }

#[test]
fn test_create_task_with_schedule_and_periods() { ... }

#[test]
fn test_create_task_with_observers() { ... }

#[test]
fn test_create_task_with_preferences() { ... }

#[test]
fn test_clone_task() { ... }

#[test]
fn test_delete_task_to_trash() { ... }

#[test]
fn test_delete_task_ultimate() { ... }

#[test]
fn test_get_task() { ... }

#[test]
fn test_get_tasks_simple() { ... }

#[test]
fn test_get_tasks_with_filter() { ... }

#[test]
fn test_get_tasks_with_filter_id() { ... }

#[test]
fn test_get_tasks_with_trash() { ... }

#[test]
fn test_get_tasks_with_details() { ... }

#[test]
fn test_modify_task_basic() { ... }

#[test]
fn test_modify_task_set_name() { ... }

#[test]
fn test_modify_task_set_comment() { ... }

#[test]
fn test_modify_task_clear_alerts() { ... }

#[test]
fn test_move_task() { ... }

#[test]
fn test_start_task() { ... }

#[test]
fn test_stop_task() { ... }

#[test]
fn test_resume_task() { ... }

#[test]
fn test_create_container_task() { ... }

#[test]
fn test_create_container_task_with_comment() { ... }
```

**IMPORTANT: XML attribute ordering.** `XmlCommand` uses `BTreeMap` so attributes are alphabetically sorted. When writing `assert_eq!`, use alphabetical attribute order. When a command has only child elements (no attributes on root), order matches insertion. For attributes on root element, they'll be sorted. Use `contains()` assertions instead of `assert_eq!` ONLY when attribute order is ambiguous on self-closing root elements with multiple attributes.

### 2. Enum exhaustive tests

In `crates/gvm-gmp/tests/test_enums.rs`, for EVERY enum:
- Test EVERY variant's `as_gmp_str()` value
- Test EVERY variant's `FromStr` round-trip
- Test that invalid string returns error

### 3. EntityId validation tests

In `crates/gvm-gmp/tests/test_types.rs`:
- Valid UUID accepted
- Empty string rejected
- Whitespace-only rejected
- Special characters rejected (except `-`, `_`, `.`)
- Display + Hash + Eq all work
- FromStr works

### 4. Client integration tests (expand)

In `crates/gvm-client/tests/client_integration.rs`, add (feature-gated `unix-socket-tests`):
- Connect to different GMP versions (22.4, 22.5, 22.6, 22.7) and verify enum variant
- Unsupported version returns error
- Send authenticate + verify response
- `call()` with server error maps to `GvmError::Server`
- Full CRUD lifecycle: create_target → create_task → start_task → get_task → stop_task → delete
- Disconnect + re-use errors

## Validation

After implementing:
1. `cargo test --workspace` — all pass
2. `cargo test -p gvm-gmp` — verify new external test files run
3. Count: `grep -r '#\[test\]' crates/gvm-gmp/tests/ | wc -l` should be >400

When done, run:
openclaw system event --text "Done: Comprehensive test suite with 400+ tests matching python-gvm coverage" --mode now
