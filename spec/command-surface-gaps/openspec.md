# python-gvm Command-Surface Gaps — OpenSpec

**Issue**: #23  
**Status**: Draft  
**Date**: 2026-03-17

---

## 1. Overview

### Problem
python-gvm (v26.11.0) includes GMP request modules that are not yet represented in rust-gvm. Closing these gaps ensures rust-gvm can serve as a complete GMP client for operational workflows.

### Goal
Add the missing GMP command modules to `gvm-gmp` and corresponding mock-server support to `gvm-mock-server`, prioritized by operational importance.

### Scope
- GMP v224 baseline modules not yet in rust-gvm
- v226 additions (audit_reports)
- **Not** in scope: "next" (22.8+) experimental commands (defer until stable)

---

## 2. Gap Analysis

### 2.1 Current rust-gvm Coverage (31 modules)

alerts, authentication, credentials, features, filters, groups, hosts, notes, nvts, overrides, permissions, port_lists, report_configs, report_formats, reports, resource_names, results, roles, scan_configs, scanners, schedules, system, tags, targets, tasks, tickets, tls_certificates, trashcan, users, version

### 2.2 Missing Modules (from python-gvm v224)

#### Tier 1 — Medium Priority (commonly operational)

| Module | python-gvm Source | GMP Commands | Notes |
|--------|------------------|--------------|-------|
| **feed** | `v224/_feed.py` | `get_feeds` | Feed sync status; single read-only command |
| **policies** | `v224/_policies.py` | CRUD on policies | Maps to scan configs with `usage_type=policy`; may share implementation with `scan_configs` |
| **audits** | `v224/_audits.py` | CRUD on audit tasks | Maps to tasks with `usage_type=audit`; may share implementation with `tasks` |

#### Tier 2 — Low Priority (diagnostic/utility)

| Module | python-gvm Source | GMP Commands | Notes |
|--------|------------------|--------------|-------|
| **help** | `v224/_help.py` | `help` | List available GMP commands; simple single-command module |
| **aggregates** | `v224/_aggregates.py` | `get_aggregates` | Statistical queries with grouping; complex filter/aggregate attrs |
| **user_settings** | `v224/_user_settings.py` | `get_user_settings`, `modify_user_setting` | User preference management |
| **system_reports** | `v224/_system_reports.py` | `get_system_reports` | Performance/system data |

#### Tier 3 — Low Priority (SecInfo — read-only)

| Module | python-gvm Source | GMP Commands | Notes |
|--------|------------------|--------------|-------|
| **secinfo** | `v224/_secinfo.py` | Generic SecInfo query | Base for CPE/CVE/advisory queries |
| **cpes** | `v224/_cpes.py` | `get_cpes` | CPE dictionary entries |
| **cves** | `v224/_cves.py` | `get_cves` | CVE entries |
| **vulnerabilities** | `v224/_vulnerabilities.py` | `get_vulns` | Vulnerability objects |
| **cert_bund_advisories** | `v224/_cert_bund_advisories.py` | `get_cert_bund_advisories` | CERT-Bund advisories |
| **dfn_cert_advisories** | `v224/_dfn_cert_advisories.py` | `get_dfn_cert_advisories` | DFN-CERT advisories |
| **operating_systems** | `v224/_operating_systems.py` | `get_operating_systems` | OS detection results |

#### v226 Addition

| Module | python-gvm Source | GMP Commands | Notes |
|--------|------------------|--------------|-------|
| **audit_reports** | `v226/_audit_reports.py` | `get_report` (usage_type=audit), `delete_report` | Check if existing `reports` module covers this with an options parameter |

### 2.3 Not a Command Module

| Item | Notes |
|------|-------|
| `severity` | Helper enums/functions only; not a GMP command. May add as utility if needed. |

---

## 3. Implementation Strategy

### 3.1 Shared-Implementation Pattern

`policies` and `audits` in python-gvm are thin wrappers around `scan_configs` and `tasks` respectively, adding `usage_type` attributes:

```python
# audits._create_audit() essentially calls:
cmd = XmlCommand("create_task")
cmd.set_attribute("usage_type", "audit")
```

**Approach**: Extend existing `scan_configs` and `tasks` modules with `usage_type` parameters rather than creating separate modules. Add type-safe `UsageType` enum:

```rust
pub enum UsageType {
    Scan,    // default
    Audit,
    Policy,
}
```

### 3.2 SecInfo Pattern

All SecInfo modules follow the same pattern: `get_<type>` with optional filter/filter_id. These can share a generic implementation:

```rust
// Generic SecInfo command builder
pub fn get_secinfo(info_type: &str, opts: GetSecInfoOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_info");
    cmd.attr("type", info_type);
    // filter, filter_id, details...
    cmd
}
```

Individual modules (`cpes`, `cves`, etc.) become thin wrappers around this.

### 3.3 Mock Server Support

For each new command:
- **Tier 1** (feed, policies, audits): Add proper stateful handling in `gvm-mock-server`
- **Tier 2** (help, aggregates, etc.): Echo-mode responses sufficient initially
- **Tier 3** (SecInfo): Add fixture responses with representative data

---

## 4. Per-Module Specifications

### 4.1 `feed` Module

```rust
// gvm-gmp/src/commands/feed.rs
pub fn get_feeds() -> XmlCommand;
```

Response contains `<feed>` elements with type, name, version, status. Mock server: return a static feed list fixture.

### 4.2 `policies` (extend `scan_configs`)

```rust
// Add to gvm-gmp/src/commands/scan_configs.rs
pub fn create_policy(name: &str, opts: CreatePolicyOpts) -> XmlCommand;
pub fn get_policies(opts: GetPoliciesOpts) -> XmlCommand;
pub fn modify_policy(id: &EntityId, opts: ModifyPolicyOpts) -> XmlCommand;
pub fn delete_policy(id: &EntityId) -> XmlCommand;
pub fn clone_policy(id: &EntityId) -> XmlCommand;
```

These emit the same XML as `create_config` etc. but with `usage_type="policy"`.

### 4.3 `audits` (extend `tasks`)

```rust
// Add to gvm-gmp/src/commands/tasks.rs
pub fn create_audit(name: &str, opts: CreateAuditOpts) -> XmlCommand;
pub fn get_audits(opts: GetAuditsOpts) -> XmlCommand;
// start_audit, stop_audit, resume_audit — same as task actions
```

### 4.4 `audit_reports` (extend `reports`)

```rust
// Add to gvm-gmp/src/commands/reports.rs
pub fn get_audit_report(id: &EntityId, opts: GetAuditReportOpts) -> XmlCommand;
pub fn delete_audit_report(id: &EntityId) -> XmlCommand;
```

These emit `get_reports` / `delete_report` with `usage_type="audit"`.

### 4.5 `help` Module

```rust
// gvm-gmp/src/commands/help.rs (or add to system.rs)
pub fn help(format: Option<HelpFormat>) -> XmlCommand;
```

### 4.6 SecInfo Modules

```rust
// gvm-gmp/src/commands/secinfo.rs
pub fn get_cpes(opts: GetSecInfoOpts) -> XmlCommand;
pub fn get_cves(opts: GetSecInfoOpts) -> XmlCommand;
pub fn get_cert_bund_advisories(opts: GetSecInfoOpts) -> XmlCommand;
pub fn get_dfn_cert_advisories(opts: GetSecInfoOpts) -> XmlCommand;
pub fn get_operating_systems(opts: GetSecInfoOpts) -> XmlCommand;
pub fn get_vulnerabilities(opts: GetSecInfoOpts) -> XmlCommand;
```

---

## 5. Testing Strategy

### 5.1 Per Command Module

| Test Type | Scope |
|-----------|-------|
| Unit test | XML encoding verification (command → expected XML string) |
| Integration | Against mock server in Stateful mode (create/get/delete cycle where applicable) |
| Enum exhaustive | Any new enum variants (UsageType, HelpFormat, InfoType) |

### 5.2 Test Count Estimate

| Tier | Modules | Tests (est.) |
|------|---------|-------------|
| Tier 1 | 3 | ~30 (shared impl reduces duplication) |
| Tier 2 | 4 | ~15 |
| Tier 3 | 7 | ~20 (generic SecInfo pattern) |
| **Total** | **14** | **~65** |

---

## 6. Implementation Phases

### Phase 1 — Tier 1 (feed, policies, audits)
- Extend `tasks.rs` with `UsageType` parameter
- Extend `scan_configs.rs` with policy variants
- Add `feed.rs`
- Add mock-server support
- Tests

### Phase 2 — Tier 2 (help, aggregates, user_settings, system_reports)
- Add individual modules
- Echo/fixture mock responses
- Tests

### Phase 3 — Tier 3 (SecInfo)
- Generic `secinfo.rs` with typed wrappers
- Fixture responses
- Tests

### Phase 4 — audit_reports
- Extend `reports.rs` with usage_type parameter
- Tests

---

## 7. Success Criteria

- [ ] All Tier 1 commands produce correct XML matching python-gvm output
- [ ] Mock server handles policies/audits in Stateful mode
- [ ] No regressions in existing 620+ tests
- [ ] Rustdoc coverage for all new public items
- [ ] SPDX headers on all new files
