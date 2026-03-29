# Phase 4: Response Models Implementation Spec

## Task

Implement Phase 4 of the response models OpenSpec for rust-gvm. This adds typed response models for all remaining GMP entities.

**Reference the existing pattern exactly.** Look at `crates/gvm-gmp/src/responses/target.rs` as the canonical template. Every new module MUST follow this pattern precisely.

## Architecture Rules

1. All files go in `crates/gvm-gmp/src/responses/`
2. Every public struct gets `#[derive(Debug, Clone, PartialEq, Eq)]`, `#[non_exhaustive]`, and `#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]`
3. Use helpers from `common.rs`: `parse_entity_meta`, `parse_named_entity`, `count_info`, `optional_u32`, `parse_bool`, `status_from_response`, `parse_document`, `parse_entity_id`, `ActionResponse`, etc.
4. SPDX header: `// SPDX-License-Identifier: AGPL-3.0-or-later` + `// SPDX-FileCopyrightText: 2026 Greenbone AG`
5. Each domain has: Entity struct, GetXxxResponse (list), CreateXxxResponse, type aliases for Modify/Delete
6. `from_response(&Response) -> Result<Self, ParseError>` on all response types
7. Entity parsing via `fn from_node(node: &XmlNode) -> Result<Self, ParseError>` (crate-private)
8. Timestamps as `Option<String>` (ISO 8601)
9. Booleans from `"1"/"0"` via `parse_bool`
10. Optional fields → `Option<T>`, missing = `None`

## Modules to Create (17 files)

### 1. `alert.rs`
```rust
pub struct Alert {
    pub meta: EntityMeta,
    pub event: Option<String>,        // e.g. "task_run_status_changed"
    pub condition: Option<String>,     // e.g. "always"
    pub method: Option<String>,        // e.g. "email"
    pub filter: Option<NamedEntity>,   // filter ref
    pub active: bool,                  // "1"/"0"
}
pub struct GetAlertsResponse { status, status_text, items: Vec<Alert>, counts: CountInfo }
pub struct CreateAlertResponse { status, status_text, id: EntityId }
pub type ModifyAlertResponse = ActionResponse;
pub type DeleteAlertResponse = ActionResponse;
```
Count element: `alert_count`

### 2. `credential.rs`
```rust
pub struct Credential {
    pub meta: EntityMeta,
    pub type_: Option<String>,         // "up", "usk", "cc", "snmp", etc.
    pub login: Option<String>,
    pub full_type: Option<String>,     // human-readable type
    pub allow_insecure: bool,
}
pub struct GetCredentialsResponse { ... items: Vec<Credential>, counts }
pub struct CreateCredentialResponse { ... id }
pub type ModifyCredentialResponse = ActionResponse;
pub type DeleteCredentialResponse = ActionResponse;
```
Count element: `credential_count`

### 3. `filter.rs`
```rust
pub struct Filter {
    pub meta: EntityMeta,
    pub type_: Option<String>,         // filter type (e.g. "task", "alert")
    pub term: Option<String>,          // filter expression
}
pub struct GetFiltersResponse { ... }
pub struct CreateFilterResponse { ... }
pub type ModifyFilterResponse = ActionResponse;
pub type DeleteFilterResponse = ActionResponse;
```
Count element: `filter_count`

### 4. `note.rs`
```rust
pub struct Note {
    pub meta: EntityMeta,
    pub text: Option<String>,
    pub nvt_oid: Option<String>,       // from <nvt oid="..."> attribute
    pub hosts: Option<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub task: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub active: bool,
    pub end_time: Option<String>,
}
pub struct GetNotesResponse { ... }
pub struct CreateNoteResponse { ... }
pub type ModifyNoteResponse = ActionResponse;
pub type DeleteNoteResponse = ActionResponse;
```
Count element: `note_count`
Note: `nvt_oid` is parsed from `<nvt oid="...">` attribute (child element named "nvt", get its "oid" attribute).

### 5. `override_.rs`
```rust
pub struct Override {
    pub meta: EntityMeta,
    pub text: Option<String>,
    pub nvt_oid: Option<String>,       // from <nvt oid="..."> attribute
    pub hosts: Option<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub new_severity: Option<String>,
    pub task: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub active: bool,
    pub end_time: Option<String>,
}
pub struct GetOverridesResponse { ... }
pub struct CreateOverrideResponse { ... }
pub type ModifyOverrideResponse = ActionResponse;
pub type DeleteOverrideResponse = ActionResponse;
```
Count element: `override_count`

### 6. `schedule.rs`
```rust
pub struct Schedule {
    pub meta: EntityMeta,
    pub icalendar: Option<String>,     // iCalendar data
    pub timezone: Option<String>,
    pub duration: Option<String>,
}
pub struct GetSchedulesResponse { ... }
pub struct CreateScheduleResponse { ... }
pub type ModifyScheduleResponse = ActionResponse;
pub type DeleteScheduleResponse = ActionResponse;
```
Count element: `schedule_count`

### 7. `tag.rs`
```rust
pub struct Tag {
    pub meta: EntityMeta,
    pub value: Option<String>,
    pub resource_type: Option<String>,
    pub resource_count: Option<u32>,   // from <resources><type>X</type><count><total>N</total></count></resources>
    pub active: bool,
}
pub struct GetTagsResponse { ... }
pub struct CreateTagResponse { ... }
pub type ModifyTagResponse = ActionResponse;
pub type DeleteTagResponse = ActionResponse;
```
Count element: `tag_count`
For resource_type/resource_count, parse from `<resources>` child: `<type>` text and `<count><total>` text.

### 8. `ticket.rs`
```rust
pub struct Ticket {
    pub meta: EntityMeta,
    pub status: Option<String>,         // "Open", "Fixed", "Closed"
    pub assigned_to: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub task: Option<NamedEntity>,
    pub open_note: Option<String>,
    pub fixed_note: Option<String>,
    pub closed_note: Option<String>,
}
pub struct GetTicketsResponse { ... }
pub struct CreateTicketResponse { ... }
pub type ModifyTicketResponse = ActionResponse;
pub type DeleteTicketResponse = ActionResponse;
```
Count element: `ticket_count`

### 9. `user.rs`
```rust
pub struct User {
    pub meta: EntityMeta,
    pub roles: Vec<NamedEntity>,        // multiple <role> children
    pub groups: Vec<NamedEntity>,       // multiple <group> children (note: groups is parent, group is child — parse <groups><group id=...><name>...</name></group></groups>)
    pub hosts_allow: Option<String>,    // "0" or "1"
    pub hosts: Option<String>,
}
pub struct GetUsersResponse { ... }
pub struct CreateUserResponse { ... }
pub type ModifyUserResponse = ActionResponse;
pub type DeleteUserResponse = ActionResponse;
```
Count element: `user_count`
Roles: iterate `node.children_named("role")` and parse each as NamedEntity (id attr + name child).
Groups: find `<groups>` child, then iterate its `<group>` children.

### 10. `group.rs`
```rust
pub struct Group {
    pub meta: EntityMeta,
    pub users: Option<String>,          // comma-separated user names
}
pub struct GetGroupsResponse { ... }
pub struct CreateGroupResponse { ... }
pub type ModifyGroupResponse = ActionResponse;
pub type DeleteGroupResponse = ActionResponse;
```
Count element: `group_count`

### 11. `role.rs`
```rust
pub struct Role {
    pub meta: EntityMeta,
    pub users: Option<String>,          // comma-separated user names
}
pub struct GetRolesResponse { ... }
pub struct CreateRoleResponse { ... }
pub type ModifyRoleResponse = ActionResponse;
pub type DeleteRoleResponse = ActionResponse;
```
Count element: `role_count`

### 12. `permission.rs`
```rust
pub struct Permission {
    pub meta: EntityMeta,
    pub subject_type: Option<String>,   // from <subject><type>...</type></subject>
    pub subject: Option<NamedEntity>,   // <subject id="..."><name>...</name></subject> — id from attr, name from child
    pub resource_type: Option<String>,  // from <resource><type>...</type></resource>
    pub resource: Option<NamedEntity>,  // <resource id="..."><name>...</name></resource>
}
pub struct GetPermissionsResponse { ... }
pub struct CreatePermissionResponse { ... }
pub type ModifyPermissionResponse = ActionResponse;
pub type DeletePermissionResponse = ActionResponse;
```
Count element: `permission_count`
For subject/resource: parse the child element, extract id from attribute, name from `<name>` child, type from `<type>` child.

### 13. `host.rs`
```rust
pub struct Host {
    pub meta: EntityMeta,
    pub ip: Option<String>,             // from <identifiers><identifier><name>ip</name><value>...</value></identifier></identifiers> OR direct <ip> child if present
    pub hostname: Option<String>,
    pub severity: Option<String>,       // from <host><severity><value>...</value></severity></host> or direct <severity> child text
    pub os: Option<String>,             // <os> child text
}
pub struct GetHostsResponse { ... }
pub struct CreateHostResponse { ... }
pub type ModifyHostResponse = ActionResponse;
pub type DeleteHostResponse = ActionResponse;
```
Count element: `asset_count` (hosts use the asset endpoint, count element is `asset_count`)
IMPORTANT: GMP hosts come from `get_assets` response, so the list tag is `<asset>` not `<host>`. The entity nodes are named `asset`, with type=host. Parse items from `node.children_named("asset")`.

Actually, looking more carefully at GMP, `get_hosts` returns a `get_assets_response` with `<asset>` children. Let me simplify: keep the entity as `Host` but the response parses `<asset>` nodes and uses `asset_count`.

### 14. `tls_certificate.rs`
```rust
pub struct TlsCertificate {
    pub meta: EntityMeta,
    pub certificate: Option<String>,    // base64 cert data
    pub issuer_dn: Option<String>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
    pub md5_fingerprint: Option<String>,
    pub sha256_fingerprint: Option<String>,
    pub subject_dn: Option<String>,
    pub valid: bool,
}
pub struct GetTlsCertificatesResponse { ... }
pub struct CreateTlsCertificateResponse { ... }
pub type ModifyTlsCertificateResponse = ActionResponse;
pub type DeleteTlsCertificateResponse = ActionResponse;
```
Count element: `tls_certificate_count`

### 15. `system.rs`
```rust
pub struct Setting {
    pub id: EntityId,                   // from id attribute
    pub name: String,
    pub comment: Option<String>,
    pub value: Option<String>,
}
pub struct GetSettingsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Setting>,
    // no counts for settings typically
}

pub struct HelpResponse {
    pub status: u16,
    pub status_text: String,
    pub help_text: String,              // body text of the response
}

pub struct DescribeAuthResponse {
    pub status: u16,
    pub status_text: String,
    pub groups: Vec<AuthGroup>,         // <group name="..."><auth_conf_setting>...</auth_conf_setting></group>
}
pub struct AuthGroup {
    pub name: String,
    pub settings: Vec<AuthConfSetting>,
}
pub struct AuthConfSetting {
    pub key: Option<String>,
    pub value: Option<String>,
}
```
Note: Settings don't have EntityMeta (no owner, in_use, writable, etc.) — they have a simpler structure. Parse `<setting id="..."><name>...</name><comment>...</comment><value>...</value></setting>`.

### 16. `report_format.rs`
```rust
pub struct ReportFormat {
    pub meta: EntityMeta,
    pub content_type: Option<String>,
    pub extension: Option<String>,
    pub summary: Option<String>,
    pub trust: Option<String>,          // "yes"/"no"
    pub active: bool,
    pub predefined: bool,
}
pub struct GetReportFormatsResponse { ... }
pub struct CreateReportFormatResponse { ... }
pub type ModifyReportFormatResponse = ActionResponse;
pub type DeleteReportFormatResponse = ActionResponse;
```
Count element: `report_format_count`

### 17. `report_config.rs`
```rust
pub struct ReportConfig {
    pub meta: EntityMeta,
    pub report_format: Option<NamedEntity>,  // ref to report format
}
pub struct GetReportConfigsResponse { ... }
pub struct CreateReportConfigResponse { ... }
pub type ModifyReportConfigResponse = ActionResponse;
pub type DeleteReportConfigResponse = ActionResponse;
```
Count element: `report_config_count`

## mod.rs Updates

Add all 17 new modules to `crates/gvm-gmp/src/responses/mod.rs`:
```rust
pub mod alert;
pub mod credential;
pub mod filter;
pub mod group;
pub mod host;
pub mod note;
pub mod override_;
pub mod permission;
pub mod report_config;
pub mod report_format;
pub mod role;
pub mod schedule;
pub mod system;
pub mod tag;
pub mod ticket;
pub mod tls_certificate;
pub mod user;
```

Add re-exports for all public types following the existing pattern.

## Testing

Each module MUST have these 5 standard tests (matching Phase 1-3 pattern):

1. `parses_multiple_*` — 2 items with all fields populated, validate counts + fields
2. `parses_empty_*` — 0 items, counts = 0
3. `parses_create_*_response` — status 201, id extraction (skip for system.rs)
4. `rejects_server_error` — non-2xx → ParseError::ServerError
5. `parses_missing_optional_*_fields` — only required fields, all optionals None

For `system.rs`, adapt tests:
- `parses_multiple_settings` — 2 settings
- `parses_empty_settings` — 0 settings
- `parses_help_response` — help text extraction
- `parses_describe_auth_response` — auth groups + settings
- `rejects_server_error` — error case

Test XML format: use `Response::from(r#"<get_xxx_response status="200" ...>...</get_xxx_response>"#)`

## Build Verification

After implementation:
1. `cargo check --all-features -p gvm-gmp` must pass
2. `cargo test -p gvm-gmp` must pass (all new + existing tests)
3. `cargo clippy --all-features -p gvm-gmp` must pass
4. No modifications to existing files except `mod.rs` (add modules + re-exports)

## Branch

Create a feature branch: `feat/response-models-phase4`
Commit message: `feat(gmp): add typed response models — Phase 4 (remaining entities)`
