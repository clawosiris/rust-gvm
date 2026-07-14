# MCP Server Integration Testing — OpenSpec Addendum

## 1. Overview

Validate gvm-mock-server by running the `clawosiris/openvas-mcp-server` (a real Python GMP client) against it. This provides end-to-end proof that mock server responses are structurally correct and behaviorally realistic — not just "looks right in a unit test" but "a real client can parse and use these responses."

### Motivation

The openvas-mcp-server uses `python-gvm` to speak GMP over Unix sockets. By pointing it at our mock server instead of a real gvmd, we get:

1. **Response validation** — python-gvm's lxml parser + EtreeCheckCommandTransform will reject malformed/non-compliant GMP XML
2. **Protocol flow validation** — the real connect → get_version → disconnect → reconnect → authenticate → commands flow
3. **Behavioral validation** — CRUD workflows (create target → create task → start → get report) work end-to-end
4. **Cross-client confidence** — if both rust-gvm and python-gvm can talk to the mock server, it's protocol-compliant

### Connection Flow (python-gvm)

Critical detail discovered from source analysis:

```
Connection 1: connect() → send get_version → receive response → disconnect()
              ↓ parse version string → select GMPv224/v225/v226/v227/GMPNext
Connection 2: connect() → authenticate(username, password) → commands... → disconnect()
```

`python-gvm` does **two separate TCP/Unix connections**: first to probe the version, then a fresh connection for the authenticated session. The mock server must handle this correctly — specifically, each connection gets an independent session with independent auth state.

### GMP Commands Used by MCP Server

Extracted from `clawosiris/openvas-mcp-server` service layer:

| Domain | Commands |
|--------|----------|
| System | `get_version` |
| Tasks | `get_task`, `get_tasks`, `create_task`, `delete_task`, `start_task`, `stop_task`, `resume_task`, `clone_task` |
| Targets | `get_target`, `get_targets`, `create_target`, `modify_target`, `delete_target`, `clone_target` |
| Reports | `get_report`, `get_reports`, `delete_report` |
| Scan Configs | `get_scan_config`, `get_scan_configs` |
| Scanners | (implicit via task creation) |
| Schedules | `get_schedule`, `get_schedules` |
| Notes | `get_notes`, `get_note`, `create_note`, `modify_note`, `delete_note` |
| Overrides | `get_overrides`, `get_override`, `create_override`, `modify_override`, `delete_override` |
| Port Lists | `get_port_list`, `get_port_lists` |
| Tickets | `get_tickets`, `get_ticket`, `create_ticket`, `modify_ticket`, `delete_ticket` |
| Assets | `get_assets` (host/os types) |
| Compliance | `get_scan_configs` (policy), `get_tasks`, `get_task`, `start_task`, `stop_task`, `get_results` |
| Vulns | `get_report`, `get_nvts` |
| Auth | `authenticate` (via base client) |

### What Must Work

1. **Version negotiation** — mock returns `<get_version_response>` with `<version>22.5</version>`, python-gvm selects GMPv225
2. **Authentication** — mock validates credentials, returns role/timezone
3. **Per-session auth state** — connection 1 (version probe) is unauthenticated; connection 2 authenticates fresh
4. **CRUD round-trips** — create/get/modify/delete for targets, tasks, notes, overrides, tickets
5. **Task lifecycle** — create → start → stop → resume → get status
6. **Filter strings** — `get_tasks(filter_string="...")` passes through
7. **Response structure** — all responses must have correct element nesting that lxml can parse

---

## 2. Mock Server Requirements (Gaps to Fill)

### 2.1 Already Working
- ✅ Unix socket listener
- ✅ TCP listener
- ✅ get_version with configurable version
- ✅ authenticate with credential validation
- ✅ Per-session auth state
- ✅ CRUD for generic resources (create/get/modify/delete)
- ✅ Task lifecycle (start/stop/resume)
- ✅ Clone support
- ✅ Trash/restore
- ✅ Filter string support (basic)
- ✅ Fault injection

### 2.2 Gaps to Address

#### Gap 1: `get_assets` command (resolved)
Current gvmd and python-gvm use the canonical `type="host|os"` attribute and
nested asset payloads. The stateful mock now follows that behavior by default,
including host lifecycle semantics and canonical host/OS responses. Historical
flat `asset_type`/`value` inputs remain available only through the explicit
`AssetInputProfile::LegacyFlatCompatibility` profile.

#### Gap 2: `get_results` command
Called by compliance service: `gmp.get_results(filter_string=...)`. Results are nested inside reports in real GMP but can also be queried directly.

**Fix:** Add result resources to the store, or return realistic fixture XML for `get_results`.

#### Gap 3: `get_nvts` command
Called by vulns service. NVTs (Network Vulnerability Tests) are a distinct resource type.

**Fix:** Add NVT fixture support — return a realistic list of NVTs.

#### Gap 4: `get_feeds` command (implicit)
Some python-gvm versions probe feeds on connect. Not critical but good to handle.

**Fix:** Return a basic `get_feeds_response` in echo mode fallback (already works).

#### Gap 5: Response XML structure for `get_report`
Reports have deeply nested XML (results, hosts, ports, NVTs inside). The current generic `Resource::to_xml()` may not produce the nested structure python-gvm expects.

**Fix:** Add report-specific XML generation with proper nesting (results, host details, etc.).

#### Gap 6: `create_note` / `create_override` argument parsing
These commands use `text`, `nvt_oid`, `hosts` elements rather than just `name`. The generic `handle_create` expects `name`.

**Fix:** Special-case create handlers for notes and overrides that extract the right elements.

#### Gap 7: `create_ticket` argument parsing
Uses `result_id`, `comment` — different from the generic name-based create.

**Fix:** Special-case create handler for tickets.

#### Gap 8: `modify_ticket` with `status` attribute
Ticket modification includes a status change — not just name/comment.

**Fix:** Extend modify handler to support ticket-specific attributes.

---

## 3. Integration Test Architecture

### 3.1 Test Harness

```
┌─────────────────────────────────────┐
│         Integration Test            │
│         (Python script)             │
│                                     │
│  1. Start mock server (binary)      │
│  2. Configure MCP server client     │
│  3. Run MCP operations via CLI/API  │
│  4. Assert results                  │
│  5. Check mock server history       │
│  6. Shutdown                        │
└──────────────┬──────────────────────┘
               │ Unix socket
┌──────────────▼──────────────────────┐
│      gvm-mock-server (binary)       │
│      --mode stateful                │
│      --socket /tmp/gvm-test.sock    │
│      --version 22.5                 │
└─────────────────────────────────────┘
```

### 3.2 Test Script (`tests/integration/test_mcp_server.py`)

A standalone Python script that:
1. Builds and starts `gvm-mock-server` binary
2. Clones/installs `openvas-mcp-server` in a venv
3. Configures it to use the mock socket
4. Exercises each MCP tool/service via the Python client
5. Reports pass/fail per operation

### 3.3 Test Scenarios

#### Scenario 1: Connection & Version
```python
# Verifies: version negotiation, two-connection flow
client = create_client(socket_path=mock_socket, style="local")
result = client.execute(lambda gmp: gmp.get_version())
assert "22.5" in str(result)
```

#### Scenario 2: Target CRUD
```python
# Verifies: create_target, get_target, modify_target, delete_target, clone_target
target_resp = client.execute(lambda gmp: gmp.create_target(
    name="Test Target", hosts=["192.168.1.0/24"]))
target_id = extract_id(target_resp)
# get, modify, clone, delete...
```

#### Scenario 3: Task Lifecycle
```python
# Verifies: create_task, start_task, get_task (status), stop_task, resume_task
task_resp = client.execute(lambda gmp: gmp.create_task(
    name="Test Scan", config_id=config_id, target_id=target_id, scanner_id=scanner_id))
task_id = extract_id(task_resp)
client.execute(lambda gmp: gmp.start_task(task_id))
status = client.execute(lambda gmp: gmp.get_task(task_id))
# verify Running status
```

#### Scenario 4: Notes/Overrides CRUD
```python
# Verifies: create_note, get_note, modify_note, delete_note
note_resp = client.execute(lambda gmp: gmp.create_note(
    text="Test note", nvt_oid="1.2.3.4"))
```

#### Scenario 5: Report Retrieval
```python
# Verifies: get_reports, get_report (with nested results)
reports = client.execute(lambda gmp: gmp.get_reports())
```

#### Scenario 6: Schedules, Port Lists, Scan Configs (read-only)
```python
# Verifies: get_schedules, get_port_lists, get_scan_configs
# (pre-seeded data)
```

---

## 4. Implementation Plan

### Phase 1: Mock Server Gaps (Rust)
1. ✅ Add a gvmd-conformant stateful `get_assets` and host lifecycle handler
2. Add special-case handlers for `get_results` and `get_nvts`
3. Add `create_note`/`create_override`/`create_ticket` with correct element parsing
4. Add `modify_ticket` with status support
5. Improve `get_report` XML structure (nested results)
6. Ensure per-connection session isolation (already works — verify)

### Phase 2: Integration Test Harness (Python)
1. Python test script that starts mock server binary
2. Uses python-gvm directly (not full MCP server) for initial validation
3. Exercises all commands from the MCP server's service layer
4. Reports per-operation pass/fail

### Phase 3: Full MCP Server Integration
1. Clone and configure openvas-mcp-server
2. Point at mock socket
3. Exercise via CLI commands or MCP tool calls
4. Validate end-to-end through the full stack

---

## 5. Success Criteria

- [ ] python-gvm can connect to mock server, negotiate version 22.5, authenticate
- [ ] All CRUD operations from the MCP server's service layer succeed
- [ ] Task lifecycle (create → start → stop → resume) works through python-gvm
- [ ] python-gvm's lxml parser accepts all mock server response XML
- [ ] No response parsing errors or unexpected status codes
- [ ] Mock server command history shows correct command sequence
