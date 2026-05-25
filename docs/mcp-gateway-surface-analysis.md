# MCP Gateway Surface Analysis

## 1. Scope

This document defines how an MCP server fits into the `rust-gvm` gateway architecture.

The key decision is simple:

- `MCP` should be a first-class gateway surface
- it should live at the same architectural layer as `REST` and `gRPC`
- every gateway capability exposed through REST or gRPC should also be reachable through MCP

This is an adapter-layer decision, not a transport-layer one. The backend remains `rust-gvm -> GMP/XML -> gvmd`.

## 2. Why MCP Is Not Just Another Client

The earlier proxy analysis treats the MCP server as a downstream consumer that would call the gateway over REST or gRPC. That simplifies one integration, but it undershoots what MCP actually is in this system.

MCP is not just "another HTTP client." It is a separate interaction model with its own strengths:

- tool-oriented invocation rather than resource-oriented HTTP routes
- structured tool schemas rather than OpenAPI or `.proto`
- agent-friendly workflows where discovery, capability descriptions, and invocation metadata matter as much as the payload
- natural support for assistant-driven orchestration, not just human-driven dashboards or service-to-service RPC

If MCP is forced to sit behind REST or gRPC as a mere client:

- the gateway ends up with two architectural layers doing request mapping
- MCP semantics become constrained by whichever frontend sits in front of it
- endpoint parity becomes accidental rather than enforced
- the MCP contract drifts from the canonical execution model

The better model is to treat `REST`, `gRPC`, and `MCP` as three peer adapters over one shared application core.

## 3. Architectural Placement

### 3.1 Layer model

```text
┌─────────────────────────────────────────────────────────────────┐
│ Gateway Surfaces                                                │
│                                                                 │
│  REST Adapter      gRPC Adapter      MCP Adapter                │
│  HTTP/JSON         Protobuf/RPC      Tools/Resources            │
└───────────────┬───────────────┬───────────────┬─────────────────┘
                │               │               │
                └───────────────┴───────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│ Shared Gateway Core                                              │
│                                                                 │
│ - command catalog                                                 │
│ - request validation                                              │
│ - auth/session handling                                           │
│ - endpoint routing                                                │
│ - policy enforcement                                              │
│ - error normalization                                             │
│ - audit events                                                    │
│ - pagination/streaming policy                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│ rust-gvm Execution Layer                                         │
│                                                                 │
│ - gvm-client                                                     │
│ - gvm-gmp                                                        │
│ - gvm-protocol                                                   │
│ - gvm-connection                                                 │
└─────────────────────────────────────────────────────────────────┘
                                │
                           GMP/XML to gvmd
```

### 3.2 Consequence

The gateway should not implement business logic three times. It should define one execution contract, then expose that contract through three surface adapters:

- REST for browser/script-friendly HTTP integrations
- gRPC for typed service-to-service and streaming-heavy integrations
- MCP for agent/tool-driven integrations

## 4. Core Design Principle: Surface Parity

The gateway should enforce **surface parity**.

That means:

- if an operation is available through REST, it must be available through MCP
- if an operation is available through gRPC, it must be available through MCP
- if an operation is intentionally absent from one surface, that omission must be explicit and documented

This rule matters because MCP will otherwise become a partial sidecar interface that falls behind the "real" API.

### 4.1 What parity means in practice

Parity does not require identical wire shapes. It requires identical gateway capability.

Examples:

- REST: `POST /api/v1/tasks/{id}/start`
- gRPC: `StartTask(TaskIdRequest)`
- MCP: tool `tasks.start` with `{ "task_id": "..." }`

All three invoke the same core operation:

- operation id: `tasks.start`
- authorization category: `scan`
- execution handler: `start_task`
- audit event name: `task.started`

The surface adapter translates into the canonical operation, not directly into GMP.

### 4.2 Surface comparison table

The customer-facing rule is:

- `gRPC = REST = MCP`
- the surface syntax changes
- the reachable capability set does not
- adding a new endpoint, RPC method, or tool on any shipped surface must trigger the equivalent exposure work for the others unless an exception is documented up front

| Canonical operation | REST surface | gRPC surface | MCP surface | Customer-visible outcome |
| --- | --- | --- | --- | --- |
| `sessions.create` | `POST /api/v1/sessions` | `CreateSession(CreateSessionRequest)` | tool `sessions.create` | create an authenticated gateway session |
| `sessions.delete` | `DELETE /api/v1/sessions/{token}` | `DeleteSession(DeleteSessionRequest)` | tool `sessions.delete` | revoke an authenticated gateway session |
| `system.get_version` | `GET /api/v1/system/version` | `GetVersion(GetVersionRequest)` | tool `system.get_version` | read gateway/backend version and capability metadata |
| `targets.list` | `GET /api/v1/targets` | `ListTargets(ListTargetsRequest)` | tool `targets.list` | enumerate targets with the same filters/pagination semantics |
| `targets.create` | `POST /api/v1/targets` | `CreateTarget(CreateTargetRequest)` | tool `targets.create` | create a target with the same validation and auth rules |
| `tasks.list` | `GET /api/v1/tasks` | `ListTasks(ListTasksRequest)` | tool `tasks.list` | enumerate tasks with the same visibility and filtering rules |
| `tasks.create` | `POST /api/v1/tasks` | `CreateTask(CreateTaskRequest)` | tool `tasks.create` | create a task through the same core workflow |
| `tasks.start` | `POST /api/v1/tasks/{id}/start` | `StartTask(StartTaskRequest)` | tool `tasks.start` | start the same task with the same authorization/audit behavior |
| `tasks.stop` | `POST /api/v1/tasks/{id}/stop` | `StopTask(StopTaskRequest)` | tool `tasks.stop` | stop the same task with the same authorization/audit behavior |
| `reports.list` | `GET /api/v1/reports` | `ListReports(ListReportsRequest)` | tool `reports.list` | enumerate reports with the same filters and visibility |
| `reports.get` | `GET /api/v1/reports/{id}` | `GetReport(GetReportRequest)` | tool `reports.get` | fetch the same report payload, subject to surface-specific presentation rules |

This table is not just documentation. It should be derivable from the canonical operation catalog and enforced by CI so parity drift is impossible to miss.

## 5. Canonical Operation Catalog

The cleanest way to preserve parity is to define a canonical command catalog inside the gateway core.

Each operation should declare:

- stable operation id
- human description
- request schema
- response schema
- auth requirements
- idempotency semantics
- streaming or pagination behavior
- backend GMP mapping
- surface exposure metadata

Example shape:

```text
Operation: reports.get
Category: report
Request: { report_id, details?, filter?, page?, page_size? }
Response: { report, results?, page_info? }
Streaming: optional
Surfaces:
  - REST: GET /api/v1/reports/{id}
  - gRPC: GetReport(GetReportRequest)
  - MCP: reports.get
Backend:
  - GMP: get_report
```

This catalog becomes the source of truth for:

- route generation
- gRPC service definitions
- MCP tool manifests
- authorization tables
- audit event names
- conformance tests

## 6. MCP Adapter Model

### 6.1 MCP should expose tools, not raw GMP

The MCP layer should not expose a "send arbitrary XML" escape hatch as its primary contract. That would bypass the value of the shared execution core and create an unstable surface.

Instead, MCP should expose named tools aligned with the canonical operation catalog.

Examples:

- `system.get_version`
- `sessions.create`
- `sessions.delete`
- `targets.list`
- `targets.create`
- `targets.modify`
- `targets.delete`
- `tasks.list`
- `tasks.create`
- `tasks.start`
- `tasks.stop`
- `reports.get`
- `reports.list`
- `assets.list`

This keeps MCP consistent with the gateway's typed surface rather than turning it into a raw transport wrapper.

### 6.1.1 Endpoint versus toolset model

The gateway should expose one capability inventory and let each adapter render it in its own idiom:

| Concern | REST | gRPC | MCP |
| --- | --- | --- | --- |
| Discovery unit | endpoint | RPC method | tool |
| Grouping model | resource/path-oriented | service/method-oriented | domain/tool-oriented |
| Input contract | JSON request/route params/query params | protobuf request message | tool input schema |
| Output contract | JSON response + status | protobuf response + status/details | tool result payload + structured error |
| Long-running work | request + polling/resource follow-up | RPC + optional stream/status methods | task-oriented tools and follow-up tools/resources |
| Customer expectation | call an endpoint | call a method | call a tool |

Different interface shapes are acceptable. Different reachable capability sets are not.

### 6.2 Tool grouping

Tools should be grouped by domain, matching the gateway core rather than REST path structure:

- `system.*`
- `sessions.*`
- `targets.*`
- `tasks.*`
- `reports.*`
- `configs.*`
- `schedules.*`
- `notes.*`
- `overrides.*`
- `tickets.*`
- `assets.*`

This grouping works well for agents because discovery stays legible and semantically organized.

### 6.3 Resource exposure

If the MCP server also exposes resources in addition to tools, those resources should be derived from the same catalog and authorization rules.

Examples:

- endpoint inventory resource
- session status resource
- report snapshot resource
- gateway health/capability resource

Resources are optional. Tool parity is mandatory.

## 7. Session and Identity Model

The earlier proxy design uses explicit session bootstrap. That still holds.

### 7.1 One session model, three surfaces

The gateway should not invent a different authentication model for MCP. All three surfaces should use the same backend session semantics:

1. authenticate once
2. bind the authenticated gvmd connection to a gateway session
3. use that session for subsequent operations
4. apply expiry/revocation/cleanup uniformly

### 7.2 MCP-specific consequence

The MCP adapter should map client identity into the same gateway session model used by REST and gRPC.

Two viable patterns:

#### Pattern A: MCP tool calls carry a gateway session token

- simplest alignment with existing proxy design
- best when MCP clients already manage auth explicitly

#### Pattern B: MCP server owns session bootstrap internally

- useful for tightly managed local deployments
- simpler for agent consumers
- but increases credential-handling responsibility inside the MCP adapter

Recommendation:

- keep the canonical gateway session model external and explicit
- allow the MCP adapter to offer a `sessions.create` tool rather than hiding session creation out of band

That preserves observability and keeps authorization behavior consistent across surfaces.

## 8. Error Model

MCP cannot be an afterthought here because agent behavior is very sensitive to error shape.

The gateway core should define normalized errors once, then map them to each adapter:

- REST: HTTP status + JSON body
- gRPC: status code + structured details
- MCP: tool error with machine-readable code + human-readable message + retry hint when applicable

Recommended canonical error fields:

- `code`
- `message`
- `category`
- `retryable`
- `details`
- `operation_id`
- `endpoint_id`

Example categories:

- `auth_failed`
- `permission_denied`
- `not_found`
- `invalid_argument`
- `conflict`
- `rate_limited`
- `backend_unavailable`
- `session_expired`
- `unsupported_operation`

Without this normalization, REST, gRPC, and MCP will drift in behavior even if they hit the same backend handler.

## 9. Long-Running Operations and Streaming

The tri-surface design has to account for differences in interaction style.

### 9.1 REST

- good for polling
- acceptable for paginated reports
- awkward for very large report payloads unless chunked download or export endpoints exist

### 9.2 gRPC

- best fit for server streaming
- strong candidate for large report retrieval, event streams, or progress channels

### 9.3 MCP

- good fit for agent-driven polling and structured partial results
- can expose explicit tools such as `tasks.status`, `reports.get_chunk`, or `reports.export`
- should not depend on REST polling semantics internally

Recommendation:

- keep the core operation model independent of polling vs streaming
- let each surface expose the most natural interaction pattern
- preserve parity at the capability level, not the transport-mechanics level

Example:

- all surfaces support report retrieval
- REST may provide paginated JSON
- gRPC may provide streaming chunks
- MCP may provide chunked tool calls or summarized + export-oriented tools

Same capability. Different surface ergonomics.

## 10. Authorization and Audit

Authorization must live below the adapters, not inside them.

If `tasks.delete` is denied:

- REST returns `403`
- gRPC returns `PERMISSION_DENIED`
- MCP returns a tool error

But the decision itself comes from one shared policy engine evaluating one canonical operation id.

The audit log should capture:

- authenticated subject
- surface: `rest | grpc | mcp`
- operation id
- endpoint id
- target resource ids when available
- result
- latency

Including `surface` in audit events is important. MCP use will often represent agent activity rather than a human dashboard or backend service.

## 11. Testing Strategy

Surface parity should be enforced by tests, not by intention.

### 11.1 Conformance tests

For each canonical operation in the catalog:

- verify REST exposure if marked enabled
- verify gRPC exposure if marked enabled
- verify MCP exposure if marked enabled
- verify new surface additions do not appear on one shipped surface without matching catalog metadata and parity bindings for the others

### 11.2 Contract drift checks

Generate or validate:

- REST route list from the catalog
- gRPC service coverage from the catalog
- MCP tool manifest coverage from the catalog

If `reports.get` exists in the catalog but not in MCP, CI should fail.

### 11.3 Behavioral equivalence tests

Select representative operations and assert that:

- REST adapter
- gRPC adapter
- MCP adapter

all yield the same core result and same normalized error category for the same backend condition.

## 12. Phased Rollout

### Phase 1: Build tri-surface core from day one

- define canonical operation catalog
- define normalized auth/session/error/audit model
- implement REST + MCP first if that is the fastest route
- keep gRPC contract-ready even if not fully exposed yet

Why:

- MCP parity is easiest to preserve when the catalog exists before surface sprawl begins

### Phase 2: Add gRPC without changing core semantics

- map existing canonical operations into `.proto`
- reuse auth, policy, and audit logic
- use streaming where it materially improves report-heavy workflows

### Phase 3: Expand enterprise deployment concerns

- multi-endpoint routing
- forwarded identity from upstream proxies
- richer event streams
- conformance automation for every exposed domain

See [MCP Implementation Roadmap](mcp-implementation-roadmap.md) for the concrete phase sequencing, crate split recommendation, first vertical slice, and CI gates.

## 13. Recommendation

Adopt the following architecture rule:

> The `rust-gvm` gateway should expose `REST`, `gRPC`, and `MCP` as peer adapters over one shared execution core. MCP is not a downstream client of the gateway; it is one of the gateway's native public surfaces.

Concretely:

- design the gateway around a canonical operation catalog
- generate or derive surface bindings from that catalog
- require endpoint parity across REST, gRPC, and MCP
- treat every new endpoint, RPC method, or MCP tool as a cross-surface change, not an adapter-local change
- centralize auth, policy, routing, errors, and audit below the adapters
- allow each surface to express the same capability using interaction patterns natural to that surface

This keeps the architecture coherent, prevents MCP drift, and makes the gateway equally useful to:

- browser and script consumers
- service-to-service integrations
- agentic and assistant-driven workflows

## 14. Open Questions

1. Should the canonical operation catalog live as Rust types, declarative metadata, or both?
2. Which MCP capabilities should be tools only, and which should also be exposed as resources?
3. Should report export/download be modeled as a shared core operation with surface-specific delivery modes?
4. Do we want a raw "expert mode" passthrough operation anywhere, or should all public surfaces stay fully catalog-driven?
5. Should the first implementation repo be `gvm-gateway` or a crate/workspace addition under `rust-gvm`?
