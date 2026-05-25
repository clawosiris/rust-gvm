# MCP Implementation Roadmap

## 1. Goal

Implement the `rust-gvm` gateway so `MCP` ships as a native public surface alongside `REST` and later `gRPC`, all backed by one shared execution core and one canonical operation catalog.

This roadmap assumes the architecture already established in [MCP Gateway Surface Analysis](mcp-gateway-surface-analysis.md):

- `REST`, `gRPC`, and `MCP` are peer adapters
- parity is enforced at the capability level
- auth, policy, routing, errors, and audit stay below the adapters

## 2. Delivery Strategy

The safest path is not "build an MCP server quickly." The safe path is:

1. freeze the canonical operation model
2. build the shared gateway core around that model
3. ship a narrow vertical slice through `REST` and `MCP`
4. expand domain coverage with parity tests
5. add `gRPC` once the core semantics are stable

That sequencing avoids the failure mode where `MCP` starts as a sidecar and later has to be pulled back into the real gateway architecture.

### 2.1 Customer-facing parity table

The contract to preserve throughout implementation is:

- customers can reach the same capability set through `REST`, `gRPC`, or `MCP`
- transport-specific syntax may differ
- missing parity must be treated as a defect unless the exception is explicitly documented
- opening a new endpoint, RPC method, or MCP tool creates a rollout obligation for the other shipped surfaces in the same capability area

| Canonical operation | REST endpoint | gRPC method | MCP tool | Required in first shipped slice |
| --- | --- | --- | --- | --- |
| `sessions.create` | `POST /api/v1/sessions` | `CreateSession` | `sessions.create` | yes |
| `sessions.delete` | `DELETE /api/v1/sessions/{token}` | `DeleteSession` | `sessions.delete` | yes |
| `system.get_version` | `GET /api/v1/system/version` | `GetVersion` | `system.get_version` | yes |
| `targets.list` | `GET /api/v1/targets` | `ListTargets` | `targets.list` | phase 4 |
| `targets.create` | `POST /api/v1/targets` | `CreateTarget` | `targets.create` | phase 4 |
| `tasks.list` | `GET /api/v1/tasks` | `ListTasks` | `tasks.list` | phase 4 |
| `tasks.create` | `POST /api/v1/tasks` | `CreateTask` | `tasks.create` | phase 4 |
| `tasks.start` | `POST /api/v1/tasks/{id}/start` | `StartTask` | `tasks.start` | phase 4 |
| `tasks.stop` | `POST /api/v1/tasks/{id}/stop` | `StopTask` | `tasks.stop` | phase 4 |
| `reports.list` | `GET /api/v1/reports` | `ListReports` | `reports.list` | phase 4 |
| `reports.get` | `GET /api/v1/reports/{id}` | `GetReport` | `reports.get` | phase 4 |

`gRPC` can land after the first `REST + MCP` slice, but the table remains the target shape from day one. The point is sequencing, not relaxing parity.

## 3. Recommended Implementation Shape

For the first implementation, keep the work inside the `rust-gvm` workspace rather than splitting immediately into a new standalone repo.

Recommendation:

- add gateway crates under the existing workspace while the contracts are still moving
- keep the public gateway binary as a separate crate/binary target
- split to a dedicated `gvm-gateway` repo only if release cadence, ownership, or dependency boundaries later require it

Suggested crate layout:

- `gvm-gateway-core`
- `gvm-gateway-rest`
- `gvm-gateway-mcp`
- `gvm-gateway-grpc` later
- `gvm-gateway-bin`

`gvm-gateway-core` should own:

- operation catalog
- request/response envelope types
- normalized error model
- session/auth abstractions
- authorization hooks
- audit event model
- backend execution traits

## 4. Phase Plan

### Phase 0: Decision Closure and Scope Freeze

Purpose: prevent churn before code exists.

Deliverables:

- confirm workspace-first implementation instead of a new repo
- define the initial operation domains
- decide which MCP affordances are mandatory in v1: tools only, or tools plus limited resources
- define the initial auth model
- define the parity rule and exception process

Decisions to lock:

- initial domains: `system`, `sessions`, `targets`, `tasks`, `reports`
- initial auth pattern: explicit session bootstrap remains the default
- initial MCP model: tools required, resources optional
- initial surface sequence: `REST + MCP` first, `gRPC` after core stabilization
- new surface exposure rule: no new capability lands on one shipped surface without the matching exposure plan for the others

Exit criteria:

- one short design note or ADR captures the above decisions
- no new adapter-specific implementation starts before this is written down

### Phase 1: Canonical Operation Catalog and Core Contracts

Purpose: create the shared language that every adapter must obey.

Deliverables:

- stable operation ids such as `tasks.start`, `reports.get`, `targets.create`
- request and response schemas expressed as Rust types
- surface exposure metadata for each operation
- normalized error taxonomy
- audit event schema
- session and execution traits

The catalog should answer, for every operation:

- what it is called
- who may invoke it
- which backend handler executes it
- which surfaces expose it
- whether it paginates, streams, or runs as a long task

Implementation notes:

- keep the catalog close to Rust types rather than inventing an external DSL first
- allow metadata-driven derivation later, but do not block the first implementation on code generation
- make "surface enabled" a first-class field so parity can be tested explicitly

Exit criteria:

- a compile-time catalog exists for the first operation set
- every operation has request/response/error metadata
- no adapter maps directly to GMP without going through a catalog-backed core operation

### Phase 2: Gateway Core Runtime

Purpose: make the shared engine real before multiplying surfaces.

Deliverables:

- runtime configuration model
- gvmd connection/session pool manager
- explicit session bootstrap flow
- request validation layer
- policy enforcement hook points
- normalized error mapping
- audit event emission
- health and capability reporting

Core runtime responsibilities:

- open and authenticate gvmd sessions
- bind gateway session tokens to live backend sessions
- serialize work per backend session where required
- apply expiry and cleanup
- emit uniform audit events for every operation

Recommended first core APIs:

- `create_session`
- `delete_session`
- `get_version`
- `execute(operation_id, request, session)`

Exit criteria:

- the core can execute at least `system.get_version` and `sessions.create/delete`
- audit and error paths work before any domain-heavy adapter logic is added

### Phase 3: REST and MCP Skeleton Adapters

Purpose: stand up both public surfaces early so parity is a lived constraint, not a promise.

Deliverables:

- REST server skeleton
- MCP server skeleton
- shared adapter-to-core mapping layer
- generated or catalog-derived capability inventory

REST first-slice endpoints:

- `POST /api/v1/sessions`
- `DELETE /api/v1/sessions/{token}`
- `GET /api/v1/system/version`

MCP first-slice tools:

- `sessions.create`
- `sessions.delete`
- `system.get_version`

First-slice comparison table:

| Capability | REST endpoint | MCP tool | Same core operation required |
| --- | --- | --- | --- |
| create session | `POST /api/v1/sessions` | `sessions.create` | `sessions.create` |
| delete session | `DELETE /api/v1/sessions/{token}` | `sessions.delete` | `sessions.delete` |
| get version | `GET /api/v1/system/version` | `system.get_version` | `system.get_version` |

Recommended MCP rule:

- do not expose raw GMP passthrough
- tool descriptions must derive from the same operation metadata used by the core

Exit criteria:

- the same core operation can be called successfully through REST and MCP
- audit logs distinguish `surface=rest` from `surface=mcp`
- error normalization is visibly identical in category across both surfaces

### Phase 4: First Useful Vertical Slice

Purpose: prove the architecture on real workflow-bearing capabilities.

Deliverables:

- `targets.list`
- `targets.create`
- `tasks.list`
- `tasks.create`
- `tasks.start`
- `tasks.stop`
- `reports.list`
- `reports.get`

Why these first:

- they are enough to validate real agent workflows
- they cover both read and write operations
- they exercise long-running behavior and larger result sets

Design requirements in this phase:

- long-running task semantics must be modeled once in the core
- REST may use standard request/response plus task polling
- MCP may use task-oriented tools, chunked responses, or summary-plus-export patterns
- both still represent the same canonical capability

Exit criteria:

- one end-to-end scan workflow can be executed through REST
- the same workflow can be executed through MCP
- parity tests exist for every operation in the vertical slice

### Phase 5: Conformance and Drift Prevention

Purpose: keep future feature work from breaking the architecture.

Deliverables:

- catalog-to-surface conformance tests
- missing-surface CI failures
- representative behavioral equivalence tests
- adapter inventory snapshots

Minimum CI gates:

- if an operation is marked REST-enabled but missing from REST bindings, fail
- if an operation is marked gRPC-enabled but missing from gRPC bindings, fail
- if an operation is marked MCP-enabled but missing from MCP tools, fail
- if a parity-required operation exists on one shipped surface but not the other, fail
- if a new endpoint, RPC method, or tool is added without a matching canonical operation entry and explicit surface metadata, fail

Recommended test layers:

- unit tests for catalog metadata
- adapter registration tests
- integration tests through mock backend flows
- selected cross-surface equivalence tests

Exit criteria:

- parity drift becomes a CI problem, not a human code review problem

### Phase 6: Domain Expansion

Purpose: widen coverage after the skeleton and first slice prove stable.

Candidate domains:

- `configs`
- `schedules`
- `assets`
- `notes`
- `overrides`
- `tickets`
- advanced report/export operations

Important rule:

- expand by domain through the catalog and core first
- then expose the new operations in both REST and MCP in the same change stream where practical

Exit criteria:

- roadmap domains are added without creating adapter-only logic islands

### Phase 7: gRPC Surface

Purpose: add the third peer adapter once the core semantics are stable enough to justify `.proto` hardening.

Deliverables:

- initial `.proto` definitions derived from the same operation set
- auth/session integration matching the existing session model
- streaming support where it materially improves report-heavy operations

Why later:

- `gRPC` locks more wire-level structure earlier than `REST` or `MCP`
- the first architectural risk is parity and core correctness, not transport breadth

Exit criteria:

- `gRPC` adds transport value without forcing core rewrites

## 5. Cross-Cutting Requirements

These must be treated as day-one requirements, not post-MVP cleanup:

- observability: logs, metrics, audit trail
- secure secret handling during session bootstrap
- explicit session lifecycle cleanup
- backpressure and concurrency limits
- versioning strategy for operation schemas
- mock-backed integration coverage

If these are deferred too far, the gateway will work in demos and fail in real deployments.

## 6. Dependencies and Risks

### Dependencies

- stable first-cut operation catalog
- clear decision on repo/crate placement
- mock-backed validation path for representative workflows
- agreement on initial session bootstrap contract

### Primary risks

- adapter drift if one surface ships ahead of the catalog
- over-designing code generation before first useful behavior exists
- credential leakage if the MCP adapter hides session bootstrap sloppily
- performance surprises around long-running reports and connection pinning
- pressure to add raw passthrough escape hatches that bypass the catalog

## 7. Recommended Immediate Next Steps

The next implementation tasks should be:

1. write an ADR confirming workspace-first gateway implementation, initial domains, and `REST + MCP first`
2. scaffold `gvm-gateway-core`, `gvm-gateway-rest`, `gvm-gateway-mcp`, and `gvm-gateway-bin`
3. implement catalog and core contracts for `system.get_version` and `sessions.create/delete`
4. expose that slice through both REST and MCP
5. add parity CI checks before adding more domains

That is the minimum path that proves the architecture instead of merely describing it.
