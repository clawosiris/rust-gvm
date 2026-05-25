# GMP API Proxy Analysis

## 1. Scope

This document focuses on exposing an API proxy in front of `gvmd`.

The direct transport between `rust-gvm` and `gvmd` is covered in [gvmd Transport Analysis for rust-gvm](gvmd-transport-analysis.md).

## 2. Why a Proxy Exists at All

gvmd exposes GMP as a raw XML stream over a persistent Unix socket or TLS connection. There is no native HTTP or gRPC interface.

That makes a proxy attractive for consumers that want:

- standard API contracts
- generated clients
- browser and script-friendly access
- simpler integration than raw GMP XML
- better handling for large responses and cross-service communication

## 3. Proxy Built on rust-gvm

Rather than waiting for Greenbone to change gvmd itself, we can build a gateway on top of `rust-gvm` that:

- talks GMP over Unix socket, SSH, or TLS to gvmd on the backend
- exposes REST, gRPC, and MCP on the frontend

```text
┌──────────────┐   REST / gRPC / MCP      ┌──────────────────┐      GMP/XML       ┌────────┐
│ Web UI       │◄────────────────────────►│ gvm-gateway      │◄──────────────────►│ gvmd   │
│ Scripts      │ HTTP/JSON, Protobuf,     │ (rust-gvm based) │   Unix socket      │        │
│ Automation   │ and MCP tools/resources  │                  │   or SSH/TLS       │        │
│ Agents       │                          │                  │                    │        │
└──────────────┘                          └──────────────────┘                    └────────┘
```

### Why this is viable

`rust-gvm` already provides the main backend building blocks:

- `gvm-connection`: Unix socket and SSH transports, with TLS planned
- `gvm-client`: async client with version negotiation and authentication
- `gvm-gmp`: typed GMP command builders
- `gvm-protocol`: response parsing and XML extraction

A gateway service can stay relatively thin if the public surfaces share one execution core:

1. Accept REST, gRPC, or MCP requests.
2. Map them to `gvm-gmp` command builders.
3. Send them via `gvm-client` and `gvm-connection` to gvmd.
4. Parse the XML response.
5. Return structured JSON, Protobuf, or MCP tool/resource payloads to the caller.

## 4. API Frontend Options

### Option A: REST/JSON proxy

Typical stack:

- `axum` or `actix-web`
- session bootstrap endpoint that accepts gvmd credentials and returns a proxy session token
- OpenAPI 3.1 for documentation and client generation

Example endpoints:

- `GET /api/v1/version`
- `POST /api/v1/sessions`
- `DELETE /api/v1/sessions/{token}`
- `GET /api/v1/tasks`
- `POST /api/v1/tasks`
- `GET /api/v1/tasks/{id}`
- `PUT /api/v1/tasks/{id}`
- `DELETE /api/v1/tasks/{id}`
- `POST /api/v1/tasks/{id}/start`
- `POST /api/v1/tasks/{id}/stop`
- `GET /api/v1/reports/{id}`
- `GET /api/v1/targets`

Strengths:

- accessible from `curl`, Postman, browsers, and any HTTP client
- OpenAPI can generate docs and SDKs
- easy to deploy beside gvmd
- good fit for simple automation and human-driven integrations

Weaknesses:

- GMP actions do not map perfectly to REST resources
- XML to JSON translation adds latency and complexity
- large reports need pagination, chunked responses, or a secondary streaming mechanism

### Option B: gRPC proxy

Typical stack:

- `tonic`
- `.proto` schemas as the contract
- HTTP/2 and TLS by default

Service sketch:

```proto
service GmpService {
  rpc GetVersion(Empty) returns (VersionResponse);
  rpc Authenticate(AuthRequest) returns (AuthResponse);
  rpc GetTasks(GetTasksRequest) returns (GetTasksResponse);
  rpc CreateTask(CreateTaskRequest) returns (CreateTaskResponse);
  rpc StartTask(TaskIdRequest) returns (TaskActionResponse);
  rpc GetReport(GetReportRequest) returns (stream ReportChunk);
}
```

Strengths:

- strongly typed contracts
- efficient Protobuf serialization
- server-side streaming for large reports
- better fit for service-to-service integrations
- auto-generated typed clients for many languages

Weaknesses:

- more upfront schema design work
- not browser-friendly without `grpc-web`
- harder to inspect manually than REST
- consumers need Protobuf and gRPC tooling

### Option C: Hybrid REST + gRPC + MCP

Expose both from one service:

- `REST` as the initial and most accessible interface for scripts, `curl`, Postman, and lightweight automation
- `gRPC` as a later addition for full-featured clients, large report retrieval, and service-to-service use
- `MCP` as a first-class agent-facing interface for tool-driven integrations
- a shared backend built on `gvm-client -> gvmd`

This is the preferred long-term model because it avoids forcing one style onto every consumer while allowing the project to preserve one core execution model across human, service, and agent-facing integrations.

## 5. Recommended Hybrid Architecture

The gateway should have five layers:

1. REST adapter for simple integrations
2. gRPC adapter for full integrations
3. MCP adapter for agent and tool-driven integrations
4. shared application core for session bootstrap, request validation, mapping, error normalization, and auditing
5. pooled gvmd session manager backed by `rust-gvm`

In practice:

- start with a shared command catalog so every public surface maps to the same core operations
- cover the highest-value operations through REST and MCP first if that is the fastest path to usable human and agent integrations
- require clients to create a proxy session by submitting gvmd credentials to the proxy once
- return a session token that the client includes on every subsequent API call
- add gRPC for complete GMP coverage, typed contracts, and streaming-heavy workflows
- route both through the same execution core so command mapping and gvmd behavior stay consistent

See [MCP Gateway Surface Analysis](mcp-gateway-surface-analysis.md) for the adapter-level model and parity requirements.
See [MCP Implementation Roadmap](mcp-implementation-roadmap.md) for the recommended build order and first implementation slice.

## 6. Connection Pooling and Session Management

This is the critical design constraint.

gvmd forks per client and the connection has session state, but this needs to be interpreted correctly.

GMP is not "conversation stateful" in the sense that most resource-oriented commands carry their own parameters and do not build up a multi-step transaction context across requests.

However, the connection is still stateful in operational terms because it retains:

- authentication state
- current user identity
- user-specific settings
- database session variables
- XML parser and stream state

That means the proxy cannot treat gvmd connections as stateless request pipes. It should:

- create an explicit proxy session per authenticated client workflow
- accept gvmd credentials only during session creation
- establish a gvmd connection, authenticate immediately, and validate the credentials up front
- store the authenticated live connection in the pool keyed by the proxy session token
- require the session token on every subsequent REST or gRPC request
- serialize work per gvmd connection because GMP is synchronous per session
- expire, close, and remove idle or revoked sessions cleanly
- apply request queuing, rate limiting, and backpressure

```text
Client A ──┐
Client B ──┤──► gvm-gateway ──► connection pool ──► gvmd
Client C ──┘       │
                   └── auth cache, rate limiting, request queuing
```

### Recommended session model

The proxy should expose an explicit session bootstrap flow.

#### Session creation

1. The client calls `POST /api/v1/sessions` or `CreateSession`.
2. The request contains the gvmd username and password for the target backend.
3. The proxy opens a new gvmd connection through `rust-gvm`.
4. The proxy sends GMP `<authenticate>` immediately.
5. If authentication succeeds, the proxy stores the authenticated connection in the pool.
6. The proxy returns a session token that refers to that pooled authenticated connection.

Example bootstrap response:

```json
{
  "session_token": "gvm_sess_9e6b2d...",
  "expires_in": 1800,
  "gmp_version": "22.7"
}
```

#### Subsequent requests

Every later REST or gRPC call must present the session token.

- REST should carry it as `Authorization: Bearer <session-token>`
- gRPC can carry it in request metadata
- the proxy uses the token to look up the corresponding authenticated gvmd connection
- all commands for that token execute on that session's bound connection

#### Session teardown

The proxy should support both explicit and automatic cleanup:

- client-driven logout or close via `DELETE /api/v1/sessions/{token}`
- idle timeout for abandoned sessions
- immediate removal on authentication failure, disconnect, or token revocation
- backend disconnect when the proxy session ends

### Why this model fits gvmd better

This design aligns with gvmd's stateful connection model:

- authentication is validated exactly once during session creation
- each proxy token maps to one authenticated gvmd session
- session-local gvmd state stays isolated to one client session
- request routing is deterministic because the token selects the connection directly
- the security boundary becomes possession of the proxy session token

### Operational tradeoffs

Pros:

- clear one-token-to-one-session mapping
- no ambiguity about which gvmd identity a request uses
- stronger isolation between clients, even when they use the same gvmd username at different times
- simpler auditing because each API request can be tied to one explicit proxy session
- avoids hidden session reuse across unrelated clients

Cons:

- clients must manage session creation and token lifecycle
- each active proxy session usually consumes a dedicated gvmd connection
- capacity planning must account for active sessions, not only request rate
- the session token must be treated as a bearer secret
- reconnect behavior needs policy: either fail the session or transparently re-authenticate using retained credentials

#### Recommendation

For the initial proxy design, adopt the explicit session-token model as the default and only supported mode.

This keeps the contract concrete:

- credentials are submitted once to start a session
- the proxy validates them by authenticating to gvmd immediately
- the returned token identifies the correct pooled authenticated connection for every later call
- session cleanup is explicit and observable

## 7. Deployment Model

The proxy should run as a standalone binary or container alongside gvmd.

```yaml
services:
  gvmd:
    image: greenbone/gvmd
    volumes:
      - gvmd-socket:/run/gvmd

  gvm-gateway:
    image: ghcr.io/clawosiris/gvm-gateway:latest
    depends_on: [gvmd]
    volumes:
      - gvmd-socket:/run/gvmd:ro
    ports:
      - "8080:8080"
      - "50051:50051"
    environment:
      - GVM_SOCKET=/run/gvmd/gvmd.sock
```

Default deployment should prefer the gvmd Unix socket. SSH and TLS backends can be added for remote routing scenarios.

## 8. Impact on Consumers

| Consumer | Current | With proxy |
|----------|---------|------------|
| `openvas-mcp-server` | Talks GMP/XML directly | Either consume the gateway's native MCP surface or reuse the shared gateway session model through MCP tools |
| `gvm-tools` / CLI automation | Talks GMP/XML directly | Start a session with gvmd credentials, then use REST with the returned token |
| GSA or other web UIs | Talks GMP/XML through existing components | Browser-facing flows can use REST if the proxy handles secure session bootstrap carefully |
| Custom services | Need GMP expertise or a GMP client library | Use session bootstrap plus REST or gRPC with a stable token-based contract |
| Ad hoc automation | `python-gvm` or raw XML | One login call yields a token, removing the need to manage raw GMP sessions directly |

## 9. Recommendation

Adopt the hybrid model in phases:

- treat `REST`, `gRPC`, and `MCP` as peer adapters over one shared execution core
- enforce capability parity so MCP does not lag behind the other gateway surfaces
- make `POST /api/v1/sessions` the mandatory entry point so the proxy can authenticate to gvmd, validate credentials, and bind a live connection to a returned token
- define the shared execution core so the gateway is ready to support multiple frontends from the beginning
- add or expand `gRPC` for complete command coverage, typed clients, and streaming-heavy use cases such as large reports

This gives the project a pragmatic path forward: immediate value through low-friction public surfaces, a concrete session model that matches gvmd's stateful behavior, and a coherent contract for browser, service, and agent-facing integrations without changing gvmd itself.

## 10. Gateway Extension

The proxy can later grow into a broader access-control gateway for:

- multi-endpoint routing across Unix, SSH, and TLS gvmd backends
- RBAC and policy enforcement
- credential isolation
- audit logging
- cross-endpoint aggregation
- multi-tenant or MSP-style deployments

See [Proxy Access Control Analysis](proxy-access-control-analysis.md) for that extension.
