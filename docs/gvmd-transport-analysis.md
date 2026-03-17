# gvmd Transport & Protocol Analysis

## 1. How gvmd Implements GMP Today

### Transport architecture

gvmd exposes GMP as a **raw XML stream over a persistent TCP/Unix socket connection**, optionally wrapped in TLS. There is no HTTP layer.

```
Client ──[ XML bytes ]──▶ [ Unix socket | TLS+TCP :9390 ] ──▶ gvmd
       ◀── [ XML bytes ] ─────────────────────────────────────◀
```

### Connection types (from gvmd source)

| Listener | Mechanism | Auth | Notes |
|----------|-----------|------|-------|
| **Unix socket** | `AF_UNIX` / `SOCK_STREAM` | Filesystem permissions + GMP `<authenticate>` | Default in container deployments. Owner/group/mode configurable via `--listen-owner`, `--listen-group`, `--listen-mode`. |
| **TLS over TCP** | `AF_INET`/`AF_INET6` on port 9390 (default) | GnuTLS mutual TLS + GMP `<authenticate>` | Enabled via `--listen <address>` + `--port <port>`. Supports DH params (`--dh-params`), priority strings (`--gnutls-priorities`). Client cert optional. |
| **SSH tunnel** | Not native to gvmd | SSH handles transport; gvmd sees Unix socket | python-gvm's `SSHConnection` tunnels via `direct-streamlocal@openssh.com` to the remote Unix socket. |

gvmd can listen on **two sockets simultaneously** (`--listen` + `--listen2`), e.g., one Unix + one TLS.

### Protocol flow

1. Client connects (Unix or TLS).
2. Client sends `<get_version/>` (pre-auth, always allowed).
3. Client sends `<authenticate><credentials>...</credentials></authenticate>`.
4. Client sends GMP commands as XML elements; gvmd responds with XML elements.
5. Connection persists (stateful session) until client disconnects.

**Key characteristics:**
- **Stateful sessions**: gvmd forks a child process per client connection. Session state (authenticated user, permissions) lives in that process.
- **XML stream framing**: No length prefix or delimiter — the client must parse XML to detect where one response ends and the next begins. This is what `XmlReader` in rust-gvm handles.
- **Synchronous request/response**: One command at a time per connection. No multiplexing, no pipelining (except `<commands>` wrapper for batching).
- **No HTTP**: GMP is **not** HTTP-based. There are no HTTP headers, no Content-Length, no chunked encoding. It's raw XML over a byte stream.

### The `manage_http_scanner.c` file

This is **not** an HTTP interface for GMP. It's gvmd's internal client for connecting to **HTTP-based scanners** (a newer scanner type introduced in 2025). gvmd itself acts as an HTTP *client* to talk to scanners — it does not expose GMP over HTTP.

---

## 2. Comparison: GMP-over-XML-stream vs REST vs gRPC

### Current: GMP over raw XML stream (TLS/Unix)

**Strengths:**
- Simple, mature, battle-tested (15+ years)
- Low overhead — no HTTP framing, headers, or content negotiation
- Stateful sessions — natural for long-lived management connections
- Works over Unix sockets (zero network exposure in container deployments)
- TLS with mutual auth provides strong transport security
- The `<commands>` wrapper allows batching multiple operations in one round-trip

**Weaknesses:**
- **No standard framing** — clients must implement XML stream parsing to detect message boundaries (error-prone, hard to implement correctly in many languages)
- **No multiplexing** — one request at a time per connection; concurrent operations require multiple connections
- **XML verbosity** — large responses (reports with thousands of results) produce enormous XML payloads with no built-in compression or pagination beyond filter params
- **No streaming** — entire response must be assembled before the client can process it (problematic for 100MB+ reports)
- **Stateful sessions** — client must manage connection lifecycle; reconnection requires re-authentication
- **Limited tooling** — no Swagger/OpenAPI, no auto-generated clients, no standard HTTP debugging tools (curl, Postman, browser dev tools)
- **No standard error model** — errors are XML elements with status codes that don't map to HTTP semantics

### Alternative A: REST API (HTTP/JSON)

**Strengths:**
- Universal client support (curl, fetch, any HTTP library in any language)
- Standard framing (Content-Length / chunked encoding) — no custom parser needed
- Stateless requests — each request carries auth (token/API key), no session management
- Mature ecosystem: OpenAPI spec → auto-generated clients, documentation, testing tools
- HTTP/2 multiplexing for concurrent requests
- Built-in caching (ETags, conditional requests)
- Pagination via standard patterns (Link headers, cursor params)
- JSON is more compact than XML for most payloads
- Easy to put behind load balancers, API gateways, rate limiters

**Weaknesses:**
- Would require a **complete API redesign** — GMP's command surface doesn't map 1:1 to REST resources (e.g., `start_task` is an action, not a CRUD operation)
- Loss of session statefulness (could be a strength or weakness depending on use case)
- HTTP overhead per request (headers, connection setup if not keep-alive)
- No built-in server-push for long-running operations (would need polling or webhooks)
- Breaking change for all existing clients (python-gvm, gvm-tools, rust-gvm, GSA)

### Alternative B: gRPC (HTTP/2 + Protobuf)

**Strengths:**
- Strongly typed contracts via `.proto` files → auto-generated clients in many languages
- Efficient binary serialization (Protobuf is 3–10× smaller than XML for structured data)
- **Streaming support** — server-side streaming (ideal for large reports), client-side streaming, bidirectional streaming
- HTTP/2 multiplexing — multiple concurrent RPCs on one connection
- Built-in deadline/timeout propagation
- TLS by default
- Excellent for internal service-to-service communication

**Weaknesses:**
- Requires Protobuf toolchain for client generation
- Not browser-friendly without grpc-web proxy
- Harder to debug than REST (binary protocol, needs grpcurl or similar)
- Would require defining a complete `.proto` schema for all GMP entities
- Less mature ecosystem for security tooling compared to REST
- Same breaking-change problem as REST

### Alternative C: GMP over WebSocket (hybrid)

**Strengths:**
- Keeps the XML command/response model (minimal protocol change)
- Adds standard framing (WebSocket frames have length headers)
- Works through HTTP proxies and load balancers
- Browser-compatible (GSA could use it directly)
- Can be upgraded from HTTP, enabling a REST+WS hybrid

**Weaknesses:**
- Still XML-verbose
- Adds WebSocket handshake overhead
- Less ecosystem tooling than pure REST
- Not a standard pattern for management APIs

---

## 3. Summary Matrix

| Dimension | GMP/XML stream | REST/JSON | gRPC/Protobuf | GMP/WebSocket |
|-----------|---------------|-----------|---------------|---------------|
| **Client effort** | High (custom XML framing) | Low (any HTTP lib) | Medium (codegen) | Medium (WS + XML) |
| **Payload size** | Large (XML) | Medium (JSON) | Small (Protobuf) | Large (XML) |
| **Streaming** | ❌ | ❌ (needs polling/SSE) | ✅ Native | ✅ Possible |
| **Multiplexing** | ❌ | ✅ (HTTP/2) | ✅ | ✅ |
| **Tooling** | Minimal | Excellent (OpenAPI) | Good (proto + grpcurl) | Moderate |
| **Breaking change** | N/A (current) | 🔴 Full redesign | 🔴 Full redesign | 🟡 Moderate |
| **Browser compat** | ❌ | ✅ | ❌ (needs proxy) | ✅ |
| **Session model** | Stateful | Stateless | Either | Either |
| **Maturity** | 15+ years | Would be new | Would be new | Would be new |

---

## 4. Implications for rust-gvm

rust-gvm currently implements the **correct** transport model for gvmd as it exists today:

- `UnixSocketConnection` — primary, containerized deployments
- `SshConnection` — remote access via SSH tunnel
- `TlsConnection` — planned (#7), for direct TLS+TCP on port 9390

There's no HTTP or gRPC interface to implement because **gvmd doesn't offer one**. If Greenbone ever adds a REST/gRPC/WebSocket interface, we'd add corresponding transport implementations.

### Practical recommendations

1. **Complete TLS transport** (#7) — this is the remaining gap for full parity with python-gvm's connection options.
2. **Implement streaming reads** (#4) — even without a protocol change, we can stream-parse large XML responses incrementally rather than buffering entire responses in memory.
3. **Watch for upstream changes** — the `manage_http_scanner.c` addition signals Greenbone is exploring HTTP-based protocols for scanner communication. If they extend this to the client-facing GMP interface, we should be ready to adapt.
4. **Consider a REST/gRPC proxy** — see Section 5 below.

---

## 5. REST/gRPC Proxy Built on rust-gvm

### The idea

Rather than waiting for Greenbone to modernize gvmd's protocol, we could build a **proxy/gateway service** on top of rust-gvm that:

- Talks GMP over Unix socket (or SSH/TLS) to gvmd on the backend
- Exposes a **REST API** or **gRPC service** to consumers on the frontend

```
┌──────────────┐       REST / gRPC        ┌──────────────────┐      GMP/XML       ┌────────┐
│  Web UI      │◄────────────────────────►│  gvm-gateway     │◄──────────────────►│  gvmd  │
│  Scripts     │   HTTP/JSON or Protobuf   │  (rust-gvm based)│   Unix socket      │        │
│  Automation  │                           │                  │   or SSH/TLS       │        │
│  MCP Server  │                           │                  │                    │        │
└──────────────┘                           └──────────────────┘                    └────────┘
```

### Why this is viable

rust-gvm already provides the complete backend stack:
- **gvm-connection**: Unix socket + SSH transports (TLS coming)
- **gvm-client**: Async client with version negotiation + auth
- **gvm-gmp**: Typed command builders for all GMP operations
- **gvm-protocol**: Response parsing (status codes, XML extraction)

A proxy service would be a relatively thin layer that:
1. Accepts HTTP/JSON or gRPC requests
2. Maps them to `gvm-gmp` command builders
3. Sends via `gvm-client` → `gvm-connection` → gvmd
4. Parses the XML response
5. Returns structured JSON or Protobuf

### Architecture options

#### Option A: REST/JSON proxy (recommended first step)

```
Technology: axum or actix-web
Auth: Bearer token / API key → maps to gvmd user credentials
Schema: OpenAPI 3.1 spec → auto-generated docs + client SDKs

Endpoints (examples):
  GET    /api/v1/version
  POST   /api/v1/auth/login          → authenticate, returns session token
  GET    /api/v1/tasks                → get_tasks
  POST   /api/v1/tasks                → create_task
  GET    /api/v1/tasks/{id}           → get_tasks task_id=...
  PUT    /api/v1/tasks/{id}           → modify_task
  DELETE /api/v1/tasks/{id}           → delete_task
  POST   /api/v1/tasks/{id}/start     → start_task
  POST   /api/v1/tasks/{id}/stop      → stop_task
  GET    /api/v1/reports/{id}         → get_reports report_id=...
  GET    /api/v1/targets              → get_targets
  ...
```

**Strengths:**
- Instantly accessible from any HTTP client (curl, browser, Postman, any language)
- OpenAPI spec enables auto-generated SDKs (TypeScript, Python, Go, Java, ...)
- Stateless requests — no session management burden on clients
- Easy to deploy as a sidecar container alongside gvmd
- Could replace GSA's backend (GSA currently talks GMP directly)
- Natural fit for the MCP server (openvas-mcp-server could use REST instead of raw GMP)

**Weaknesses:**
- REST doesn't map perfectly to all GMP operations (e.g., `start_task` is an action, not a resource)
- Response translation: XML → JSON adds latency and complexity
- Large reports: need pagination or streaming (SSE / chunked responses)

**Estimated effort:** Medium. The command mapping is mechanical; the real work is auth management (session pooling to gvmd) and large-response handling.

#### Option B: gRPC proxy

```
Technology: tonic (Rust gRPC framework)
Schema: .proto files → auto-generated clients in 10+ languages
Transport: HTTP/2, TLS built-in

Service definition (sketch):
  service GmpService {
    rpc GetVersion(Empty) returns (VersionResponse);
    rpc Authenticate(AuthRequest) returns (AuthResponse);
    rpc GetTasks(GetTasksRequest) returns (GetTasksResponse);
    rpc CreateTask(CreateTaskRequest) returns (CreateTaskResponse);
    rpc StartTask(TaskIdRequest) returns (TaskActionResponse);
    rpc GetReport(GetReportRequest) returns (stream ReportChunk);  // server streaming!
    ...
  }
```

**Strengths:**
- **Server-side streaming** for large reports — the killer feature. Clients receive report chunks as they're parsed from the gvmd XML response, without buffering the entire thing.
- Strongly typed contracts — `.proto` is the single source of truth
- Binary serialization — 3–10× smaller than JSON for structured vulnerability data
- Auto-generated clients with full type safety
- Built-in deadline propagation, metadata, interceptors
- Excellent for service-to-service (e.g., MCP server → gRPC proxy → gvmd)

**Weaknesses:**
- Not browser-friendly without grpc-web proxy
- Requires Protobuf toolchain for consumers
- Harder to debug/inspect than REST
- More upfront design work (defining all message types in `.proto`)

**Estimated effort:** Medium-High. Proto schema design is significant, but tonic makes the Rust implementation straightforward.

#### Option C: Hybrid (REST + gRPC)

Expose **both** from the same service:
- REST for human/script consumers (curl, Postman, simple automation)
- gRPC for programmatic/service consumers (MCP server, custom integrations)
- Share the same backend: gvm-client → gvmd

This is a common pattern (e.g., Google APIs expose both REST and gRPC from the same service).

### Connection pooling

A critical design consideration: gvmd forks per client and sessions are stateful. The proxy should:

- Maintain a **pool of authenticated gvmd connections** (one per gvmd user)
- Multiplex incoming REST/gRPC requests onto pooled connections
- Handle reconnection transparently
- This transforms gvmd's "one connection = one session" model into a scalable multi-client service

```
Client A ──┐
Client B ──┤──► gvm-gateway ──► connection pool ──► gvmd (2-3 forked processes)
Client C ──┘       │
                   └── auth cache, rate limiting, request queuing
```

### Deployment model

The proxy would be a standalone binary (or Docker image) that runs alongside gvmd:

```yaml
# docker-compose example
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
      - "8080:8080"   # REST
      - "50051:50051"  # gRPC (optional)
    environment:
      - GVM_SOCKET=/run/gvmd/gvmd.sock
```

### Impact on existing projects

| Consumer | Current | With proxy |
|----------|---------|------------|
| openvas-mcp-server | Talks GMP/XML directly | Could use REST or gRPC — much simpler integration |
| gvm-rools (gvm-cli) | Talks GMP/XML directly | Could add `--rest` transport option |
| GSA (web UI) | Talks GMP/XML via gsad | Could talk REST directly — removes gsad dependency |
| Custom automation | python-gvm or raw XML | Standard HTTP/JSON — any language, no GMP library needed |
| AI/LLM tool use | Needs GMP expertise | OpenAPI spec enables native tool calling |

### Recommendation

**Start with REST** (Option A):
1. It's the fastest to deliver value (any HTTP client can use it immediately)
2. OpenAPI spec is a force multiplier (auto-docs, auto-clients)
3. Add gRPC later for streaming (large reports) and service-to-service efficiency
4. The proxy architecture decouples consumers from gvmd's protocol — if Greenbone changes GMP, only the proxy needs updating

This could be a new repo (`gvm-gateway`) or a new crate in the rust-gvm workspace.
