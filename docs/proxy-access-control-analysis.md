# Proxy Access Control Analysis: Multi-Endpoint Authorization Gateway

**Related**: [gvmd Transport & Protocol Analysis](gvmd-transport-analysis.md), Section 5 (REST/gRPC Proxy)

---

## 1. Problem Statement

The proxy concept in the transport analysis focuses on **protocol translation** — REST/gRPC frontend, GMP backend, single gvmd. But real deployments look different:

```
                                    ┌─────────────┐
                                ┌──►│ gvmd-prod    │  (production scanners)
┌──────────┐                    │   └─────────────┘
│ SOC team  │──┐                │   ┌─────────────┐
└──────────┘  │   ┌───────────┐ ├──►│ gvmd-staging │  (staging/QA)
┌──────────┐  ├──►│ gvm-      │ │   └─────────────┘
│ DevSecOps │──┤  │ gateway   │─┤   ┌─────────────┐
└──────────┘  │   └───────────┘ ├──►│ gvmd-dmz     │  (DMZ network)
┌──────────┐  │                 │   └─────────────┘
│ Auditor   │──┘                │   ┌─────────────┐
└──────────┘                    └──►│ gvmd-client-A│  (MSP: customer A)
                                    └─────────────┘
```

**Questions the gateway must answer:**
1. Which clients (identities) exist?
2. Which gvmd endpoints exist?
3. Who can connect to what? (authorization policy)
4. What operations can they perform? (fine-grained permissions)
5. How do we audit all of this?

---

## 2. Architecture: The Access Control Plane

### 2.1 Core Components

```
┌─────────────────────────────────────────────────────────────────────┐
│  gvm-gateway                                                        │
│                                                                     │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────────┐ │
│  │ Auth Layer   │──►│ Policy Engine │──►│ Endpoint Router          │ │
│  │              │   │              │   │                          │ │
│  │ • API keys   │   │ • Who → What │   │ • Connection pool /gvmd1 │ │
│  │ • OAuth/OIDC │   │ • Operations │   │ • Connection pool /gvmd2 │ │
│  │ • mTLS certs │   │ • Rate limits│   │ • Connection pool /gvmd3 │ │
│  │ • LDAP/AD    │   │ • Time-based │   │ • Health checks          │ │
│  └─────────────┘   └──────────────┘   └──────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Audit Log                                                       ││
│  │ • Who accessed what endpoint, when, which operations, results   ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Entity Model

```
Endpoint                          Client Identity
├── id: "prod-scanner"            ├── id: "soc-team-lead"
├── name: "Production gvmd"       ├── name: "Alice"
├── transport:                    ├── auth_method: "oidc"
│   ├── kind: "unix"              ├── roles: ["soc-analyst", "prod-admin"]
│   └── socket: "/run/gvmd/..."   └── metadata: { team: "SOC", ... }
├── gmp_credentials:
│   ├── username: "admin"         Policy Rule
│   └── password: (vault ref)     ├── id: "rule-001"
├── tags: ["production", "zone-a"]├── subject: { role: "soc-analyst" }
├── health_check_interval: 30s    ├── endpoint: { tags: ["production"] }
└── max_connections: 5            ├── operations: ["read", "scan"]
                                  ├── deny_operations: ["delete_*"]
                                  └── schedule: { hours: "06:00-22:00" }
```

### 2.3 Request Flow

```
1. Client authenticates (API key / OIDC token / mTLS cert)
       ↓
2. Gateway resolves client identity → roles
       ↓
3. Client requests operation on endpoint:
   POST /api/v1/endpoints/prod-scanner/tasks
       ↓
4. Policy engine evaluates:
   - Does client have access to "prod-scanner"? (endpoint binding)
   - Can this role create tasks? (operation check)
   - Is this within allowed time window? (schedule check)
   - Has rate limit been exceeded? (throttle check)
       ↓
5. If allowed → route to correct gvmd connection pool
   If denied → 403 with audit log entry
       ↓
6. Execute GMP command on target gvmd
       ↓
7. Return response, log audit trail
```

---

## 3. Authorization Model

### 3.1 Role-Based Access Control (RBAC)

The simplest model. Map roles to (endpoint, operations) tuples.

```yaml
roles:
  soc-analyst:
    endpoints: ["prod-scanner", "dmz-scanner"]
    operations:
      - "get_*"           # read anything
      - "create_target"   # can define scan targets
      - "create_task"     # can create scan tasks
      - "start_task"      # can launch scans
      - "get_reports"     # can read results
    deny:
      - "delete_*"        # cannot delete anything
      - "modify_setting"  # cannot change global settings

  devsecops:
    endpoints: ["staging-scanner"]
    operations: ["*"]     # full access to staging

  auditor:
    endpoints: ["prod-scanner", "dmz-scanner", "staging-scanner"]
    operations:
      - "get_*"           # read-only across all endpoints
    deny:
      - "create_*"
      - "modify_*"
      - "delete_*"
      - "start_*"
      - "stop_*"

  msp-client-a:
    endpoints: ["client-a-scanner"]
    operations: ["*"]     # full access to their own scanner only
```

### 3.2 Attribute-Based Access Control (ABAC) — Future

For complex policies: evaluate attributes of client, endpoint, operation, and context.

```
ALLOW if:
  client.team == "SOC"
  AND endpoint.tags CONTAINS "production"
  AND operation.category == "read"
  AND time.hour BETWEEN 6 AND 22
  AND client.ip IN ["10.0.0.0/8"]
```

ABAC is more flexible but harder to reason about. Recommend starting with RBAC, evolve if needed.

### 3.3 Operation Categories

Map GMP commands to coarse-grained operation categories:

| Category | GMP Commands | Description |
|----------|-------------|-------------|
| `read` | `get_version`, `get_tasks`, `get_targets`, `get_reports`, `get_scan_configs`, ... | Read-only queries |
| `scan` | `create_target`, `create_task`, `start_task`, `stop_task`, `resume_task` | Scan lifecycle |
| `manage` | `create_*`, `modify_*`, `delete_*` (except scan lifecycle) | Resource management |
| `admin` | `modify_setting`, `create_user`, `delete_user`, `modify_auth` | Administrative |
| `report` | `get_reports` (with filter), `get_results` | Report access (may want separate from general `read` for data sensitivity) |

Fine-grained per-command permissions available when categories are too coarse.

---

## 4. Multi-Endpoint Management

### 4.1 Endpoint Registry

The gateway maintains a registry of gvmd endpoints:

```yaml
endpoints:
  - id: prod-scanner
    display_name: "Production Scanner (Zone A)"
    transport:
      kind: unix
      socket_path: /run/gvmd-prod/gvmd.sock
    credentials:
      username: admin
      password_ref: vault://gvm/prod/admin  # external secret reference
    pool:
      min_connections: 2
      max_connections: 10
      idle_timeout: 300s
    health:
      interval: 30s
      timeout: 5s
    tags: [production, zone-a, internal]

  - id: dmz-scanner
    display_name: "DMZ Scanner"
    transport:
      kind: ssh
      host: gvmd-dmz.internal
      port: 22
      username: gvm-proxy
      key_path: /etc/gvm-gateway/ssh/dmz.key
      socket_path: /run/gvmd/gvmd.sock
    credentials:
      username: proxy-user
      password_ref: vault://gvm/dmz/proxy
    pool:
      max_connections: 5
    tags: [dmz, external-facing]

  - id: client-a
    display_name: "Client A (Managed)"
    transport:
      kind: tls
      host: 10.100.1.10
      port: 9390
      ca_cert: /etc/gvm-gateway/tls/client-a-ca.pem
      client_cert: /etc/gvm-gateway/tls/gateway.pem
      client_key: /etc/gvm-gateway/tls/gateway.key
    credentials:
      username: msp-admin
      password_ref: vault://gvm/client-a/msp
    pool:
      max_connections: 3
    tags: [msp, client-a]
```

### 4.2 Transport Heterogeneity

A key strength of building on rust-gvm: the gateway can use **different transports per endpoint**. One gvmd reached via Unix socket, another via SSH tunnel, a third via TLS — all abstracted behind the same `Connection` trait.

```rust
// rust-gvm's Connection trait already enables this:
trait Connection: Send + Sync {
    async fn send(&mut self, command: &[u8]) -> Result<(), ConnectionError>;
    async fn read_response(&mut self) -> Result<Vec<u8>, ConnectionError>;
    async fn disconnect(&mut self) -> Result<(), ConnectionError>;
}
// UnixSocketConnection, SshConnection, TlsConnection all implement this
```

### 4.3 Connection Pool Design

Each endpoint gets its own connection pool. Connections are pre-authenticated:

```
Endpoint "prod-scanner":
  ┌────────────────────────────────────┐
  │ Pool (min=2, max=10)               │
  │                                    │
  │  conn-1: [authenticated, idle]     │  ← ready for requests
  │  conn-2: [authenticated, active]   │  ← processing a get_reports
  │  conn-3: [authenticated, active]   │  ← processing a start_task
  │  ...                               │
  └────────────────────────────────────┘
```

**Pool behavior:**
- Pre-warm `min_connections` on startup
- Scale up to `max_connections` under load
- Shrink back after `idle_timeout`
- Health-check connections periodically (`get_version`)
- Re-authenticate on connection failure
- Queue requests when pool is exhausted (bounded queue → 503 on overflow)

### 4.4 Health Monitoring

The gateway has visibility across all endpoints:

```
GET /api/v1/admin/endpoints/status

{
  "endpoints": [
    {
      "id": "prod-scanner",
      "status": "healthy",
      "gmp_version": "22.6",
      "pool": { "active": 2, "idle": 3, "max": 10 },
      "last_health_check": "2026-03-18T12:00:05Z",
      "latency_ms": 12
    },
    {
      "id": "dmz-scanner",
      "status": "degraded",
      "gmp_version": "22.4",
      "pool": { "active": 1, "idle": 0, "max": 5 },
      "error": "2 health checks failed (timeout)",
      "last_success": "2026-03-18T11:58:00Z",
      "latency_ms": 340
    }
  ]
}
```

---

## 5. API Design: Endpoint-Scoped Routes

### 5.1 URL Structure

The REST API becomes endpoint-scoped:

```
/api/v1/endpoints                         # list accessible endpoints
/api/v1/endpoints/{endpoint_id}/version   # get_version on specific gvmd
/api/v1/endpoints/{endpoint_id}/tasks     # CRUD tasks on specific gvmd
/api/v1/endpoints/{endpoint_id}/targets
/api/v1/endpoints/{endpoint_id}/reports
/api/v1/endpoints/{endpoint_id}/reports/{id}/results
...
```

Or a header-based approach for cleaner URLs:

```
X-GVM-Endpoint: prod-scanner
GET /api/v1/tasks
```

**Recommendation:** URL-scoped is more explicit, easier to document, and works with standard HTTP tools. Header-based as optional convenience.

### 5.2 Cross-Endpoint Operations

Some operations span endpoints:

```
# List all tasks across all accessible endpoints
GET /api/v1/tasks?endpoints=all

# Returns:
{
  "tasks": [
    { "endpoint": "prod-scanner", "id": "abc-123", "name": "Weekly scan", "status": "Done" },
    { "endpoint": "dmz-scanner",  "id": "def-456", "name": "DMZ perimeter", "status": "Running" },
    { "endpoint": "client-a",     "id": "ghi-789", "name": "Client A full", "status": "Requested" }
  ]
}
```

This is a **significant value add** — gvmd has no native multi-instance aggregation. The gateway becomes the single pane of glass.

### 5.3 Cross-Endpoint Report Aggregation

For enterprises running multiple scanners:

```
GET /api/v1/reports/aggregate?endpoints=prod-scanner,dmz-scanner&severity=high

# Aggregated vulnerability view across infrastructure
{
  "total_high": 47,
  "by_endpoint": {
    "prod-scanner": { "high": 31, "medium": 128, "low": 203 },
    "dmz-scanner":  { "high": 16, "medium": 44,  "low": 67  }
  },
  "top_vulnerabilities": [
    { "nvt": "1.3.6.1.4.1.25623.1.0.12345", "name": "...", "count": 12, "endpoints": ["prod-scanner", "dmz-scanner"] }
  ]
}
```

---

## 6. Audit Trail

Every operation through the gateway is logged:

```json
{
  "timestamp": "2026-03-18T14:23:07Z",
  "client_id": "alice@soc-team",
  "client_ip": "10.0.1.50",
  "endpoint": "prod-scanner",
  "operation": "start_task",
  "gmp_command": "start_task",
  "resource_id": "abc-123-def",
  "policy_decision": "ALLOW",
  "policy_rule": "rule-001 (soc-analyst → prod-scanner → scan)",
  "duration_ms": 145,
  "gmp_status": "202",
  "request_id": "req-7a8b9c"
}
```

**Audit capabilities:**
- Who accessed which endpoint, when
- What operations were performed
- Which policy rule authorized (or denied) the action
- Full request/response correlation
- Export to SIEM (syslog, JSON, OpenTelemetry)

This is critical for compliance (SOC 2, ISO 27001, PCI DSS) — proving that vulnerability scan operations are authorized and auditable.

---

## 7. Security Considerations

### 7.1 Credential Isolation

The gateway holds gvmd credentials — this is both a strength and a risk:

**Strength:** Clients never see gvmd passwords. They authenticate to the gateway (OIDC, API key, mTLS), and the gateway uses its own credentials per endpoint. Credential rotation is centralized.

**Risk:** The gateway becomes a high-value target. Mitigations:
- Credentials stored in external vault (HashiCorp Vault, AWS Secrets Manager)
- Gateway process runs with minimal privileges
- Credential material never logged
- Memory protection (zeroize on drop — the `secrecy`/`zeroize` crates)

### 7.2 Network Segmentation

The gateway can enforce network topology constraints:

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Corporate LAN    │────►│  gvm-gateway    │────►│ Scanner VLAN │
│ (clients here)   │     │  (DMZ / bridge) │     │ (gvmd here)  │
└─────────────────┘     └─────────────────┘     └──────────────┘
```

Only the gateway has network access to gvmd. Clients cannot bypass it. This is a significant improvement over giving GMP access directly to end users.

### 7.3 Blast Radius Containment

If a client credential is compromised:
- **Without gateway:** Attacker has direct GMP access — can delete targets, exfiltrate reports, modify scan configs
- **With gateway:** Attacker is limited to the compromised identity's policy — read-only auditor can only read, scoped to their endpoints

---

## 8. Deployment Scenarios

### 8.1 Single-Tenant (Simple)

One gvmd, gateway adds REST + auth + audit:

```yaml
services:
  gvmd:
    image: greenbone/gvmd
    volumes: [gvmd-socket:/run/gvmd]

  gvm-gateway:
    image: ghcr.io/clawosiris/gvm-gateway
    volumes: [gvmd-socket:/run/gvmd:ro]
    ports: ["8443:8443"]
    environment:
      GVM_GATEWAY_CONFIG: /etc/gvm-gateway/config.yaml
```

### 8.2 Multi-Scanner Enterprise

Central gateway managing scanners across network zones:

```yaml
services:
  gvm-gateway:
    image: ghcr.io/clawosiris/gvm-gateway
    ports: ["8443:8443"]
    volumes:
      - ./config.yaml:/etc/gvm-gateway/config.yaml:ro
      - ./tls:/etc/gvm-gateway/tls:ro
    environment:
      VAULT_ADDR: https://vault.internal:8200
```

Gateway connects to remote gvmd instances via SSH/TLS (no shared Docker volumes needed).

### 8.3 MSP Multi-Tenant

Managed Security Provider serving multiple customers, each with isolated scanners:

```
Customer A ──► gvm-gateway ──► gvmd-client-a (10.100.1.x)
Customer B ──► gvm-gateway ──► gvmd-client-b (10.100.2.x)
Customer C ──► gvm-gateway ──► gvmd-client-c (10.100.3.x)
MSP SOC    ──► gvm-gateway ──► (all of the above, read-only)
```

Strict tenant isolation through policy engine. Customer A cannot see Customer B's endpoints.

---

## 9. Implementation Considerations

### 9.1 What rust-gvm Already Provides

| Component | Status | Notes |
|-----------|--------|-------|
| Unix socket transport | ✅ Complete | `UnixSocketConnection` |
| SSH transport | ✅ Complete | `SshConnection` |
| TLS transport | ✅ Implemented | `TlsConnection` with verified roots/SAN and optional client identity |
| GMP command builders | ✅ Complete | All `gvm-gmp` commands |
| Response parsing | ✅ Complete | `Response` + `child_text()` |
| Version negotiation | ✅ Complete | `GmpClient` auto-negotiates |
| Connection trait | ✅ Complete | Polymorphic over transport |
| Buffer limits | ✅ PR #36 | `max_buffer_bytes` on XmlReader |
| Host key verification | ✅ PR #36 | `KnownHosts` by default, custom known-hosts file, or `Fingerprint` pinning |

### 9.2 What the Gateway Would Add

| Component | Complexity | Notes |
|-----------|-----------|-------|
| REST API layer (axum) | Medium | Endpoint-scoped routes, OpenAPI |
| Auth layer (OIDC + API keys) | Medium | Tower middleware |
| Policy engine (RBAC) | Medium | Config-driven, evaluate per request |
| Connection pool | Medium | Per-endpoint, async pool with health checks |
| Endpoint registry | Low | YAML/TOML config, runtime reload |
| Audit logging | Low | Structured JSON, syslog, OTEL export |
| Admin API | Low | Endpoint status, pool stats, policy reload |
| gRPC layer (tonic) | Medium | Can come later, share backend with REST |
| Cross-endpoint aggregation | High | Requires response normalization across GMP versions |
| ABAC policy engine | High | Future — start with RBAC |

### 9.3 Suggested Phasing

**Phase 1: Single-endpoint gateway with auth + audit**
- REST API (axum + OpenAPI)
- Single gvmd endpoint
- API key authentication
- Operation-level RBAC
- Audit logging
- Connection pooling
- *Delivers: REST access, auth, audit trail*

**Phase 2: Multi-endpoint with routing**
- Endpoint registry (multiple gvmd)
- Endpoint-scoped routes
- Per-endpoint connection pools
- Health monitoring dashboard
- Policy: who → which endpoint
- *Delivers: multi-scanner management*

**Phase 3: Enterprise features**
- OIDC/LDAP integration
- Cross-endpoint aggregation queries
- gRPC interface with streaming
- Vault integration for credentials
- SIEM export (syslog, OTEL)
- *Delivers: enterprise/MSP readiness*

---

## 10. Relationship to Existing Greenbone Components

### GSA (Greenbone Security Assistant)

GSA is Greenbone's web UI. It talks GMP to gvmd via an intermediary daemon (`gsad`). The gateway could **replace gsad** as the backend for GSA (or a modern web UI) by providing a proper REST API.

### openvas-mcp-server

The MCP server currently needs to implement its own GMP connection handling. With the gateway, it would be a simple REST client — dramatically simpler integration.

### gvm-tools / gvm-rools

CLI tools could gain a `--gateway` transport option alongside `--unix`, `--ssh`, `--tls`:

```bash
gvm-cli --gateway https://gateway.internal:8443 \
        --endpoint prod-scanner \
        --api-key $GVM_API_KEY \
        --xml "<get_tasks/>"
```

---

## 11. Architectural Options: Flow Control Layer Separation

A key design decision is where to place access control. The gateway concept from Sections 1–10 puts everything in one component. But access control decomposes into two distinct layers that can be separated:

| Layer | Concern | Protocol awareness | Decision basis |
|-------|---------|-------------------|----------------|
| **Flow control** (L3/L4/identity) | "Can source X connect to destination Y?" | None — protocol-agnostic | Identity, network, endpoint, time |
| **Operation control** (L7/application) | "Can this identity perform `delete_target` on this endpoint?" | Must parse GMP | Identity, operation, resource, context |

The flow control proxy can't distinguish "read report" from "delete all targets" — both are TCP streams to the same destination. Operation-level authorization requires parsing the GMP command, which only the protocol gateway can do. This natural boundary suggests separation.

### Option A: Monolith — Single gvm-gateway (all-in-one)

Everything in one component, as described in Sections 1–10.

```
┌──────────┐     ┌─────────────────────────────────────────────┐     ┌────────┐
│ Clients  │────►│ gvm-gateway                                  │────►│ gvmd   │
│          │     │                                              │     │        │
│          │     │ • Identity / Auth (OIDC, API key, mTLS)      │     │        │
│          │     │ • Flow policy (src → dst allow/deny)         │     │        │
│          │     │ • REST/gRPC → GMP translation                │     │        │
│          │     │ • Operation-level RBAC                       │     │        │
│          │     │ • Connection pooling                         │     │        │
│          │     │ • Audit (connection + operation)             │     │        │
└──────────┘     └─────────────────────────────────────────────┘     └────────┘
```

**Strengths:**
- Simplest deployment — one binary, one config
- Single auth decision point — no token passing between layers
- Lowest latency — no extra hop
- Easiest to reason about — all policy in one place
- Good for small/medium deployments (1–5 gvmd endpoints)

**Weaknesses:**
- Flow control logic is bespoke and GVM-specific — can't reuse for other services
- If gateway is compromised, both layers fall
- Must implement mTLS termination, rate limiting, IP allowlisting from scratch
- Doesn't leverage existing infrastructure (service mesh, API gateway)
- Harder to scale flow control and protocol translation independently

**Best for:** Single-team deployments, container sidecars, proof-of-concept.

### Option B: Two-Layer — Separate Flow Control Proxy + Protocol Gateway

Split access control into two components at the natural protocol boundary.

```
┌──────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌────────┐
│ Clients  │────►│ Flow Control     │────►│ Protocol         │────►│ gvmd   │
│          │     │ Proxy            │     │ Gateway          │     │        │
│          │     │                  │     │                  │     │        │
│          │     │ • Identity       │     │ • REST→GMP       │     │        │
│          │     │ • Src→Dst policy │     │ • Op-level RBAC  │     │        │
│          │     │ • Rate limiting  │     │ • Conn pooling   │     │        │
│          │     │ • TLS term/re    │     │ • Aggregation    │     │        │
│          │     │ • Conn audit     │     │ • Response cache │     │        │
└──────────┘     └──────────────────┘     └──────────────────┘     └────────┘
                   L3/L4/identity            L7/application
                   (protocol-agnostic)       (GMP-aware)
```

**Strengths:**
- **Defense in depth** — compromise of protocol gateway doesn't bypass flow control; compromise of flow proxy doesn't give operation-level access
- **Reusability** — same flow control proxy governs gvmd, GSA, MCP server, any future service
- **Leverage existing infra** — flow layer can be Envoy, Istio, Cilium, Traefik, Kong — battle-tested, not custom
- **Independent scaling** — flow control is lightweight (L3/L4 decisions); protocol gateway is heavier (XML parsing, pooling)
- **Separation of ownership** — network/platform team owns flow policy; application team owns operation policy
- **Standard pattern** — mirrors how enterprises already deploy services (API gateway → backend)

**Weaknesses:**
- Extra network hop (typically <1ms within same host/pod)
- Two things to deploy, configure, monitor
- Identity must be passed between layers (forwarded headers, mTLS passthrough)
- More complex troubleshooting — "which layer denied this?"

**Best for:** Enterprise deployments, multi-team organizations, MSP multi-tenant.

### Option C: Leverage Existing Service Mesh + Thin Gateway

Use an existing service mesh or API gateway for all flow control; build only the GMP-aware protocol gateway.

```
┌──────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌────────┐
│ Clients  │────►│ Envoy / Istio /  │────►│ gvm-gateway      │────►│ gvmd   │
│          │     │ Cilium / Kong    │     │ (thin: GMP only)  │     │        │
│          │     │                  │     │                  │     │        │
│          │     │ • mTLS           │     │ • REST→GMP       │     │        │
│          │     │ • AuthN (OIDC)   │     │ • Op-level RBAC  │     │        │
│          │     │ • AuthZ (OPA)    │     │ • Conn pooling   │     │        │
│          │     │ • Rate limiting  │     │ • Aggregation    │     │        │
│          │     │ • Observability  │     │ • Response cache │     │        │
└──────────┘     └──────────────────┘     └──────────────────┘     └────────┘
                   Existing infrastructure    Custom (rust-gvm based)
```

**Strengths:**
- Minimal custom code — only build what's GVM-specific
- All infrastructure concerns (TLS, rate limiting, observability, circuit breaking) handled by proven tools
- OPA (Open Policy Agent) for flow policy — declarative, auditable, standard
- Built-in observability (Prometheus metrics, distributed tracing)
- Enterprises likely already running a mesh — this is just another backend

**Weaknesses:**
- Requires Kubernetes or equivalent orchestration (not suitable for bare Docker/compose)
- Configuration spread across mesh config + gateway config + OPA policies — more moving parts
- Mesh adds operational complexity for smaller teams
- Overkill for single-scanner deployments

**Best for:** Kubernetes-native organizations, large enterprises with existing service mesh.

### Option D: Sidecar Model — Protocol Gateway per gvmd, Centralized Flow Control

Flip the topology: deploy a thin protocol gateway as a sidecar to each gvmd, with a centralized flow control plane routing traffic.

```
                                    ┌───────────────────────────┐
                                ┌──►│ gvm-sidecar + gvmd-prod   │
┌──────────┐   ┌─────────────┐ │   │ (REST→GMP, local socket)  │
│ Clients  │──►│ Flow Control │─┤   └───────────────────────────┘
│          │   │ / Router     │ │   ┌───────────────────────────┐
│          │   │              │ ├──►│ gvm-sidecar + gvmd-staging │
│          │   │ • Identity   │ │   └───────────────────────────┘
│          │   │ • Routing    │ │   ┌───────────────────────────┐
│          │   │ • Policy     │ └──►│ gvm-sidecar + gvmd-dmz    │
└──────────┘   └─────────────┘     └───────────────────────────┘
                                    (each sidecar talks local
                                     Unix socket to its gvmd)
```

**Strengths:**
- Each sidecar connects via local Unix socket — simplest, most secure transport
- No remote GMP connections — flow control proxy handles all remote networking
- Sidecars are identical, stateless, easy to deploy via container orchestration
- Natural fit for Kubernetes DaemonSet/sidecar injection
- Flow control plane can be anything (Envoy, custom, managed service)
- Operation-level RBAC can live in sidecar (close to gvmd) or centrally — flexible

**Weaknesses:**
- More instances to manage (one sidecar per gvmd)
- Cross-endpoint aggregation needs a separate aggregation service (or the flow control plane does it)
- Connection pooling is per-sidecar (simpler but less flexible)
- Requires deploying the sidecar everywhere a gvmd runs

**Best for:** Container-orchestrated environments, geo-distributed scanners, edge deployments.

### Comparison Matrix

| Dimension | A: Monolith | B: Two-Layer | C: Mesh + Gateway | D: Sidecar |
|-----------|-------------|-------------|-------------------|------------|
| **Deployment complexity** | Low | Medium | High | Medium |
| **Custom code** | High (all bespoke) | Medium | Low (GMP only) | Medium |
| **Defense in depth** | ❌ Single point | ✅ Two layers | ✅ Mesh + app | ✅ Distributed |
| **Reuse for non-GVM** | ❌ | ✅ Flow proxy | ✅ Mesh | ✅ Flow plane |
| **Existing infra leverage** | ❌ | ⚡ Partial | ✅ Full | ⚡ Partial |
| **Bare Docker/compose** | ✅ | ✅ | ❌ Needs K8s | ⚡ Possible |
| **Kubernetes-native** | ⚡ Works | ✅ | ✅ Ideal | ✅ Ideal |
| **MSP multi-tenant** | ⚡ Possible | ✅ Good | ✅ Best | ✅ Good |
| **Small team overhead** | Low | Medium | High | Medium |
| **Cross-endpoint aggregation** | ✅ Built-in | ✅ In gateway | ✅ In gateway | Needs aggregator |
| **Latency** | Lowest | +1 hop | +1 hop | Lowest (local) |

### Recommendation

**Start with Option A** (monolith) for Phase 1 — it's the fastest to deliver value and easiest to validate the design. The REST→GMP translation, operation-level RBAC, and connection pooling are the hard problems worth solving first.

**Evolve toward Option B** as the deployment grows beyond a single team or when the flow control proxy needs to govern non-GVM services too. The monolith's auth layer can be extracted cleanly if designed with this boundary in mind from the start.

**Option C** is the right answer for organizations already running Kubernetes + service mesh — but that's a deployment decision, not an architectural one. The protocol gateway (gvm-gateway) should work behind any proxy.

**Option D** is worth considering for geo-distributed or edge scanner deployments where remote GMP connections are undesirable.

The key design principle: **build the protocol gateway to be proxy-agnostic.** It should work standalone (Option A), behind a dedicated flow proxy (Option B), behind a service mesh (Option C), or as a sidecar (Option D). The auth layer should accept both direct authentication (API keys) and forwarded identity (from an upstream proxy). This keeps all options open.

---

## 12. Open Questions

1. **Configuration format**: YAML? TOML? Should policy be separate from endpoint config?
2. **Dynamic vs static config**: Hot-reload on SIGHUP? Admin API for runtime changes? Or immutable config requiring restart?
3. **Credential management**: Built-in encrypted store vs mandatory external vault?
4. **Multi-user GMP sessions**: One gvmd user per endpoint (gateway acts as single identity), or pass-through (map client identity to distinct gvmd users)?
5. **Caching**: Cache `get_version`, `get_scan_configs`, `get_scanners` responses? They change rarely. TTL-based or invalidation?
6. **Rate limiting**: Per-client, per-endpoint, or per-operation? Token bucket or sliding window?
7. **Repo structure**: New repo `gvm-gateway`? Or new crate in rust-gvm workspace?
