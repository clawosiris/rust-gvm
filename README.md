# rust-gvm

Rust client library for the [Greenbone Management Protocol (GMP)](https://docs.greenbone.net/API/GMP/gmp-22.5.html) — a reimplementation of [python-gvm](https://github.com/greenbone/python-gvm) with type safety, async-first design, and a programmable mock server for testing.

[![CI](https://github.com/clawosiris/rust-gvm/actions/workflows/ci.yml/badge.svg)](https://github.com/clawosiris/rust-gvm/actions/workflows/ci.yml)
[![Nightly](https://github.com/clawosiris/rust-gvm/actions/workflows/nightly.yml/badge.svg)](https://github.com/clawosiris/rust-gvm/actions/workflows/nightly.yml)

## Overview

rust-gvm provides everything needed to talk to [Greenbone Vulnerability Manager (gvmd)](https://github.com/greenbone/gvmd) — from low-level XML framing to high-level typed commands — plus a standalone mock server that speaks the GMP protocol over Unix sockets or TCP, enabling integration testing without a real Greenbone instance.

### Crate Structure

| Crate | Purpose | Status |
|-------|---------|--------|
| [`gvm-protocol`](crates/gvm-protocol/) | Sans-I/O XML framing, command builder, response parser | ✅ Implemented |
| [`gvm-mock-server`](crates/gvm-mock-server/) | Programmable mock GMP server (4 modes, fault injection) | ✅ Implemented |
| [`gvm-connection`](crates/gvm-connection/) | Transport layer (Unix socket, TLS, SSH) | 🔧 Unix socket done |
| [`gvm-gmp`](crates/gvm-gmp/) | Typed GMP command builders per version (22.4–22.8+) | 📋 Spec'd |
| [`gvm-client`](crates/gvm-client/) | High-level async client with version negotiation | 📋 Spec'd |

```
┌─────────────────────────────────┐
│         gvm-client              │  High-level API, version negotiation
├─────────────────────────────────┤
│         gvm-gmp                 │  Typed commands per GMP version
├─────────────────────────────────┤
│       gvm-protocol              │  Sans-I/O XML framing + response parsing
├─────────────────────────────────┤
│      gvm-connection             │  Unix socket / TLS / SSH transports
└─────────────────────────────────┘

  gvm-mock-server  ← Standalone mock for testing any GMP client
```

## Quick Start

### Mock Server (library usage)

```rust
use gvm_mock_server::{MockGmpServer, ServerMode, GmpVersion};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await?;

    println!("Mock GMP server listening at: {:?}", server.socket_path());
    // Connect with any GMP client (rust-gvm, python-gvm, etc.)

    server.shutdown().await;
    Ok(())
}
```

### Mock Server (standalone binary)

```bash
# Start a stateful mock server on a Unix socket
gvm-mock-server --mode stateful --version 22.5 --socket /tmp/gvmd.sock

# Or on TCP
gvm-mock-server --mode stateful --version 22.5 --tcp 127.0.0.1:9390
```

Then connect with python-gvm:

```python
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

conn = UnixSocketConnection(path="/tmp/gvmd.sock")
with GMP(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
    gmp.authenticate("admin", "admin")
    targets = gmp.get_targets()
    print(targets)
```

## Mock Server

The mock server is the most developed component. It's designed to be a drop-in test server for any GMP client library — Rust, Python, Go, or shell scripts.

### Server Modes

| Mode | Description |
|------|-------------|
| **Echo** | Returns well-formed `<command_response status="200"/>` for any recognized command |
| **Fixture** | Returns pre-built realistic GMP XML from a fixture library (90+ commands) |
| **Stateful** | Full in-memory CRUD with authentication, task lifecycle, and resource relationships |
| **Scenario** | Plays back scripted command→response sequences (strict or lenient matching) |

### Features

- **4 server modes** — from simple echo to full stateful CRUD
- **Unix socket + TCP listeners** — compatible with python-gvm's `UnixSocketConnection` and `TLSConnection`
- **Per-session authentication** — supports python-gvm's two-connection flow (version probe + auth session)
- **Task lifecycle** — New → Running → Stopped → Done state machine
- **Fault injection** — disconnect, delay, malformed XML, error codes, truncated responses
- **Scenario playback** — deterministic scripted sequences for regression tests
- **Command history** — inspect what the server received after tests
- **Pre-seeding** — populate the store before tests via builder API
- **Template substitution** — `{{uuid}}`, `{{now}}`, `{{version}}` in fixture responses
- **Resource filtering** — basic GMP filter string support (`name=foo status=Running`)

### Validated Against

The mock server is validated against [python-gvm](https://github.com/greenbone/python-gvm) in CI, exercising the full protocol flow: version negotiation, authentication, target/task CRUD, notes lifecycle, and cleanup.

## Connection Crate

`gvm-connection` provides async transport implementations behind the `GvmConnection` trait:

```rust
use gvm_connection::{GvmConnection, UnixSocketConfig, UnixSocketConnection};

let config = UnixSocketConfig::new("/run/gvmd/gvmd.sock");
let mut conn = UnixSocketConnection::new(config);

conn.connect().await?;
conn.send(b"<get_version/>").await?;
let response_bytes = conn.read().await?;  // Uses XmlReader for frame detection
conn.disconnect().await?;
```

### Transports

| Transport | Status | Feature Flag |
|-----------|--------|-------------|
| Unix socket | ✅ Implemented | `unix` (default) |
| TLS over TCP | 📋 Planned | `tls` |
| SSH tunnel | 📋 Planned | `ssh` |

The Unix socket transport supports the full python-gvm reconnect pattern (connect → get_version → disconnect → reconnect → authenticate → commands) and is integration-tested against `gvm-mock-server`.

## Protocol Crate

`gvm-protocol` provides the transport-agnostic building blocks:

- **`XmlCommand`** — Builder for GMP XML commands with attributes, child elements, and text content
- **`Response`** — Parser for GMP XML responses (status codes, child text extraction, id extraction)
- **`XmlReader`** — Streaming XML completeness detector for framing GMP messages over byte streams

## Implementation Status

See [docs/STATUS.md](docs/STATUS.md) for detailed implementation status of each crate and GMP command coverage.

## Building

```bash
# Build everything
cargo build --workspace

# Run all tests (255+ tests)
cargo test --workspace

# Run python-gvm integration tests
make test-integration

# Build the mock server binary
cargo build --release -p gvm-mock-server
```

### Requirements

- Rust 1.75+ (MSRV)
- Python 3.10+ with `python-gvm` (for integration tests only)

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| **CI** | Push/PR to main | Format, clippy, test, doc, deny, coverage, MSRV, python-gvm integration |
| **Nightly** | Daily 04:00 UTC + manual | Full CI + cross-platform binary builds (5 targets) |
| **Release** | `v*` tag push | Full test → cross-platform builds → GitHub Release with checksums |

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/clawosiris/rust-gvm/releases) or the rolling [nightly](https://github.com/clawosiris/rust-gvm/releases/tag/nightly) pre-release.

| Platform | Binary |
|----------|--------|
| Linux x86_64 (glibc) | `gvm-mock-server-linux-amd64.tar.gz` |
| Linux x86_64 (musl, static) | `gvm-mock-server-linux-amd64-musl.tar.gz` |
| Linux ARM64 | `gvm-mock-server-linux-arm64.tar.gz` |
| macOS x86_64 | `gvm-mock-server-macos-amd64.tar.gz` |
| macOS ARM64 | `gvm-mock-server-macos-arm64.tar.gz` |

## Specs

Design specifications live in [`spec/`](spec/):

- [`openspec.md`](spec/openspec.md) — Full library architecture and crate specs
- [`mock-server-openspec.md`](spec/mock-server-openspec.md) — Mock server design and API
- [`mock-server-tests-openspec.md`](spec/mock-server-tests-openspec.md) — Test plan
- [`library-tests-openspec.md`](spec/library-tests-openspec.md) — Library test plan
- [`mcp-server-integration-spec.md`](spec/mcp-server-integration-spec.md) — MCP server integration testing

## License

GPL-3.0-or-later — matching python-gvm and the Greenbone ecosystem.

## Related Projects

- [python-gvm](https://github.com/greenbone/python-gvm) — Official Python GMP library
- [gvmd](https://github.com/greenbone/gvmd) — Greenbone Vulnerability Manager daemon
- [openvas-mcp-server](https://github.com/clawosiris/openvas-mcp-server) — MCP Server for OpenVAS/Greenbone
