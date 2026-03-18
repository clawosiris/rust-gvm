# gvmd Transport Analysis for rust-gvm

## 1. Scope

This document focuses on the transport and protocol boundary between `rust-gvm` and `gvmd` as it exists today.

It does not cover exposing a new API in front of `gvmd`. That analysis now lives in [GMP API Proxy Analysis](gmp-api-proxy-analysis.md).

## 2. How gvmd Implements GMP Today

### Transport architecture

gvmd exposes GMP as a raw XML stream over a persistent TCP or Unix socket connection, optionally wrapped in TLS. There is no HTTP layer.

```text
rust-gvm client ──[ XML bytes ]──▶ [ Unix socket | TLS+TCP :9390 ] ──▶ gvmd
                ◀── [ XML bytes ]─────────────────────────────────────◀
```

### Connection types

| Listener | Mechanism | Auth | Notes |
|----------|-----------|------|-------|
| Unix socket | `AF_UNIX` / `SOCK_STREAM` | Filesystem permissions + GMP `<authenticate>` | Default in container deployments. Owner, group, and mode are configurable via `--listen-owner`, `--listen-group`, `--listen-mode`. |
| TLS over TCP | `AF_INET`/`AF_INET6` on port 9390 by default | GnuTLS mutual TLS + GMP `<authenticate>` | Enabled via `--listen <address>` and `--port <port>`. Supports DH params via `--dh-params` and priority strings via `--gnutls-priorities`. Client cert is optional. |
| SSH tunnel | Not native to gvmd | SSH handles transport; gvmd still sees a Unix socket | `python-gvm` uses `direct-streamlocal@openssh.com` to tunnel to the remote Unix socket. |

gvmd can listen on two sockets simultaneously via `--listen` and `--listen2`, for example one Unix socket and one TLS listener.

### Protocol flow

1. Client connects over Unix socket or TLS.
2. Client sends `<get_version/>`, which is available before authentication.
3. Client sends `<authenticate><credentials>...</credentials></authenticate>`.
4. Client sends GMP commands as XML elements; gvmd responds with XML elements.
5. The connection persists until the client disconnects.

### Key characteristics

- Stateful sessions: gvmd forks a child process per client connection. Authenticated user state and permissions live in that process.
- XML stream framing: there is no length prefix or record delimiter. Clients must parse XML to detect message boundaries. This is what `XmlReader` in `rust-gvm` handles.
- Synchronous request and response: one command at a time per connection. There is no multiplexing or pipelining beyond the GMP `<commands>` wrapper for batching.
- No HTTP: GMP is not HTTP-based. There are no HTTP headers, no `Content-Length`, and no chunked transfer encoding.

### The `manage_http_scanner.c` file

This is not an HTTP interface for GMP. It is gvmd's internal client for connecting to HTTP-based scanners. gvmd itself acts as an HTTP client there; it does not expose GMP over HTTP.

## 3. Transport Implications for rust-gvm

`rust-gvm` currently implements the correct transport model for gvmd as it exists today:

- `UnixSocketConnection` for primary containerized deployments
- `SshConnection` for remote access via SSH tunnel
- `TlsConnection` as the remaining planned parity item for direct TLS+TCP on port 9390

There is no native HTTP or gRPC transport to implement in `rust-gvm` today because gvmd does not expose either interface.

## 4. Strengths and Constraints of the Current Transport

### Strengths

- Mature and battle-tested transport model
- Low framing overhead
- Natural fit for long-lived management sessions
- Works well with Unix sockets in local and containerized deployments
- TLS with mutual authentication provides strong transport security
- GMP supports batching through the `<commands>` wrapper

### Constraints

- No standard framing; clients need XML stream parsing
- No multiplexing; concurrency requires multiple connections
- XML is verbose for large payloads such as reports
- Responses are typically processed as full XML documents unless the client implements incremental parsing
- Reconnection requires re-authentication because sessions are stateful
- Tooling is limited compared to HTTP-based APIs
- Error handling is encoded in GMP XML rather than a standard transport error model

## 5. Practical Recommendations

1. Complete `TlsConnection` support to reach parity with existing gvmd connection modes.
2. Improve incremental or streaming XML reads so large report responses do not need to be buffered fully in memory.
3. Keep the transport abstraction centered on gvmd's real interfaces: Unix socket, SSH tunnel, and TLS.
4. Watch upstream changes in gvmd, especially around newer HTTP-based scanner integrations, but do not assume that implies a client-facing HTTP API.
5. Treat any REST or gRPC exposure as a separate proxy or gateway concern rather than part of the direct `rust-gvm` transport layer.

## 6. Related Documents

- [GMP API Proxy Analysis](gmp-api-proxy-analysis.md)
- [Proxy Access Control Analysis](proxy-access-control-analysis.md)
