# Task: Implement gvm-connection Crate (Unix Socket Transport)

## Context

The `gvm-connection` crate provides async transport for communicating with gvmd. This task implements the Unix socket transport — the most common connection method and the one used by the mock server tests.

The crate already has `Cargo.toml` with dependencies configured. The `src/lib.rs` is a placeholder.

## What to Build

### 1. Error Types (`src/error.rs`)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("not connected to server")]
    NotConnected,

    #[error("already connected")]
    AlreadyConnected,

    #[error("connection failed: {0}")]
    ConnectFailed(#[source] std::io::Error),

    #[error("send failed: {0}")]
    SendFailed(#[source] std::io::Error),

    #[error("read failed: {0}")]
    ReadFailed(#[source] std::io::Error),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("socket not found: {0}")]
    SocketNotFound(String),
}

pub type Result<T> = std::result::Result<T, ConnectionError>;
```

### 2. Connection Trait (`src/connection.rs`)

```rust
use async_trait::async_trait;

#[async_trait]
pub trait GvmConnection: Send + Sync {
    /// Connect to the server.
    async fn connect(&mut self) -> crate::Result<()>;

    /// Disconnect from the server.
    async fn disconnect(&mut self) -> crate::Result<()>;

    /// Send data to the server.
    async fn send(&mut self, data: &[u8]) -> crate::Result<()>;

    /// Read a complete GMP response from the server.
    /// Uses XmlReader to detect complete XML elements.
    async fn read(&mut self) -> crate::Result<Vec<u8>>;

    /// Check if currently connected.
    fn is_connected(&self) -> bool;
}
```

Note: We need the `async-trait` crate. Add it to Cargo.toml dependencies:
```toml
async-trait = "0.1"
```

Actually, check if we can use Rust native async traits (edition 2021, Rust 1.75+). Rust 1.75 stabilized `async fn in traits` for `dyn`-safe traits. Since our MSRV is 1.75 and we need `dyn GvmConnection`, we should use `async-trait` crate for now (dyn dispatch with native async traits requires Rust 1.80+). Add `async-trait = "0.1"` to the workspace dependencies in the root Cargo.toml and reference it in gvm-connection's Cargo.toml.

### 3. Unix Socket Connection (`src/unix.rs`)

```rust
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::connection::GvmConnection;
use crate::error::{ConnectionError, Result};

/// Configuration for Unix socket connections.
#[derive(Debug, Clone)]
pub struct UnixSocketConfig {
    /// Path to the Unix socket.
    pub path: PathBuf,
    /// Connection timeout.
    pub timeout: Duration,
    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
}

impl Default for UnixSocketConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/run/gvmd/gvmd.sock"),
            timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
        }
    }
}

impl UnixSocketConfig {
    /// Create config with a custom socket path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Unix socket connection to gvmd.
pub struct UnixSocketConnection {
    config: UnixSocketConfig,
    stream: Option<UnixStream>,
}

impl UnixSocketConnection {
    /// Create a new Unix socket connection with the given config.
    pub fn new(config: UnixSocketConfig) -> Self {
        Self {
            config,
            stream: None,
        }
    }

    /// Create a connection with default config pointing to the given path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self::new(UnixSocketConfig::new(path))
    }
}

#[async_trait::async_trait]
impl GvmConnection for UnixSocketConnection {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(ConnectionError::AlreadyConnected);
        }

        if !self.config.path.exists() {
            return Err(ConnectionError::SocketNotFound(
                self.config.path.display().to_string(),
            ));
        }

        let stream = tokio::time::timeout(
            self.config.timeout,
            UnixStream::connect(&self.config.path),
        )
        .await
        .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
        .map_err(ConnectionError::ConnectFailed)?;

        self.stream = Some(stream);
        tracing::debug!("Connected to {}", self.config.path.display());
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
            tracing::debug!("Disconnected from {}", self.config.path.display());
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
        stream
            .write_all(data)
            .await
            .map_err(ConnectionError::SendFailed)?;
        Ok(())
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
        let mut buf = vec![0u8; self.config.read_buffer_size];
        let mut xml_reader = gvm_protocol::XmlReader::new();

        loop {
            let n = tokio::time::timeout(
                self.config.timeout,
                stream.read(&mut buf),
            )
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
            .map_err(ConnectionError::ReadFailed)?;

            if n == 0 {
                return Err(ConnectionError::ReadFailed(
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed"),
                ));
            }

            let _ = xml_reader.feed(&buf[..n]);

            if xml_reader.is_complete() {
                return Ok(xml_reader.into_data());
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}
```

### 4. Update `src/lib.rs`

```rust
//! Transport layer for GVM connections.
//!
//! Provides async connection implementations for communicating with gvmd:
//! - Unix domain sockets (default)
//! - TLS over TCP (feature: `tls`)
//! - SSH tunnels (feature: `ssh`)

pub mod connection;
pub mod error;

#[cfg(feature = "unix")]
pub mod unix;

pub use connection::GvmConnection;
pub use error::{ConnectionError, Result};

#[cfg(feature = "unix")]
pub use unix::{UnixSocketConfig, UnixSocketConnection};
```

### 5. Integration Tests (`tests/unix_connection.rs`)

Test against the mock server to validate the full send/receive cycle:

```rust
#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]

use gvm_connection::{GvmConnection, UnixSocketConfig, UnixSocketConnection};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::XmlCommand;

async fn start_mock() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
        .expect("mock server start failed")
}

#[tokio::test]
async fn connect_and_get_version() {
    let server = start_mock().await;
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");
    assert!(conn.is_connected());

    // Send get_version
    let cmd = XmlCommand::new("get_version");
    conn.send(&cmd.to_bytes()).await.expect("send failed");

    // Read response
    let response_data = conn.read().await.expect("read failed");
    let response = gvm_protocol::Response::new(response_data);
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));

    conn.disconnect().await.expect("disconnect failed");
    assert!(!conn.is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn connect_authenticate_and_create_target() {
    let server = start_mock().await;
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");

    // Authenticate
    let auth_cmd = XmlCommand::new("authenticate")
        .child_with_text("credentials", "")  // We'll build this manually
        ;
    // Build auth XML manually since it has nested structure
    let auth_xml = b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>";
    conn.send(auth_xml).await.expect("send auth failed");
    let auth_resp = conn.read().await.expect("read auth failed");
    let auth_response = gvm_protocol::Response::new(auth_resp);
    assert_eq!(auth_response.status_code(), Some(200));

    // Create target
    let create_xml = b"<create_target><name>Test Target</name><hosts>192.168.1.0/24</hosts></create_target>";
    conn.send(create_xml).await.expect("send create failed");
    let create_resp = conn.read().await.expect("read create failed");
    let create_response = gvm_protocol::Response::new(create_resp);
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn reconnect_flow() {
    // Test the python-gvm two-connection pattern
    let server = start_mock().await;
    let socket_path = server.socket_path().expect("should have socket");

    // Connection 1: version probe
    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect 1 failed");

    conn.send(b"<get_version/>").await.expect("send failed");
    let resp = conn.read().await.expect("read failed");
    let response = gvm_protocol::Response::new(resp);
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));

    conn.disconnect().await.expect("disconnect 1 failed");

    // Connection 2: auth + commands
    let config2 = UnixSocketConfig::new(server.socket_path().expect("socket"));
    let mut conn2 = UnixSocketConnection::new(config2);
    conn2.connect().await.expect("connect 2 failed");

    conn2.send(b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>")
        .await.expect("send auth failed");
    let auth_resp = conn2.read().await.expect("read auth failed");
    assert_eq!(gvm_protocol::Response::new(auth_resp).status_code(), Some(200));

    conn2.send(b"<get_tasks/>").await.expect("send tasks failed");
    let tasks_resp = conn2.read().await.expect("read tasks failed");
    assert_eq!(gvm_protocol::Response::new(tasks_resp).status_code(), Some(200));

    conn2.disconnect().await.expect("disconnect 2 failed");
    server.shutdown().await;
}

#[tokio::test]
async fn connect_not_connected_errors() {
    let mut conn = UnixSocketConnection::with_path("/nonexistent/socket.sock");
    assert!(!conn.is_connected());

    // Send without connecting should fail
    let result = conn.send(b"<get_version/>").await;
    assert!(result.is_err());

    // Read without connecting should fail
    let result = conn.read().await;
    assert!(result.is_err());

    // Connect to nonexistent socket should fail
    let result = conn.connect().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn double_connect_errors() {
    let server = start_mock().await;
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");
    let result = conn.connect().await;
    assert!(result.is_err()); // AlreadyConnected

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}
```

### 6. Unit Tests (`src/error.rs` and `src/unix.rs`)

Add unit tests for config and error types:

In `src/error.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ConnectionError::NotConnected;
        assert_eq!(err.to_string(), "not connected to server");
    }

    #[test]
    fn test_timeout_error() {
        let err = ConnectionError::Timeout(std::time::Duration::from_secs(5));
        assert!(err.to_string().contains("5s"));
    }

    #[test]
    fn test_socket_not_found() {
        let err = ConnectionError::SocketNotFound("/tmp/missing.sock".to_string());
        assert!(err.to_string().contains("/tmp/missing.sock"));
    }
}
```

In `src/unix.rs` add tests for config:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UnixSocketConfig::default();
        assert_eq!(config.path, PathBuf::from("/run/gvmd/gvmd.sock"));
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_custom_config() {
        let config = UnixSocketConfig::new("/tmp/test.sock")
            .with_timeout(Duration::from_secs(30));
        assert_eq!(config.path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_with_path() {
        let conn = UnixSocketConnection::with_path("/tmp/test.sock");
        assert!(!conn.is_connected());
    }
}
```

## Cargo.toml Changes

Add to root `Cargo.toml` workspace dependencies:
```toml
async-trait = "0.1"
```

Add to `crates/gvm-connection/Cargo.toml` dependencies:
```toml
async-trait = { workspace = true }
```

## Execution Order

1. Add `async-trait` to workspace and crate Cargo.toml
2. Create `src/error.rs` with error types and tests
3. Create `src/connection.rs` with trait
4. Create `src/unix.rs` with implementation and unit tests
5. Update `src/lib.rs` with module registration and re-exports
6. Create `tests/unix_connection.rs` integration tests
7. Run `cargo test --workspace` — all must pass
8. Run `cargo clippy --workspace` — no warnings
9. Commit: `feat(connection): implement Unix socket transport with mock server integration tests`

When completely finished, run:
```
openclaw system event --text "Done: Implemented gvm-connection Unix socket transport" --mode now
```
