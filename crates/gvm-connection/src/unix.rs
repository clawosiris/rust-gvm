// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Unix domain socket transport for gvmd.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::connection::{write_all_and_flush_with_timeout, GvmConnection};
use crate::error::{ConnectionError, Result};

/// Configuration for Unix socket connections.
#[derive(Debug, Clone)]
pub struct UnixSocketConfig {
    /// Path to the Unix socket.
    pub path: PathBuf,
    /// Connect, request-write/flush, and response-read timeout.
    pub timeout: Duration,
    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
    /// Maximum XML response size in bytes before aborting the read.
    pub max_response_bytes: Option<usize>,
}

impl Default for UnixSocketConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/run/gvmd/gvmd.sock"),
            timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
            max_response_bytes: Some(64 * 1024 * 1024),
        }
    }
}

impl UnixSocketConfig {
    /// Create config with a custom socket path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Self::default()
        }
    }

    /// Set the transport operation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum XML response size in bytes.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: Option<usize>) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

/// Unix socket connection to gvmd.
pub struct UnixSocketConnection {
    config: UnixSocketConfig,
    stream: Option<UnixStream>,
    response_reader: gvm_protocol::XmlReader,
    pending_read: Vec<u8>,
}

impl std::fmt::Debug for UnixSocketConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixSocketConnection")
            .field("config", &self.config)
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl UnixSocketConnection {
    /// Create a new Unix socket connection with the given config.
    #[must_use]
    pub fn new(config: UnixSocketConfig) -> Self {
        let response_reader = gvm_protocol::XmlReader::with_buffer_limit(config.max_response_bytes);
        Self {
            config,
            stream: None,
            response_reader,
            pending_read: Vec::new(),
        }
    }

    /// Create a connection with default config pointing to the given path.
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self::new(UnixSocketConfig::new(path))
    }

    fn invalidate_protocol_read(&mut self, error: &gvm_protocol::ProtocolError) -> ConnectionError {
        self.invalidate_connection();
        protocol_read_error(error)
    }

    fn invalidate_connection(&mut self) {
        self.stream.take();
        self.response_reader.reset();
        self.pending_read.clear();
    }
}

#[async_trait::async_trait]
impl GvmConnection for UnixSocketConnection {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(ConnectionError::AlreadyConnected);
        }

        self.response_reader.reset();
        self.pending_read.clear();

        if !self.config.path.exists() {
            return Err(ConnectionError::SocketNotFound(
                self.config.path.display().to_string(),
            ));
        }

        let stream =
            tokio::time::timeout(self.config.timeout, UnixStream::connect(&self.config.path))
                .await
                .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
                .map_err(ConnectionError::ConnectFailed)?;

        self.stream = Some(stream);
        tracing::debug!("connected to {}", self.config.path.display());
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.response_reader.reset();
        self.pending_read.clear();
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
            tracing::debug!("disconnected from {}", self.config.path.display());
        }

        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let result = {
            let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
            write_all_and_flush_with_timeout(stream, data, self.config.timeout).await
        };
        if result.is_err() {
            self.invalidate_connection();
        }
        result
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        if self.stream.is_none() {
            return Err(ConnectionError::NotConnected);
        }

        if !self.pending_read.is_empty() {
            let consumed = match self.response_reader.feed_frame(&self.pending_read) {
                Ok(consumed) => consumed,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            self.pending_read.drain(..consumed);
            let frame = match self.response_reader.take_frame() {
                Ok(frame) => frame,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if let Some(frame) = frame {
                return Ok(frame);
            }
            debug_assert!(self.pending_read.is_empty());
        }

        let mut buf = vec![0_u8; self.config.read_buffer_size];

        loop {
            let read_result = {
                let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
                tokio::time::timeout(self.config.timeout, stream.read(&mut buf)).await
            };
            let n = match read_result {
                Ok(Ok(n)) => n,
                Ok(Err(error)) => {
                    self.invalidate_connection();
                    return Err(ConnectionError::ReadFailed(error));
                }
                Err(_) => {
                    self.invalidate_connection();
                    return Err(ConnectionError::Timeout(self.config.timeout));
                }
            };

            if n == 0 {
                self.invalidate_connection();
                return Err(ConnectionError::ReadFailed(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }

            let consumed = match self.response_reader.feed_frame(&buf[..n]) {
                Ok(consumed) => consumed,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if consumed < n {
                self.pending_read.extend_from_slice(&buf[consumed..n]);
            }

            let frame = match self.response_reader.take_frame() {
                Ok(frame) => frame,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if let Some(frame) = frame {
                return Ok(frame);
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

fn protocol_read_error(error: &gvm_protocol::ProtocolError) -> ConnectionError {
    ConnectionError::ReadFailed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UnixSocketConfig::default();
        assert_eq!(config.path, PathBuf::from("/run/gvmd/gvmd.sock"));
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_response_bytes, Some(64 * 1024 * 1024));
    }

    #[test]
    fn test_custom_config() {
        let config = UnixSocketConfig::new("/tmp/test.sock")
            .with_timeout(Duration::from_secs(30))
            .with_max_response_bytes(Some(1024));
        assert_eq!(config.path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_response_bytes, Some(1024));
    }

    #[test]
    fn test_with_path() {
        let conn = UnixSocketConnection::with_path("/tmp/test.sock");
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_connection_debug_redacts_pending_response() {
        let mut conn = UnixSocketConnection::with_path("/tmp/test.sock");
        conn.pending_read
            .extend_from_slice(b"<secret>do-not-log</secret>");

        let debug = format!("{conn:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("do-not-log"));
        assert!(debug.contains("connected"));
    }
}
