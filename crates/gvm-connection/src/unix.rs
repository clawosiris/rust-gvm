// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Unix domain socket transport for gvmd.

use std::path::PathBuf;
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

    /// Set the timeout.
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
#[derive(Debug)]
pub struct UnixSocketConnection {
    config: UnixSocketConfig,
    stream: Option<UnixStream>,
}

impl UnixSocketConnection {
    /// Create a new Unix socket connection with the given config.
    #[must_use]
    pub fn new(config: UnixSocketConfig) -> Self {
        Self {
            config,
            stream: None,
        }
    }

    /// Create a connection with default config pointing to the given path.
    #[must_use]
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
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
            tracing::debug!("disconnected from {}", self.config.path.display());
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
        let mut buf = vec![0_u8; self.config.read_buffer_size];
        let mut xml_reader =
            gvm_protocol::XmlReader::with_buffer_limit(self.config.max_response_bytes);

        loop {
            let n = tokio::time::timeout(self.config.timeout, stream.read(&mut buf))
                .await
                .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
                .map_err(ConnectionError::ReadFailed)?;

            if n == 0 {
                return Err(ConnectionError::ReadFailed(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }

            xml_reader.feed(&buf[..n]).map_err(|error| {
                ConnectionError::ReadFailed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    error.to_string(),
                ))
            })?;

            if xml_reader.is_complete() {
                return Ok(xml_reader.into_data());
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
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
}
