// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Error types for GVM transport connections.

use thiserror::Error;

/// Errors returned by connection implementations.
#[derive(Error, Debug)]
pub enum ConnectionError {
    /// The operation requires an active connection.
    #[error("not connected to server")]
    NotConnected,

    /// The connection is already established.
    #[error("already connected")]
    AlreadyConnected,

    /// Connecting to the remote server failed.
    #[error("connection failed: {0}")]
    ConnectFailed(#[source] std::io::Error),

    /// Sending data to the remote server failed.
    #[error("send failed: {0}")]
    SendFailed(#[source] std::io::Error),

    /// Reading data from the remote server failed.
    #[error("read failed: {0}")]
    ReadFailed(#[source] std::io::Error),

    /// An operation exceeded the configured timeout.
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// The configured Unix socket path does not exist.
    #[error("socket not found: {0}")]
    SocketNotFound(String),
}

/// Result alias for connection operations.
pub type Result<T> = std::result::Result<T, ConnectionError>;

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
