//! Error types for the high-level GMP client.

use std::time::Duration;

use gvm_connection::ConnectionError;
use thiserror::Error;

/// High-level client errors.
#[derive(Debug, Error)]
pub enum GvmError {
    /// Transport-level failure.
    #[error("connection error: {0}")]
    Connection(String),

    /// Response or version XML could not be parsed.
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// Client state does not permit the requested operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Server returned a non-success GMP status code.
    #[error("server error (status {status}): {message}")]
    Server {
        /// GMP status code returned by the server.
        status: u16,
        /// GMP status text returned by the server.
        message: String,
    },

    /// Server advertised an unsupported GMP version.
    #[error("unsupported GMP version: {0}.{1}")]
    UnsupportedVersion(u16, u16),

    /// Operation timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),

    /// Low-level I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ConnectionError> for GvmError {
    fn from(value: ConnectionError) -> Self {
        match value {
            ConnectionError::Timeout(duration) => Self::Timeout(duration),
            ConnectionError::ConnectFailed(error)
            | ConnectionError::SendFailed(error)
            | ConnectionError::ReadFailed(error) => Self::Connection(error.to_string()),
            other => Self::Connection(other.to_string()),
        }
    }
}
