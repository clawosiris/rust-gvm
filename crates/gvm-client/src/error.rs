// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Error types for the high-level GMP client.

use std::time::Duration;

use gvm_connection::ConnectionError;
use gvm_gmp::responses::ParseError;
use thiserror::Error;

/// High-level client errors.
#[derive(Debug, Error)]
pub enum GvmError {
    /// Transport-level failure.
    #[error("connection error: {0}")]
    Connection(#[source] ConnectionError),

    /// Response model parsing failure.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

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
}

impl From<ConnectionError> for GvmError {
    fn from(value: ConnectionError) -> Self {
        match value {
            ConnectionError::Timeout(duration) => Self::Timeout(duration),
            other => Self::Connection(other),
        }
    }
}
