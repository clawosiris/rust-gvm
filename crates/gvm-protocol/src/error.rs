// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Protocol error types.

/// Errors that can occur in the GMP protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// XML parsing failed.
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// Protocol state machine is in an invalid state for the requested operation.
    #[error("Invalid protocol state: {0}")]
    InvalidState(String),

    /// The streaming XML buffer exceeded its configured size limit.
    #[error("XML buffer exceeded configured limit of {max} bytes")]
    BufferOverflow {
        /// The configured buffer size limit in bytes.
        max: usize,
    },

    /// Server returned an error status.
    #[error("Server error (status {status}): {message}")]
    ServerError {
        /// The GMP status code.
        status: u16,
        /// The status text from the server.
        message: String,
    },
}
