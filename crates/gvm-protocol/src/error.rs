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

    /// Server returned an error status.
    #[error("Server error (status {status}): {message}")]
    ServerError {
        /// The GMP status code.
        status: u16,
        /// The status text from the server.
        message: String,
    },
}
