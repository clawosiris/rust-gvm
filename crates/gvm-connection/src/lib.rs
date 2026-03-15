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
