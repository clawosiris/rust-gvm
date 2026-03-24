// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

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

#[cfg(any())]
pub mod ssh;

pub use connection::GvmConnection;
pub use error::{ConnectionError, Result};

#[cfg(feature = "unix")]
pub use unix::{UnixSocketConfig, UnixSocketConnection};

#[cfg(any())]
pub use ssh::{SshAuth, SshConfig, SshConnection, SshHostKeyPolicy};
