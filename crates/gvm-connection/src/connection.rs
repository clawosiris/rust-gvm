// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared connection trait for GVM transports.

use async_trait::async_trait;

/// Abstraction over async transports that communicate with gvmd.
#[async_trait]
pub trait GvmConnection: Send + Sync {
    /// Connect to the server.
    ///
    /// # Errors
    /// Returns an error if the transport cannot establish a connection.
    async fn connect(&mut self) -> crate::Result<()>;

    /// Disconnect from the server.
    ///
    /// # Errors
    /// Returns an error if the transport cannot shut down cleanly.
    async fn disconnect(&mut self) -> crate::Result<()>;

    /// Send data to the server.
    ///
    /// # Errors
    /// Returns an error if the transport is disconnected or the write fails.
    async fn send(&mut self, data: &[u8]) -> crate::Result<()>;

    /// Read a complete GMP response from the server.
    ///
    /// Uses `XmlReader` to detect complete XML elements.
    ///
    /// # Errors
    /// Returns an error if the transport is disconnected, the read times out,
    /// or the stream closes before a full response is received.
    async fn read(&mut self) -> crate::Result<Vec<u8>>;

    /// Check if currently connected.
    fn is_connected(&self) -> bool;
}
