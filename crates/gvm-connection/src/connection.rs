// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared connection trait for GVM transports.

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::ConnectionError;

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
    /// A send error leaves the outcome of the request ambiguous. Implementations
    /// therefore invalidate an active transport before returning the error.
    ///
    /// # Errors
    /// Returns an error if the transport is disconnected, the write times out,
    /// or the write or flush fails.
    async fn send(&mut self, data: &[u8]) -> crate::Result<()>;

    /// Read a complete GMP response from the server.
    ///
    /// Uses `XmlReader` to detect complete XML elements.
    /// A read error invalidates an active transport so a late response cannot
    /// be mistaken for the response to a later request.
    ///
    /// # Errors
    /// Returns an error if the transport is disconnected, the read times out,
    /// or the stream closes before a full response is received.
    async fn read(&mut self) -> crate::Result<Vec<u8>>;

    /// Check if currently connected.
    fn is_connected(&self) -> bool;
}

pub(crate) async fn write_all_and_flush_with_timeout<W>(
    writer: &mut W,
    data: &[u8],
    operation_timeout: Duration,
) -> crate::Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(operation_timeout, async {
        writer.write_all(data).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| ConnectionError::Timeout(operation_timeout))?
    .map_err(ConnectionError::SendFailed)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;

    struct PendingFlushWriter;

    impl AsyncWrite for PendingFlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn outbound_deadline_covers_write_backpressure() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let result =
            write_all_and_flush_with_timeout(&mut writer, &[0_u8; 1024], Duration::from_millis(10))
                .await;

        assert!(matches!(result, Err(ConnectionError::Timeout(_))));
    }

    #[tokio::test]
    async fn outbound_deadline_covers_flush() {
        let mut writer = PendingFlushWriter;
        let result = write_all_and_flush_with_timeout(
            &mut writer,
            b"<get_version/>",
            Duration::from_millis(10),
        )
        .await;

        assert!(matches!(result, Err(ConnectionError::Timeout(_))));
        writer.shutdown().await.expect("shutdown");
    }
}
