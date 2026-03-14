//! Network listeners for Unix sockets and TCP.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;

use crate::fixtures::FixtureStore;
use crate::handler::SessionHandler;
use crate::history::CommandHistory;
use crate::version::GmpVersion;
use crate::ServerMode;

/// Shared state across all sessions.
pub struct ListenerState {
    /// Server operating mode.
    pub mode: ServerMode,
    /// GMP version to advertise.
    pub version: GmpVersion,
    /// Command history shared with all sessions.
    pub history: CommandHistory,
    /// Counter for assigning session IDs.
    pub session_counter: AtomicU64,
    /// Fixture store (if using Fixture mode).
    pub fixtures: Option<FixtureStore>,
    /// Shutdown signal.
    pub shutdown: Arc<Notify>,
}

impl ListenerState {
    fn next_session_id(&self) -> u64 {
        self.session_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Run a Unix socket listener.
pub async fn run_unix_listener(
    listener: UnixListener,
    state: Arc<ListenerState>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_stream(stream, &state).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Unix accept error: {e}");
                    }
                }
            }
            () = state.shutdown.notified() => {
                tracing::debug!("Unix listener shutting down");
                break;
            }
        }
    }
}

/// Run a TCP listener.
pub async fn run_tcp_listener(
    listener: TcpListener,
    state: Arc<ListenerState>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        tracing::debug!("TCP connection from {addr}");
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_stream(stream, &state).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!("TCP accept error: {e}");
                    }
                }
            }
            () = state.shutdown.notified() => {
                tracing::debug!("TCP listener shutting down");
                break;
            }
        }
    }
}

/// Handle a single client connection (works for both Unix and TCP streams).
async fn handle_stream<S>(mut stream: S, state: &ListenerState)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let session_id = state.next_session_id();
    let handler = SessionHandler::new(
        state.mode,
        state.version,
        state.history.clone(),
        session_id,
        state.fixtures.clone(),
    );

    let mut buf = vec![0u8; 16 * 1024];
    let mut xml_buf = Vec::new();

    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break, // Connection closed
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("Read error on session {session_id}: {e}");
                break;
            }
        };

        xml_buf.extend_from_slice(&buf[..n]);

        // Try to find complete XML commands in the buffer.
        // GMP uses a simple protocol: one XML document per command,
        // terminated by the closing tag of the root element.
        while let Some(response_data) = try_extract_command(&mut xml_buf, &handler) {
            if let Err(e) = stream.write_all(&response_data).await {
                tracing::debug!("Write error on session {session_id}: {e}");
                return;
            }
        }
    }
}

/// Try to extract a complete XML command from the buffer.
/// Returns the response bytes if a complete command was found and processed.
fn try_extract_command(buf: &mut Vec<u8>, handler: &SessionHandler) -> Option<Vec<u8>> {
    // Simple approach: look for a complete XML element.
    // We use a quick heuristic — find the root element close.
    // For self-closing elements: />
    // For elements with children: find matching close tag.

    let text = std::str::from_utf8(buf).ok()?;
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return None;
    }

    // Use the XmlReader from gvm-protocol for proper detection
    let mut reader = gvm_protocol::XmlReader::new();
    if reader.feed(buf).is_err() {
        // Bad XML — consume and return error
        let consumed = buf.clone();
        buf.clear();
        return Some(handler.handle_command(&consumed));
    }

    if reader.is_complete() {
        let command_xml = buf.clone();
        buf.clear();
        Some(handler.handle_command(&command_xml))
    } else {
        None // Need more data
    }
}
