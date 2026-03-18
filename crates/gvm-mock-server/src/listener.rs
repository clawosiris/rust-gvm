// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Network listeners for Unix sockets and TCP.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;

use crate::fault::FaultEngine;
use crate::fixtures::FixtureStore;
use crate::handler::{HandleResult, SessionHandler};
use crate::history::CommandHistory;
use crate::response_gen::LargeReportConfig;
use crate::scenario::{ScenarioMode, ScenarioStep};
use crate::store::ResourceStore;
use crate::version::GmpVersion;
use crate::ServerMode;

/// Shared state across all sessions.
pub struct ListenerState {
    /// Server operating mode.
    pub(crate) mode: ServerMode,
    /// GMP version to advertise.
    pub(crate) version: GmpVersion,
    /// Command history shared with all sessions.
    pub(crate) history: CommandHistory,
    /// Counter for assigning session IDs.
    pub(crate) session_counter: AtomicU64,
    /// Fixture store (if using Fixture mode).
    pub(crate) fixtures: Option<FixtureStore>,
    /// Resource store (if using Stateful mode).
    pub(crate) store: Option<ResourceStore>,
    /// Scenario configuration (if using Scenario mode).
    pub(crate) scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
    /// Large synthetic report configuration.
    pub(crate) large_report: Option<LargeReportConfig>,
    /// Fault injection engine.
    pub(crate) fault_engine: FaultEngine,
    /// Shutdown signal.
    pub(crate) shutdown: Arc<Notify>,
}

impl ListenerState {
    pub(crate) fn next_session_id(&self) -> u64 {
        self.session_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Run a Unix socket listener.
pub async fn run_unix_listener(listener: UnixListener, state: Arc<ListenerState>) {
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
pub async fn run_tcp_listener(listener: TcpListener, state: Arc<ListenerState>) {
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
        state.store.clone(),
        state.scenario_config.clone(),
        state.large_report,
        state.fault_engine.fork(),
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
        loop {
            match try_extract_command(&mut xml_buf, &handler) {
                CommandResult::Response { bytes, delay } => {
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    if let Err(e) = stream.write_all(&bytes).await {
                        tracing::debug!("Write error on session {session_id}: {e}");
                        return;
                    }
                }
                CommandResult::NeedMore => break,
                CommandResult::Disconnect => {
                    tracing::debug!("Fault: disconnecting session {session_id}");
                    return;
                }
            }
        }
    }
}

/// Result of trying to extract a command.
pub(crate) enum CommandResult {
    /// A response to send back (optionally after delay).
    Response {
        bytes: Vec<u8>,
        delay: Option<std::time::Duration>,
    },
    /// Need more data.
    NeedMore,
    /// Disconnect (fault injection).
    Disconnect,
}

/// Try to extract a complete XML command from the buffer.
pub(crate) fn try_extract_command(buf: &mut Vec<u8>, handler: &SessionHandler) -> CommandResult {
    // Simple approach: look for a complete XML element.
    // We use a quick heuristic — find the root element close.
    // For self-closing elements: />
    // For elements with children: find matching close tag.

    let Ok(text) = std::str::from_utf8(buf) else {
        return CommandResult::NeedMore;
    };
    if text.trim_start().is_empty() {
        return CommandResult::NeedMore;
    }

    let mut reader = gvm_protocol::XmlReader::new();
    // TODO: detect malformed XML explicitly instead of waiting for a complete element.
    let _ = reader.feed(buf);

    if reader.is_complete() {
        let command_xml = buf.clone();
        buf.clear();
        match handler.handle_command(&command_xml) {
            HandleResult::Respond { bytes, delay } => CommandResult::Response { bytes, delay },
            HandleResult::Disconnect => CommandResult::Disconnect,
        }
    } else {
        CommandResult::NeedMore
    }
}
