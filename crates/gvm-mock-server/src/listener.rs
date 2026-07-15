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
use crate::response_gen::{error_response, LargeReportConfig};
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
    /// Maximum size of one XML request.
    pub(crate) max_request_bytes: Option<usize>,
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
    let mut xml_reader = gvm_protocol::XmlReader::with_buffer_limit(state.max_request_bytes);

    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break, // Connection closed
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("Read error on session {session_id}: {e}");
                break;
            }
        };

        let mut offset = 0;
        while offset < n {
            let (consumed, result) =
                try_extract_command(&mut xml_reader, &buf[offset..n], &handler);
            offset = offset.saturating_add(consumed);

            match result {
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
                CommandResult::Reject { bytes, reason } => {
                    tracing::debug!("Rejecting session {session_id} input: {reason}");
                    let _ = stream.write_all(&bytes).await;
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
    /// Reject malformed or oversized XML and close the session.
    Reject { bytes: Vec<u8>, reason: String },
}

/// Try to extract a complete XML command from the buffer.
pub(crate) fn try_extract_command(
    reader: &mut gvm_protocol::XmlReader,
    data: &[u8],
    handler: &SessionHandler,
) -> (usize, CommandResult) {
    let consumed = match reader.feed_frame(data) {
        Ok(consumed) => consumed,
        Err(error) => {
            return (
                0,
                CommandResult::Reject {
                    bytes: error_response("unknown", 400, "Malformed or oversized XML request"),
                    reason: error.to_string(),
                },
            );
        }
    };

    let command_xml = match reader.take_frame() {
        Ok(Some(command_xml)) => command_xml,
        Ok(None) => return (consumed, CommandResult::NeedMore),
        Err(error) => {
            return (
                consumed,
                CommandResult::Reject {
                    bytes: error_response("unknown", 400, "Malformed or oversized XML request"),
                    reason: error.to_string(),
                },
            );
        }
    };

    let result = match handler.handle_command(&command_xml) {
        HandleResult::Respond { bytes, delay } => CommandResult::Response { bytes, delay },
        HandleResult::Disconnect => CommandResult::Disconnect,
    };
    (consumed, result)
}
