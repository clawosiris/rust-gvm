//! The main mock GMP server.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::fault::FaultEngine;
use crate::fixtures::FixtureStore;
use crate::history::{CommandHistory, CommandRecord};
use crate::listener::{run_tcp_listener, run_unix_listener, ListenerState};
use crate::scenario::{ScenarioMode, ScenarioStep};
use crate::store::ResourceStore;
use crate::version::GmpVersion;
use crate::ServerMode;

/// A running mock GMP server.
pub struct MockGmpServer {
    /// The Unix socket path (if using Unix transport).
    socket_path: Option<PathBuf>,
    /// The TCP address (if using TCP transport).
    tcp_addr: Option<std::net::SocketAddr>,
    /// Command history shared with all sessions.
    history: CommandHistory,
    /// Shutdown signal.
    shutdown: Arc<Notify>,
    /// Background listener task handle.
    _listener_handle: JoinHandle<()>,
}

impl MockGmpServer {
    /// Create a builder for configuring the mock server.
    pub fn builder() -> crate::builder::MockGmpServerBuilder {
        crate::builder::MockGmpServerBuilder::new()
    }

    /// Create and start a new mock server from components.
    pub(crate) async fn start_unix(
        socket_path: PathBuf,
        mode: ServerMode,
        version: GmpVersion,
        fixtures: Option<FixtureStore>,
        store: Option<ResourceStore>,
        fault_engine: FaultEngine,
        scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
    ) -> Result<Self, std::io::Error> {
        // Remove existing socket if present
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        let history = CommandHistory::new();
        let shutdown = Arc::new(Notify::new());

        let state = Arc::new(ListenerState {
            mode,
            version,
            history: history.clone(),
            session_counter: AtomicU64::new(0),
            fixtures,
            store,
            scenario_config,
            fault_engine: fault_engine.clone(),
            shutdown: Arc::clone(&shutdown),
        });

        let handle = tokio::spawn(async move {
            run_unix_listener(listener, state).await;
        });

        Ok(Self {
            socket_path: Some(socket_path),
            tcp_addr: None,
            history,
            shutdown,
            _listener_handle: handle,
        })
    }

    /// Create and start a new mock server on TCP.
    pub(crate) async fn start_tcp(
        addr: &str,
        mode: ServerMode,
        version: GmpVersion,
        fixtures: Option<FixtureStore>,
        store: Option<ResourceStore>,
        fault_engine: FaultEngine,
        scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let history = CommandHistory::new();
        let shutdown = Arc::new(Notify::new());

        let state = Arc::new(ListenerState {
            mode,
            version,
            history: history.clone(),
            session_counter: AtomicU64::new(0),
            fixtures,
            store,
            scenario_config,
            fault_engine: fault_engine.clone(),
            shutdown: Arc::clone(&shutdown),
        });

        let handle = tokio::spawn(async move {
            run_tcp_listener(listener, state).await;
        });

        Ok(Self {
            socket_path: None,
            tcp_addr: Some(local_addr),
            history,
            shutdown,
            _listener_handle: handle,
        })
    }

    /// Get the Unix socket path (if using Unix transport).
    pub fn socket_path(&self) -> Option<&Path> {
        self.socket_path.as_deref()
    }

    /// Get the TCP address (if using TCP transport).
    pub fn tcp_addr(&self) -> Option<std::net::SocketAddr> {
        self.tcp_addr
    }

    /// Get the TCP port (convenience for random port assignment).
    pub fn port(&self) -> Option<u16> {
        self.tcp_addr.map(|a| a.port())
    }

    /// Get the command history.
    pub fn command_history(&self) -> Vec<CommandRecord> {
        self.history.all()
    }

    /// Get the number of commands received.
    pub fn command_count(&self) -> usize {
        self.history.len()
    }

    /// Clear the command history.
    pub fn clear_history(&self) {
        self.history.clear();
    }

    /// Shut down the server and clean up resources.
    pub async fn shutdown(self) {
        self.shutdown.notify_one();

        // Clean up Unix socket
        if let Some(ref path) = self.socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}
