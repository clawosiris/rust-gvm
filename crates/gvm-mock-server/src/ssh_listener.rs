// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! SSH listener for the mock GMP server.

use std::sync::Arc;

use russh::keys::ssh_key::HashAlg;
use russh::server::{self, Auth, Server as _, Session};
use russh::{Channel, ChannelMsg};
use tokio::net::TcpListener;

use crate::handler::SessionHandler;
use crate::listener::{try_extract_command, CommandResult, ListenerState};

#[derive(Clone)]
struct MockSshServer {
    state: Arc<ListenerState>,
}

impl server::Server for MockSshServer {
    type Handler = MockSshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        if let Some(addr) = peer_addr {
            tracing::debug!("SSH connection from {addr}");
        }

        MockSshHandler {
            state: Arc::clone(&self.state),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        tracing::debug!("SSH session error: {error}");
    }
}

struct MockSshHandler {
    state: Arc<ListenerState>,
}

pub(crate) fn generate_host_key() -> Result<russh::keys::PrivateKey, std::io::Error> {
    russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .map_err(std::io::Error::other)
}

pub(crate) fn host_key_fingerprint(host_key: &russh::keys::PrivateKey) -> String {
    host_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string()
        .trim_start_matches("SHA256:")
        .to_string()
}

impl server::Handler for MockSshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let accepted = match &self.state.store {
            Some(store) => store.credentials_match(user, password),
            None => true,
        };

        if accepted {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        mut channel: Channel<server::Msg>,
        socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!("SSH direct-streamlocal open for {socket_path}");

        let state = Arc::clone(&self.state);
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

        tokio::spawn(async move {
            let mut xml_buf = Vec::new();

            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        xml_buf.extend_from_slice(&data);

                        loop {
                            match try_extract_command(&mut xml_buf, &handler) {
                                CommandResult::Response { bytes, delay } => {
                                    if let Some(delay) = delay {
                                        tokio::time::sleep(delay).await;
                                    }

                                    if let Err(error) = channel.data(&bytes[..]).await {
                                        tracing::debug!(
                                            "SSH write error on session {session_id}: {error}"
                                        );
                                        return;
                                    }
                                }
                                CommandResult::NeedMore => break,
                                CommandResult::Disconnect => {
                                    tracing::debug!(
                                        "Fault: disconnecting SSH session {session_id}"
                                    );
                                    let _ = channel.close().await;
                                    return;
                                }
                            }
                        }
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    ChannelMsg::OpenFailure(error) => {
                        tracing::debug!(
                            "SSH channel open failure on session {session_id}: {error:?}"
                        );
                        break;
                    }
                    ChannelMsg::ExtendedData { .. }
                    | ChannelMsg::RequestPty { .. }
                    | ChannelMsg::RequestShell { .. }
                    | ChannelMsg::Exec { .. }
                    | ChannelMsg::Signal { .. }
                    | ChannelMsg::RequestSubsystem { .. }
                    | ChannelMsg::RequestX11 { .. }
                    | ChannelMsg::SetEnv { .. }
                    | ChannelMsg::WindowChange { .. }
                    | ChannelMsg::AgentForward { .. }
                    | ChannelMsg::Open { .. }
                    | ChannelMsg::XonXoff { .. }
                    | ChannelMsg::ExitStatus { .. }
                    | ChannelMsg::ExitSignal { .. }
                    | ChannelMsg::WindowAdjusted { .. }
                    | ChannelMsg::Success
                    | ChannelMsg::Failure => {}
                    _ => {}
                }
            }
        });

        Ok(true)
    }
}

/// Run an SSH listener on the given address.
///
/// # Errors
/// Returns an I/O error if the listener fails to accept connections or the SSH
/// server fails during startup.
pub async fn run_ssh_listener(
    listener: TcpListener,
    host_key: russh::keys::PrivateKey,
    state: Arc<ListenerState>,
) -> Result<(), std::io::Error> {
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..server::Config::default()
    });

    let shutdown = Arc::clone(&state.shutdown);
    let mut server = MockSshServer { state };
    let mut running = server.run_on_socket(config, &listener);
    let shutdown_handle = running.handle();

    tokio::select! {
        result = &mut running => result,
        () = shutdown.notified() => {
            shutdown_handle.shutdown("mock ssh listener shutting down".to_string());
            Ok(())
        }
    }
}
