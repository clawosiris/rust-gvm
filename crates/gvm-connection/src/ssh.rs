// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! SSH transport for gvmd over a remote Unix socket.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::agent::client::AgentClient;
use russh::keys::{self, PrivateKeyWithHashAlg};
use russh::{AgentAuthError, Channel, ChannelMsg, Disconnect};
use tokio::io::AsyncWriteExt;

use crate::connection::GvmConnection;
use crate::error::{ConnectionError, Result};

/// Configuration for SSH tunnel connections.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// SSH server hostname or IP.
    pub hostname: String,
    /// SSH server port.
    pub port: u16,
    /// SSH username.
    pub username: String,
    /// Authentication method.
    pub auth: SshAuth,
    /// Remote gvmd Unix socket path.
    pub remote_socket: String,
    /// Connection timeout.
    pub timeout: Duration,
    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),
            port: 22,
            username: "root".to_string(),
            auth: SshAuth::Agent,
            remote_socket: "/run/gvmd/gvmd.sock".to_string(),
            timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
        }
    }
}

impl SshConfig {
    /// Create config with the required SSH endpoint and authentication.
    #[must_use]
    pub fn new(hostname: impl Into<String>, username: impl Into<String>, auth: SshAuth) -> Self {
        Self {
            hostname: hostname.into(),
            username: username.into(),
            auth,
            ..Self::default()
        }
    }

    /// Set the SSH port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the remote gvmd socket path.
    #[must_use]
    pub fn with_remote_socket(mut self, remote_socket: impl Into<String>) -> Self {
        self.remote_socket = remote_socket.into();
        self
    }

    /// Set the operation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// SSH authentication methods.
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(String),
    /// Private key authentication.
    PrivateKey {
        /// Path to the private key file.
        key_path: PathBuf,
        /// Optional passphrase for the key.
        passphrase: Option<String>,
    },
    /// SSH agent authentication.
    Agent,
}

#[derive(Debug, Default)]
struct AcceptAllServerKeys;

impl client::Handler for AcceptAllServerKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Production callers should verify host keys instead of accepting all of them.
        Ok(true)
    }
}

/// SSH connection to a remote gvmd Unix socket.
pub struct SshConnection {
    config: SshConfig,
    session: Option<client::Handle<AcceptAllServerKeys>>,
    channel: Option<Channel<client::Msg>>,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("config", &self.config)
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl SshConnection {
    /// Create a new SSH connection with the given config.
    #[must_use]
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            session: None,
            channel: None,
        }
    }

    fn connect_error(error: impl std::fmt::Display) -> ConnectionError {
        ConnectionError::ConnectFailed(std::io::Error::other(error.to_string()))
    }

    fn read_error(error: impl std::fmt::Display) -> ConnectionError {
        ConnectionError::ReadFailed(std::io::Error::other(error.to_string()))
    }

    async fn authenticate(
        config: &SshConfig,
        session: &mut client::Handle<AcceptAllServerKeys>,
    ) -> Result<()> {
        let result = match &config.auth {
            SshAuth::Password(password) => tokio::time::timeout(
                config.timeout,
                session.authenticate_password(config.username.clone(), password.clone()),
            )
            .await
            .map_err(|_| ConnectionError::Timeout(config.timeout))?
            .map_err(Self::connect_error)?,
            SshAuth::PrivateKey {
                key_path,
                passphrase,
            } => {
                let key_pair = keys::load_secret_key(key_path, passphrase.as_deref())
                    .map_err(Self::connect_error)?;
                let hash_alg =
                    tokio::time::timeout(config.timeout, session.best_supported_rsa_hash())
                        .await
                        .map_err(|_| ConnectionError::Timeout(config.timeout))?
                        .map_err(Self::connect_error)?
                        .flatten();

                tokio::time::timeout(
                    config.timeout,
                    session.authenticate_publickey(
                        config.username.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
                    ),
                )
                .await
                .map_err(|_| ConnectionError::Timeout(config.timeout))?
                .map_err(Self::connect_error)?
            }
            SshAuth::Agent => {
                let mut agent = tokio::time::timeout(config.timeout, AgentClient::connect_env())
                    .await
                    .map_err(|_| ConnectionError::Timeout(config.timeout))?
                    .map_err(Self::connect_error)?;
                let public_key = tokio::time::timeout(config.timeout, agent.request_identities())
                    .await
                    .map_err(|_| ConnectionError::Timeout(config.timeout))?
                    .map_err(Self::connect_error)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        Self::connect_error("ssh-agent did not return any identities")
                    })?;
                let hash_alg =
                    tokio::time::timeout(config.timeout, session.best_supported_rsa_hash())
                        .await
                        .map_err(|_| ConnectionError::Timeout(config.timeout))?
                        .map_err(Self::connect_error)?
                        .flatten();

                tokio::time::timeout(
                    config.timeout,
                    session.authenticate_publickey_with(
                        config.username.clone(),
                        public_key,
                        hash_alg,
                        &mut agent,
                    ),
                )
                .await
                .map_err(|_| ConnectionError::Timeout(config.timeout))?
                .map_err(|error: AgentAuthError| Self::connect_error(error))?
            }
        };

        if result.success() {
            Ok(())
        } else {
            Err(ConnectionError::ConnectFailed(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                auth_failure_message(&result),
            )))
        }
    }
}

fn auth_failure_message(result: &client::AuthResult) -> String {
    match result {
        client::AuthResult::Success => "authentication succeeded".to_string(),
        client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => format!(
            "ssh authentication failed (partial_success: {partial_success}, remaining_methods: {remaining_methods:?})"
        ),
    }
}

#[async_trait::async_trait]
impl GvmConnection for SshConnection {
    async fn connect(&mut self) -> Result<()> {
        if self.is_connected() {
            return Err(ConnectionError::AlreadyConnected);
        }

        let ssh_config = Arc::new(client::Config {
            nodelay: true,
            ..client::Config::default()
        });

        let mut session = tokio::time::timeout(
            self.config.timeout,
            client::connect(
                ssh_config,
                (self.config.hostname.as_str(), self.config.port),
                AcceptAllServerKeys,
            ),
        )
        .await
        .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
        .map_err(Self::connect_error)?;

        Self::authenticate(&self.config, &mut session).await?;

        let channel = tokio::time::timeout(
            self.config.timeout,
            session.channel_open_direct_streamlocal(self.config.remote_socket.clone()),
        )
        .await
        .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
        .map_err(Self::connect_error)?;

        self.session = Some(session);
        self.channel = Some(channel);
        tracing::debug!(
            "connected to {}:{} via ssh",
            self.config.hostname,
            self.config.port
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(channel) = self.channel.take() {
            channel.close().await.map_err(Self::connect_error)?;
        }

        if let Some(session) = self.session.take() {
            tokio::time::timeout(
                self.config.timeout,
                session.disconnect(Disconnect::ByApplication, "", "English"),
            )
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
            .map_err(Self::connect_error)?;
        }

        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let channel = self.channel.as_ref().ok_or(ConnectionError::NotConnected)?;
        let mut writer = channel.make_writer();

        tokio::time::timeout(self.config.timeout, writer.write_all(data))
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
            .map_err(ConnectionError::SendFailed)?;
        tokio::time::timeout(self.config.timeout, writer.flush())
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
            .map_err(ConnectionError::SendFailed)?;

        Ok(())
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        let channel = self.channel.as_mut().ok_or(ConnectionError::NotConnected)?;
        let mut xml_reader = gvm_protocol::XmlReader::new();
        let mut response = Vec::with_capacity(self.config.read_buffer_size);

        loop {
            let message = tokio::time::timeout(self.config.timeout, channel.wait())
                .await
                .map_err(|_| ConnectionError::Timeout(self.config.timeout))?;

            match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    response.extend_from_slice(&data);
                    xml_reader.feed(&data).map_err(|error| {
                        ConnectionError::ReadFailed(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            error.to_string(),
                        ))
                    })?;

                    if xml_reader.is_complete() {
                        return Ok(response);
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    return Err(ConnectionError::ReadFailed(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ssh channel closed",
                    )));
                }
                Some(ChannelMsg::OpenFailure(error)) => {
                    return Err(Self::read_error(format!("{error:?}")));
                }
                Some(
                    ChannelMsg::WindowAdjusted { .. } | ChannelMsg::Success | ChannelMsg::Failure,
                ) => {}
                Some(other) => {
                    return Err(Self::read_error(format!(
                        "unexpected ssh channel message: {other:?}"
                    )));
                }
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.session.is_some() && self.channel.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SshConfig::default();
        assert_eq!(config.hostname, "localhost");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "root");
        assert_eq!(config.remote_socket, "/run/gvmd/gvmd.sock");
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_custom_config() {
        let config = SshConfig::new(
            "scanner.example",
            "alice",
            SshAuth::Password("secret".into()),
        )
        .with_port(2222)
        .with_remote_socket("/tmp/gvmd.sock")
        .with_timeout(Duration::from_secs(15));

        assert_eq!(config.hostname, "scanner.example");
        assert_eq!(config.username, "alice");
        assert_eq!(config.port, 2222);
        assert_eq!(config.remote_socket, "/tmp/gvmd.sock");
        assert_eq!(config.timeout, Duration::from_secs(15));
    }

    #[test]
    fn test_not_connected_initially() {
        let conn = SshConnection::new(SshConfig::default());
        assert!(!conn.is_connected());
    }
}
