// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! SSH transport for gvmd over a remote Unix socket.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::connection::{write_all_and_flush_with_timeout, GvmConnection};
use crate::error::{ConnectionError, Result};
use russh::client;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{self, PrivateKeyWithHashAlg};
use russh::{AgentAuthError, Channel, ChannelMsg, Disconnect};

/// Configuration for SSH tunnel connections.
#[derive(Clone)]
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
    /// Connect, authentication, channel, request-write/flush, and response-read timeout.
    pub timeout: Duration,
    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
    /// Maximum XML response size in bytes before aborting the read.
    pub max_response_bytes: Option<usize>,
    /// SSH host key verification policy.
    pub host_key_policy: SshHostKeyPolicy,
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("remote_socket", &self.remote_socket)
            .field("timeout", &self.timeout)
            .field("read_buffer_size", &self.read_buffer_size)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("host_key_policy", &self.host_key_policy)
            .finish()
    }
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
            max_response_bytes: Some(64 * 1024 * 1024),
            host_key_policy: SshHostKeyPolicy::KnownHosts,
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

    /// Set the maximum XML response size in bytes.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: Option<usize>) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Set the SSH host key verification policy.
    #[must_use]
    pub fn with_host_key_policy(mut self, host_key_policy: SshHostKeyPolicy) -> Self {
        self.host_key_policy = host_key_policy;
        self
    }
}

/// SSH authentication methods.
#[derive(Clone)]
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

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"<redacted>").finish(),
            Self::PrivateKey {
                key_path,
                passphrase,
            } => {
                let redacted_passphrase = passphrase.as_ref().map(|_| "<redacted>");
                f.debug_struct("PrivateKey")
                    .field("key_path", key_path)
                    .field("passphrase", &redacted_passphrase)
                    .finish()
            }
            Self::Agent => f.write_str("Agent"),
        }
    }
}

/// SSH host key verification policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshHostKeyPolicy {
    /// Require the server key to match the user's `~/.ssh/known_hosts` file.
    KnownHosts,
    /// Require the server key to match a specific OpenSSH `known_hosts` file.
    KnownHostsFile(PathBuf),
    /// Accept any server key.
    ///
    /// This is insecure and vulnerable to man-in-the-middle attacks. Use only in tests or when
    /// an external layer already authenticates the SSH server.
    AcceptAll,
    /// Require the server key fingerprint to match a pinned SHA-256 base64 fingerprint.
    Fingerprint(String),
}

#[derive(Debug, Clone)]
struct SshServerKeyVerifier {
    hostname: String,
    port: u16,
    policy: SshHostKeyPolicy,
}

impl SshServerKeyVerifier {
    fn new(hostname: impl Into<String>, port: u16, policy: SshHostKeyPolicy) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            policy,
        }
    }

    fn check_server_key_with<F>(
        &self,
        server_public_key: &PublicKey,
        check_default_known_hosts: F,
    ) -> std::result::Result<bool, russh::Error>
    where
        F: FnOnce(&str, u16, &PublicKey) -> std::result::Result<bool, keys::Error>,
    {
        Ok(match &self.policy {
            SshHostKeyPolicy::KnownHosts => {
                check_default_known_hosts(&self.hostname, self.port, server_public_key)?
            }
            SshHostKeyPolicy::KnownHostsFile(path) => {
                keys::check_known_hosts_path(&self.hostname, self.port, server_public_key, path)?
            }
            SshHostKeyPolicy::AcceptAll => true,
            SshHostKeyPolicy::Fingerprint(expected) => {
                host_key_fingerprint(server_public_key) == normalize_fingerprint(expected)
            }
        })
    }
}

impl client::Handler for SshServerKeyVerifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        self.check_server_key_with(server_public_key, keys::check_known_hosts)
    }
}

/// SSH connection to a remote gvmd Unix socket.
pub struct SshConnection {
    config: SshConfig,
    session: Option<client::Handle<SshServerKeyVerifier>>,
    channel: Option<Channel<client::Msg>>,
    response_reader: gvm_protocol::XmlReader,
    pending_read: Vec<u8>,
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
        let response_reader = gvm_protocol::XmlReader::with_buffer_limit(config.max_response_bytes);
        let pending_read = Vec::with_capacity(config.read_buffer_size);
        Self {
            config,
            session: None,
            channel: None,
            response_reader,
            pending_read,
        }
    }

    fn connect_error(error: impl std::fmt::Display) -> ConnectionError {
        ConnectionError::ConnectFailed(std::io::Error::other(error.to_string()))
    }

    fn read_error(error: impl std::fmt::Display) -> ConnectionError {
        ConnectionError::ReadFailed(std::io::Error::other(error.to_string()))
    }

    fn disconnect_error(error: impl std::fmt::Display) -> ConnectionError {
        ConnectionError::DisconnectFailed(error.to_string())
    }

    fn invalidate_protocol_read(&mut self, error: &gvm_protocol::ProtocolError) -> ConnectionError {
        self.invalidate_connection();
        protocol_read_error(error)
    }

    fn invalidate_connection(&mut self) {
        self.channel.take();
        self.session.take();
        self.response_reader.reset();
        self.pending_read.clear();
    }

    async fn authenticate(
        config: &SshConfig,
        session: &mut client::Handle<SshServerKeyVerifier>,
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
                let identity = tokio::time::timeout(config.timeout, agent.request_identities())
                    .await
                    .map_err(|_| ConnectionError::Timeout(config.timeout))?
                    .map_err(Self::connect_error)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        Self::connect_error("ssh-agent did not return any identities")
                    })?;
                let public_key = identity.public_key().into_owned();
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

fn host_key_fingerprint(server_public_key: &PublicKey) -> String {
    server_public_key
        .fingerprint(HashAlg::Sha256)
        .to_string()
        .trim_start_matches("SHA256:")
        .to_string()
}

fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint.trim().trim_start_matches("SHA256:").to_string()
}

#[async_trait::async_trait]
impl GvmConnection for SshConnection {
    async fn connect(&mut self) -> Result<()> {
        if self.is_connected() {
            return Err(ConnectionError::AlreadyConnected);
        }

        self.response_reader.reset();
        self.pending_read.clear();

        let ssh_config = Arc::new(client::Config {
            nodelay: true,
            ..client::Config::default()
        });

        let mut session = tokio::time::timeout(
            self.config.timeout,
            client::connect(
                ssh_config,
                (self.config.hostname.as_str(), self.config.port),
                SshServerKeyVerifier::new(
                    &self.config.hostname,
                    self.config.port,
                    self.config.host_key_policy.clone(),
                ),
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
        self.response_reader.reset();
        self.pending_read.clear();
        if let Some(channel) = self.channel.take() {
            channel.close().await.map_err(Self::disconnect_error)?;
        }

        if let Some(session) = self.session.take() {
            tokio::time::timeout(
                self.config.timeout,
                session.disconnect(Disconnect::ByApplication, "", "English"),
            )
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
            .map_err(Self::disconnect_error)?;
        }

        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let result = {
            let channel = self.channel.as_ref().ok_or(ConnectionError::NotConnected)?;
            let mut writer = channel.make_writer();
            write_all_and_flush_with_timeout(&mut writer, data, self.config.timeout).await
        };
        if result.is_err() {
            self.invalidate_connection();
        }
        result
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        if self.channel.is_none() {
            return Err(ConnectionError::NotConnected);
        }

        if !self.pending_read.is_empty() {
            let consumed = match self.response_reader.feed_frame(&self.pending_read) {
                Ok(consumed) => consumed,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            self.pending_read.drain(..consumed);
            let frame = match self.response_reader.take_frame() {
                Ok(frame) => frame,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if let Some(frame) = frame {
                return Ok(frame);
            }
            debug_assert!(self.pending_read.is_empty());
        }

        loop {
            let wait_result = {
                let channel = self.channel.as_mut().ok_or(ConnectionError::NotConnected)?;
                tokio::time::timeout(self.config.timeout, channel.wait()).await
            };
            let message = match wait_result {
                Ok(message) => message,
                Err(_) => {
                    self.invalidate_connection();
                    return Err(ConnectionError::Timeout(self.config.timeout));
                }
            };

            match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let consumed = match self.response_reader.feed_frame(&data) {
                        Ok(consumed) => consumed,
                        Err(error) => return Err(self.invalidate_protocol_read(&error)),
                    };
                    if consumed < data.len() {
                        self.pending_read.extend_from_slice(&data[consumed..]);
                    }

                    let frame = match self.response_reader.take_frame() {
                        Ok(frame) => frame,
                        Err(error) => return Err(self.invalidate_protocol_read(&error)),
                    };
                    if let Some(frame) = frame {
                        return Ok(frame);
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    self.invalidate_connection();
                    return Err(ConnectionError::ReadFailed(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ssh channel closed",
                    )));
                }
                Some(ChannelMsg::OpenFailure(error)) => {
                    let error = Self::read_error(format!("{error:?}"));
                    self.invalidate_connection();
                    return Err(error);
                }
                Some(
                    ChannelMsg::WindowAdjusted { .. } | ChannelMsg::Success | ChannelMsg::Failure,
                ) => {}
                Some(other) => {
                    let error =
                        Self::read_error(format!("unexpected ssh channel message: {other:?}"));
                    self.invalidate_connection();
                    return Err(error);
                }
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.session.is_some() && self.channel.is_some()
    }
}

fn protocol_read_error(error: &gvm_protocol::ProtocolError) -> ConnectionError {
    ConnectionError::ReadFailed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler;
    use russh::keys::ssh_key::rand_core::{TryCryptoRng, TryRng, UnwrapErr};

    struct SystemRng;

    fn map_getrandom_error(_: getrandom::Error) -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::Other)
    }

    impl TryRng for SystemRng {
        type Error = std::io::Error;

        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            let mut bytes = [0_u8; 4];
            getrandom::fill(&mut bytes).map_err(map_getrandom_error)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).map_err(map_getrandom_error)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
            getrandom::fill(dst).map_err(map_getrandom_error)
        }
    }

    impl TryCryptoRng for SystemRng {}

    #[test]
    fn test_default_config() {
        let config = SshConfig::default();
        assert_eq!(config.hostname, "localhost");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "root");
        assert_eq!(config.remote_socket, "/run/gvmd/gvmd.sock");
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_response_bytes, Some(64 * 1024 * 1024));
        assert_eq!(config.host_key_policy, SshHostKeyPolicy::KnownHosts);
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
        assert_eq!(config.max_response_bytes, Some(64 * 1024 * 1024));
    }

    #[test]
    fn test_not_connected_initially() {
        let conn = SshConnection::new(SshConfig::default());
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_password_debug_redacts_secret() {
        let debug = format!("{:?}", SshAuth::Password("secret".into()));
        assert!(!debug.contains("secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn test_config_debug_redacts_private_key_passphrase() {
        let config = SshConfig::new(
            "scanner.example",
            "alice",
            SshAuth::PrivateKey {
                key_path: PathBuf::from("/tmp/id_ed25519"),
                passphrase: Some("hunter2".into()),
            },
        );

        let debug = format!("{debug:?}", debug = config);
        assert!(debug.contains("/tmp/id_ed25519"));
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn test_accept_all_host_key_policy() {
        let mut rng = UnwrapErr(SystemRng);
        let public_key = keys::PrivateKey::random(&mut rng, keys::Algorithm::Ed25519)
            .expect("host key")
            .public_key()
            .clone();
        let mut verifier =
            SshServerKeyVerifier::new("scanner.example", 22, SshHostKeyPolicy::AcceptAll);

        let accepted = tokio_test::block_on(verifier.check_server_key(&public_key)).expect("ok");

        assert!(accepted);
    }

    #[test]
    fn test_default_known_hosts_policy() {
        let mut rng = UnwrapErr(SystemRng);
        let public_key = keys::PrivateKey::random(&mut rng, keys::Algorithm::Ed25519)
            .expect("host key")
            .public_key()
            .clone();
        let verifier =
            SshServerKeyVerifier::new("scanner.example", 2222, SshHostKeyPolicy::KnownHosts);

        let accepted = verifier
            .check_server_key_with(&public_key, |hostname, port, received_key| {
                assert_eq!(hostname, "scanner.example");
                assert_eq!(port, 2222);
                assert_eq!(received_key, &public_key);
                Ok(true)
            })
            .expect("known host check");

        assert!(accepted);
    }

    #[test]
    fn test_fingerprint_host_key_policy() {
        let mut rng = UnwrapErr(SystemRng);
        let private_key =
            keys::PrivateKey::random(&mut rng, keys::Algorithm::Ed25519).expect("host key");
        let public_key = private_key.public_key().clone();
        let fingerprint = host_key_fingerprint(&public_key);
        let mut verifier = SshServerKeyVerifier::new(
            "scanner.example",
            22,
            SshHostKeyPolicy::Fingerprint(fingerprint.clone()),
        );

        let accepted = tokio_test::block_on(verifier.check_server_key(&public_key)).expect("ok");
        let rejected = tokio_test::block_on(
            SshServerKeyVerifier::new(
                "scanner.example",
                22,
                SshHostKeyPolicy::Fingerprint("invalid".into()),
            )
            .check_server_key(&public_key),
        )
        .expect("ok");

        assert!(accepted);
        assert_eq!(
            normalize_fingerprint(&format!("SHA256:{fingerprint}")),
            fingerprint
        );
        assert!(!rejected);
    }

    #[test]
    fn test_known_hosts_file_policy() {
        let mut rng = UnwrapErr(SystemRng);
        let private_key =
            keys::PrivateKey::random(&mut rng, keys::Algorithm::Ed25519).expect("host key");
        let public_key = private_key.public_key().clone();
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "[scanner.example]:2222 {}\n",
                public_key.to_openssh().expect("OpenSSH public key")
            ),
        )
        .expect("write known_hosts");

        let mut matching = SshServerKeyVerifier::new(
            "scanner.example",
            2222,
            SshHostKeyPolicy::KnownHostsFile(path.clone()),
        );
        let accepted =
            tokio_test::block_on(matching.check_server_key(&public_key)).expect("known host check");
        let mut unknown = SshServerKeyVerifier::new(
            "other.example",
            2222,
            SshHostKeyPolicy::KnownHostsFile(path),
        );
        let rejected = tokio_test::block_on(unknown.check_server_key(&public_key))
            .expect("unknown host check");

        assert!(accepted);
        assert!(!rejected);
    }
}
