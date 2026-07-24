// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Verified TLS transport for gvmd.

use std::fmt;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::connection::{write_all_and_flush_with_timeout, GvmConnection};
use crate::error::{ConnectionError, Result};

const DEFAULT_GVM_PORT: u16 = 9390;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// PEM-encoded certificate chain and unencrypted private key for mutual TLS.
#[derive(Clone)]
pub struct TlsClientIdentity {
    certificate_chain_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

impl TlsClientIdentity {
    /// Create a client identity from PEM-encoded certificate and private-key data.
    #[must_use]
    pub fn from_pem(
        certificate_chain_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            certificate_chain_pem: certificate_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    /// Load a client identity from PEM files.
    ///
    /// The private key must be an unencrypted PKCS#1, PKCS#8, or SEC1 key.
    ///
    /// # Errors
    /// Returns an I/O error when either file cannot be read.
    pub fn from_files(
        certificate_chain_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        Ok(Self::from_pem(
            std::fs::read(certificate_chain_path)?,
            std::fs::read(private_key_path)?,
        ))
    }

    fn parse(
        &self,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        let certificates = parse_certificates(&self.certificate_chain_pem, "client certificate")?;
        let private_key = rustls_pemfile::private_key(&mut Cursor::new(&self.private_key_pem))
            .map_err(|error| invalid_configuration(format!("invalid client private key: {error}")))?
            .ok_or_else(|| {
                invalid_configuration(
                    "client private key is missing, encrypted, or in an unsupported PEM format",
                )
            })?;
        Ok((certificates, private_key))
    }
}

impl fmt::Debug for TlsClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientIdentity")
            .field(
                "certificate_chain_pem_bytes",
                &self.certificate_chain_pem.len(),
            )
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

/// Configuration for a verified TLS connection.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// DNS name or IP address used for the TCP connection.
    pub hostname: String,
    /// TCP port, normally gvmd's port 9390.
    pub port: u16,
    /// DNS name or IP address required in the server certificate SAN.
    pub server_name: String,
    /// TCP connect, TLS handshake, request-write/flush, and response-read timeout.
    pub timeout: Duration,
    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
    /// Maximum XML response size in bytes before aborting the read.
    pub max_response_bytes: Option<usize>,
    /// Whether to trust roots from the host platform certificate store.
    pub use_native_roots: bool,
    root_certificates_pem: Vec<Vec<u8>>,
    client_identity: Option<TlsClientIdentity>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new("127.0.0.1")
    }
}

impl TlsConfig {
    /// Create verified TLS settings for a hostname or IP address.
    ///
    /// Native trust roots and SAN verification are enabled. Custom or private
    /// certificate authorities can be added with [`Self::with_root_certificate_pem`].
    #[must_use]
    pub fn new(hostname: impl Into<String>) -> Self {
        let hostname = hostname.into();
        Self {
            server_name: hostname.clone(),
            hostname,
            port: DEFAULT_GVM_PORT,
            timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
            max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
            use_native_roots: true,
            root_certificates_pem: Vec::new(),
            client_identity: None,
        }
    }

    /// Set a custom TCP port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the DNS name or IP address required in the server certificate SAN.
    #[must_use]
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    /// Enable or disable platform-native trust roots.
    ///
    /// Disabling them does not disable verification. At least one custom root
    /// must then be configured or connecting fails.
    #[must_use]
    pub fn with_native_roots(mut self, enabled: bool) -> Self {
        self.use_native_roots = enabled;
        self
    }

    /// Add one or more PEM-encoded root CA certificates.
    #[must_use]
    pub fn with_root_certificate_pem(mut self, certificate_pem: impl Into<Vec<u8>>) -> Self {
        self.root_certificates_pem.push(certificate_pem.into());
        self
    }

    /// Add root CA certificates from a PEM file.
    ///
    /// # Errors
    /// Returns an I/O error when the file cannot be read.
    pub fn with_root_certificate_file(
        self,
        certificate_path: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        Ok(self.with_root_certificate_pem(std::fs::read(certificate_path)?))
    }

    /// Present a client certificate during a mutual-TLS handshake.
    #[must_use]
    pub fn with_client_identity(mut self, identity: TlsClientIdentity) -> Self {
        self.client_identity = Some(identity);
        self
    }

    /// Set the transport operation timeout.
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

    fn client_config(&self) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();

        if self.use_native_roots {
            let native = rustls_native_certs::load_native_certs();
            let native_error_count = native.errors.len();
            let (added, ignored) = root_store.add_parsable_certificates(native.certs);
            log_native_root_load(native_error_count, ignored, added);
        }

        for certificate_pem in &self.root_certificates_pem {
            for certificate in parse_certificates(certificate_pem, "root certificate")? {
                root_store.add(certificate).map_err(|error| {
                    invalid_configuration(format!("invalid root certificate: {error}"))
                })?;
            }
        }

        if root_store.is_empty() {
            return Err(invalid_configuration(
                "no usable TLS trust roots; enable native roots or add a custom root certificate",
            ));
        }

        let builder = ClientConfig::builder().with_root_certificates(root_store);
        match &self.client_identity {
            Some(identity) => {
                let (certificate_chain, private_key) = identity.parse()?;
                builder
                    .with_client_auth_cert(certificate_chain, private_key)
                    .map_err(|error| {
                        invalid_configuration(format!("invalid client identity: {error}"))
                    })
            }
            None => Ok(builder.with_no_client_auth()),
        }
    }
}

/// Verified TLS connection to gvmd.
///
/// With TLS 1.3, a server-side client-certificate rejection can arrive after
/// the client has locally completed `connect()`. In that case the first
/// [`GvmConnection::send`] or [`GvmConnection::read`] reports the TLS alert.
pub struct TlsConnection {
    config: TlsConfig,
    stream: Option<TlsStream<TcpStream>>,
    response_reader: gvm_protocol::XmlReader,
    pending_read: Vec<u8>,
}

impl fmt::Debug for TlsConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsConnection")
            .field("config", &self.config)
            .field("connected", &self.stream.is_some())
            .finish()
    }
}

impl TlsConnection {
    /// Create a TLS connection from verified settings.
    #[must_use]
    pub fn new(config: TlsConfig) -> Self {
        let response_reader = gvm_protocol::XmlReader::with_buffer_limit(config.max_response_bytes);
        let pending_read = Vec::with_capacity(config.read_buffer_size);
        Self {
            config,
            stream: None,
            response_reader,
            pending_read,
        }
    }

    fn invalidate_protocol_read(&mut self, error: &gvm_protocol::ProtocolError) -> ConnectionError {
        self.invalidate_connection();
        protocol_read_error(error)
    }

    fn invalidate_connection(&mut self) {
        self.stream.take();
        self.response_reader.reset();
        self.pending_read.clear();
    }
}

#[async_trait::async_trait]
impl GvmConnection for TlsConnection {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(ConnectionError::AlreadyConnected);
        }

        self.response_reader.reset();
        self.pending_read.clear();

        let client_config = self.config.client_config()?;
        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|error| invalid_configuration(format!("invalid TLS server name: {error}")))?;
        let tcp_stream = tokio::time::timeout(
            self.config.timeout,
            TcpStream::connect((self.config.hostname.as_str(), self.config.port)),
        )
        .await
        .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
        .map_err(ConnectionError::ConnectFailed)?;

        let stream = tokio::time::timeout(
            self.config.timeout,
            TlsConnector::from(Arc::new(client_config)).connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| ConnectionError::Timeout(self.config.timeout))?
        .map_err(|error| ConnectionError::ConnectFailed(std::io::Error::other(error)))?;

        self.stream = Some(stream);
        tracing::debug!(
            host = %self.config.hostname,
            port = self.config.port,
            server_name = %self.config.server_name,
            "connected with verified TLS"
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.response_reader.reset();
        self.pending_read.clear();
        if let Some(mut stream) = self.stream.take() {
            stream
                .shutdown()
                .await
                .map_err(|error| ConnectionError::DisconnectFailed(error.to_string()))?;
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let result = {
            let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
            write_all_and_flush_with_timeout(stream, data, self.config.timeout).await
        };
        if result.is_err() {
            self.invalidate_connection();
        }
        result
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        if self.stream.is_none() {
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

        let mut buffer = vec![0_u8; self.config.read_buffer_size];

        loop {
            let read_result = {
                let stream = self.stream.as_mut().ok_or(ConnectionError::NotConnected)?;
                tokio::time::timeout(self.config.timeout, stream.read(&mut buffer)).await
            };
            let read = match read_result {
                Ok(Ok(read)) => read,
                Ok(Err(error)) => {
                    self.invalidate_connection();
                    return Err(ConnectionError::ReadFailed(error));
                }
                Err(_) => {
                    self.invalidate_connection();
                    return Err(ConnectionError::Timeout(self.config.timeout));
                }
            };

            if read == 0 {
                self.invalidate_connection();
                return Err(ConnectionError::ReadFailed(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS connection closed before a complete response",
                )));
            }

            let consumed = match self.response_reader.feed_frame(&buffer[..read]) {
                Ok(consumed) => consumed,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if consumed < read {
                self.pending_read.extend_from_slice(&buffer[consumed..read]);
            }

            let frame = match self.response_reader.take_frame() {
                Ok(frame) => frame,
                Err(error) => return Err(self.invalidate_protocol_read(&error)),
            };
            if let Some(frame) = frame {
                return Ok(frame);
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

fn protocol_read_error(error: &gvm_protocol::ProtocolError) -> ConnectionError {
    ConnectionError::ReadFailed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    ))
}

fn parse_certificates(
    pem: &[u8],
    description: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| invalid_configuration(format!("invalid {description}: {error}")))?;
    if certificates.is_empty() {
        return Err(invalid_configuration(format!(
            "{description} PEM contains no certificates"
        )));
    }
    Ok(certificates)
}

fn invalid_configuration(message: impl Into<String>) -> ConnectionError {
    ConnectionError::InvalidConfiguration(message.into())
}

fn log_native_root_load(error_count: usize, ignored: usize, added: usize) {
    if error_count > 0 || ignored > 0 {
        tracing::warn!(
            error_count,
            ignored,
            "some native TLS root certificates could not be loaded"
        );
    }
    tracing::debug!(added, "loaded native TLS root certificates");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_verified_and_uses_gvmd_port() {
        let config = TlsConfig::default();
        assert_eq!(config.hostname, "127.0.0.1");
        assert_eq!(config.server_name, "127.0.0.1");
        assert_eq!(config.port, 9390);
        assert!(config.use_native_roots);
        assert_eq!(config.max_response_bytes, Some(DEFAULT_MAX_RESPONSE_BYTES));
    }

    #[test]
    fn client_identity_debug_redacts_private_key() {
        let identity = TlsClientIdentity::from_pem(b"certificate".to_vec(), b"secret-key".to_vec());
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-key"));
    }

    #[test]
    fn new_connection_is_disconnected() {
        let connection = TlsConnection::new(TlsConfig::default());
        assert!(!connection.is_connected());
    }

    #[test]
    fn native_root_load_diagnostics_cover_clean_and_partial_loads() {
        log_native_root_load(0, 0, 1);
        log_native_root_load(1, 2, 0);
    }

    #[test]
    fn native_root_client_configuration_is_usable() {
        TlsConfig::default()
            .client_config()
            .expect("platform trust store should contain usable roots");
    }
}
