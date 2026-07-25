// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Builder for configuring and starting a [`MockGmpServer`].

use std::path::PathBuf;

use tempfile::Builder;

use crate::fault::{Fault, FaultEngine};
use crate::fixtures::FixtureStore;
use crate::response_gen::LargeReportConfig;
use crate::scenario::{ScenarioMode, ScenarioStep};
use crate::server::{MockGmpServer, ServerOptions, UnixSocketBinding};
use crate::store::{AssetInputProfile, ResourceStore};
use crate::version::GmpVersion;
use crate::ServerMode;

const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// Builder for [`MockGmpServer`].
pub struct MockGmpServerBuilder {
    mode: ServerMode,
    version: GmpVersion,
    transport: Transport,
    fixture_overrides: Vec<(String, String)>,
    credentials: Option<(String, String)>,
    seed_fn: Option<Box<dyn FnOnce(&ResourceStore) + Send>>,
    faults: Vec<Fault>,
    scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
    large_report: Option<LargeReportConfig>,
    max_request_bytes: Option<usize>,
    asset_input_profile: AssetInputProfile,
    #[cfg(feature = "tls")]
    client_ca_certificate: Option<PathBuf>,
    #[cfg(feature = "ssh")]
    ssh_authorized_keys: Vec<(String, String)>,
    #[cfg(feature = "ssh")]
    ssh_auth_delay_once: Option<std::time::Duration>,
    #[cfg(feature = "ssh")]
    ssh_channel_open_delay_once: Option<std::time::Duration>,
}

enum Transport {
    UnixSocket(PathBuf),
    UnixSocketAuto,
    Tcp(String),
    #[cfg(feature = "tls")]
    Tls(String),
    #[cfg(feature = "ssh")]
    Ssh(String),
    None,
}

impl MockGmpServerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            mode: ServerMode::Echo,
            version: GmpVersion::default(),
            transport: Transport::None,
            fixture_overrides: Vec::new(),
            credentials: None,
            seed_fn: None,
            faults: Vec::new(),
            scenario_config: None,
            large_report: None,
            max_request_bytes: Some(DEFAULT_MAX_REQUEST_BYTES),
            asset_input_profile: AssetInputProfile::GvmdStrict,
            #[cfg(feature = "tls")]
            client_ca_certificate: None,
            #[cfg(feature = "ssh")]
            ssh_authorized_keys: Vec::new(),
            #[cfg(feature = "ssh")]
            ssh_auth_delay_once: None,
            #[cfg(feature = "ssh")]
            ssh_channel_open_delay_once: None,
        }
    }

    /// Set the server mode.
    #[must_use]
    pub fn mode(mut self, mode: ServerMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the GMP version to advertise.
    #[must_use]
    pub fn version(mut self, version: GmpVersion) -> Self {
        self.version = version;
        self
    }

    /// Configure scenario playback mode.
    #[must_use]
    pub fn scenario(mut self, mode: ScenarioMode, steps: Vec<ScenarioStep>) -> Self {
        self.mode = ServerMode::Scenario;
        self.scenario_config = Some((mode, steps));
        self
    }

    /// Listen on a specific Unix socket path.
    #[must_use]
    pub fn unix_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.transport = Transport::UnixSocket(path.into());
        self
    }

    /// Listen on an auto-generated temporary Unix socket.
    #[must_use]
    pub fn unix_socket_auto(mut self) -> Self {
        self.transport = Transport::UnixSocketAuto;
        self
    }

    /// Listen on a TCP address (e.g., "127.0.0.1:9390" or "127.0.0.1:0" for random port).
    #[must_use]
    pub fn tcp(mut self, addr: impl Into<String>) -> Self {
        self.transport = Transport::Tcp(addr.into());
        self
    }

    /// Listen with TLS on a TCP address using a generated self-signed server certificate.
    ///
    /// The running server exposes the certificate through
    /// [`MockGmpServer::tls_certificate_pem`](crate::MockGmpServer::tls_certificate_pem)
    /// so clients can pin it as a root certificate.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls(mut self, addr: impl Into<String>) -> Self {
        self.transport = Transport::Tls(addr.into());
        self
    }

    /// Require clients to present a certificate signed by a CA in the PEM file.
    ///
    /// Without this option, TLS still encrypts the transport and presents the
    /// server certificate, but client-certificate authentication is disabled.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn require_client_cert(mut self, ca_certificate_path: impl Into<PathBuf>) -> Self {
        self.client_ca_certificate = Some(ca_certificate_path.into());
        self
    }

    /// Listen on an SSH address (e.g., "127.0.0.1:2222" or "127.0.0.1:0" for random port).
    #[cfg(feature = "ssh")]
    #[must_use]
    pub fn ssh(mut self, addr: impl Into<String>) -> Self {
        self.transport = Transport::Ssh(addr.into());
        self
    }

    /// Authorize one OpenSSH public key for an SSH username.
    ///
    /// This narrow test control lets clients exercise private-key and agent
    /// authentication against the in-process mock server.
    #[cfg(feature = "ssh")]
    #[must_use]
    pub fn ssh_authorized_key(
        mut self,
        username: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Self {
        self.ssh_authorized_keys
            .push((username.into(), public_key.into()));
        self
    }

    /// Delay the first SSH authentication attempt by the given duration.
    ///
    /// The delay is consumed once across all connections to the server so a
    /// client can prove that retry after an authentication timeout is clean.
    #[cfg(feature = "ssh")]
    #[must_use]
    pub fn ssh_auth_delay_once(mut self, delay: std::time::Duration) -> Self {
        self.ssh_auth_delay_once = Some(delay);
        self
    }

    /// Delay the first SSH direct-streamlocal channel open.
    ///
    /// The delay is consumed once across all connections to the server so a
    /// client can retry after a channel-open timeout.
    #[cfg(feature = "ssh")]
    #[must_use]
    pub fn ssh_channel_open_delay_once(mut self, delay: std::time::Duration) -> Self {
        self.ssh_channel_open_delay_once = Some(delay);
        self
    }

    /// Set credentials for Stateful mode authentication.
    #[must_use]
    pub fn credentials(mut self, username: &str, password: &str) -> Self {
        self.credentials = Some((username.to_string(), password.to_string()));
        self
    }

    /// Seed the resource store before starting (Stateful mode only).
    #[must_use]
    pub fn seed(mut self, f: impl FnOnce(&ResourceStore) + Send + 'static) -> Self {
        self.seed_fn = Some(Box::new(f));
        self
    }

    /// Select the input profile for stateful asset commands.
    ///
    /// The default is [`AssetInputProfile::GvmdStrict`]. Select
    /// [`AssetInputProfile::LegacyFlatCompatibility`] only for compatibility
    /// with the mock server's historical flat asset command shapes.
    #[must_use]
    pub fn asset_input_profile(mut self, profile: AssetInputProfile) -> Self {
        self.asset_input_profile = profile;
        self
    }

    /// Inject a fault for error testing.
    #[must_use]
    pub fn inject_fault(mut self, fault: Fault) -> Self {
        self.faults.push(fault);
        self
    }

    /// Override a fixture response for a specific command.
    #[must_use]
    pub fn override_response(mut self, command: &str, xml: &str) -> Self {
        self.fixture_overrides
            .push((command.to_string(), xml.to_string()));
        self
    }

    /// Enable large synthetic report generation for reports created via `start_task`.
    ///
    /// # Example
    /// ```no_run
    /// use gvm_mock_server::{LargeReportConfig, MockGmpServer, ServerMode};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockGmpServer::builder()
    ///     .mode(ServerMode::Stateful)
    ///     .large_report(LargeReportConfig::default())
    ///     .unix_socket_auto()
    ///     .build()
    ///     .await?;
    /// server.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn large_report(mut self, config: LargeReportConfig) -> Self {
        self.large_report = Some(config);
        self
    }

    /// Set the maximum size of one XML request.
    ///
    /// The default is 64 MiB. Pass `None` to disable the per-request byte
    /// limit. XML nesting remains independently bounded to 256 elements.
    #[must_use]
    pub fn with_max_request_bytes(mut self, max_request_bytes: Option<usize>) -> Self {
        self.max_request_bytes = max_request_bytes;
        self
    }

    /// Build and start the mock server.
    ///
    /// # Errors
    /// Returns an I/O error if the server cannot bind to the requested address.
    pub async fn build(self) -> Result<MockGmpServer, std::io::Error> {
        let Self {
            mode,
            version,
            transport,
            fixture_overrides,
            credentials,
            seed_fn,
            faults,
            scenario_config,
            large_report,
            max_request_bytes,
            asset_input_profile,
            #[cfg(feature = "tls")]
            client_ca_certificate,
            #[cfg(feature = "ssh")]
            ssh_authorized_keys,
            #[cfg(feature = "ssh")]
            ssh_auth_delay_once,
            #[cfg(feature = "ssh")]
            ssh_channel_open_delay_once,
        } = self;

        if max_request_bytes == Some(0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "max_request_bytes must be greater than zero or None",
            ));
        }

        #[cfg(feature = "tls")]
        if client_ca_certificate.is_some() && !matches!(&transport, Transport::Tls(_)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "require_client_cert() can only be used with tls()",
            ));
        }

        let fixtures = if mode == ServerMode::Fixture || !fixture_overrides.is_empty() {
            let mut store = FixtureStore::new(version);
            for (cmd, xml) in &fixture_overrides {
                store.insert(cmd, xml);
            }
            Some(store)
        } else {
            None
        };

        let fault_engine = if faults.is_empty() {
            FaultEngine::none()
        } else {
            FaultEngine::new(faults)
        };

        assert!(
            seed_fn.is_none() || mode == ServerMode::Stateful,
            "seed() is only supported in Stateful mode"
        );

        let store = if mode == ServerMode::Stateful {
            let s = match credentials {
                Some((ref u, ref p)) => ResourceStore::with_credentials(u, p),
                None => ResourceStore::new(),
            };
            s.set_asset_input_profile(asset_input_profile);
            if let Some(seed_fn) = seed_fn {
                seed_fn(&s);
            }
            Some(s)
        } else {
            None
        };

        let options = ServerOptions {
            scenario_config,
            large_report,
            max_request_bytes,
            #[cfg(feature = "ssh")]
            ssh_authorized_keys,
            #[cfg(feature = "ssh")]
            ssh_auth_delay_once,
            #[cfg(feature = "ssh")]
            ssh_channel_open_delay_once,
        };

        match transport {
            Transport::UnixSocket(path) => {
                MockGmpServer::start_unix(
                    UnixSocketBinding {
                        path,
                        temp_dir: None,
                    },
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    options,
                )
                .await
            }
            Transport::UnixSocketAuto => {
                use std::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let id = COUNTER.fetch_add(1, Ordering::Relaxed);
                // Keep the socket under /tmp so Unix domain path length stays well below SUN_LEN.
                let dir = Builder::new().prefix("gvmd-test").tempdir_in("/tmp")?;
                let path = dir.path().join(format!("{id}.sock"));
                MockGmpServer::start_unix(
                    UnixSocketBinding {
                        path,
                        temp_dir: Some(dir),
                    },
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    options,
                )
                .await
            }
            Transport::Tcp(addr) => {
                MockGmpServer::start_tcp(
                    &addr,
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    options,
                )
                .await
            }
            #[cfg(feature = "tls")]
            Transport::Tls(addr) => {
                MockGmpServer::start_tls(
                    &addr,
                    client_ca_certificate.as_deref(),
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    options,
                )
                .await
            }
            #[cfg(feature = "ssh")]
            Transport::Ssh(addr) => {
                MockGmpServer::start_ssh(
                    &addr,
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    options,
                )
                .await
            }
            Transport::None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No transport configured. Use .unix_socket(), .unix_socket_auto(), .tcp(), or another transport method enabled for this build",
            )),
        }
    }
}

impl Default for MockGmpServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
