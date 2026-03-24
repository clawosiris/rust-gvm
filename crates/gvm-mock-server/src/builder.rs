// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Builder for configuring and starting a [`MockGmpServer`].

use std::path::PathBuf;

use crate::fault::{Fault, FaultEngine};
use crate::fixtures::FixtureStore;
use crate::response_gen::LargeReportConfig;
use crate::scenario::{ScenarioMode, ScenarioStep};
use crate::server::MockGmpServer;
use crate::store::ResourceStore;
use crate::version::GmpVersion;
use crate::ServerMode;

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
}

enum Transport {
    UnixSocket(PathBuf),
    UnixSocketAuto,
    Tcp(String),
    #[cfg(any())]
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

    /// Listen on an SSH address (e.g., "127.0.0.1:2222" or "127.0.0.1:0" for random port).
    #[cfg(any())]
    #[must_use]
    pub fn ssh(mut self, addr: impl Into<String>) -> Self {
        self.transport = Transport::Ssh(addr.into());
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
        } = self;

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
            if let Some(seed_fn) = seed_fn {
                seed_fn(&s);
            }
            Some(s)
        } else {
            None
        };

        match transport {
            Transport::UnixSocket(path) => {
                MockGmpServer::start_unix(
                    path,
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    scenario_config,
                    large_report,
                )
                .await
            }
            Transport::UnixSocketAuto => {
                use std::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let id = COUNTER.fetch_add(1, Ordering::Relaxed);
                let dir = std::env::temp_dir();
                let path = dir.join(format!("gvmd-test-{}-{id}.sock", std::process::id()));
                MockGmpServer::start_unix(
                    path,
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    scenario_config,
                    large_report,
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
                    scenario_config,
                    large_report,
                )
                .await
            }
            #[cfg(any())]
            Transport::Ssh(addr) => {
                MockGmpServer::start_ssh(
                    &addr,
                    mode,
                    version,
                    fixtures,
                    store,
                    fault_engine,
                    scenario_config,
                    large_report,
                )
                .await
            }
            Transport::None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No transport configured. Use .unix_socket(), .unix_socket_auto(), .tcp(), or .ssh()",
            )),
        }
    }
}

impl Default for MockGmpServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
