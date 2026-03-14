//! Builder for configuring and starting a [`MockGmpServer`].

use std::path::PathBuf;

use crate::fixtures::FixtureStore;
use crate::server::MockGmpServer;
use crate::version::GmpVersion;
use crate::ServerMode;

/// Builder for [`MockGmpServer`].
pub struct MockGmpServerBuilder {
    mode: ServerMode,
    version: GmpVersion,
    transport: Transport,
    fixture_overrides: Vec<(String, String)>,
}

enum Transport {
    UnixSocket(PathBuf),
    UnixSocketAuto,
    Tcp(String),
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

    /// Override a fixture response for a specific command.
    #[must_use]
    pub fn override_response(mut self, command: &str, xml: &str) -> Self {
        self.fixture_overrides
            .push((command.to_string(), xml.to_string()));
        self
    }

    /// Build and start the mock server.
    ///
    /// # Errors
    /// Returns an I/O error if the server cannot bind to the requested address.
    pub async fn build(self) -> Result<MockGmpServer, std::io::Error> {
        let fixtures = if self.mode == ServerMode::Fixture || !self.fixture_overrides.is_empty() {
            let mut store = FixtureStore::new(self.version);
            for (cmd, xml) in &self.fixture_overrides {
                store.insert(cmd, xml);
            }
            Some(store)
        } else {
            None
        };

        match self.transport {
            Transport::UnixSocket(path) => {
                MockGmpServer::start_unix(path, self.mode, self.version, fixtures).await
            }
            Transport::UnixSocketAuto => {
                let dir = std::env::temp_dir();
                let path = dir.join(format!("gvmd-test-{}.sock", std::process::id()));
                MockGmpServer::start_unix(path, self.mode, self.version, fixtures).await
            }
            Transport::Tcp(addr) => {
                MockGmpServer::start_tcp(&addr, self.mode, self.version, fixtures).await
            }
            Transport::None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No transport configured. Use .unix_socket(), .unix_socket_auto(), or .tcp()",
            )),
        }
    }
}

impl Default for MockGmpServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
