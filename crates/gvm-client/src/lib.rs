// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! High-level async GMP client with version negotiation.
//!
//! Combines [`gvm_connection`], [`gvm_protocol`], and [`gvm_gmp`] into a
//! single client that connects, negotiates the GMP version, and provides
//! typed access to all GMP commands.

#![forbid(unsafe_code)]

mod error;
mod typed;
mod version;

use gvm_connection::GvmConnection;
use gvm_gmp::commands::agent_groups::{
    clone_agent_group, create_agent_group, delete_agent_group, get_agent_group, get_agent_groups,
    modify_agent_group,
};
use gvm_gmp::commands::credentials::get_credential_stores;
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::integration_configs::{
    get_integration_config, get_integration_configs, modify_integration_config,
};
use gvm_gmp::commands::report_configs::{
    create_report_config, delete_report_config, get_report_configs, modify_report_config,
};
use gvm_gmp::commands::reports::{
    get_report_applications, get_report_closed_cves, get_report_cves, get_report_errors,
    get_report_hosts, get_report_operating_systems, get_report_ports, get_report_tls_certificates,
    get_report_vulns,
};
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::version::get_version;
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::{Request, Response};

pub use error::GvmError;
pub use gvm_gmp::commands::agent_groups::{
    CreateAgentGroupOpts, GetAgentGroupsOpts, ModifyAgentGroupOpts,
};
pub use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigsOpts, ModifyIntegrationConfigOpts,
};
pub use gvm_gmp::commands::report_configs::ModifyReportConfigOpts;
pub use gvm_gmp::commands::reports::{GetReportDetailsOpts, GetReportExportOpts};
pub use version::{
    command_supported, map_supported_version, minimum_version_for_command, parse_version_text,
    required_version_label,
};

/// High-level async GMP client over an abstract transport.
#[derive(Debug)]
pub struct GmpClient<C: GvmConnection> {
    connection: C,
    version: GmpVersion,
}

impl<C: GvmConnection> GmpClient<C> {
    /// Connect, negotiate GMP version, and construct a client.
    ///
    /// # Errors
    /// Returns an error if the transport fails, version negotiation fails, or
    /// the server advertises an unsupported GMP version.
    pub async fn connect(mut connection: C) -> Result<Self, GvmError> {
        connection.connect().await?;

        let response = Self::send_on(&mut connection, get_version()).await?;
        let response = Self::raise_for_status(response)?;
        let version_text = response.child_text("version").ok_or_else(|| {
            GvmError::XmlParse("missing <version> in get_version response".to_string())
        })?;
        let version = map_supported_version(parse_version_text(&version_text)?)?;

        Ok(Self {
            connection,
            version,
        })
    }

    /// Return the negotiated GMP version.
    #[must_use]
    pub fn version(&self) -> GmpVersion {
        self.version
    }

    /// Send a request and return the raw parsed response.
    ///
    /// # Errors
    /// Returns an error if request transmission or response parsing fails.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        let request_bytes = request.to_bytes();
        self.ensure_command_supported(&request_bytes)?;
        Self::send_on_bytes(&mut self.connection, request_bytes).await
    }

    /// Send a request and raise a server error on non-2xx responses.
    ///
    /// # Errors
    /// Returns an error if transport fails, parsing fails, or the server
    /// responds with a non-success status.
    pub async fn call<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        let response = self.send(request).await?;
        Self::raise_for_status(response)
    }

    /// Disconnect the underlying transport.
    ///
    /// # Errors
    /// Returns an error if the transport fails to disconnect.
    pub async fn disconnect(&mut self) -> Result<(), GvmError> {
        self.connection.disconnect().await?;
        Ok(())
    }

    /// Borrow the underlying connection.
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Mutably borrow the underlying connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection
    }

    /// Consume the client and return the underlying connection.
    #[must_use]
    pub fn into_inner(self) -> C {
        self.connection
    }

    async fn send_on<R: Request>(connection: &mut C, request: R) -> Result<Response, GvmError> {
        Self::send_on_bytes(connection, request.to_bytes()).await
    }

    async fn send_on_bytes(
        connection: &mut C,
        request_bytes: Vec<u8>,
    ) -> Result<Response, GvmError> {
        connection.send(&request_bytes).await?;
        let bytes = connection.read().await?;
        Ok(Response::new(bytes))
    }

    fn ensure_command_supported(&self, request_bytes: &[u8]) -> Result<(), GvmError> {
        let Some(command_name) = request_command_name(request_bytes) else {
            return Ok(());
        };

        if version::command_supported(command_name, self.version) {
            return Ok(());
        }

        let required =
            version::required_version_label(command_name).unwrap_or("a newer GMP version");

        Err(GvmError::UnsupportedCommand {
            command: command_name.to_string(),
            version: self.version,
            required,
        })
    }

    /// Get a single integration configuration.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        details: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.call(get_integration_config(integration_config_id, details))
            .await
    }

    /// List integration configurations.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_integration_configs(
        &mut self,
        opts: GetIntegrationConfigsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_integration_configs(opts)).await
    }

    /// Modify an integration configuration.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        opts: ModifyIntegrationConfigOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_integration_config(integration_config_id, opts))
            .await
    }

    /// Create an agent group.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn create_agent_group(
        &mut self,
        name: &str,
        agent_ids: &[EntityId],
        scheduler_cron_time: &str,
        opts: CreateAgentGroupOpts,
    ) -> Result<Response, GvmError> {
        self.call(create_agent_group(
            name,
            agent_ids,
            scheduler_cron_time,
            opts,
        ))
        .await
    }

    /// Clone an agent group.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn clone_agent_group(
        &mut self,
        agent_group_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.call(clone_agent_group(agent_group_id)).await
    }

    /// Get a single agent group.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agent_group(
        &mut self,
        agent_group_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.call(get_agent_group(agent_group_id)).await
    }

    /// List agent groups.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agent_groups(
        &mut self,
        opts: GetAgentGroupsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_agent_groups(opts)).await
    }

    /// Modify an agent group.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        scheduler_cron_time: &str,
        opts: ModifyAgentGroupOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_agent_group(
            agent_group_id,
            scheduler_cron_time,
            opts,
        ))
        .await
    }

    /// Delete an agent group.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn delete_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.call(delete_agent_group(agent_group_id, ultimate))
            .await
    }

    /// Get host summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_hosts(report_id, opts)).await
    }

    /// Get port summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_ports(report_id, opts)).await
    }

    /// Get application summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_applications(report_id, opts)).await
    }

    /// Get operating system summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_operating_systems(report_id, opts))
            .await
    }

    /// Get CVE summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_cves(report_id, opts)).await
    }

    fn raise_for_status(response: Response) -> Result<Response, GvmError> {
        if response.is_success() {
            return Ok(response);
        }

        Err(GvmError::Server {
            status: response.status_code().unwrap_or(0),
            message: response
                .status_text()
                .unwrap_or_else(|| "Unknown error".to_string()),
        })
    }
}

/// GMP 22.4 client wrapper.
#[derive(Debug)]
pub struct Gmp224<C: GvmConnection>(GmpClient<C>);

/// GMP 22.5 client wrapper.
#[derive(Debug)]
pub struct Gmp225<C: GvmConnection>(GmpClient<C>);

/// GMP 22.6 client wrapper.
#[derive(Debug)]
pub struct Gmp226<C: GvmConnection>(GmpClient<C>);

/// GMP 22.7 client wrapper.
#[derive(Debug)]
pub struct Gmp227<C: GvmConnection>(GmpClient<C>);

/// GMP next-version client wrapper.
#[derive(Debug)]
pub struct GmpNext<C: GvmConnection>(GmpClient<C>);

/// Commands available in GMP 22.6 and later.
#[async_trait::async_trait]
pub trait Gmp226Commands {
    /// Send a `get_features` request.
    async fn get_features(&mut self) -> Result<Response, GvmError>;

    /// Send a `create_report_config` request.
    async fn create_report_config(
        &mut self,
        name: &str,
        report_format_id: &str,
    ) -> Result<Response, GvmError>;

    /// Send a `get_report_configs` request.
    async fn get_report_configs(&mut self) -> Result<Response, GvmError>;

    /// Send a `modify_report_config` request.
    async fn modify_report_config(
        &mut self,
        id: &str,
        opts: ModifyReportConfigOpts,
    ) -> Result<Response, GvmError>;

    /// Send a `delete_report_config` request.
    async fn delete_report_config(&mut self, id: &str) -> Result<Response, GvmError>;
}

/// Commands available only in GMP 22.8 and later.
#[async_trait::async_trait]
pub trait GmpNextCommands {
    /// Create an agent group.
    async fn create_agent_group(
        &mut self,
        name: &str,
        agent_ids: &[EntityId],
        scheduler_cron_time: &str,
        opts: CreateAgentGroupOpts,
    ) -> Result<Response, GvmError>;

    /// Clone an agent group.
    async fn clone_agent_group(&mut self, agent_group_id: &EntityId) -> Result<Response, GvmError>;

    /// Get a single agent group.
    async fn get_agent_group(&mut self, agent_group_id: &EntityId) -> Result<Response, GvmError>;

    /// List agent groups.
    async fn get_agent_groups(&mut self, opts: GetAgentGroupsOpts) -> Result<Response, GvmError>;

    /// Modify an agent group.
    async fn modify_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        scheduler_cron_time: &str,
        opts: ModifyAgentGroupOpts,
    ) -> Result<Response, GvmError>;

    /// Delete an agent group.
    async fn delete_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError>;

    /// Get a single integration configuration.
    async fn get_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        details: Option<bool>,
    ) -> Result<Response, GvmError>;

    /// List integration configurations.
    async fn get_integration_configs(
        &mut self,
        opts: GetIntegrationConfigsOpts,
    ) -> Result<Response, GvmError>;

    /// Modify an integration configuration.
    async fn modify_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        opts: ModifyIntegrationConfigOpts,
    ) -> Result<Response, GvmError>;

    /// Get report host summaries.
    async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report port summaries.
    async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report application summaries.
    async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report operating system summaries.
    async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report CVE summaries.
    async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report vulnerability summaries.
    async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report vulnerability summaries using python-gvm's descriptive helper name.
    async fn get_report_vulnerabilities(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.get_report_vulns(report_id, opts).await
    }

    /// Get report TLS certificate summaries.
    async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report error summaries.
    async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report closed CVE summaries.
    async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// List timezones.
    async fn get_timezones(&mut self) -> Result<Response, GvmError>;

    /// List credential stores.
    async fn get_credential_stores(&mut self) -> Result<Response, GvmError>;
}

macro_rules! impl_gmp226_commands {
    ($client:ident) => {
        #[async_trait::async_trait]
        impl<C: GvmConnection + Send> Gmp226Commands for $client<C> {
            async fn get_features(&mut self) -> Result<Response, GvmError> {
                self.0.call(get_features()).await
            }

            async fn create_report_config(
                &mut self,
                name: &str,
                report_format_id: &str,
            ) -> Result<Response, GvmError> {
                self.0
                    .call(create_report_config(name, report_format_id))
                    .await
            }

            async fn get_report_configs(&mut self) -> Result<Response, GvmError> {
                self.0.call(get_report_configs()).await
            }

            async fn modify_report_config(
                &mut self,
                id: &str,
                opts: ModifyReportConfigOpts,
            ) -> Result<Response, GvmError> {
                self.0.call(modify_report_config(id, opts)).await
            }

            async fn delete_report_config(&mut self, id: &str) -> Result<Response, GvmError> {
                self.0.call(delete_report_config(id)).await
            }
        }
    };
}

/// Versioned GMP client wrapper selected during negotiation.
#[derive(Debug)]
pub enum GmpVersioned<C: GvmConnection> {
    /// GMP 22.4
    V224(Gmp224<C>),
    /// GMP 22.5
    V225(Gmp225<C>),
    /// GMP 22.6
    V226(Gmp226<C>),
    /// GMP 22.7
    V227(Gmp227<C>),
    /// Newer than 22.7 within supported major 22.
    Next(GmpNext<C>),
}

impl<C: GvmConnection> GmpVersioned<C> {
    fn inner(&self) -> &GmpClient<C> {
        match self {
            Self::V224(client) => &client.0,
            Self::V225(client) => &client.0,
            Self::V226(client) => &client.0,
            Self::V227(client) => &client.0,
            Self::Next(client) => &client.0,
        }
    }

    fn inner_mut(&mut self) -> &mut GmpClient<C> {
        match self {
            Self::V224(client) => &mut client.0,
            Self::V225(client) => &mut client.0,
            Self::V226(client) => &mut client.0,
            Self::V227(client) => &mut client.0,
            Self::Next(client) => &mut client.0,
        }
    }

    /// Connect and wrap the negotiated client by version.
    ///
    /// # Errors
    /// Returns an error if the transport or negotiation fails.
    pub async fn connect(connection: C) -> Result<Self, GvmError> {
        let client = GmpClient::connect(connection).await?;
        Ok(match client.version() {
            GmpVersion(22, 4) => Self::V224(Gmp224(client)),
            GmpVersion(22, 5) => Self::V225(Gmp225(client)),
            GmpVersion(22, 6) => Self::V226(Gmp226(client)),
            GmpVersion(22, 7) => Self::V227(Gmp227(client)),
            _ => Self::Next(GmpNext(client)),
        })
    }

    /// Return the negotiated GMP version.
    #[must_use]
    pub fn version(&self) -> GmpVersion {
        self.inner().version()
    }

    /// Send a request and return the raw parsed response.
    ///
    /// # Errors
    /// Returns an error if request transmission or response parsing fails.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        self.inner_mut().send(request).await
    }

    /// Send a request and raise a server error on non-2xx responses.
    ///
    /// # Errors
    /// Returns an error if transport fails, parsing fails, or the server
    /// responds with a non-success status.
    pub async fn call<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        self.inner_mut().call(request).await
    }

    /// Disconnect the underlying transport.
    ///
    /// # Errors
    /// Returns an error if the transport fails to disconnect.
    pub async fn disconnect(&mut self) -> Result<(), GvmError> {
        self.inner_mut().disconnect().await
    }
}

impl_gmp226_commands!(Gmp226);
impl_gmp226_commands!(Gmp227);
impl_gmp226_commands!(GmpNext);

#[async_trait::async_trait]
impl<C: GvmConnection + Send> GmpNextCommands for GmpNext<C> {
    async fn create_agent_group(
        &mut self,
        name: &str,
        agent_ids: &[EntityId],
        scheduler_cron_time: &str,
        opts: CreateAgentGroupOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .create_agent_group(name, agent_ids, scheduler_cron_time, opts)
            .await
    }

    async fn clone_agent_group(&mut self, agent_group_id: &EntityId) -> Result<Response, GvmError> {
        self.0.clone_agent_group(agent_group_id).await
    }

    async fn get_agent_group(&mut self, agent_group_id: &EntityId) -> Result<Response, GvmError> {
        self.0.get_agent_group(agent_group_id).await
    }

    async fn get_agent_groups(&mut self, opts: GetAgentGroupsOpts) -> Result<Response, GvmError> {
        self.0.get_agent_groups(opts).await
    }

    async fn modify_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        scheduler_cron_time: &str,
        opts: ModifyAgentGroupOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .modify_agent_group(agent_group_id, scheduler_cron_time, opts)
            .await
    }

    async fn delete_agent_group(
        &mut self,
        agent_group_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.0.delete_agent_group(agent_group_id, ultimate).await
    }

    async fn get_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        details: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.0
            .get_integration_config(integration_config_id, details)
            .await
    }

    async fn get_integration_configs(
        &mut self,
        opts: GetIntegrationConfigsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_integration_configs(opts).await
    }

    async fn modify_integration_config(
        &mut self,
        integration_config_id: &EntityId,
        opts: ModifyIntegrationConfigOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .modify_integration_config(integration_config_id, opts)
            .await
    }

    async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_report_hosts(report_id, opts).await
    }

    async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_report_ports(report_id, opts).await
    }

    async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_report_applications(report_id, opts).await
    }

    async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_report_operating_systems(report_id, opts).await
    }

    async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_report_cves(report_id, opts).await
    }

    async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_vulns(report_id, opts)).await
    }

    async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(get_report_tls_certificates(report_id, opts))
            .await
    }

    async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_errors(report_id, opts)).await
    }

    async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_closed_cves(report_id, opts)).await
    }

    async fn get_timezones(&mut self) -> Result<Response, GvmError> {
        self.0.call(get_timezones()).await
    }

    async fn get_credential_stores(&mut self) -> Result<Response, GvmError> {
        self.0.call(get_credential_stores()).await
    }
}

fn request_command_name(request_bytes: &[u8]) -> Option<&str> {
    let request = std::str::from_utf8(request_bytes).ok()?.trim_start();
    let request = request.strip_prefix('<')?;
    let end = request
        .find(|ch: char| ch == '>' || ch == '/' || ch.is_whitespace())
        .unwrap_or(request.len());
    Some(&request[..end])
}
