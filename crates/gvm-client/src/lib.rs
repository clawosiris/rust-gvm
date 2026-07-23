// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! High-level async GMP client with version negotiation.
//!
//! Combines [`gvm_connection`], [`gvm_protocol`], and [`gvm_gmp`] into a
//! single client that connects, negotiates the GMP version, and provides
//! typed access to all GMP commands.
//!
//! Opt-in wire tracing on [`GmpClient`] observes redacted request and response
//! XML at the client boundary. This is separate from GMP `details` flags, which
//! are request parameters that ask gvmd for more or less resource detail.

#![forbid(unsafe_code)]

mod error;
mod typed;
mod version;

use std::fmt;
use std::sync::Arc;

use gvm_connection::GvmConnection;
use gvm_gmp::commands::agent_groups::{
    clone_agent_group, create_agent_group, delete_agent_group, get_agent_group, get_agent_groups,
    modify_agent_group,
};
use gvm_gmp::commands::agents::{
    delete_agent, get_agent, get_agent_installer_instruction, get_agent_support_bundle, get_agents,
    modify_agent, modify_agent_control_scan_config, sync_agents,
};
use gvm_gmp::commands::credentials::{
    create_credential_store_credential, get_credential_store, get_credential_stores,
    get_credential_stores_with_opts, modify_credential_store_credential, verify_credential_store,
};
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::integration_configs::{
    get_integration_config, get_integration_configs, modify_integration_config,
};
use gvm_gmp::commands::oci_image_targets::{
    clone_oci_image_target, create_oci_image_target, delete_oci_image_target, get_oci_image_target,
    get_oci_image_targets, modify_oci_image_target,
};
use gvm_gmp::commands::report_configs::{
    clone_report_config, create_report_config, delete_report_config, get_report_configs,
    modify_report_config,
};
use gvm_gmp::commands::reports::{
    get_report_applications, get_report_closed_cves, get_report_cves, get_report_errors,
    get_report_hosts, get_report_operating_systems, get_report_ports, get_report_tls_certificates,
    get_report_vulns,
};
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::tasks::create_agent_group_task;
use gvm_gmp::commands::tasks::create_oci_image_target_task as build_oci_image_target_task;
use gvm_gmp::commands::tasks::create_web_application_task;
use gvm_gmp::commands::version::get_version;
use gvm_gmp::commands::web_application_targets::{
    clone_web_application_target, create_web_application_target, delete_web_application_target,
    get_web_application_target, get_web_application_targets, modify_web_application_target,
};
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::{Request, Response};

pub use error::GvmError;
pub use gvm_gmp::commands::agent_groups::{
    CreateAgentGroupOpts, GetAgentGroupsOpts, ModifyAgentGroupOpts,
};
pub use gvm_gmp::commands::agents::{
    AgentConfigOpts, AgentControlConfig, AgentHeartbeatConfig, AgentInstallerLanguage,
    AgentRetryConfig, AgentScriptExecutorConfig, GetAgentsOpts, ModifyAgentControlScanConfigOpts,
    ModifyAgentOpts,
};
pub use gvm_gmp::commands::credentials::{
    CredentialStoreCredentialOpts, GetCredentialStoresOpts, ModifyCredentialStoreCredentialOpts,
};
pub use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigsOpts, ModifyIntegrationConfigOpts,
};
pub use gvm_gmp::commands::oci_image_targets::{
    CreateOciImageTargetOpts, GetOciImageTargetsOpts, ModifyOciImageTargetOpts,
};
pub use gvm_gmp::commands::report_configs::ModifyReportConfigOpts;
pub use gvm_gmp::commands::reports::{GetReportDetailsOpts, GetReportExportOpts, ImportReportOpts};
pub use gvm_gmp::commands::tasks::CreateAgentGroupTaskOpts;
pub use gvm_gmp::commands::tasks::CreateOciImageTargetTaskOpts;
pub use gvm_gmp::commands::tasks::CreateWebApplicationTaskOpts;
pub use gvm_gmp::commands::web_application_targets::{
    CreateWebApplicationTargetOpts, GetWebApplicationTargetsOpts, ModifyWebApplicationTargetOpts,
};
pub use gvm_gmp::enums::CredentialStoreCredentialType;
pub use version::{
    command_supported, map_supported_version, minimum_version_for_command, parse_version_text,
    required_version_label,
};

/// High-level async GMP client over an abstract transport.
pub struct GmpClient<C: GvmConnection> {
    connection: C,
    version: GmpVersion,
    wire_trace: Option<Arc<dyn WireTrace>>,
}

impl<C: GvmConnection + fmt::Debug> fmt::Debug for GmpClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmpClient")
            .field("connection", &self.connection)
            .field("version", &self.version)
            .field("wire_trace_enabled", &self.wire_trace.is_some())
            .finish()
    }
}

/// Direction of a GMP wire trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireTraceDirection {
    /// XML bytes sent to gvmd.
    Request,
    /// XML bytes received from gvmd.
    Response,
}

/// Redacted GMP wire data captured at the client boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTraceEvent {
    /// Whether the bytes are outbound request XML or inbound response XML.
    pub direction: WireTraceDirection,
    /// Redacted XML bytes.
    pub bytes: Vec<u8>,
}

/// Sink for opt-in GMP wire trace events.
///
/// Events are redacted by default before this callback is invoked. The tracing
/// hook is disabled unless configured explicitly on [`GmpClient`].
pub trait WireTrace: Send + Sync + 'static {
    /// Receive a redacted GMP wire trace event.
    fn trace(&self, event: WireTraceEvent);
}

impl<F> WireTrace for F
where
    F: Fn(WireTraceEvent) + Send + Sync + 'static,
{
    fn trace(&self, event: WireTraceEvent) {
        self(event);
    }
}

impl<C: GvmConnection> GmpClient<C> {
    /// Connect, negotiate GMP version, and construct a client.
    ///
    /// # Errors
    /// Returns an error if the transport fails, version negotiation fails, or
    /// the server advertises an unsupported GMP version.
    pub async fn connect(connection: C) -> Result<Self, GvmError> {
        Self::connect_inner(connection, None).await
    }

    /// Connect, negotiate GMP version, and construct a client with wire tracing.
    ///
    /// The trace sink receives redacted request and response XML for the version
    /// negotiation request and later client calls.
    ///
    /// # Errors
    /// Returns an error if the transport fails, version negotiation fails, or
    /// the server advertises an unsupported GMP version.
    pub async fn connect_with_wire_trace<T>(connection: C, wire_trace: T) -> Result<Self, GvmError>
    where
        T: WireTrace,
    {
        Self::connect_inner(connection, Some(Arc::new(wire_trace))).await
    }

    async fn connect_inner(
        mut connection: C,
        wire_trace: Option<Arc<dyn WireTrace>>,
    ) -> Result<Self, GvmError> {
        connection.connect().await?;

        let response = Self::send_on(&mut connection, get_version(), wire_trace.as_deref()).await?;
        let response = Self::raise_for_status(response)?;
        let version_text = response.child_text("version").ok_or_else(|| {
            GvmError::XmlParse("missing <version> in get_version response".to_string())
        })?;
        let version = map_supported_version(parse_version_text(&version_text)?)?;

        Ok(Self {
            connection,
            version,
            wire_trace,
        })
    }

    /// Return the negotiated GMP version.
    #[must_use]
    pub fn version(&self) -> GmpVersion {
        self.version
    }

    /// Enable redacted GMP wire tracing on this client.
    #[must_use]
    pub fn with_wire_trace<T>(mut self, wire_trace: T) -> Self
    where
        T: WireTrace,
    {
        self.wire_trace = Some(Arc::new(wire_trace));
        self
    }

    /// Disable GMP wire tracing on this client.
    #[must_use]
    pub fn without_wire_trace(mut self) -> Self {
        self.wire_trace = None;
        self
    }

    /// Send a request and return the raw parsed response.
    ///
    /// # Errors
    /// Returns an error if request transmission or response parsing fails.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        let semantic_command_name = request.semantic_command_name();
        let request_bytes = request.to_bytes();
        self.ensure_command_supported(&request_bytes, semantic_command_name)?;
        Self::send_on_bytes(
            &mut self.connection,
            request_bytes,
            self.wire_trace.as_deref(),
        )
        .await
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

    async fn send_on<R: Request>(
        connection: &mut C,
        request: R,
        wire_trace: Option<&dyn WireTrace>,
    ) -> Result<Response, GvmError> {
        Self::send_on_bytes(connection, request.to_bytes(), wire_trace).await
    }

    async fn send_on_bytes(
        connection: &mut C,
        request_bytes: Vec<u8>,
        wire_trace: Option<&dyn WireTrace>,
    ) -> Result<Response, GvmError> {
        emit_wire_trace(wire_trace, WireTraceDirection::Request, &request_bytes);
        connection.send(&request_bytes).await?;
        let bytes = connection.read().await?;
        emit_wire_trace(wire_trace, WireTraceDirection::Response, &bytes);
        Ok(Response::new(bytes))
    }

    fn ensure_command_supported(
        &self,
        request_bytes: &[u8],
        semantic_command_name: Option<&'static str>,
    ) -> Result<(), GvmError> {
        let Some(command_name) = request_command_name(request_bytes) else {
            return Ok(());
        };

        let semantic_command_name = semantic_command_name
            .or_else(|| next_only_semantic_command(command_name, request_bytes));
        let unsupported_semantic =
            semantic_command_name.filter(|name| !version::command_supported(name, self.version));
        if unsupported_semantic.is_none() && version::command_supported(command_name, self.version)
        {
            return Ok(());
        }

        let command = unsupported_semantic.unwrap_or(command_name);
        let required = version::required_version_label(command).unwrap_or("a newer GMP version");

        Err(GvmError::UnsupportedCommand {
            command: command.to_string(),
            version: self.version,
            required,
        })
    }

    pub(crate) fn ensure_semantic_command_supported(
        &self,
        command_name: &str,
    ) -> Result<(), GvmError> {
        if version::command_supported(command_name, self.version) {
            return Ok(());
        }

        Err(GvmError::UnsupportedCommand {
            command: command_name.to_string(),
            version: self.version,
            required: version::required_version_label(command_name)
                .unwrap_or("a newer GMP version"),
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

    /// List agents.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agents(&mut self, opts: GetAgentsOpts) -> Result<Response, GvmError> {
        self.call(get_agents(opts)).await
    }

    /// Get a single agent.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agent(&mut self, agent_id: &EntityId) -> Result<Response, GvmError> {
        self.call(get_agent(agent_id)).await
    }

    /// Modify one or more agents.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_agent(
        &mut self,
        agent_ids: &[EntityId],
        opts: ModifyAgentOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_agent(agent_ids, opts)).await
    }

    /// Delete one or more agents.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn delete_agent(&mut self, agent_ids: &[EntityId]) -> Result<Response, GvmError> {
        self.call(delete_agent(agent_ids)).await
    }

    /// Synchronize agents.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn sync_agents(&mut self) -> Result<Response, GvmError> {
        self.call(sync_agents()).await
    }

    /// Modify the agent-control scan configuration defaults.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_agent_control_scan_config(
        &mut self,
        agent_control_id: &EntityId,
        opts: ModifyAgentControlScanConfigOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_agent_control_scan_config(agent_control_id, opts))
            .await
    }

    /// Get agent installer instructions.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agent_installer_instruction(
        &mut self,
        scanner_id: &EntityId,
        language: AgentInstallerLanguage,
        origin_url: &str,
    ) -> Result<Response, GvmError> {
        self.call(get_agent_installer_instruction(
            scanner_id, language, origin_url,
        ))
        .await
    }

    /// Get an agent support bundle.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_agent_support_bundle(
        &mut self,
        agent_uuid: &EntityId,
        days: Option<u32>,
    ) -> Result<Response, GvmError> {
        self.call(get_agent_support_bundle(agent_uuid, days)).await
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

    /// Create an OCI image target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn create_oci_image_target(
        &mut self,
        name: &str,
        image_references: &[String],
        opts: CreateOciImageTargetOpts,
    ) -> Result<Response, GvmError> {
        self.call(create_oci_image_target(name, image_references, opts))
            .await
    }

    /// Clone an OCI image target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn clone_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.call(clone_oci_image_target(oci_image_target_id)).await
    }

    /// Get a single OCI image target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.call(get_oci_image_target(oci_image_target_id, tasks))
            .await
    }

    /// List OCI image targets.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_oci_image_targets(
        &mut self,
        opts: GetOciImageTargetsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_oci_image_targets(opts)).await
    }

    /// Modify an OCI image target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        opts: ModifyOciImageTargetOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_oci_image_target(oci_image_target_id, opts))
            .await
    }

    /// Delete an OCI image target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn delete_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.call(delete_oci_image_target(oci_image_target_id, ultimate))
            .await
    }

    /// Create a web application target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn create_web_application_target(
        &mut self,
        name: &str,
        urls: &[String],
        opts: CreateWebApplicationTargetOpts,
    ) -> Result<Response, GvmError> {
        self.call(create_web_application_target(name, urls, opts))
            .await
    }

    /// Clone a web application target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn clone_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.call(clone_web_application_target(web_application_target_id))
            .await
    }

    /// Get a single web application target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.call(get_web_application_target(web_application_target_id, tasks))
            .await
    }

    /// List web application targets.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_web_application_targets(
        &mut self,
        opts: GetWebApplicationTargetsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_web_application_targets(opts)).await
    }

    /// Modify a web application target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn modify_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        opts: ModifyWebApplicationTargetOpts,
    ) -> Result<Response, GvmError> {
        self.call(modify_web_application_target(
            web_application_target_id,
            opts,
        ))
        .await
    }

    /// Delete a web application target.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn delete_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.call(delete_web_application_target(
            web_application_target_id,
            ultimate,
        ))
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

fn emit_wire_trace(
    wire_trace: Option<&dyn WireTrace>,
    direction: WireTraceDirection,
    bytes: &[u8],
) {
    if let Some(wire_trace) = wire_trace {
        wire_trace.trace(WireTraceEvent {
            direction,
            bytes: redact_wire_bytes(bytes),
        });
    }
}

fn redact_wire_bytes(bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return b"<non-utf8-redacted/>".to_vec();
    };

    let mut text = text.to_string();
    for tag in [
        "password",
        "private",
        "private_key",
        "passphrase",
        "secret",
        "auth_password",
        "privacy_password",
        "key",
    ] {
        text = redact_xml_element_text(&text, tag);
    }
    text.into_bytes()
}

fn redact_xml_element_text(input: &str, tag: &str) -> String {
    let mut redacted = String::with_capacity(input.len());
    let close = format!("</{tag}>");
    let mut rest = input;

    while let Some(open_start) = find_open_element(rest, tag) {
        let (before, after_before) = rest.split_at(open_start);
        redacted.push_str(before);

        let Some(open_end) = after_before.find('>') else {
            redacted.push_str(after_before);
            return redacted;
        };
        let (open_tag, after_open) = after_before.split_at(open_end + 1);
        redacted.push_str(open_tag);

        if open_tag.trim_end().ends_with("/>") {
            rest = after_open;
            continue;
        }

        let Some(close_start) = after_open.find(&close) else {
            redacted.push_str(after_open);
            return redacted;
        };
        redacted.push_str("<redacted>");
        redacted.push_str(&close);
        rest = &after_open[close_start + close.len()..];
    }

    redacted.push_str(rest);
    redacted
}

fn find_open_element(input: &str, tag: &str) -> Option<usize> {
    let open_prefix = format!("<{tag}");
    let mut search_start = 0;

    while let Some(relative_start) = input[search_start..].find(&open_prefix) {
        let start = search_start + relative_start;
        let after_tag = start + open_prefix.len();
        let next = input[after_tag..].chars().next();

        if next.is_some_and(|ch| ch == '>' || ch == '/' || ch.is_whitespace()) {
            return Some(start);
        }

        search_start = after_tag;
    }

    None
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

    /// Send a `clone_report_config` request.
    async fn clone_report_config(&mut self, id: &str) -> Result<Response, GvmError>;

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
    /// List agents.
    async fn get_agents(&mut self, opts: GetAgentsOpts) -> Result<Response, GvmError>;

    /// Get a single agent.
    async fn get_agent(&mut self, agent_id: &EntityId) -> Result<Response, GvmError>;

    /// Modify one or more agents.
    async fn modify_agent(
        &mut self,
        agent_ids: &[EntityId],
        opts: ModifyAgentOpts,
    ) -> Result<Response, GvmError>;

    /// Delete one or more agents.
    async fn delete_agent(&mut self, agent_ids: &[EntityId]) -> Result<Response, GvmError>;

    /// Synchronize agents.
    async fn sync_agents(&mut self) -> Result<Response, GvmError>;

    /// Modify the agent-control scan configuration defaults.
    async fn modify_agent_control_scan_config(
        &mut self,
        agent_control_id: &EntityId,
        opts: ModifyAgentControlScanConfigOpts,
    ) -> Result<Response, GvmError>;

    /// Get agent installer instructions.
    async fn get_agent_installer_instruction(
        &mut self,
        scanner_id: &EntityId,
        language: AgentInstallerLanguage,
        origin_url: &str,
    ) -> Result<Response, GvmError>;

    /// Get an agent support bundle.
    async fn get_agent_support_bundle(
        &mut self,
        agent_uuid: &EntityId,
        days: Option<u32>,
    ) -> Result<Response, GvmError>;

    /// Create an agent group.
    async fn create_agent_group(
        &mut self,
        name: &str,
        agent_ids: &[EntityId],
        scheduler_cron_time: &str,
        opts: CreateAgentGroupOpts,
    ) -> Result<Response, GvmError>;

    /// Create a task that scans an agent group.
    async fn create_agent_group_task(
        &mut self,
        name: &str,
        agent_group_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateAgentGroupTaskOpts,
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

    /// Create an OCI image target.
    async fn create_oci_image_target(
        &mut self,
        name: &str,
        image_references: &[String],
        opts: CreateOciImageTargetOpts,
    ) -> Result<Response, GvmError>;

    /// Create a task that scans an OCI image target.
    async fn create_oci_image_target_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<Response, GvmError>;

    /// Create a task that scans an OCI image target using python-gvm's
    /// historical container-image helper name.
    async fn create_container_image_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<Response, GvmError> {
        self.create_oci_image_target_task(name, oci_image_target_id, scanner_id, opts)
            .await
    }

    /// Clone an OCI image target.
    async fn clone_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
    ) -> Result<Response, GvmError>;

    /// Get a single OCI image target.
    async fn get_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError>;

    /// List OCI image targets.
    async fn get_oci_image_targets(
        &mut self,
        opts: GetOciImageTargetsOpts,
    ) -> Result<Response, GvmError>;

    /// Modify an OCI image target.
    async fn modify_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        opts: ModifyOciImageTargetOpts,
    ) -> Result<Response, GvmError>;

    /// Delete an OCI image target.
    async fn delete_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError>;

    /// Create a web application target.
    async fn create_web_application_target(
        &mut self,
        name: &str,
        urls: &[String],
        opts: CreateWebApplicationTargetOpts,
    ) -> Result<Response, GvmError>;

    /// Clone a web application target.
    async fn clone_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
    ) -> Result<Response, GvmError>;

    /// Get a single web application target.
    async fn get_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError>;

    /// List web application targets.
    async fn get_web_application_targets(
        &mut self,
        opts: GetWebApplicationTargetsOpts,
    ) -> Result<Response, GvmError>;

    /// Modify a web application target.
    async fn modify_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        opts: ModifyWebApplicationTargetOpts,
    ) -> Result<Response, GvmError>;

    /// Delete a web application target.
    async fn delete_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError>;

    /// Create a scan task for a web application target.
    async fn create_web_application_task(
        &mut self,
        name: &str,
        web_application_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateWebApplicationTaskOpts,
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

    /// Verify a credential store connection.
    async fn verify_credential_store(
        &mut self,
        credential_store_id: &EntityId,
    ) -> Result<Response, GvmError>;

    /// List credential stores with optional filters.
    async fn get_credential_stores_with_opts(
        &mut self,
        opts: GetCredentialStoresOpts,
    ) -> Result<Response, GvmError>;

    /// Get a single credential store.
    async fn get_credential_store(
        &mut self,
        credential_store_id: &EntityId,
        details: Option<bool>,
    ) -> Result<Response, GvmError>;

    /// Create a credential-store-backed credential.
    async fn create_credential_store_credential(
        &mut self,
        name: &str,
        credential_type: CredentialStoreCredentialType,
        vault_id: &str,
        host_identifier: &str,
        opts: CredentialStoreCredentialOpts,
    ) -> Result<Response, GvmError>;

    /// Modify a credential-store-backed credential.
    async fn modify_credential_store_credential(
        &mut self,
        credential_id: &EntityId,
        opts: ModifyCredentialStoreCredentialOpts,
    ) -> Result<Response, GvmError>;
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

            async fn clone_report_config(&mut self, id: &str) -> Result<Response, GvmError> {
                self.0.call(clone_report_config(id)).await
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
    fn from_client(client: GmpClient<C>) -> Self {
        match client.version() {
            GmpVersion(22, 4) => Self::V224(Gmp224(client)),
            GmpVersion(22, 5) => Self::V225(Gmp225(client)),
            GmpVersion(22, 6) => Self::V226(Gmp226(client)),
            GmpVersion(22, 7) => Self::V227(Gmp227(client)),
            _ => Self::Next(GmpNext(client)),
        }
    }

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
        Ok(Self::from_client(client))
    }

    /// Connect with wire tracing and wrap the negotiated client by version.
    ///
    /// The trace sink receives redacted request and response XML for the version
    /// negotiation request and later client calls.
    ///
    /// # Errors
    /// Returns an error if the transport or negotiation fails.
    pub async fn connect_with_wire_trace<T>(connection: C, wire_trace: T) -> Result<Self, GvmError>
    where
        T: WireTrace,
    {
        let client = GmpClient::connect_with_wire_trace(connection, wire_trace).await?;
        Ok(Self::from_client(client))
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
    async fn get_agents(&mut self, opts: GetAgentsOpts) -> Result<Response, GvmError> {
        self.0.get_agents(opts).await
    }

    async fn get_agent(&mut self, agent_id: &EntityId) -> Result<Response, GvmError> {
        self.0.get_agent(agent_id).await
    }

    async fn modify_agent(
        &mut self,
        agent_ids: &[EntityId],
        opts: ModifyAgentOpts,
    ) -> Result<Response, GvmError> {
        self.0.modify_agent(agent_ids, opts).await
    }

    async fn delete_agent(&mut self, agent_ids: &[EntityId]) -> Result<Response, GvmError> {
        self.0.delete_agent(agent_ids).await
    }

    async fn sync_agents(&mut self) -> Result<Response, GvmError> {
        self.0.sync_agents().await
    }

    async fn modify_agent_control_scan_config(
        &mut self,
        agent_control_id: &EntityId,
        opts: ModifyAgentControlScanConfigOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .modify_agent_control_scan_config(agent_control_id, opts)
            .await
    }

    async fn get_agent_installer_instruction(
        &mut self,
        scanner_id: &EntityId,
        language: AgentInstallerLanguage,
        origin_url: &str,
    ) -> Result<Response, GvmError> {
        self.0
            .get_agent_installer_instruction(scanner_id, language, origin_url)
            .await
    }

    async fn get_agent_support_bundle(
        &mut self,
        agent_uuid: &EntityId,
        days: Option<u32>,
    ) -> Result<Response, GvmError> {
        self.0.get_agent_support_bundle(agent_uuid, days).await
    }

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

    async fn create_agent_group_task(
        &mut self,
        name: &str,
        agent_group_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateAgentGroupTaskOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(create_agent_group_task(
                name,
                agent_group_id,
                scanner_id,
                opts,
            ))
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

    async fn create_oci_image_target(
        &mut self,
        name: &str,
        image_references: &[String],
        opts: CreateOciImageTargetOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .create_oci_image_target(name, image_references, opts)
            .await
    }

    async fn create_oci_image_target_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(build_oci_image_target_task(
                name,
                oci_image_target_id,
                scanner_id,
                opts,
            ))
            .await
    }

    async fn clone_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.0.clone_oci_image_target(oci_image_target_id).await
    }

    async fn get_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.0
            .get_oci_image_target(oci_image_target_id, tasks)
            .await
    }

    async fn get_oci_image_targets(
        &mut self,
        opts: GetOciImageTargetsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_oci_image_targets(opts).await
    }

    async fn modify_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        opts: ModifyOciImageTargetOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .modify_oci_image_target(oci_image_target_id, opts)
            .await
    }

    async fn delete_oci_image_target(
        &mut self,
        oci_image_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.0
            .delete_oci_image_target(oci_image_target_id, ultimate)
            .await
    }

    async fn create_web_application_target(
        &mut self,
        name: &str,
        urls: &[String],
        opts: CreateWebApplicationTargetOpts,
    ) -> Result<Response, GvmError> {
        self.0.create_web_application_target(name, urls, opts).await
    }

    async fn clone_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.0
            .clone_web_application_target(web_application_target_id)
            .await
    }

    async fn get_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.0
            .get_web_application_target(web_application_target_id, tasks)
            .await
    }

    async fn get_web_application_targets(
        &mut self,
        opts: GetWebApplicationTargetsOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_web_application_targets(opts).await
    }

    async fn modify_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        opts: ModifyWebApplicationTargetOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .modify_web_application_target(web_application_target_id, opts)
            .await
    }

    async fn delete_web_application_target(
        &mut self,
        web_application_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<Response, GvmError> {
        self.0
            .delete_web_application_target(web_application_target_id, ultimate)
            .await
    }

    async fn create_web_application_task(
        &mut self,
        name: &str,
        web_application_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateWebApplicationTaskOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(create_web_application_task(
                name,
                web_application_target_id,
                scanner_id,
                opts,
            ))
            .await
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

    async fn verify_credential_store(
        &mut self,
        credential_store_id: &EntityId,
    ) -> Result<Response, GvmError> {
        self.0
            .call(verify_credential_store(credential_store_id))
            .await
    }

    async fn get_credential_stores_with_opts(
        &mut self,
        opts: GetCredentialStoresOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_credential_stores_with_opts(opts)).await
    }

    async fn get_credential_store(
        &mut self,
        credential_store_id: &EntityId,
        details: Option<bool>,
    ) -> Result<Response, GvmError> {
        self.0
            .call(get_credential_store(credential_store_id, details))
            .await
    }

    async fn create_credential_store_credential(
        &mut self,
        name: &str,
        credential_type: CredentialStoreCredentialType,
        vault_id: &str,
        host_identifier: &str,
        opts: CredentialStoreCredentialOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(create_credential_store_credential(
                name,
                credential_type,
                vault_id,
                host_identifier,
                opts,
            ))
            .await
    }

    async fn modify_credential_store_credential(
        &mut self,
        credential_id: &EntityId,
        opts: ModifyCredentialStoreCredentialOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(modify_credential_store_credential(credential_id, opts))
            .await
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

fn next_only_semantic_command(command_name: &str, request_bytes: &[u8]) -> Option<&'static str> {
    match command_name {
        "create_credential" if request_contains_credential_store_type(request_bytes) => {
            Some("create_credential_store_credential")
        }
        "modify_credential" if request_contains_credential_store_modify_field(request_bytes) => {
            Some("modify_credential_store_credential")
        }
        _ => None,
    }
}

fn request_contains_credential_store_type(request_bytes: &[u8]) -> bool {
    let Ok(request) = std::str::from_utf8(request_bytes) else {
        return false;
    };
    request_element_text(request, "type").is_some_and(|value| value.starts_with("cs_"))
}

fn request_element_text<'a>(request: &'a str, element_name: &str) -> Option<&'a str> {
    let opening = format!("<{element_name}");
    let closing = format!("</{element_name}>");
    let mut search_from = 0;

    while let Some(relative_start) = request[search_from..].find(&opening) {
        let element_start = search_from + relative_start;
        let after_name = element_start + opening.len();
        let delimiter = request.as_bytes().get(after_name).copied()?;
        if delimiter != b'>' && !delimiter.is_ascii_whitespace() {
            search_from = after_name;
            continue;
        }

        let opening_end = after_name + request[after_name..].find('>')?;
        if request[..opening_end].trim_end().ends_with('/') {
            return Some("");
        }
        let content_start = opening_end + 1;
        let content_end = content_start + request[content_start..].find(&closing)?;
        return Some(request[content_start..content_end].trim());
    }

    None
}

fn request_contains_credential_store_modify_field(request_bytes: &[u8]) -> bool {
    let Ok(request) = std::str::from_utf8(request_bytes) else {
        return false;
    };
    ["credential_store_id", "vault_id", "host_identifier"]
        .iter()
        .any(|field| request_contains_element(request, field))
}

fn request_contains_element(request: &str, element_name: &str) -> bool {
    let opening = format!("<{element_name}");
    let mut search_from = 0;
    while let Some(relative_start) = request[search_from..].find(&opening) {
        let after_name = search_from + relative_start + opening.len();
        let Some(delimiter) = request.as_bytes().get(after_name).copied() else {
            return false;
        };
        if matches!(delimiter, b'>' | b'/') || delimiter.is_ascii_whitespace() {
            return true;
        }
        search_from = after_name;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use gvm_connection::{ConnectionError, GvmConnection};

    use super::*;

    #[derive(Debug)]
    struct ScriptedConnection {
        responses: VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        connected: bool,
    }

    impl ScriptedConnection {
        fn new<I, S>(responses: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: AsRef<[u8]>,
        {
            Self {
                responses: responses
                    .into_iter()
                    .map(|response| response.as_ref().to_vec())
                    .collect(),
                sent: Arc::new(Mutex::new(Vec::new())),
                connected: false,
            }
        }

        fn sent(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.sent)
        }
    }

    #[async_trait]
    impl GvmConnection for ScriptedConnection {
        async fn connect(&mut self) -> gvm_connection::Result<()> {
            self.connected = true;
            Ok(())
        }

        async fn disconnect(&mut self) -> gvm_connection::Result<()> {
            self.connected = false;
            Ok(())
        }

        async fn send(&mut self, data: &[u8]) -> gvm_connection::Result<()> {
            if !self.connected {
                return Err(ConnectionError::NotConnected);
            }
            self.sent.lock().expect("sent lock").push(data.to_vec());
            Ok(())
        }

        async fn read(&mut self) -> gvm_connection::Result<Vec<u8>> {
            self.responses.pop_front().ok_or_else(|| {
                ConnectionError::ReadFailed(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "scripted response exhausted",
                ))
            })
        }

        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    fn version_response(version: &str) -> String {
        format!(
            r#"<get_version_response status="200" status_text="OK"><version>{version}</version></get_version_response>"#
        )
    }

    fn auth_response() -> &'static str {
        r#"<authenticate_response status="200" status_text="OK"/>"#
    }

    fn event_text(event: &WireTraceEvent) -> String {
        String::from_utf8(event.bytes.clone()).expect("trace event is utf-8")
    }

    #[tokio::test]
    async fn connect_with_wire_trace_emits_redacted_typed_helper_events() {
        let connection =
            ScriptedConnection::new([version_response("22.7"), auth_response().to_string()]);
        let sent = connection.sent();
        let events = Arc::new(Mutex::new(Vec::new()));
        let trace_events = Arc::clone(&events);

        let mut client = GmpClient::connect_with_wire_trace(connection, move |event| {
            trace_events.lock().expect("trace lock").push(event);
        })
        .await
        .expect("client connects");

        client
            .authenticate("admin", "secret-password")
            .await
            .expect("authenticate succeeds");

        let sent = sent.lock().expect("sent lock");
        assert_eq!(sent.len(), 2);
        assert_eq!(
            std::str::from_utf8(&sent[0]).expect("utf-8"),
            "<get_version/>"
        );
        assert!(std::str::from_utf8(&sent[1])
            .expect("utf-8")
            .contains("<password>secret-password</password>"));

        let events = events.lock().expect("trace lock");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].direction, WireTraceDirection::Request);
        assert_eq!(event_text(&events[0]), "<get_version/>");
        assert_eq!(events[1].direction, WireTraceDirection::Response);
        assert!(event_text(&events[1]).contains("<get_version_response"));
        assert_eq!(events[2].direction, WireTraceDirection::Request);

        let auth_request = event_text(&events[2]);
        assert!(auth_request.contains("<authenticate>"));
        assert!(auth_request.contains("<password><redacted></password>"));
        assert!(!auth_request.contains("secret-password"));

        assert_eq!(events[3].direction, WireTraceDirection::Response);
        assert!(event_text(&events[3]).contains("<authenticate_response"));
    }

    #[tokio::test]
    async fn default_client_does_not_emit_wire_trace() {
        let connection = ScriptedConnection::new([version_response("22.7")]);

        let client = GmpClient::connect(connection)
            .await
            .expect("client connects");

        assert!(client.wire_trace.is_none());
    }

    #[tokio::test]
    async fn versioned_connect_with_wire_trace_wraps_negotiated_client() {
        let connection = ScriptedConnection::new([version_response("22.6")]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let trace_events = Arc::clone(&events);

        let client = GmpVersioned::connect_with_wire_trace(connection, move |event| {
            trace_events.lock().expect("trace lock").push(event);
        })
        .await
        .expect("client connects");

        assert!(matches!(client, GmpVersioned::V226(_)));

        let events = events.lock().expect("trace lock");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].direction, WireTraceDirection::Request);
        assert_eq!(event_text(&events[0]), "<get_version/>");
    }

    #[test]
    fn credential_store_create_semantic_detection_matches_next_shape() {
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><type>cs_pw</type></create_credential>",
            ),
            Some("create_credential_store_credential")
        );
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><type>up</type></create_credential>",
            ),
            None
        );
        assert_eq!(
            next_only_semantic_command(
                "modify_credential",
                b"<modify_credential><type>cs_pw</type></modify_credential>",
            ),
            None
        );
        assert!(!request_contains_credential_store_type(b"\xff"));

        for credential_type in [
            "cs_cc", "cs_snmp", "cs_up", "cs_usk", "cs_smime", "cs_pgp", "cs_pw",
        ] {
            let request =
                format!("<create_credential><type>{credential_type}</type></create_credential>");
            assert!(request_contains_credential_store_type(request.as_bytes()));
        }
        assert!(request_contains_credential_store_type(
            b"<create_credential><type>\n  cs_future \t</type></create_credential>"
        ));
    }

    #[test]
    fn credential_store_modify_semantic_detection_matches_next_shape() {
        for field in ["credential_store_id", "vault_id", "host_identifier"] {
            let request = format!(
                "<modify_credential credential_id=\"credential-1\"><{field}>value</{field}></modify_credential>"
            );
            assert_eq!(
                next_only_semantic_command("modify_credential", request.as_bytes()),
                Some("modify_credential_store_credential")
            );
            assert!(request_contains_credential_store_modify_field(
                request.as_bytes()
            ));
        }

        assert_eq!(
            next_only_semantic_command(
                "modify_credential",
                b"<modify_credential credential_id=\"credential-1\"><comment>keep</comment></modify_credential>",
            ),
            None
        );
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><vault_id>vault-1</vault_id></create_credential>",
            ),
            None
        );
        assert!(!request_contains_credential_store_modify_field(b"\xff"));
        assert!(request_contains_credential_store_modify_field(
            b"<modify_credential><vault_id/></modify_credential>"
        ));
        assert!(request_contains_credential_store_modify_field(
            b"<modify_credential><host_identifier ></host_identifier></modify_credential>"
        ));
    }

    #[test]
    fn credential_store_create_semantic_gate_uses_next_version() {
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
        };
        let error = client
            .ensure_command_supported(
                b"<create_credential><type>cs_up</type></create_credential>",
                None,
            )
            .expect_err("credential-store create is gated before 22.8");

        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                ref command,
                version: GmpVersion(22, 7),
                required: "22.8",
            } if command == "create_credential_store_credential"
        ));

        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
        };
        client
            .ensure_command_supported(
                b"<create_credential><type>cs_up</type></create_credential>",
                None,
            )
            .expect("credential-store create is available in 22.8");
        client
            .ensure_command_supported(b"<get_version/>", None)
            .expect("normal supported command still passes");
    }

    #[test]
    fn credential_store_modify_semantic_gate_uses_next_version() {
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
        };
        let error = client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"><vault_id>vault-1</vault_id></modify_credential>",
                None,
            )
            .expect_err("credential-store modify is gated before 22.8");

        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                ref command,
                version: GmpVersion(22, 7),
                required: "22.8",
            } if command == "modify_credential_store_credential"
        ));

        let error = client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"/>",
                Some("modify_credential_store_credential"),
            )
            .expect_err("semantic request metadata is gated before 22.8");
        assert!(matches!(
            error,
            GvmError::UnsupportedCommand { command, .. }
                if command == "modify_credential_store_credential"
        ));
        assert!(client
            .ensure_semantic_command_supported("modify_credential_store_credential")
            .is_err());

        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
        };
        client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"><vault_id>vault-1</vault_id></modify_credential>",
                None,
            )
            .expect("credential-store modify is available in 22.8");
        client
            .ensure_semantic_command_supported("modify_credential_store_credential")
            .expect("semantic helper is available in 22.8");
    }

    #[tokio::test]
    async fn next_trait_create_credential_store_credential_sends_request() {
        let mut connection = ScriptedConnection::new([
            r#"<create_credential_response id="credential-1" status="201" status_text="Created"/>"#,
        ]);
        connection.connect().await.expect("connection opens");
        let mut client = GmpNext(GmpClient {
            connection,
            version: GmpVersion(22, 8),
            wire_trace: None,
        });

        let response = client
            .create_credential_store_credential(
                "Credential",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
                CredentialStoreCredentialOpts::default(),
            )
            .await
            .expect("request succeeds");

        assert_eq!(response.status_code(), Some(201));
    }

    #[tokio::test]
    async fn next_trait_modify_credential_store_credential_sends_request() {
        let mut connection = ScriptedConnection::new([
            r#"<modify_credential_response status="200" status_text="OK"/>"#,
        ]);
        connection.connect().await.expect("connection opens");
        let mut client = GmpNext(GmpClient {
            connection,
            version: GmpVersion(22, 8),
            wire_trace: None,
        });

        let response = client
            .modify_credential_store_credential(
                &EntityId::new("credential-1").expect("valid id"),
                ModifyCredentialStoreCredentialOpts {
                    vault_id: Some("vault-1".into()),
                    ..Default::default()
                },
            )
            .await
            .expect("request succeeds");

        assert_eq!(response.status_code(), Some(200));
    }

    #[test]
    fn redacts_known_credential_elements() {
        let bytes = br#"<root><password>pw</password><private>key</private><private_key>key2</private_key><passphrase>phrase</passphrase><secret>oidc-secret</secret><auth_password>auth</auth_password><privacy_password>privacy</privacy_password><password algorithm="x">again</password></root>"#;

        let redacted = String::from_utf8(redact_wire_bytes(bytes)).expect("utf-8");

        assert_eq!(
            redacted,
            r#"<root><password><redacted></password><private><redacted></private><private_key><redacted></private_key><passphrase><redacted></passphrase><secret><redacted></secret><auth_password><redacted></auth_password><privacy_password><redacted></privacy_password><password algorithm="x"><redacted></password></root>"#
        );
        assert!(!redacted.contains(">pw<"));
        assert!(!redacted.contains(">key<"));
        assert!(!redacted.contains(">key2<"));
        assert!(!redacted.contains(">phrase<"));
        assert!(!redacted.contains(">oidc-secret<"));
        assert!(!redacted.contains(">auth<"));
        assert!(!redacted.contains(">privacy<"));
        assert!(!redacted.contains(">again<"));
    }

    #[test]
    fn redacts_modify_license_key_element() {
        let request = gvm_gmp::commands::system::modify_license("license-secret").to_bytes();

        let redacted = String::from_utf8(redact_wire_bytes(&request)).expect("utf-8");

        assert_eq!(
            redacted,
            "<modify_license><key><redacted></key></modify_license>"
        );
        assert!(!redacted.contains("license-secret"));
    }

    #[test]
    fn redaction_ignores_similar_and_self_closing_tags() {
        let bytes = br#"<root><password_hash>keep</password_hash><secret_name>keep-secret-name</secret_name><password/><secret/><password>pw</password><secret>s</secret></root>"#;

        let redacted = String::from_utf8(redact_wire_bytes(bytes)).expect("utf-8");

        assert_eq!(
            redacted,
            r#"<root><password_hash>keep</password_hash><secret_name>keep-secret-name</secret_name><password/><secret/><password><redacted></password><secret><redacted></secret></root>"#
        );
    }

    #[test]
    fn redacts_non_utf8_wire_bytes() {
        assert_eq!(redact_wire_bytes(&[0xff]), b"<non-utf8-redacted/>");
    }
}
