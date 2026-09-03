// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Agent command builders.

use gvm_protocol::{xml_command::XmlElement, Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str};
use crate::responses::{
    DeleteAgentResponse, GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse,
    GetAgentsResponse, ModifyAgentControlScanConfigResponse, ModifyAgentResponse,
    SyncAgentsResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Supported agent installer instruction languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstallerLanguage {
    /// English instructions.
    En,
    /// German instructions.
    De,
}

impl AgentInstallerLanguage {
    /// Return the GMP wire value.
    #[must_use]
    pub fn as_gmp_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }
}

/// Options for `get_agents` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAgentsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Retry defaults inside an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentRetryConfig {
    /// Number of retry attempts.
    pub attempts: Option<u32>,
    /// Retry delay in seconds.
    pub delay_in_seconds: Option<u32>,
    /// Maximum retry jitter in seconds.
    pub max_jitter_in_seconds: Option<u32>,
}

/// Agent-control section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentControlConfig {
    /// Retry configuration.
    pub retry: Option<AgentRetryConfig>,
}

/// Agent-script-executor section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentScriptExecutorConfig {
    /// Bulk size.
    pub bulk_size: Option<u32>,
    /// Bulk throttle time in milliseconds.
    pub bulk_throttle_time_in_ms: Option<u32>,
    /// Indexer directory depth.
    pub indexer_dir_depth: Option<u32>,
    /// Scheduler cron expressions.
    pub scheduler_cron_time: Vec<String>,
}

/// Heartbeat section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentHeartbeatConfig {
    /// Heartbeat interval in seconds.
    pub interval_in_seconds: Option<u32>,
    /// Missed-heartbeat count before the agent is considered inactive.
    pub miss_until_inactive: Option<u32>,
}

/// Agent configuration payload shared by agent update commands.
#[derive(Debug, Clone, Default)]
pub struct AgentConfigOpts {
    /// Agent-control configuration.
    pub agent_control: Option<AgentControlConfig>,
    /// Agent-script-executor configuration.
    pub agent_script_executor: Option<AgentScriptExecutorConfig>,
    /// Heartbeat configuration.
    pub heartbeat: Option<AgentHeartbeatConfig>,
}

/// Optional fields for `modify_agent` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyAgentOpts {
    /// Whether the selected agents are authorized.
    pub authorized: Option<bool>,
    /// Whether selected agents should update to the latest version.
    pub update_to_latest: Option<bool>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional agent configuration update.
    pub config: Option<AgentConfigOpts>,
}

/// Optional fields for `modify_agent_control_scan_config` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyAgentControlScanConfigOpts {
    /// Default configuration for agents controlled by this scanner.
    pub agent_defaults: Option<AgentConfigOpts>,
    /// Default update-to-latest value for controlled agents.
    pub update_to_latest: Option<bool>,
}

/// Semantic request for listing agents.
#[derive(Debug, Clone, Default)]
pub struct GetAgentsRequest(GetAgentsOpts);

impl GetAgentsRequest {
    /// Create an agent-list request.
    #[must_use]
    pub fn new(opts: GetAgentsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetAgentsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agents(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetAgentsRequest {
    type Response = GetAgentsResponse;
}

/// Semantic request for one agent.
#[derive(Debug, Clone)]
pub struct GetAgentRequest(EntityId);

impl GetAgentRequest {
    /// Create a single-agent request.
    #[must_use]
    pub fn new(agent_id: EntityId) -> Self {
        Self(agent_id)
    }
}

impl Request for GetAgentRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agent(&self.0).to_bytes()
    }
}

impl GmpRequest for GetAgentRequest {
    type Response = GetAgentsResponse;
}

/// Semantic request for modifying agents.
#[derive(Debug, Clone)]
pub struct ModifyAgentRequest {
    agent_ids: Vec<EntityId>,
    opts: ModifyAgentOpts,
}

impl ModifyAgentRequest {
    /// Create an agent-modification request.
    #[must_use]
    pub fn new(agent_ids: Vec<EntityId>, opts: ModifyAgentOpts) -> Self {
        Self { agent_ids, opts }
    }
}

impl Request for ModifyAgentRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_agent(&self.agent_ids, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyAgentRequest {
    type Response = ModifyAgentResponse;
}

/// Semantic request for deleting agents.
#[derive(Debug, Clone)]
pub struct DeleteAgentRequest(Vec<EntityId>);

impl DeleteAgentRequest {
    /// Create an agent-deletion request.
    #[must_use]
    pub fn new(agent_ids: Vec<EntityId>) -> Self {
        Self(agent_ids)
    }
}

impl Request for DeleteAgentRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_agent(&self.0).to_bytes()
    }
}

impl GmpRequest for DeleteAgentRequest {
    type Response = DeleteAgentResponse;
}

/// Semantic request for synchronizing agents.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncAgentsRequest;

impl SyncAgentsRequest {
    /// Create an agent-synchronization request.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Request for SyncAgentsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        sync_agents().to_bytes()
    }
}

impl GmpRequest for SyncAgentsRequest {
    type Response = SyncAgentsResponse;
}

/// Semantic request for modifying agent-control defaults.
#[derive(Debug, Clone)]
pub struct ModifyAgentControlScanConfigRequest {
    agent_control_id: EntityId,
    opts: ModifyAgentControlScanConfigOpts,
}

impl ModifyAgentControlScanConfigRequest {
    /// Create an agent-control defaults request.
    #[must_use]
    pub fn new(agent_control_id: EntityId, opts: ModifyAgentControlScanConfigOpts) -> Self {
        Self {
            agent_control_id,
            opts,
        }
    }
}

impl Request for ModifyAgentControlScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_agent_control_scan_config(&self.agent_control_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyAgentControlScanConfigRequest {
    type Response = ModifyAgentControlScanConfigResponse;
}

/// Semantic request for agent installer instructions.
#[derive(Debug, Clone)]
pub struct GetAgentInstallerInstructionRequest {
    scanner_id: EntityId,
    language: AgentInstallerLanguage,
    origin_url: String,
}

impl GetAgentInstallerInstructionRequest {
    /// Create an installer-instruction request.
    #[must_use]
    pub fn new(
        scanner_id: EntityId,
        language: AgentInstallerLanguage,
        origin_url: impl Into<String>,
    ) -> Self {
        Self {
            scanner_id,
            language,
            origin_url: origin_url.into(),
        }
    }
}

impl Request for GetAgentInstallerInstructionRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agent_installer_instruction(&self.scanner_id, self.language, &self.origin_url)
            .to_bytes()
    }
}

impl GmpRequest for GetAgentInstallerInstructionRequest {
    type Response = GetAgentInstallerInstructionResponse;
}

/// Semantic request for an agent support bundle.
#[derive(Debug, Clone)]
pub struct GetAgentSupportBundleRequest {
    agent_uuid: EntityId,
    days: Option<u32>,
}

impl GetAgentSupportBundleRequest {
    /// Create a support-bundle request.
    #[must_use]
    pub fn new(agent_uuid: EntityId, days: Option<u32>) -> Self {
        Self { agent_uuid, days }
    }
}

impl Request for GetAgentSupportBundleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agent_support_bundle(&self.agent_uuid, self.days).to_bytes()
    }
}

impl GmpRequest for GetAgentSupportBundleRequest {
    type Response = GetAgentSupportBundleResponse;
}

/// Build a `get_agents` request.
#[must_use]
pub fn get_agents(opts: GetAgentsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_agents");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_agent` request.
#[must_use]
pub fn get_agent(agent_id: &EntityId) -> impl Request {
    XmlCommand::new("get_agents").attribute("agent_id", agent_id.as_str())
}

/// Build a `modify_agent` request.
#[must_use]
pub fn modify_agent(agent_ids: &[EntityId], opts: ModifyAgentOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_agent");
    add_agents_element(&mut cmd, agent_ids);
    if let Some(authorized) = opts.authorized {
        cmd.add_element_with_text("authorized", bool_str(authorized));
    }
    if let Some(update_to_latest) = opts.update_to_latest {
        cmd.add_element_with_text("update_to_latest", bool_str(update_to_latest));
    }
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(config) = opts.config.as_ref() {
        let config_element = cmd.add_element("config");
        add_agent_config(config_element, config);
    }
    cmd
}

/// Build a `delete_agent` request.
#[must_use]
pub fn delete_agent(agent_ids: &[EntityId]) -> impl Request {
    let mut cmd = XmlCommand::new("delete_agent");
    add_agents_element(&mut cmd, agent_ids);
    cmd
}

/// Build a `sync_agents` request.
#[must_use]
pub fn sync_agents() -> impl Request {
    XmlCommand::new("sync_agents")
}

/// Build a `modify_agent_control_scan_config` request.
#[must_use]
pub fn modify_agent_control_scan_config(
    agent_control_id: &EntityId,
    opts: ModifyAgentControlScanConfigOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_agent_control_scan_config")
        .attribute("agent_control_id", agent_control_id.as_str());
    let defaults = cmd.add_element("config_defaults");
    if let Some(agent_defaults) = opts.agent_defaults.as_ref() {
        let agent_defaults_element = defaults.add_child("agent_defaults");
        add_agent_config(agent_defaults_element, agent_defaults);
    }
    if let Some(update_to_latest) = opts.update_to_latest {
        defaults
            .add_child("agent_control_defaults")
            .add_child_with_text("update_to_latest", bool_str(update_to_latest));
    }
    cmd
}

/// Build a `get_agent_installer_instruction` request.
#[must_use]
pub fn get_agent_installer_instruction(
    scanner_id: &EntityId,
    language: AgentInstallerLanguage,
    origin_url: &str,
) -> impl Request {
    XmlCommand::new("get_agent_installer_instruction")
        .attribute("language", language.as_gmp_str())
        .attribute("origin_url", origin_url)
        .attribute("scanner_id", scanner_id.as_str())
}

/// Build a `get_agent_support_bundle` request.
#[must_use]
pub fn get_agent_support_bundle(agent_uuid: &EntityId, days: Option<u32>) -> impl Request {
    let mut cmd =
        XmlCommand::new("get_agent_support_bundle").attribute("agent_uuid", agent_uuid.as_str());
    if let Some(days) = days {
        cmd.set_attribute("days", &days.to_string());
    }
    cmd
}

fn add_agents_element(cmd: &mut XmlCommand, agent_ids: &[EntityId]) {
    let agents = cmd.add_element("agents");
    for agent_id in agent_ids {
        agents
            .add_child("agent")
            .set_attribute("id", agent_id.as_str());
    }
}

fn add_agent_config(parent: &mut XmlElement, opts: &AgentConfigOpts) {
    if let Some(agent_control) = opts.agent_control.as_ref() {
        add_agent_control_config(parent.add_child("agent_control"), agent_control);
    }
    if let Some(agent_script_executor) = opts.agent_script_executor.as_ref() {
        add_agent_script_executor_config(
            parent.add_child("agent_script_executor"),
            agent_script_executor,
        );
    }
    if let Some(heartbeat) = opts.heartbeat.as_ref() {
        add_heartbeat_config(parent.add_child("heartbeat"), heartbeat);
    }
}

fn add_agent_control_config(parent: &mut XmlElement, opts: &AgentControlConfig) {
    if let Some(retry) = opts.retry.as_ref() {
        let retry_element = parent.add_child("retry");
        add_u32_child(retry_element, "attempts", retry.attempts);
        add_u32_child(retry_element, "delay_in_seconds", retry.delay_in_seconds);
        add_u32_child(
            retry_element,
            "max_jitter_in_seconds",
            retry.max_jitter_in_seconds,
        );
    }
}

fn add_agent_script_executor_config(parent: &mut XmlElement, opts: &AgentScriptExecutorConfig) {
    add_u32_child(parent, "bulk_size", opts.bulk_size);
    add_u32_child(
        parent,
        "bulk_throttle_time_in_ms",
        opts.bulk_throttle_time_in_ms,
    );
    add_u32_child(parent, "indexer_dir_depth", opts.indexer_dir_depth);
    if !opts.scheduler_cron_time.is_empty() {
        let scheduler = parent.add_child("scheduler_cron_time");
        for item in &opts.scheduler_cron_time {
            scheduler.add_child_with_text("item", item);
        }
    }
}

fn add_heartbeat_config(parent: &mut XmlElement, opts: &AgentHeartbeatConfig) {
    add_u32_child(parent, "interval_in_seconds", opts.interval_in_seconds);
    add_u32_child(parent, "miss_until_inactive", opts.miss_until_inactive);
}

fn add_u32_child(parent: &mut XmlElement, name: &str, value: Option<u32>) {
    if let Some(value) = value {
        parent.add_child_with_text(name, &value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;
    use crate::responses::{
        DeleteAgentResponse, GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse,
        GetAgentsResponse, ModifyAgentControlScanConfigResponse, ModifyAgentResponse,
        SyncAgentsResponse,
    };

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn sample_config() -> AgentConfigOpts {
        AgentConfigOpts {
            agent_control: Some(AgentControlConfig {
                retry: Some(AgentRetryConfig {
                    attempts: Some(3),
                    delay_in_seconds: Some(10),
                    max_jitter_in_seconds: Some(5),
                }),
            }),
            agent_script_executor: Some(AgentScriptExecutorConfig {
                bulk_size: Some(20),
                bulk_throttle_time_in_ms: Some(100),
                indexer_dir_depth: Some(4),
                scheduler_cron_time: vec!["0 */6 * * *".into(), "30 */6 * * *".into()],
            }),
            heartbeat: Some(AgentHeartbeatConfig {
                interval_in_seconds: Some(60),
                miss_until_inactive: Some(3),
            }),
        }
    }

    #[test]
    fn agent_get_builds_xml() {
        assert_eq!(
            xml(get_agents(GetAgentsOpts {
                filter_string: Some("scanner=agent-controller".into()),
                filter_id: Some(id("filter-1")),
            })),
            "<get_agents filt_id=\"filter-1\" filter=\"scanner=agent-controller\"/>"
        );
        assert_eq!(
            xml(get_agent(&id("agent-1"))),
            "<get_agents agent_id=\"agent-1\"/>"
        );
    }

    #[test]
    fn agent_modify_and_delete_build_xml() {
        assert_eq!(
            xml(modify_agent(
                &[id("agent-1"), id("agent-2")],
                ModifyAgentOpts {
                    authorized: Some(true),
                    update_to_latest: Some(false),
                    comment: Some("managed".into()),
                    config: Some(sample_config()),
                },
            )),
            "<modify_agent><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents><authorized>1</authorized><update_to_latest>0</update_to_latest><comment>managed</comment><config><agent_control><retry><attempts>3</attempts><delay_in_seconds>10</delay_in_seconds><max_jitter_in_seconds>5</max_jitter_in_seconds></retry></agent_control><agent_script_executor><bulk_size>20</bulk_size><bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms><indexer_dir_depth>4</indexer_dir_depth><scheduler_cron_time><item>0 */6 * * *</item><item>30 */6 * * *</item></scheduler_cron_time></agent_script_executor><heartbeat><interval_in_seconds>60</interval_in_seconds><miss_until_inactive>3</miss_until_inactive></heartbeat></config></modify_agent>"
        );
        assert_eq!(
            xml(delete_agent(&[id("agent-1"), id("agent-2")])),
            "<delete_agent><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents></delete_agent>"
        );
    }

    #[test]
    fn agent_sync_and_control_config_build_xml() {
        assert_eq!(xml(sync_agents()), "<sync_agents/>");
        assert_eq!(
            xml(modify_agent_control_scan_config(
                &id("scanner-1"),
                ModifyAgentControlScanConfigOpts {
                    agent_defaults: Some(sample_config()),
                    update_to_latest: Some(true),
                },
            )),
            "<modify_agent_control_scan_config agent_control_id=\"scanner-1\"><config_defaults><agent_defaults><agent_control><retry><attempts>3</attempts><delay_in_seconds>10</delay_in_seconds><max_jitter_in_seconds>5</max_jitter_in_seconds></retry></agent_control><agent_script_executor><bulk_size>20</bulk_size><bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms><indexer_dir_depth>4</indexer_dir_depth><scheduler_cron_time><item>0 */6 * * *</item><item>30 */6 * * *</item></scheduler_cron_time></agent_script_executor><heartbeat><interval_in_seconds>60</interval_in_seconds><miss_until_inactive>3</miss_until_inactive></heartbeat></agent_defaults><agent_control_defaults><update_to_latest>1</update_to_latest></agent_control_defaults></config_defaults></modify_agent_control_scan_config>"
        );
    }

    #[test]
    fn agent_installer_and_support_bundle_build_xml() {
        assert_eq!(
            xml(get_agent_installer_instruction(
                &id("scanner-1"),
                AgentInstallerLanguage::En,
                "https://gvmd.example",
            )),
            "<get_agent_installer_instruction language=\"en\" origin_url=\"https://gvmd.example\" scanner_id=\"scanner-1\"/>"
        );
        assert_eq!(
            xml(get_agent_support_bundle(&id("agent-1"), Some(14))),
            "<get_agent_support_bundle agent_uuid=\"agent-1\" days=\"14\"/>"
        );
        assert_eq!(
            xml(get_agent_support_bundle(&id("agent-1"), None)),
            "<get_agent_support_bundle agent_uuid=\"agent-1\"/>"
        );
    }

    #[test]
    fn semantic_requests_preserve_builder_bytes_and_response_associations() {
        fn agents<R: GmpRequest<Response = GetAgentsResponse>>(_: &R) {}
        fn modify<R: GmpRequest<Response = ModifyAgentResponse>>(_: &R) {}
        fn delete<R: GmpRequest<Response = DeleteAgentResponse>>(_: &R) {}
        fn sync<R: GmpRequest<Response = SyncAgentsResponse>>(_: &R) {}
        fn control<R: GmpRequest<Response = ModifyAgentControlScanConfigResponse>>(_: &R) {}
        fn instruction<R: GmpRequest<Response = GetAgentInstallerInstructionResponse>>(_: &R) {}
        fn bundle<R: GmpRequest<Response = GetAgentSupportBundleResponse>>(_: &R) {}

        let agent_id = id("agent-1");
        let agent_ids = vec![agent_id.clone(), id("agent-2")];
        let list_opts = GetAgentsOpts {
            filter_string: Some("scanner=agent-controller".into()),
            filter_id: Some(id("filter-1")),
        };
        let modify_opts = ModifyAgentOpts {
            authorized: Some(true),
            update_to_latest: Some(false),
            comment: Some("managed".into()),
            config: Some(sample_config()),
        };
        let control_opts = ModifyAgentControlScanConfigOpts {
            agent_defaults: Some(sample_config()),
            update_to_latest: Some(true),
        };

        let list = GetAgentsRequest::new(list_opts.clone());
        agents(&list);
        assert_eq!(list.to_bytes(), get_agents(list_opts).to_bytes());
        let get = GetAgentRequest::new(agent_id.clone());
        agents(&get);
        assert_eq!(get.to_bytes(), get_agent(&agent_id).to_bytes());
        let modify_request = ModifyAgentRequest::new(agent_ids.clone(), modify_opts.clone());
        modify(&modify_request);
        assert_eq!(
            modify_request.to_bytes(),
            modify_agent(&agent_ids, modify_opts).to_bytes()
        );
        let delete_request = DeleteAgentRequest::new(agent_ids.clone());
        delete(&delete_request);
        assert_eq!(
            delete_request.to_bytes(),
            delete_agent(&agent_ids).to_bytes()
        );
        let sync_request = SyncAgentsRequest::new();
        sync(&sync_request);
        assert_eq!(sync_request.to_bytes(), sync_agents().to_bytes());
        let control_request =
            ModifyAgentControlScanConfigRequest::new(agent_id.clone(), control_opts.clone());
        control(&control_request);
        assert_eq!(
            control_request.to_bytes(),
            modify_agent_control_scan_config(&agent_id, control_opts).to_bytes()
        );
        let instruction_request = GetAgentInstallerInstructionRequest::new(
            agent_id.clone(),
            AgentInstallerLanguage::De,
            "https://gvmd.example",
        );
        instruction(&instruction_request);
        assert_eq!(
            instruction_request.to_bytes(),
            get_agent_installer_instruction(
                &agent_id,
                AgentInstallerLanguage::De,
                "https://gvmd.example",
            )
            .to_bytes()
        );
        let bundle_request = GetAgentSupportBundleRequest::new(agent_id.clone(), Some(14));
        bundle(&bundle_request);
        assert_eq!(
            bundle_request.to_bytes(),
            get_agent_support_bundle(&agent_id, Some(14)).to_bytes()
        );
    }
}
