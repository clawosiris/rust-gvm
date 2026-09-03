// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Agent response models.

use base64::Engine as _;
use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_bool, parse_document, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Agent {
    pub meta: EntityMeta,
    pub authorized: Option<bool>,
    pub update_to_latest: Option<bool>,
    pub status: Option<String>,
    pub version: Option<String>,
    pub last_update_time: Option<String>,
    pub last_contact_time: Option<String>,
    pub scanner: Option<NamedEntity>,
    pub config: Option<AgentConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentConfig {
    pub agent_control: Option<AgentControlConfig>,
    pub agent_script_executor: Option<AgentScriptExecutorConfig>,
    pub heartbeat: Option<AgentHeartbeatConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentControlConfig {
    pub retry: Option<AgentRetryConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentRetryConfig {
    pub attempts: Option<u32>,
    pub delay_in_seconds: Option<u32>,
    pub max_jitter_in_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentScriptExecutorConfig {
    pub bulk_size: Option<u32>,
    pub bulk_throttle_time_in_ms: Option<u32>,
    pub indexer_dir_depth: Option<u32>,
    pub scheduler_cron_time: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentHeartbeatConfig {
    pub interval_in_seconds: Option<u32>,
    pub miss_until_inactive: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAgentsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Agent>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAgentInstallerInstructionResponse {
    pub status: u16,
    pub status_text: String,
    pub language: String,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAgentSupportBundleResponse {
    pub status: u16,
    pub status_text: String,
    pub file: AgentSupportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentSupportBundle {
    pub name: String,
    pub content_type: Option<String>,
    pub size: Option<u32>,
    pub content: Vec<u8>,
    pub encoding: Option<String>,
}

impl Agent {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            authorized: optional_bool(node, "authorized")?,
            update_to_latest: optional_bool(node, "update_to_latest")?,
            status: node.optional_child_text("status"),
            version: node.optional_child_text("version"),
            last_update_time: node.optional_child_text("last_update_time"),
            last_contact_time: node.optional_child_text("last_contact_time"),
            scanner: parse_named_entity(node, "scanner")?,
            config: node
                .child("config")
                .map(AgentConfig::from_node)
                .transpose()?,
        })
    }
}

impl AgentConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            agent_control: node
                .child("agent_control")
                .map(AgentControlConfig::from_node)
                .transpose()?,
            agent_script_executor: node
                .child("agent_script_executor")
                .map(AgentScriptExecutorConfig::from_node)
                .transpose()?,
            heartbeat: node
                .child("heartbeat")
                .map(AgentHeartbeatConfig::from_node)
                .transpose()?,
        })
    }
}

impl AgentControlConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            retry: node
                .child("retry")
                .map(AgentRetryConfig::from_node)
                .transpose()?,
        })
    }
}

impl AgentRetryConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            attempts: optional_u32(node, "attempts", "retry.attempts")?,
            delay_in_seconds: optional_u32(node, "delay_in_seconds", "retry.delay_in_seconds")?,
            max_jitter_in_seconds: optional_u32(
                node,
                "max_jitter_in_seconds",
                "retry.max_jitter_in_seconds",
            )?,
        })
    }
}

impl AgentScriptExecutorConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            bulk_size: optional_u32(node, "bulk_size", "agent_script_executor.bulk_size")?,
            bulk_throttle_time_in_ms: optional_u32(
                node,
                "bulk_throttle_time_in_ms",
                "agent_script_executor.bulk_throttle_time_in_ms",
            )?,
            indexer_dir_depth: optional_u32(
                node,
                "indexer_dir_depth",
                "agent_script_executor.indexer_dir_depth",
            )?,
            scheduler_cron_time: node
                .child("scheduler_cron_time")
                .map(|schedule| {
                    schedule
                        .children_named("item")
                        .map(|item| item.text.trim().to_owned())
                        .filter(|item| !item.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

impl AgentHeartbeatConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            interval_in_seconds: optional_u32(
                node,
                "interval_in_seconds",
                "heartbeat.interval_in_seconds",
            )?,
            miss_until_inactive: optional_u32(
                node,
                "miss_until_inactive",
                "heartbeat.miss_until_inactive",
            )?,
        })
    }
}

impl GetAgentsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("agent")
            .map(Agent::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "agent_count")?,
        })
    }
}

impl GmpResponse for GetAgentsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GetAgentInstallerInstructionResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
            language: root.required_child_text("language")?,
            instruction: root.required_child_text("instruction")?,
        })
    }
}

impl GmpResponse for GetAgentInstallerInstructionResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GetAgentSupportBundleResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let file = root
            .child("file")
            .ok_or_else(|| ParseError::MissingElement("file".to_string()))?;
        Ok(Self {
            status,
            status_text,
            file: AgentSupportBundle::from_node(file)?,
        })
    }
}

impl GmpResponse for GetAgentSupportBundleResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl AgentSupportBundle {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let content_node = node
            .child("content")
            .ok_or_else(|| ParseError::MissingElement("file.content".to_string()))?;
        let encoding = content_node.attr("encoding").map(ToString::to_string);
        let content = match encoding.as_deref() {
            Some("base64") => base64::engine::general_purpose::STANDARD
                .decode(strip_ascii_whitespace(&content_node.text))
                .map_err(|_| ParseError::InvalidValue {
                    field: "file.content".to_string(),
                    value: content_node.text.clone(),
                })?,
            Some(other) => {
                return Err(ParseError::InvalidValue {
                    field: "file.content.encoding".to_string(),
                    value: other.to_string(),
                });
            }
            None => content_node.text.as_bytes().to_vec(),
        };
        let size = optional_u32(node, "size", "file.size")?;
        if let Some(expected) = size {
            if content.len() != expected as usize {
                return Err(ParseError::InvalidValue {
                    field: "file.size".to_string(),
                    value: expected.to_string(),
                });
            }
        }
        Ok(Self {
            name: node.required_child_text("name")?,
            content_type: node.optional_child_text("content_type"),
            size,
            content,
            encoding,
        })
    }
}

fn optional_bool(node: &XmlNode, name: &str) -> Result<Option<bool>, ParseError> {
    node.optional_child_text(name)
        .map(|value| parse_bool(&value, name))
        .transpose()
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

pub type ModifyAgentResponse = ActionResponse;
pub type DeleteAgentResponse = ActionResponse;
pub type SyncAgentsResponse = ActionResponse;
pub type ModifyAgentControlScanConfigResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_agents_with_config() {
        let response = Response::from(
            r#"<get_agents_response status="200" status_text="OK">
                <agent id="agent-1">
                    <owner><name>admin</name></owner>
                    <name>Agent One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <authorized>1</authorized>
                    <update_to_latest>0</update_to_latest>
                    <status>active</status>
                    <version>1.2.3</version>
                    <last_update_time>2026-01-03T00:00:00Z</last_update_time>
                    <last_contact_time>2026-01-04T00:00:00Z</last_contact_time>
                    <scanner id="scanner-1"><name>Agent Controller</name></scanner>
                    <config>
                        <agent_control>
                            <retry>
                                <attempts>3</attempts>
                                <delay_in_seconds>10</delay_in_seconds>
                                <max_jitter_in_seconds>5</max_jitter_in_seconds>
                            </retry>
                        </agent_control>
                        <agent_script_executor>
                            <bulk_size>20</bulk_size>
                            <bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms>
                            <indexer_dir_depth>4</indexer_dir_depth>
                            <scheduler_cron_time>
                                <item> 0 */6 * * * </item>
                                <item>30 */6 * * *</item>
                                <item>   </item>
                            </scheduler_cron_time>
                        </agent_script_executor>
                        <heartbeat>
                            <interval_in_seconds>60</interval_in_seconds>
                            <miss_until_inactive>3</miss_until_inactive>
                        </heartbeat>
                    </config>
                </agent>
                <agent id="agent-2"><name>Agent Two</name><authorized>false</authorized></agent>
                <agent_count>2<filtered>2</filtered><page>1</page></agent_count>
            </get_agents_response>"#,
        );

        let parsed = GetAgentsResponse::from_response(&response).expect("agents parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        let agent = &parsed.items[0];
        assert_eq!(agent.meta.name, "Agent One");
        assert_eq!(agent.authorized, Some(true));
        assert_eq!(agent.update_to_latest, Some(false));
        assert_eq!(agent.status.as_deref(), Some("active"));
        assert_eq!(
            agent.scanner.as_ref().map(|scanner| scanner.name.as_str()),
            Some("Agent Controller")
        );
        let executor = agent
            .config
            .as_ref()
            .and_then(|config| config.agent_script_executor.as_ref())
            .expect("executor config");
        assert_eq!(
            executor.scheduler_cron_time,
            vec!["0 */6 * * *", "30 */6 * * *"]
        );
        assert_eq!(parsed.items[1].authorized, Some(false));
    }

    #[test]
    fn parses_empty_agents() {
        let response = Response::from(
            r#"<get_agents_response status="200" status_text="OK"><agent_count>0<filtered>0</filtered></agent_count></get_agents_response>"#,
        );

        let parsed = GetAgentsResponse::from_response(&response).expect("agents parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_installer_instruction() {
        let response = Response::from(
            r#"<get_agent_installer_instruction_response status="200" status_text="OK"><language>en</language><instruction>Install it.</instruction></get_agent_installer_instruction_response>"#,
        );

        let parsed = GetAgentInstallerInstructionResponse::from_response(&response)
            .expect("instruction parses");

        assert_eq!(parsed.language, "en");
        assert_eq!(parsed.instruction, "Install it.");
    }

    #[test]
    fn parses_base64_support_bundle() {
        let response = Response::from(
            r#"<get_agent_support_bundle_response status="200" status_text="OK">
                <file>
                    <name>bundle.tar.gz</name>
                    <content_type>application/octet-stream</content_type>
                    <size>10</size>
                    <content encoding="base64">aGVs bG8t&#10;bW9jaw==</content>
                </file>
            </get_agent_support_bundle_response>"#,
        );

        let parsed =
            GetAgentSupportBundleResponse::from_response(&response).expect("support bundle parses");

        assert_eq!(parsed.file.name, "bundle.tar.gz");
        assert_eq!(
            parsed.file.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(parsed.file.size, Some(10));
        assert_eq!(parsed.file.content, b"hello-mock");
        assert_eq!(parsed.file.encoding.as_deref(), Some("base64"));
    }

    #[test]
    fn rejects_support_bundle_size_mismatch() {
        let response = Response::from(
            r#"<get_agent_support_bundle_response status="200" status_text="OK">
                <file><name>bundle</name><size>11</size><content encoding="base64">aGVsbG8tbW9jaw==</content></file>
            </get_agent_support_bundle_response>"#,
        );

        let error = GetAgentSupportBundleResponse::from_response(&response)
            .expect_err("size mismatch rejected");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, .. } if field == "file.size"
        ));
    }

    #[test]
    fn rejects_malformed_support_bundle_base64() {
        let response = Response::from(
            r#"<get_agent_support_bundle_response status="200" status_text="OK">
                <file><name>bundle</name><content encoding="base64">not-base64***</content></file>
            </get_agent_support_bundle_response>"#,
        );

        let error = GetAgentSupportBundleResponse::from_response(&response)
            .expect_err("invalid base64 rejected");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, .. } if field == "file.content"
        ));
    }

    #[test]
    fn rejects_semantically_incomplete_support_bundle() {
        let response = Response::from(
            r#"<get_agent_support_bundle_response status="200" status_text="OK"><file><content>data</content></file></get_agent_support_bundle_response>"#,
        );

        let error = GetAgentSupportBundleResponse::from_response(&response)
            .expect_err("missing name rejected");

        assert!(matches!(error, ParseError::MissingElement(field) if field == "name"));
    }
}
