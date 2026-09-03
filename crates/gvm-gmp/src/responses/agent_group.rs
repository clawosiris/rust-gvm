// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Agent group response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, status_from_response,
    ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AgentGroup {
    pub meta: EntityMeta,
    pub scheduler_cron_time: Option<String>,
    pub agents: Vec<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAgentGroupsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<AgentGroup>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateAgentGroupResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl AgentGroup {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            scheduler_cron_time: node.optional_child_text("scheduler_cron_time"),
            agents: parse_agents(node)?,
        })
    }
}

impl GetAgentGroupsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("agent_group")
            .map(AgentGroup::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "agent_group_count")?,
        })
    }
}

impl GmpResponse for GetAgentGroupsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateAgentGroupResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

impl GmpResponse for CreateAgentGroupResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

fn parse_agents(node: &XmlNode) -> Result<Vec<NamedEntity>, ParseError> {
    let Some(agents) = node.child("agents") else {
        return Ok(Vec::new());
    };
    agents
        .children_named("agent")
        .map(|agent| {
            let raw_id = agent
                .attr("id")
                .ok_or_else(|| ParseError::MissingElement("agents.agent.id".to_string()))?;
            Ok(NamedEntity {
                id: parse_entity_id(raw_id, "agents.agent.id")?,
                name: agent.optional_child_text("name").unwrap_or_default(),
            })
        })
        .collect()
}

pub type CloneAgentGroupResponse = CreateAgentGroupResponse;
pub type ModifyAgentGroupResponse = ActionResponse;
pub type DeleteAgentGroupResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_agent_groups() {
        let response = Response::from(
            r#"<get_agent_groups_response status="200" status_text="OK">
                <agent_group id="group-1">
                    <owner><name>admin</name></owner>
                    <name>Group One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <scheduler_cron_time>0 */5 * * *</scheduler_cron_time>
                    <agents>
                        <agent id="agent-1"><name>Agent One</name></agent>
                        <agent id="agent-2"><name>Agent Two</name></agent>
                    </agents>
                </agent_group>
                <agent_group id="group-2"><name>Group Two</name></agent_group>
                <agent_group_count>2<filtered>2</filtered><page>1</page></agent_group_count>
            </get_agent_groups_response>"#,
        );

        let parsed = GetAgentGroupsResponse::from_response(&response).expect("agent groups parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].meta.name, "Group One");
        assert_eq!(
            parsed.items[0].scheduler_cron_time.as_deref(),
            Some("0 */5 * * *")
        );
        assert_eq!(parsed.items[0].agents.len(), 2);
        assert_eq!(parsed.items[0].agents[0].name, "Agent One");
        assert!(parsed.items[1].agents.is_empty());
    }

    #[test]
    fn parses_empty_agent_groups() {
        let response = Response::from(
            r#"<get_agent_groups_response status="200" status_text="OK"><agent_group_count>0<filtered>0</filtered></agent_group_count></get_agent_groups_response>"#,
        );

        let parsed = GetAgentGroupsResponse::from_response(&response).expect("agent groups parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_agent_group_response() {
        let response = Response::from(
            r#"<create_agent_group_response status="201" status_text="OK, resource created" id="group-1"/>"#,
        );

        let parsed = CreateAgentGroupResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "group-1");
    }

    #[test]
    fn rejects_agent_without_id() {
        let response = Response::from(
            r#"<get_agent_groups_response status="200" status_text="OK">
                <agent_group id="group-1"><name>Group</name><agents><agent><name>Agent</name></agent></agents></agent_group>
            </get_agent_groups_response>"#,
        );

        let error =
            GetAgentGroupsResponse::from_response(&response).expect_err("missing id rejected");

        assert!(matches!(
            error,
            ParseError::MissingElement(field) if field == "agents.agent.id"
        ));
    }
}
