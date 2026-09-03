// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Web application target response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_csv_list, parse_document, parse_entity_id, parse_entity_meta,
    parse_entity_ref, status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity,
    ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WebApplicationTarget {
    pub meta: EntityMeta,
    pub urls: Vec<String>,
    pub exclude_urls: Vec<String>,
    pub credential: Option<NamedEntity>,
    pub tasks: Vec<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetWebApplicationTargetsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<WebApplicationTarget>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateWebApplicationTargetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl WebApplicationTarget {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            urls: node
                .optional_child_text("urls")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            exclude_urls: node
                .optional_child_text("exclude_urls")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            credential: parse_entity_ref(node, "credential")?,
            tasks: parse_tasks(node)?,
        })
    }
}

impl GetWebApplicationTargetsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("web_application_target")
            .map(WebApplicationTarget::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "web_application_target_count")?,
        })
    }
}

impl GmpResponse for GetWebApplicationTargetsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateWebApplicationTargetResponse {
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

impl GmpResponse for CreateWebApplicationTargetResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyWebApplicationTargetResponse = ActionResponse;
pub type DeleteWebApplicationTargetResponse = ActionResponse;

fn parse_tasks(node: &XmlNode) -> Result<Vec<NamedEntity>, ParseError> {
    let Some(tasks) = node.child("tasks") else {
        return Ok(Vec::new());
    };
    tasks
        .children_named("task")
        .map(|task| {
            let raw_id = task
                .attr("id")
                .ok_or_else(|| ParseError::MissingElement("tasks.task.id".to_string()))?;
            Ok(NamedEntity {
                id: parse_entity_id(raw_id, "tasks.task.id")?,
                name: task.optional_child_text("name").unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_web_application_targets() {
        let response = Response::from(
            r#"<get_web_application_targets_response status="200" status_text="OK">
                <web_application_target id="web-1">
                    <owner><name>admin</name></owner>
                    <name>Web One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <urls>https://example.com, https://example.com/app, </urls>
                    <exclude_urls>https://example.com/logout</exclude_urls>
                    <credential id="cred-1"><name>HTTP</name></credential>
                    <tasks><task id="task-1"><name>Scan Web</name></task></tasks>
                </web_application_target>
                <web_application_target id="web-2">
                    <name>Web Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </web_application_target>
                <web_application_target_count>2<filtered>2</filtered><page>1</page></web_application_target_count>
            </get_web_application_targets_response>"#,
        );

        let parsed =
            GetWebApplicationTargetsResponse::from_response(&response).expect("targets parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0].urls,
            vec![
                "https://example.com".to_string(),
                "https://example.com/app".to_string()
            ]
        );
        assert_eq!(
            parsed.items[0].exclude_urls,
            vec!["https://example.com/logout".to_string()]
        );
        assert_eq!(
            parsed.items[0]
                .credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("HTTP")
        );
        assert_eq!(parsed.items[0].tasks[0].name, "Scan Web");
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_web_application_targets() {
        let response = Response::from(
            r#"<get_web_application_targets_response status="200" status_text="OK"><web_application_target_count>0<filtered>0</filtered></web_application_target_count></get_web_application_targets_response>"#,
        );

        let parsed =
            GetWebApplicationTargetsResponse::from_response(&response).expect("targets parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_web_application_target_response() {
        let response = Response::from(
            r#"<create_web_application_target_response status="201" status_text="OK, resource created" id="web-1"/>"#,
        );

        let parsed =
            CreateWebApplicationTargetResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "web-1");
    }

    #[test]
    fn rejects_malformed_task_reference() {
        let response = Response::from(
            r#"<get_web_application_targets_response status="200" status_text="OK">
                <web_application_target id="web-1">
                    <name>Web One</name>
                    <tasks><task><name>missing id</name></task></tasks>
                </web_application_target>
            </get_web_application_targets_response>"#,
        );

        let error =
            GetWebApplicationTargetsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(error, ParseError::MissingElement(field) if field == "tasks.task.id"));
    }
}
