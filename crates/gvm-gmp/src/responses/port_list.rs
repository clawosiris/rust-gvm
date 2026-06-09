// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Port-list response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortList {
    pub meta: EntityMeta,
    pub port_count: Option<u32>,
    pub tcp_count: Option<u32>,
    pub udp_count: Option<u32>,
    pub port_range: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetPortListsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<PortList>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreatePortListResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl PortList {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            port_count: optional_u32(node, "port_count", "port_count")?,
            tcp_count: optional_u32(node, "tcp_count", "tcp_count")?,
            udp_count: optional_u32(node, "udp_count", "udp_count")?,
            port_range: node.optional_child_text("port_range"),
        })
    }
}

impl GetPortListsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("port_list")
            .map(PortList::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "port_list_count")?,
        })
    }
}

impl CreatePortListResponse {
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

pub type ModifyPortListResponse = ActionResponse;
pub type DeletePortListResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_port_lists() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK">
                <port_list id="pl-1">
                    <owner><name>admin</name></owner>
                    <name>All TCP</name>
                    <comment>default</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <port_count>65535</port_count>
                    <tcp_count>65535</tcp_count>
                    <udp_count>0</udp_count>
                    <port_range>T:1-65535</port_range>
                </port_list>
                <port_list id="pl-2">
                    <name>UDP</name>
                </port_list>
                <port_list_count>2<filtered>2</filtered><page>1</page></port_list_count>
            </get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].port_count, Some(65535));
        assert_eq!(parsed.items[0].tcp_count, Some(65535));
        assert_eq!(parsed.items[0].udp_count, Some(0));
        assert_eq!(parsed.items[0].port_range.as_deref(), Some("T:1-65535"));
    }

    #[test]
    fn parses_empty_port_lists() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK"><port_list_count>0<filtered>0</filtered></port_list_count></get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_port_list_response() {
        let response = Response::from(
            r#"<create_port_list_response status="201" status_text="OK, resource created" id="pl-1"/>"#,
        );

        let parsed = CreatePortListResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "pl-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_port_lists_response status="500" status_text="Failed"/>"#);

        let error = GetPortListsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Failed"
        ));
    }

    #[test]
    fn parses_missing_optional_port_list_fields() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK">
                <port_list id="pl-1">
                    <name>Only Required</name>
                </port_list>
            </get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");
        let port_list = &parsed.items[0];

        assert_eq!(port_list.meta.comment, None);
        assert_eq!(port_list.port_count, None);
        assert_eq!(port_list.tcp_count, None);
        assert_eq!(port_list.udp_count, None);
        assert_eq!(port_list.port_range, None);
    }
}
