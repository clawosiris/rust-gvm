// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Host (asset) response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, status_from_response,
    ActionResponse, CountInfo, EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Host {
    pub meta: EntityMeta,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub severity: Option<String>,
    pub os: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetHostsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Host>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateHostResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Host {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let ip = node
            .child("identifiers")
            .and_then(|ids| {
                ids.children_named("identifier")
                    .find(|id| id.child_text("name").as_deref() == Some("ip"))
                    .and_then(|id| id.optional_child_text("value"))
            })
            .or_else(|| node.optional_child_text("ip"));

        let hostname = node
            .child("identifiers")
            .and_then(|ids| {
                ids.children_named("identifier")
                    .find(|id| id.child_text("name").as_deref() == Some("hostname"))
                    .and_then(|id| id.optional_child_text("value"))
            })
            .or_else(|| node.optional_child_text("hostname"));

        let severity = node
            .child("severity")
            .and_then(|s| {
                s.optional_child_text("value")
                    .or_else(|| (!s.text.is_empty()).then_some(s.text.clone()))
            })
            .or_else(|| node.optional_child_text("severity"));

        Ok(Self {
            meta: parse_entity_meta(node)?,
            ip,
            hostname,
            severity,
            os: node.optional_child_text("os"),
        })
    }
}

impl GetHostsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("asset")
            .map(Host::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "asset_count")?,
        })
    }
}

impl CreateHostResponse {
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

pub type ModifyHostResponse = ActionResponse;
pub type DeleteHostResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_hosts() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="h-1">
                    <owner><name>admin</name></owner>
                    <name>Host One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <identifiers>
                        <identifier>
                            <name>ip</name>
                            <value>192.168.1.1</value>
                        </identifier>
                        <identifier>
                            <name>hostname</name>
                            <value>host1.example.com</value>
                        </identifier>
                    </identifiers>
                    <severity><value>7.5</value></severity>
                    <os>Linux</os>
                </asset>
                <asset id="h-2">
                    <name>Host Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <ip>10.0.0.1</ip>
                </asset>
                <asset_count>2<filtered>2</filtered><page>1</page></asset_count>
            </get_assets_response>"#,
        );

        let parsed = GetHostsResponse::from_response(&response).expect("hosts parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(
            parsed.items[0].hostname.as_deref(),
            Some("host1.example.com")
        );
        assert_eq!(parsed.items[0].severity.as_deref(), Some("7.5"));
        assert_eq!(parsed.items[0].os.as_deref(), Some("Linux"));
        assert_eq!(parsed.items[1].ip.as_deref(), Some("10.0.0.1"));
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_hosts() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK"><asset_count>0<filtered>0</filtered></asset_count></get_assets_response>"#,
        );

        let parsed = GetHostsResponse::from_response(&response).expect("hosts parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_host_response() {
        let response = Response::from(
            r#"<create_asset_response status="201" status_text="OK, resource created" id="h-1"/>"#,
        );

        let parsed = CreateHostResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "h-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_assets_response status="400" status_text="Bad request"/>"#);

        let error = GetHostsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_host_fields() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="h-1">
                    <name>Only Required</name>
                </asset>
            </get_assets_response>"#,
        );

        let parsed = GetHostsResponse::from_response(&response).expect("hosts parse");
        let host = &parsed.items[0];

        assert_eq!(host.meta.comment, None);
        assert_eq!(host.ip, None);
        assert_eq!(host.hostname, None);
        assert_eq!(host.severity, None);
        assert_eq!(host.os, None);
    }
}
