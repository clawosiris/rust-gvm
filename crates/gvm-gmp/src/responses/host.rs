// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Host (asset) response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError, XmlNode,
};
use crate::{EntityId, GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssetSource {
    pub id: Option<EntityId>,
    pub source_type: String,
    pub data: Option<String>,
    pub deleted: Option<bool>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostOperatingSystem {
    pub id: Option<EntityId>,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostIdentifier {
    pub id: Option<EntityId>,
    pub name: String,
    pub value: String,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub source: Option<AssetSource>,
    pub operating_system: Option<HostOperatingSystem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDetail {
    pub name: String,
    pub value: String,
    pub source: Option<AssetSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Host {
    pub meta: EntityMeta,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub severity: Option<String>,
    pub os: Option<String>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub identifiers: Vec<HostIdentifier>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub details: Vec<HostDetail>,
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
    pub(crate) fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let identifiers = node
            .child("identifiers")
            .map(|identifiers| {
                identifiers
                    .children_named("identifier")
                    .map(HostIdentifier::from_node)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let host = node.child("host");
        let details = host
            .map(|host| {
                host.children_named("detail")
                    .map(HostDetail::from_node)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        let ip = identifiers
            .iter()
            .find(|identifier| identifier.name == "ip")
            .map(|identifier| identifier.value.clone())
            .or_else(|| node.optional_child_text("ip"));
        let hostname = identifiers
            .iter()
            .find(|identifier| identifier.name == "hostname")
            .map(|identifier| identifier.value.clone())
            .or_else(|| node.optional_child_text("hostname"));
        let severity = host
            .and_then(|host| host.child("severity"))
            .and_then(|s| {
                s.optional_child_text("value")
                    .or_else(|| (!s.text.is_empty()).then_some(s.text.clone()))
            })
            .or_else(|| {
                node.child("severity").and_then(|severity| {
                    severity
                        .optional_child_text("value")
                        .or_else(|| (!severity.text.is_empty()).then_some(severity.text.clone()))
                })
            });
        let os = identifiers
            .iter()
            .find(|identifier| identifier.name == "OS")
            .and_then(|identifier| identifier.operating_system.as_ref())
            .map(|os| os.title.clone())
            .or_else(|| node.optional_child_text("os"));

        Ok(Self {
            meta: parse_entity_meta(node)?,
            ip,
            hostname,
            severity,
            os,
            identifiers,
            details,
        })
    }
}

impl AssetSource {
    fn from_node(node: &XmlNode, field: &str) -> Result<Self, ParseError> {
        Ok(Self {
            id: optional_node_id(node, &format!("{field}.id"))?,
            source_type: node
                .required_child_text("type")
                .map_err(|_| ParseError::MissingElement(format!("{field}.type")))?,
            data: node.optional_child_text("data"),
            deleted: node
                .optional_child_text("deleted")
                .map(|value| parse_bool(&value, &format!("{field}.deleted")))
                .transpose()?,
            name: node.optional_child_text("name"),
        })
    }
}

impl HostOperatingSystem {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            id: optional_node_id(node, "identifier.os.id")?,
            title: node
                .required_child_text("title")
                .map_err(|_| ParseError::MissingElement("identifier.os.title".to_string()))?,
        })
    }
}

impl HostIdentifier {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            id: optional_node_id(node, "identifier.id")?,
            name: node.required_child_text("name")?,
            value: node.required_child_text("value")?,
            creation_time: node.optional_child_text("creation_time"),
            modification_time: node.optional_child_text("modification_time"),
            source: node
                .child("source")
                .map(|source| AssetSource::from_node(source, "identifier.source"))
                .transpose()?,
            operating_system: node
                .child("os")
                .map(HostOperatingSystem::from_node)
                .transpose()?,
        })
    }
}

impl HostDetail {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            name: node.required_child_text("name")?,
            value: node.required_child_text("value")?,
            source: node
                .child("source")
                .map(|source| AssetSource::from_node(source, "host.detail.source"))
                .transpose()?,
        })
    }
}

fn optional_node_id(node: &XmlNode, field: &str) -> Result<Option<EntityId>, ParseError> {
    node.attr("id")
        .filter(|id| !id.is_empty())
        .map(|id| parse_entity_id(id, field))
        .transpose()
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

impl GmpResponse for GetHostsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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

impl GmpResponse for CreateHostResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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
