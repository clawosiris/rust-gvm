// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Asset response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, parse_u32,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError, XmlNode,
};
use crate::responses::host::Host;
use crate::EntityId;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatingSystemHost {
    pub id: EntityId,
    pub name: String,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatingSystemAsset {
    pub meta: EntityMeta,
    pub title: String,
    pub installs: u32,
    pub all_installs: u32,
    pub latest_severity: Option<String>,
    pub highest_severity: Option<String>,
    pub average_severity: Option<String>,
    pub host_count: u32,
    pub hosts: Vec<OperatingSystemHost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Asset {
    Host(Host),
    OperatingSystem(OperatingSystemAsset),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAssetsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Asset>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateAssetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: Option<EntityId>,
}

impl Asset {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let asset_type = node
            .child_text("type")
            .ok_or_else(|| ParseError::MissingElement("asset.type".to_string()))?;

        match asset_type.as_str() {
            "host" => {
                if node.child("host").is_none() {
                    return Err(ParseError::MissingElement("asset.host".to_string()));
                }
                Host::from_node(node).map(Self::Host)
            }
            "os" => OperatingSystemAsset::from_node(node).map(Self::OperatingSystem),
            value => Err(ParseError::InvalidValue {
                field: "asset.type".to_string(),
                value: value.to_string(),
            }),
        }
    }
}

impl OperatingSystemAsset {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let os = node
            .child("os")
            .ok_or_else(|| ParseError::MissingElement("asset.os".to_string()))?;
        let hosts = os
            .child("hosts")
            .ok_or_else(|| ParseError::MissingElement("asset.os.hosts".to_string()))?;

        Ok(Self {
            meta: parse_entity_meta(node)?,
            title: required_text(os, "title", "asset.os.title")?,
            installs: required_u32(os, "installs", "asset.os.installs")?,
            all_installs: required_u32(os, "all_installs", "asset.os.all_installs")?,
            latest_severity: severity_value(os, "latest_severity"),
            highest_severity: severity_value(os, "highest_severity"),
            average_severity: severity_value(os, "average_severity"),
            host_count: parse_u32(&hosts.text, "asset.os.hosts.count")?,
            hosts: hosts
                .children_named("asset")
                .map(OperatingSystemHost::from_node)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl OperatingSystemHost {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            id: parse_entity_id(
                node.attr("id").ok_or_else(|| {
                    ParseError::MissingElement("asset.os.hosts.asset.id".to_string())
                })?,
                "asset.os.hosts.asset.id",
            )?,
            name: required_text(node, "name", "asset.os.hosts.asset.name")?,
            severity: severity_value(node, "severity"),
        })
    }
}

impl GetAssetsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("asset")
            .map(Asset::from_node)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "asset_count")?,
        })
    }
}

impl CreateAssetResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = root
            .attr("id")
            .map(|id| parse_entity_id(id, "id"))
            .transpose()?;

        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

pub type ModifyAssetResponse = ActionResponse;
pub type DeleteAssetResponse = ActionResponse;

fn severity_value(node: &XmlNode, name: &str) -> Option<String> {
    node.child(name)
        .and_then(|severity| severity.optional_child_text("value"))
}

fn required_text(node: &XmlNode, name: &str, field: &str) -> Result<String, ParseError> {
    node.child_text(name)
        .ok_or_else(|| ParseError::MissingElement(field.to_string()))
}

fn required_u32(node: &XmlNode, name: &str, field: &str) -> Result<u32, ParseError> {
    parse_u32(&required_text(node, name, field)?, field)
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_current_runtime_host_asset() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="host-1">
                    <owner><name>admin</name></owner>
                    <name>192.0.2.10</name>
                    <comment>edge host</comment>
                    <creation_time>2026-07-14T10:00:00Z</creation_time>
                    <modification_time>2026-07-14T11:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <permissions><permission><name>Everything</name></permission></permissions>
                    <identifiers>
                        <identifier id="identifier-ip">
                            <name>ip</name><value>192.0.2.10</value>
                            <creation_time>2026-07-14T10:00:00Z</creation_time>
                            <modification_time>2026-07-14T10:00:00Z</modification_time>
                            <source id="user-1">
                                <type>User</type><data></data><deleted>0</deleted><name>admin</name>
                            </source>
                        </identifier>
                        <identifier id="identifier-hostname">
                            <name>hostname</name><value>edge.example.test</value>
                            <creation_time>2026-07-14T10:00:00Z</creation_time>
                            <modification_time>2026-07-14T10:00:00Z</modification_time>
                            <source id="report-1">
                                <type>Report Host Detail</type><data>hostname</data><deleted>0</deleted><name></name>
                            </source>
                        </identifier>
                        <identifier id="identifier-os">
                            <name>OS</name><value>cpe:/o:example:linux</value>
                            <creation_time>2026-07-14T10:00:00Z</creation_time>
                            <modification_time>2026-07-14T10:00:00Z</modification_time>
                            <source id="report-1">
                                <type>Report Host Detail</type><data>best_os_cpe</data><deleted>0</deleted><name></name>
                            </source>
                            <os id="os-1"><title>Example Linux</title></os>
                        </identifier>
                    </identifiers>
                    <type>host</type>
                    <host>
                        <severity><value>8.4</value></severity>
                        <detail>
                            <name>best_os_cpe</name><value>cpe:/o:example:linux</value>
                            <source id="report-1"><type>Report Host Detail</type></source>
                        </detail>
                        <routes><route><host distance="1" same_source="1"><ip>192.0.2.1</ip></host></route></routes>
                    </host>
                </asset>
                <filters id=""><term>first=1 rows=10</term><keywords></keywords></filters>
                <sort><field>name<order>ascending</order></field></sort>
                <assets start="1" max="10"/>
                <asset_count>1<filtered>1</filtered><page>1</page></asset_count>
            </get_assets_response>"#,
        );

        let parsed = GetAssetsResponse::from_response(&response).expect("asset response parses");
        let Asset::Host(host) = &parsed.items[0] else {
            panic!("expected host asset");
        };

        assert_eq!(host.meta.id.as_str(), "host-1");
        assert_eq!(host.ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(host.hostname.as_deref(), Some("edge.example.test"));
        assert_eq!(host.severity.as_deref(), Some("8.4"));
        assert_eq!(host.os.as_deref(), Some("Example Linux"));
        assert_eq!(host.identifiers.len(), 3);
        assert_eq!(host.details.len(), 1);
        assert_eq!(
            host.details[0]
                .source
                .as_ref()
                .expect("runtime detail should include a source")
                .source_type,
            "Report Host Detail"
        );
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn parses_current_runtime_operating_system_asset() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="os-1">
                    <owner><name>admin</name></owner>
                    <name>cpe:/o:example:linux</name>
                    <comment></comment>
                    <creation_time>2026-07-14T10:00:00Z</creation_time>
                    <modification_time>2026-07-14T11:00:00Z</modification_time>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <permissions><permission><name>get_assets</name></permission></permissions>
                    <type>os</type>
                    <os>
                        <latest_severity><value>6.1</value></latest_severity>
                        <highest_severity><value>9.8</value></highest_severity>
                        <average_severity><value>7.95</value></average_severity>
                        <title>Example Linux</title>
                        <installs>2</installs>
                        <all_installs>3</all_installs>
                        <hosts>2
                            <asset id="host-1"><name>192.0.2.10</name><severity><value>9.8</value></severity></asset>
                            <asset id="host-2"><name>192.0.2.11</name><severity><value>6.1</value></severity></asset>
                        </hosts>
                    </os>
                </asset>
                <assets start="1" max="10"/>
                <asset_count>1<filtered>1</filtered><page>1</page></asset_count>
            </get_assets_response>"#,
        );

        let parsed = GetAssetsResponse::from_response(&response).expect("asset response parses");
        let Asset::OperatingSystem(os) = &parsed.items[0] else {
            panic!("expected operating-system asset");
        };

        assert_eq!(os.meta.id.as_str(), "os-1");
        assert_eq!(os.title, "Example Linux");
        assert_eq!(os.installs, 2);
        assert_eq!(os.all_installs, 3);
        assert_eq!(os.latest_severity.as_deref(), Some("6.1"));
        assert_eq!(os.highest_severity.as_deref(), Some("9.8"));
        assert_eq!(os.average_severity.as_deref(), Some("7.95"));
        assert_eq!(os.host_count, 2);
        assert_eq!(os.hosts.len(), 2);
        assert_eq!(os.hosts[0].id.as_str(), "host-1");
        assert_eq!(os.hosts[0].severity.as_deref(), Some("9.8"));
    }

    #[test]
    fn parses_empty_asset_response() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset_count>0<filtered>0</filtered><page>0</page></asset_count>
            </get_assets_response>"#,
        );

        let parsed = GetAssetsResponse::from_response(&response).expect("empty response parses");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn rejects_server_error() {
        let response = Response::from(
            r#"<get_assets_response status="404" status_text="Failed to find type 'printer'"/>"#,
        );

        let error = GetAssetsResponse::from_response(&response).expect_err("server error expected");

        assert!(matches!(
            error,
            ParseError::ServerError { status: 404, message }
                if message == "Failed to find type 'printer'"
        ));
    }

    #[test]
    fn rejects_missing_empty_and_unknown_asset_types() {
        for (asset_xml, expected_value) in [
            ("<asset id=\"asset-1\"><name>missing</name></asset>", None),
            (
                "<asset id=\"asset-1\"><name>empty</name><type></type></asset>",
                Some(""),
            ),
            (
                "<asset id=\"asset-1\"><name>unknown</name><type>printer</type></asset>",
                Some("printer"),
            ),
        ] {
            let response = Response::from(
                format!(
                    "<get_assets_response status=\"200\" status_text=\"OK\">{asset_xml}</get_assets_response>"
                )
                .into_bytes(),
            );
            let error = GetAssetsResponse::from_response(&response).expect_err("type rejected");

            match expected_value {
                None => assert!(matches!(
                    error,
                    ParseError::MissingElement(field) if field == "asset.type"
                )),
                Some(expected) => assert!(matches!(
                    error,
                    ParseError::InvalidValue { field, value }
                        if field == "asset.type" && value == expected
                )),
            }
        }
    }

    #[test]
    fn rejects_type_payload_mismatch() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="host-1"><name>192.0.2.10</name><type>host</type><os/></asset>
            </get_assets_response>"#,
        );

        let error = GetAssetsResponse::from_response(&response).expect_err("mismatch rejected");

        assert!(matches!(
            error,
            ParseError::MissingElement(field) if field == "asset.host"
        ));
    }

    #[test]
    fn create_asset_id_is_optional_for_report_import() {
        let direct = Response::from(
            r#"<create_asset_response status="201" status_text="OK, resource created" id="host-1"/>"#,
        );
        let report_import = Response::from(
            r#"<create_asset_response status="201" status_text="OK, resource created"/>"#,
        );

        assert_eq!(
            CreateAssetResponse::from_response(&direct)
                .expect("direct create parses")
                .id
                .expect("direct create should include an id")
                .as_str(),
            "host-1"
        );
        assert_eq!(
            CreateAssetResponse::from_response(&report_import)
                .expect("report import parses")
                .id,
            None
        );
    }
}
