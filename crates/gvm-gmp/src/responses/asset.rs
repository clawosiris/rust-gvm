// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Asset response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta,
    parse_entity_meta_optional_name, parse_u32, status_from_response, ActionResponse, CountInfo,
    EntityMeta, ParseError, XmlNode,
};
use crate::responses::host::Host;
use crate::{EntityId, GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AssetKind {
    Host,
    OperatingSystem,
    TlsCertificate,
    Custom(String),
}

impl AssetKind {
    #[must_use]
    pub fn from_gmp_str(value: &str) -> Self {
        match value {
            "host" => Self::Host,
            "os" => Self::OperatingSystem,
            "tls_certificate" | "tls-cert" | "tls_cert" => Self::TlsCertificate,
            other => Self::Custom(other.to_string()),
        }
    }

    #[must_use]
    pub fn as_gmp_str(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::OperatingSystem => "os",
            Self::TlsCertificate => "tls_certificate",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssetIdentifier {
    pub name: Option<String>,
    pub value: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericAsset {
    pub meta: EntityMeta,
    pub asset_type: Option<AssetKind>,
    pub type_: Option<AssetKind>,
    pub value: Option<String>,
    pub identifiers: Vec<AssetIdentifier>,
    pub severity: Option<String>,
}

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
    pub value: Option<String>,
    pub hosts_count: Option<u32>,
    pub severity: Option<String>,
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
    Generic(GenericAsset),
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
pub struct GetOperatingSystemAssetsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<OperatingSystemAsset>,
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
            .optional_child_text("type")
            .or_else(|| node.optional_child_text("asset_type"))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ParseError::MissingElement("asset.type".to_string()))?;

        match asset_type.as_str() {
            "host" => {
                if node.child("host").is_none() {
                    return Err(ParseError::MissingElement("asset.host".to_string()));
                }
                Host::from_node(node).map(Self::Host)
            }
            "os" => OperatingSystemAsset::from_node(node).map(Self::OperatingSystem),
            _ => GenericAsset::from_node(node).map(Self::Generic),
        }
    }
}

impl GenericAsset {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta_optional_name(node)?,
            asset_type: node
                .optional_child_text("asset_type")
                .map(|value| AssetKind::from_gmp_str(&value)),
            type_: node
                .optional_child_text("type")
                .map(|value| AssetKind::from_gmp_str(&value)),
            value: node.optional_child_text("value"),
            identifiers: parse_identifiers(node),
            severity: parse_generic_severity(node),
        })
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
            value: node
                .optional_child_text("value")
                .or_else(|| node.optional_child_text("name")),
            hosts_count: Some(parse_u32(&hosts.text, "asset.os.hosts.count")?),
            severity: severity_value(os, "latest_severity"),
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

impl GmpResponse for GetAssetsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GetOperatingSystemAssetsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("asset")
            .map(OperatingSystemAsset::from_node)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "asset_count")?,
        })
    }
}

impl GmpResponse for GetOperatingSystemAssetsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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

impl GmpResponse for CreateAssetResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyAssetResponse = ActionResponse;
pub type DeleteAssetResponse = ActionResponse;

fn severity_value(node: &XmlNode, name: &str) -> Option<String> {
    node.child(name)
        .and_then(|severity| severity.optional_child_text("value"))
}

fn parse_identifiers(node: &XmlNode) -> Vec<AssetIdentifier> {
    node.child("identifiers")
        .map(|identifiers| {
            identifiers
                .children_named("identifier")
                .map(|identifier| AssetIdentifier {
                    name: identifier.optional_child_text("name"),
                    value: identifier.optional_child_text("value"),
                    source: identifier.child("source").and_then(|source| {
                        source
                            .optional_child_text("name")
                            .or_else(|| source.optional_child_text("type"))
                            .or_else(|| (!source.text.is_empty()).then(|| source.text.clone()))
                    }),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_generic_severity(node: &XmlNode) -> Option<String> {
    node.child("severity")
        .and_then(|severity| {
            severity
                .optional_child_text("value")
                .or_else(|| (!severity.text.is_empty()).then(|| severity.text.clone()))
        })
        .or_else(|| node.optional_child_text("severity"))
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

    fn as_host(asset: &Asset) -> Option<&Host> {
        match asset {
            Asset::Host(host) => Some(host),
            Asset::OperatingSystem(_) | Asset::Generic(_) => None,
        }
    }

    fn as_operating_system(asset: &Asset) -> Option<&OperatingSystemAsset> {
        match asset {
            Asset::OperatingSystem(os) => Some(os),
            Asset::Host(_) | Asset::Generic(_) => None,
        }
    }

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
        let host = as_host(&parsed.items[0]).expect("expected host asset");
        assert!(as_operating_system(&parsed.items[0]).is_none());
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
        let os = as_operating_system(&parsed.items[0]).expect("expected operating-system asset");
        assert!(as_host(&parsed.items[0]).is_none());
        assert_eq!(os.meta.id.as_str(), "os-1");
        assert_eq!(os.value.as_deref(), Some("cpe:/o:example:linux"));
        assert_eq!(os.hosts_count, Some(2));
        assert_eq!(os.severity.as_deref(), Some("6.1"));
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
    fn rejects_missing_and_invalid_operating_system_host_ids() {
        for host in [
            "<asset><name>192.0.2.10</name></asset>",
            "<asset id=\"not a valid id\"><name>192.0.2.10</name></asset>",
        ] {
            let response = Response::from(
                format!(
                    "<get_assets_response status=\"200\" status_text=\"OK\">\
                     <asset id=\"os-1\"><name>cpe:/o:example:linux</name><type>os</type><os>\
                     <title>Example Linux</title><installs>1</installs><all_installs>1</all_installs>\
                     <hosts>1{host}</hosts></os></asset></get_assets_response>"
                )
                .into_bytes(),
            );

            assert!(GetAssetsResponse::from_response(&response).is_err());
        }
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
    fn rejects_missing_and_empty_asset_types() {
        for asset_xml in [
            "<asset id=\"asset-1\"><name>missing</name></asset>",
            "<asset id=\"asset-1\"><name>empty</name><type></type></asset>",
        ] {
            let response = Response::from(
                format!(
                    "<get_assets_response status=\"200\" status_text=\"OK\">{asset_xml}</get_assets_response>"
                )
                .into_bytes(),
            );
            let error = GetAssetsResponse::from_response(&response).expect_err("type rejected");

            assert!(matches!(
                error,
                ParseError::MissingElement(field) if field == "asset.type"
            ));
        }
    }

    #[test]
    fn preserves_custom_and_tls_asset_types() {
        let response = Response::from(
            r#"<get_assets_response status="200" status_text="OK">
                <asset id="asset-1"><name>Firmware</name><type>firmware</type><value>UEFI</value></asset>
                <asset id="asset-2"><name>Certificate</name><type>tls_certificate</type></asset>
                <asset_count>2<filtered>2</filtered><page>1</page></asset_count>
            </get_assets_response>"#,
        );

        let parsed = GetAssetsResponse::from_response(&response).expect("custom assets parse");
        let Asset::Generic(custom) = &parsed.items[0] else {
            panic!("custom asset should use the forward-compatible model");
        };
        assert_eq!(
            custom.type_,
            Some(AssetKind::Custom("firmware".to_string()))
        );
        assert_eq!(custom.value.as_deref(), Some("UEFI"));

        let Asset::Generic(certificate) = &parsed.items[1] else {
            panic!("TLS certificate should use the generic asset model");
        };
        assert_eq!(certificate.type_, Some(AssetKind::TlsCertificate));
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
