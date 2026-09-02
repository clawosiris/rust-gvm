// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Scan-config response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanConfig {
    pub meta: EntityMeta,
    pub usage_type: Option<String>,
    pub type_: Option<u32>,
    pub family_count: Option<u32>,
    pub nvt_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetScanConfigsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ScanConfig>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateScanConfigResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

/// NVT metadata attached to a configured preference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanConfigPreferenceNvt {
    /// NVT object identifier.
    pub oid: String,
    /// Optional NVT name.
    pub name: Option<String>,
}

/// A default or configured NVT/scanner preference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanConfigPreference {
    /// NVT metadata, present for configuration-scoped preference responses.
    pub nvt: Option<ScanConfigPreferenceNvt>,
    /// Preference name.
    pub name: String,
    /// Optional preference identifier.
    pub id: Option<String>,
    /// Optional preference type.
    pub type_: Option<String>,
    /// Optional configured or default value.
    pub value: Option<String>,
    /// Alternate allowed values in wire order.
    pub alternatives: Vec<String>,
    /// Optional default value.
    pub default: Option<String>,
}

/// Typed response for `get_preferences` requests owned by scan configs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetScanConfigPreferencesResponse {
    /// GMP response status.
    pub status: u16,
    /// GMP response status text.
    pub status_text: String,
    /// Returned preferences in wire order.
    pub items: Vec<ScanConfigPreference>,
}

impl ScanConfig {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            usage_type: node.optional_child_text("usage_type"),
            type_: optional_u32(node, "type", "type")?,
            family_count: optional_u32(node, "family_count", "family_count")?,
            nvt_count: optional_u32(node, "nvt_count", "nvt_count")?,
        })
    }
}

impl GetScanConfigsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("config")
            .map(ScanConfig::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "config_count")?,
        })
    }
}

impl GmpResponse for GetScanConfigsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateScanConfigResponse {
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

impl GmpResponse for CreateScanConfigResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl ScanConfigPreference {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let nvt = node
            .child("nvt")
            .map(|nvt| {
                let oid = nvt
                    .attr("oid")
                    .filter(|oid| !oid.is_empty())
                    .ok_or_else(|| ParseError::MissingElement("preference.nvt.oid".to_string()))?;
                Ok::<_, ParseError>(ScanConfigPreferenceNvt {
                    oid: oid.to_string(),
                    name: nvt.optional_child_text("name"),
                })
            })
            .transpose()?;
        Ok(Self {
            nvt,
            name: node
                .required_child_text("name")
                .map_err(|_| ParseError::MissingElement("preference.name".to_string()))?,
            id: node.optional_child_text("id"),
            type_: node.optional_child_text("type"),
            value: node.child("value").map(|value| value.text.clone()),
            alternatives: node
                .children_named("alt")
                .map(|alt| alt.text.clone())
                .collect(),
            default: node.child("default").map(|default| default.text.clone()),
        })
    }
}

impl GetScanConfigPreferencesResponse {
    /// Parse a typed preference response.
    ///
    /// # Errors
    /// Returns an error for a non-success status or malformed preference XML.
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("preference")
            .map(ScanConfigPreference::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
        })
    }
}

impl GmpResponse for GetScanConfigPreferencesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyScanConfigResponse = ActionResponse;
pub type DeleteScanConfigResponse = ActionResponse;
pub type SyncConfigResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_scan_configs() {
        let response = Response::from(
            r#"<get_configs_response status="200" status_text="OK">
                <config id="cfg-1">
                    <owner><name>admin</name></owner>
                    <name>Full and fast</name>
                    <comment>Most NVT families enabled</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <usage_type>scan</usage_type>
                    <type>0</type>
                    <family_count>12<growing>1</growing></family_count>
                    <nvt_count>74231<growing>0</growing></nvt_count>
                </config>
                <config id="cfg-2">
                    <name>Policy</name>
                    <usage_type>policy</usage_type>
                    <type>7</type>
                </config>
                <config_count>2<filtered>2</filtered><page>1</page></config_count>
            </get_configs_response>"#,
        );

        let parsed = GetScanConfigsResponse::from_response(&response).expect("configs parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.items[0].usage_type.as_deref(), Some("scan"));
        assert_eq!(parsed.items[1].usage_type.as_deref(), Some("policy"));
        assert_eq!(parsed.items[0].type_, Some(0));
        assert_eq!(parsed.items[1].type_, Some(7));
        assert_eq!(parsed.items[0].family_count, Some(12));
        assert_eq!(parsed.items[0].nvt_count, Some(74_231));
        assert_eq!(parsed.items[1].family_count, None);
        assert_eq!(parsed.items[1].nvt_count, None);
    }

    #[test]
    fn parses_empty_scan_configs() {
        let response = Response::from(
            r#"<get_configs_response status="200" status_text="OK"><config_count>0<filtered>0</filtered></config_count></get_configs_response>"#,
        );

        let parsed = GetScanConfigsResponse::from_response(&response).expect("configs parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.filtered, Some(0));
    }

    #[test]
    fn parses_create_scan_config_response() {
        let response = Response::from(
            r#"<create_config_response status="201" status_text="OK, resource created" id="cfg-1"/>"#,
        );

        let parsed = CreateScanConfigResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "cfg-1");
    }

    #[test]
    fn parses_default_and_configured_preferences() {
        let response = Response::from(
            r#"<get_preferences_response status="200" status_text="OK">
                <preference>
                    <name>1.3.6.1:1:entry:Timeout :</name>
                    <value>5</value>
                    <alt>10</alt><alt>20</alt><default>5</default>
                </preference>
                <preference>
                    <nvt oid="1.3.6.1"><name>Services</name></nvt>
                    <id>1</id><name>Timeout :</name><type>entry</type><value></value>
                </preference>
            </get_preferences_response>"#,
        );

        let parsed =
            GetScanConfigPreferencesResponse::from_response(&response).expect("preferences parse");
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].value.as_deref(), Some("5"));
        assert_eq!(parsed.items[0].alternatives, ["10", "20"]);
        assert_eq!(parsed.items[0].default.as_deref(), Some("5"));
        assert_eq!(
            parsed.items[1].nvt.as_ref().map(|nvt| nvt.oid.as_str()),
            Some("1.3.6.1")
        );
        assert_eq!(
            parsed.items[1]
                .nvt
                .as_ref()
                .and_then(|nvt| nvt.name.as_deref()),
            Some("Services")
        );
        assert_eq!(parsed.items[1].value.as_deref(), Some(""));
    }

    #[test]
    fn rejects_preference_nvt_without_oid() {
        let response = Response::from(
            r#"<get_preferences_response status="200" status_text="OK">
                <preference><nvt><name>Services</name></nvt><name>Timeout</name></preference>
            </get_preferences_response>"#,
        );

        let error = GetScanConfigPreferencesResponse::from_response(&response)
            .expect_err("missing NVT OID must fail");
        assert!(
            matches!(error, ParseError::MissingElement(field) if field == "preference.nvt.oid")
        );
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_configs_response status="404" status_text="Not Found"/>"#);

        let error = GetScanConfigsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 404,
                message
            } if message == "Not Found"
        ));
    }

    #[test]
    fn parses_missing_optional_scan_config_fields() {
        let response = Response::from(
            r#"<get_configs_response status="200" status_text="OK">
                <config id="cfg-1">
                    <name>Only Required</name>
                </config>
            </get_configs_response>"#,
        );

        let parsed = GetScanConfigsResponse::from_response(&response).expect("configs parse");
        let config = &parsed.items[0];

        assert_eq!(config.meta.comment, None);
        assert_eq!(config.usage_type, None);
        assert_eq!(config.type_, None);
        assert_eq!(config.family_count, None);
        assert_eq!(config.nvt_count, None);
        assert!(!config.meta.in_use);
    }

    #[test]
    fn rejects_invalid_scan_config_counts() {
        for (element, field) in [
            ("<family_count>many</family_count>", "family_count"),
            ("<nvt_count>many</nvt_count>", "nvt_count"),
        ] {
            let xml = format!(
                r#"<get_configs_response status="200" status_text="OK">
                    <config id="cfg-1"><name>Invalid</name>{element}</config>
                </get_configs_response>"#
            );
            let response = Response::from(xml.as_str());

            let error =
                GetScanConfigsResponse::from_response(&response).expect_err("count must fail");
            assert!(
                matches!(error, ParseError::InvalidValue { field: actual, value }
                    if actual == field && value == "many")
            );
        }
    }

    #[test]
    fn parses_known_and_unknown_scan_config_types() {
        let response = Response::from(
            r#"<get_configs_response status="200" status_text="OK">
                <config id="cfg-1"><name>OpenVAS</name><type>0</type></config>
                <config id="cfg-2"><name>OSP</name><type>1</type></config>
                <config id="cfg-3"><name>Future</name><type>42</type></config>
            </get_configs_response>"#,
        );

        let parsed = GetScanConfigsResponse::from_response(&response).expect("configs parse");

        assert_eq!(parsed.items[0].type_, Some(0));
        assert_eq!(parsed.items[1].type_, Some(1));
        assert_eq!(parsed.items[2].type_, Some(42));
    }
}
