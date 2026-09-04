// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Generic config response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConfigUsageKind {
    Scan,
    Audit,
    Policy,
    Custom(String),
}

impl ConfigUsageKind {
    #[must_use]
    pub fn from_gmp_str(value: &str) -> Self {
        match value {
            "scan" => Self::Scan,
            "audit" => Self::Audit,
            "policy" => Self::Policy,
            other => Self::Custom(other.to_string()),
        }
    }

    #[must_use]
    pub fn as_gmp_str(&self) -> &str {
        match self {
            Self::Scan => "scan",
            Self::Audit => "audit",
            Self::Policy => "policy",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericConfig {
    pub meta: EntityMeta,
    pub usage_type: Option<ConfigUsageKind>,
    pub type_: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetConfigsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<GenericConfig>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateConfigResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl GenericConfig {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            usage_type: node
                .optional_child_text("usage_type")
                .map(|value| ConfigUsageKind::from_gmp_str(&value)),
            type_: optional_u32(node, "type", "type")?,
        })
    }
}

impl GetConfigsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("config")
            .map(GenericConfig::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "config_count")?,
        })
    }
}

impl GmpResponse for GetConfigsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateConfigResponse {
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

impl GmpResponse for CreateConfigResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyConfigResponse = ActionResponse;
pub type DeleteConfigResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_generic_config_usage_types_and_counts() {
        let response = Response::from(
            r#"<get_configs_response status="200" status_text="OK">
                <config id="config-1"><name>Full and fast</name><usage_type>scan</usage_type><type>0</type></config>
                <config id="config-2"><name>Policy</name><usage_type>policy</usage_type><type>7</type></config>
                <config id="config-3"><name>Future</name><usage_type>future</usage_type><type>42</type></config>
                <config_count>3<filtered>3</filtered><page>1</page></config_count>
            </get_configs_response>"#,
        );

        let parsed = GetConfigsResponse::from_response(&response).expect("configs parse");

        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.counts.total, Some(3));
        assert_eq!(parsed.items[0].usage_type, Some(ConfigUsageKind::Scan));
        assert_eq!(parsed.items[1].usage_type, Some(ConfigUsageKind::Policy));
        assert_eq!(
            parsed.items[2].usage_type,
            Some(ConfigUsageKind::Custom("future".into()))
        );
        assert_eq!(parsed.items[2].type_, Some(42));
    }

    #[test]
    fn parses_empty_and_create_config_responses() {
        let empty = Response::from(
            r#"<get_configs_response status="200" status_text="OK"><config_count>0<filtered>0</filtered></config_count></get_configs_response>"#,
        );
        assert!(GetConfigsResponse::from_response(&empty)
            .expect("empty parses")
            .items
            .is_empty());

        let created = Response::from(
            r#"<create_config_response status="201" status_text="OK, resource created" id="config-1"/>"#,
        );
        assert_eq!(
            CreateConfigResponse::from_response(&created)
                .expect("create parses")
                .id
                .as_str(),
            "config-1"
        );
    }
}
