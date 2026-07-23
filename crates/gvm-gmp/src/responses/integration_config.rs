// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration-configuration response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_meta, status_from_response, ActionResponse, CountInfo,
    EntityMeta, ParseError, XmlNode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntegrationConfigService {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntegrationConfigOidc {
    pub url: String,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntegrationConfig {
    pub meta: EntityMeta,
    pub service: Option<IntegrationConfigService>,
    pub oidc: Option<IntegrationConfigOidc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetIntegrationConfigsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<IntegrationConfig>,
    pub counts: CountInfo,
}

impl IntegrationConfigService {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            url: node.required_child_text("url")?,
        })
    }
}

impl IntegrationConfigOidc {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let client = node
            .child("client")
            .ok_or_else(|| ParseError::MissingElement("oidc.client".to_string()))?;
        Ok(Self {
            url: node.required_child_text("url")?,
            client_id: client.required_child_text("id")?,
        })
    }
}

impl IntegrationConfig {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            service: node
                .child("service")
                .map(IntegrationConfigService::from_node)
                .transpose()?,
            oidc: node
                .child("oidc")
                .map(IntegrationConfigOidc::from_node)
                .transpose()?,
        })
    }
}

impl GetIntegrationConfigsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("integration_config")
            .map(IntegrationConfig::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "integration_config_count")?,
        })
    }
}

pub type ModifyIntegrationConfigResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_detailed_integration_config() {
        let response = Response::from(
            r#"<get_integration_configs_response status="200" status_text="OK">
                <integration_config id="ic-1">
                    <owner><name>admin</name></owner>
                    <name>Security Intelligence</name>
                    <comment>Primary integration</comment>
                    <creation_time>2026-03-20T15:21:22Z</creation_time>
                    <modification_time>2026-03-20T15:27:56Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <service><url>https://service.example</url></service>
                    <oidc>
                        <url>https://oidc.example</url>
                        <client><id>client-id</id></client>
                    </oidc>
                </integration_config>
                <integration_config_count>1<filtered>1</filtered><page>1</page></integration_config_count>
            </get_integration_configs_response>"#,
        );

        let parsed =
            GetIntegrationConfigsResponse::from_response(&response).expect("response parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.counts.total, Some(1));
        assert_eq!(parsed.items[0].meta.name, "Security Intelligence");
        assert_eq!(
            parsed.items[0]
                .service
                .as_ref()
                .map(|service| service.url.as_str()),
            Some("https://service.example")
        );
        assert_eq!(
            parsed.items[0]
                .oidc
                .as_ref()
                .map(|oidc| oidc.client_id.as_str()),
            Some("client-id")
        );
    }

    #[test]
    fn parses_summary_and_empty_list_responses() {
        let summary = Response::from(
            r#"<get_integration_configs_response status="200" status_text="OK">
                <integration_config id="ic-1"><name>Summary</name></integration_config>
            </get_integration_configs_response>"#,
        );
        let parsed =
            GetIntegrationConfigsResponse::from_response(&summary).expect("summary parses");
        assert_eq!(parsed.items.len(), 1);
        assert!(parsed.items[0].service.is_none());
        assert!(parsed.items[0].oidc.is_none());
        assert_eq!(parsed.counts, CountInfo::default());

        let empty = Response::from(
            r#"<get_integration_configs_response status="200" status_text="OK"><integration_config_count>0<filtered>0</filtered><page>0</page></integration_config_count></get_integration_configs_response>"#,
        );
        let parsed = GetIntegrationConfigsResponse::from_response(&empty).expect("empty parses");
        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn rejects_incomplete_details_and_server_errors() {
        let incomplete = Response::from(
            r#"<get_integration_configs_response status="200" status_text="OK"><integration_config id="ic-1"><name>Broken</name><oidc><url>https://oidc.example</url></oidc></integration_config></get_integration_configs_response>"#,
        );
        assert!(matches!(
            GetIntegrationConfigsResponse::from_response(&incomplete),
            Err(ParseError::MissingElement(field)) if field == "oidc.client"
        ));

        let error = Response::from(
            r#"<get_integration_configs_response status="404" status_text="Not found"/>"#,
        );
        assert!(matches!(
            GetIntegrationConfigsResponse::from_response(&error),
            Err(ParseError::ServerError {
                status: 404,
                message
            }) if message == "Not found"
        ));
    }

    #[test]
    fn parses_modify_response() {
        let response = Response::from(
            r#"<modify_integration_config_response status="200" status_text="OK"/>"#,
        );
        let parsed = ModifyIntegrationConfigResponse::from_response(&response)
            .expect("modify response parses");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
    }
}
