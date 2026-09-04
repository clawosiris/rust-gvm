// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report config response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportConfig {
    pub meta: EntityMeta,
    pub report_format: Option<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportConfigsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportConfig>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateReportConfigResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl ReportConfig {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            report_format: parse_named_entity(node, "report_format")?,
        })
    }
}

impl GetReportConfigsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("report_config")
            .map(ReportConfig::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "report_config_count")?,
        })
    }
}

impl CreateReportConfigResponse {
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

impl GmpResponse for GetReportConfigsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GmpResponse for CreateReportConfigResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyReportConfigResponse = ActionResponse;
pub type DeleteReportConfigResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_report_configs() {
        let response = Response::from(
            r#"<get_report_configs_response status="200" status_text="OK">
                <report_config id="rc-1">
                    <owner><name>admin</name></owner>
                    <name>Config One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <report_format id="rf-1"><name>HTML</name></report_format>
                </report_config>
                <report_config id="rc-2">
                    <name>Config Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </report_config>
                <report_config_count>2<filtered>2</filtered><page>1</page></report_config_count>
            </get_report_configs_response>"#,
        );

        let parsed =
            GetReportConfigsResponse::from_response(&response).expect("report_configs parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0]
                .report_format
                .as_ref()
                .map(|rf| rf.name.as_str()),
            Some("HTML")
        );
        assert_eq!(
            parsed.items[0]
                .report_format
                .as_ref()
                .map(|rf| rf.id.as_str()),
            Some("rf-1")
        );
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_report_configs() {
        let response = Response::from(
            r#"<get_report_configs_response status="200" status_text="OK"><report_config_count>0<filtered>0</filtered></report_config_count></get_report_configs_response>"#,
        );

        let parsed =
            GetReportConfigsResponse::from_response(&response).expect("report_configs parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_report_config_response() {
        let response = Response::from(
            r#"<create_report_config_response status="201" status_text="OK, resource created" id="rc-1"/>"#,
        );

        let parsed = CreateReportConfigResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "rc-1");
    }

    #[test]
    fn rejects_server_error() {
        let response = Response::from(
            r#"<get_report_configs_response status="400" status_text="Bad request"/>"#,
        );

        let error = GetReportConfigsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_report_config_fields() {
        let response = Response::from(
            r#"<get_report_configs_response status="200" status_text="OK">
                <report_config id="rc-1">
                    <name>Only Required</name>
                </report_config>
            </get_report_configs_response>"#,
        );

        let parsed =
            GetReportConfigsResponse::from_response(&response).expect("report_configs parse");
        let rc = &parsed.items[0];

        assert_eq!(rc.meta.comment, None);
        assert_eq!(rc.report_format, None);
    }
}
