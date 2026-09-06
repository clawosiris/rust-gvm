// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report format response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportFormat {
    pub meta: EntityMeta,
    pub content_type: Option<String>,
    pub extension: Option<String>,
    pub summary: Option<String>,
    pub trust: Option<String>,
    pub active: bool,
    pub predefined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportFormatsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportFormat>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateReportFormatResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl ReportFormat {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            content_type: node.optional_child_text("content_type"),
            extension: node.optional_child_text("extension"),
            summary: node.optional_child_text("summary"),
            trust: node.optional_child_text("trust"),
            active: node
                .optional_child_text("active")
                .map(|value| parse_bool(&value, "active"))
                .transpose()?
                .unwrap_or(false),
            predefined: node
                .optional_child_text("predefined")
                .map(|value| parse_bool(&value, "predefined"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetReportFormatsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("report_format")
            .map(ReportFormat::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "report_format_count")?,
        })
    }
}

impl CreateReportFormatResponse {
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

impl GmpResponse for GetReportFormatsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GmpResponse for CreateReportFormatResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyReportFormatResponse = ActionResponse;
pub type DeleteReportFormatResponse = ActionResponse;
pub type VerifyReportFormatResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_report_formats() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="rf-1">
                    <owner><name>admin</name></owner>
                    <name>Format One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <content_type>text/html</content_type>
                    <extension>html</extension>
                    <summary>HTML Report</summary>
                    <trust>yes</trust>
                    <active>1</active>
                    <predefined>1</predefined>
                </report_format>
                <report_format id="rf-2">
                    <name>Format Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <active>0</active>
                    <predefined>0</predefined>
                </report_format>
                <report_format_count>2<filtered>2</filtered><page>1</page></report_format_count>
            </get_report_formats_response>"#,
        );

        let parsed =
            GetReportFormatsResponse::from_response(&response).expect("report_formats parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].content_type.as_deref(), Some("text/html"));
        assert_eq!(parsed.items[0].extension.as_deref(), Some("html"));
        assert_eq!(parsed.items[0].summary.as_deref(), Some("HTML Report"));
        assert_eq!(parsed.items[0].trust.as_deref(), Some("yes"));
        assert!(parsed.items[0].active);
        assert!(parsed.items[0].predefined);
        assert!(!parsed.items[1].active);
        assert!(!parsed.items[1].predefined);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_report_formats() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK"><report_format_count>0<filtered>0</filtered></report_format_count></get_report_formats_response>"#,
        );

        let parsed =
            GetReportFormatsResponse::from_response(&response).expect("report_formats parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_report_format_response() {
        let response = Response::from(
            r#"<create_report_format_response status="201" status_text="OK, resource created" id="rf-1"/>"#,
        );

        let parsed = CreateReportFormatResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "rf-1");
    }

    #[test]
    fn rejects_server_error() {
        let response = Response::from(
            r#"<get_report_formats_response status="400" status_text="Bad request"/>"#,
        );

        let error = GetReportFormatsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_report_format_fields() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="rf-1">
                    <name>Only Required</name>
                </report_format>
            </get_report_formats_response>"#,
        );

        let parsed =
            GetReportFormatsResponse::from_response(&response).expect("report_formats parse");
        let rf = &parsed.items[0];

        assert_eq!(rf.meta.comment, None);
        assert_eq!(rf.content_type, None);
        assert_eq!(rf.extension, None);
        assert_eq!(rf.summary, None);
        assert_eq!(rf.trust, None);
        assert!(!rf.active);
        assert!(!rf.predefined);
    }
}
