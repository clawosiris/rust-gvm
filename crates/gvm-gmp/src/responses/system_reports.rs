// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-report response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemReport {
    pub name: String,
    pub title: Option<String>,
    pub report: Option<String>,
    pub report_format: Option<String>,
    pub report_duration: Option<u64>,
    pub report_start_time: Option<String>,
    pub report_end_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetSystemReportsResponse {
    pub status: u16,
    pub status_text: String,
    pub reports: Vec<SystemReport>,
}

impl SystemReport {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let name = node.required_child_text("name")?;
        let title = node.optional_child_text("title");
        let report_node = node.child("report");
        let report = report_node
            .map(|report| report.text.clone())
            .filter(|content| !content.is_empty());
        let report_format = report_node
            .and_then(|report| report.attr("format"))
            .map(ToString::to_string);
        let report_duration = report_node
            .and_then(|report| report.attr("duration"))
            .filter(|duration| !duration.is_empty())
            .map(|duration| {
                duration.parse().map_err(|_| ParseError::InvalidValue {
                    field: "system_report.report.duration".to_string(),
                    value: duration.to_string(),
                })
            })
            .transpose()?;
        let report_start_time = report_node
            .and_then(|report| report.attr("start_time"))
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let report_end_time = report_node
            .and_then(|report| report.attr("end_time"))
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        Ok(Self {
            name,
            title,
            report,
            report_format,
            report_duration,
            report_start_time,
            report_end_time,
        })
    }
}

impl GetSystemReportsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let reports = root
            .children_named("system_report")
            .map(SystemReport::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            reports,
        })
    }
}

impl GmpResponse for GetSystemReportsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_system_reports_response() {
        let response = Response::from(
            r#"<get_system_reports_response status="200" status_text="OK">
                <system_report>
                    <name>load</name>
                    <title>System Load</title>
                    <report format="txt" start_time="2026-07-23T12:00:00Z"
                            end_time="2026-07-23T13:00:00Z" duration="">TG9hZDogMC41</report>
                </system_report>
                <system_report>
                    <name>mem</name>
                    <title>Memory Usage</title>
                </system_report>
            </get_system_reports_response>"#,
        );

        let parsed =
            GetSystemReportsResponse::from_response(&response).expect("parse system reports");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.reports.len(), 2);
        assert_eq!(parsed.reports[0].name, "load");
        assert_eq!(parsed.reports[0].title.as_deref(), Some("System Load"));
        assert_eq!(parsed.reports[0].report.as_deref(), Some("TG9hZDogMC41"));
        assert_eq!(parsed.reports[0].report_format.as_deref(), Some("txt"));
        assert_eq!(parsed.reports[0].report_duration, None);
        assert_eq!(
            parsed.reports[0].report_start_time.as_deref(),
            Some("2026-07-23T12:00:00Z")
        );
        assert_eq!(
            parsed.reports[0].report_end_time.as_deref(),
            Some("2026-07-23T13:00:00Z")
        );
        assert!(parsed.reports[1].report.is_none());
        assert_eq!(parsed.reports[1].report_format, None);
        assert_eq!(parsed.reports[1].report_duration, None);
        assert_eq!(parsed.reports[1].report_start_time, None);
        assert_eq!(parsed.reports[1].report_end_time, None);
    }

    #[test]
    fn parses_empty_system_reports() {
        let response =
            Response::from(r#"<get_system_reports_response status="200" status_text="OK"/>"#);

        let parsed = GetSystemReportsResponse::from_response(&response).expect("parse");

        assert!(parsed.reports.is_empty());
    }

    #[test]
    fn rejects_invalid_report_duration() {
        let response = Response::from(
            r#"<get_system_reports_response status="200" status_text="OK">
                <system_report>
                    <name>load</name>
                    <title>System Load</title>
                    <report format="png" duration="invalid">cG5n</report>
                </system_report>
            </get_system_reports_response>"#,
        );

        assert!(matches!(
            GetSystemReportsResponse::from_response(&response),
            Err(ParseError::InvalidValue { field, value })
                if field == "system_report.report.duration" && value == "invalid"
        ));
    }
}
