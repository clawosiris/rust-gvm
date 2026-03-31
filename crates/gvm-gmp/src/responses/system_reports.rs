// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-report response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemReport {
    pub name: String,
    pub title: Option<String>,
    pub report: Option<String>,
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
        let report = node.optional_child_text("report");
        Ok(Self {
            name,
            title,
            report,
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
                    <report>Load: 0.5</report>
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
        assert_eq!(parsed.reports[0].report.as_deref(), Some("Load: 0.5"));
        assert!(parsed.reports[1].report.is_none());
    }

    #[test]
    fn parses_empty_system_reports() {
        let response =
            Response::from(r#"<get_system_reports_response status="200" status_text="OK"/>"#);

        let parsed = GetSystemReportsResponse::from_response(&response).expect("parse");

        assert!(parsed.reports.is_empty());
    }
}
