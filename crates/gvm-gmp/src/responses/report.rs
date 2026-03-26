// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Report {
    pub meta: EntityMeta,
    pub task: Option<NamedEntity>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub result_count: Option<ResultCount>,
    pub severity: Option<Severity>,
    pub host_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResultCount {
    pub full: Option<u32>,
    pub filtered: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Severity {
    pub full: Option<String>,
    pub filtered: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Report>,
    pub counts: CountInfo,
}

impl Report {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let details = node.child("report");
        Ok(Self {
            meta: parse_entity_meta(node)?,
            task: parse_named_entity(node, "task")?,
            scan_start: details.and_then(|report| report.optional_child_text("scan_start")),
            scan_end: details.and_then(|report| report.optional_child_text("scan_end")),
            result_count: details
                .and_then(|report| report.child("result_count"))
                .map(|count| -> Result<ResultCount, ParseError> {
                    Ok(ResultCount {
                        full: count
                            .optional_child_text("full")
                            .map(|value| {
                                value.parse::<u32>().map_err(|_| ParseError::InvalidValue {
                                    field: "result_count.full".to_string(),
                                    value,
                                })
                            })
                            .transpose()?,
                        filtered: optional_u32(count, "filtered", "result_count.filtered")?,
                    })
                })
                .transpose()?,
            severity: details
                .and_then(|report| report.child("severity"))
                .map(|severity| Severity {
                    full: severity.optional_child_text("full"),
                    filtered: severity.optional_child_text("filtered"),
                }),
            host_count: details
                .and_then(|report| report.child("hosts"))
                .map(|hosts| optional_u32(hosts, "count", "hosts.count"))
                .transpose()?
                .flatten(),
        })
    }
}

impl GetReportsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("report")
            .map(Report::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "report_count")?,
        })
    }
}

pub type DeleteReportResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_reports() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="rpt-1">
                    <owner><name>admin</name></owner>
                    <name>Report 2026-01-15</name>
                    <comment></comment>
                    <creation_time>2026-01-15T10:30:00Z</creation_time>
                    <modification_time>2026-01-15T11:00:00Z</modification_time>
                    <writable>0</writable>
                    <in_use>0</in_use>
                    <task id="task-1"><name>Discovery Scan</name></task>
                    <report id="rpt-1">
                        <scan_start>2026-01-15T10:30:00Z</scan_start>
                        <scan_end>2026-01-15T11:00:00Z</scan_end>
                        <result_count><full>42</full><filtered>42</filtered></result_count>
                        <severity><full>10.0</full><filtered>10.0</filtered></severity>
                        <hosts><count>5</count></hosts>
                    </report>
                </report>
                <report id="rpt-2">
                    <name>Report 2026-01-16</name>
                </report>
                <report_count>2<filtered>2</filtered></report_count>
            </get_reports_response>"#,
        );

        let parsed = GetReportsResponse::from_response(&response).expect("reports parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(
            parsed.items[0].task.as_ref().map(|task| task.name.as_str()),
            Some("Discovery Scan")
        );
        assert_eq!(
            parsed.items[0].scan_start.as_deref(),
            Some("2026-01-15T10:30:00Z")
        );
        assert_eq!(parsed.items[0].host_count, Some(5));
        assert_eq!(
            parsed.items[0]
                .result_count
                .as_ref()
                .and_then(|count| count.full),
            Some(42)
        );
        assert_eq!(parsed.items[1].scan_start, None);
    }

    #[test]
    fn parses_empty_reports() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK"><report_count>0<filtered>0</filtered></report_count></get_reports_response>"#,
        );

        let parsed = GetReportsResponse::from_response(&response).expect("reports parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.filtered, Some(0));
    }

    #[test]
    fn parses_nested_report_details() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="rpt-1">
                    <name>Detailed Report</name>
                    <report id="rpt-1">
                        <scan_start>2026-01-15T10:30:00Z</scan_start>
                        <scan_end>2026-01-15T11:00:00Z</scan_end>
                        <result_count><full>7</full><filtered>3</filtered></result_count>
                        <severity><full>9.8</full><filtered>7.5</filtered></severity>
                        <hosts><count>2</count></hosts>
                    </report>
                </report>
            </get_reports_response>"#,
        );

        let parsed = GetReportsResponse::from_response(&response).expect("reports parse");
        let report = &parsed.items[0];

        assert_eq!(report.scan_end.as_deref(), Some("2026-01-15T11:00:00Z"));
        assert_eq!(
            report
                .result_count
                .as_ref()
                .and_then(|count| count.filtered),
            Some(3)
        );
        assert_eq!(
            report
                .severity
                .as_ref()
                .and_then(|severity| severity.full.as_deref()),
            Some("9.8")
        );
        assert_eq!(report.host_count, Some(2));
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_reports_response status="500" status_text="Backend down"/>"#);

        let error = GetReportsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Backend down"
        ));
    }

    #[test]
    fn parses_missing_optional_report_fields() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="rpt-1">
                    <name>Only Required</name>
                </report>
            </get_reports_response>"#,
        );

        let parsed = GetReportsResponse::from_response(&response).expect("reports parse");
        let report = &parsed.items[0];

        assert_eq!(report.meta.comment, None);
        assert_eq!(report.task, None);
        assert_eq!(report.scan_start, None);
        assert_eq!(report.result_count, None);
        assert_eq!(report.severity, None);
        assert_eq!(report.host_count, None);
    }
}
