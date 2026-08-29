// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Structured scan-report response models.

use gvm_protocol::Response;

use crate::responses::audit_report::{
    nested_optional_u32, parse_filter, parse_page, parse_sort, parse_task, ReportFilter,
    ReportPage, ReportSort, StructuredReportResourceCounts, StructuredReportTask,
};
use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_meta, parse_u32, status_from_response,
    CountInfo, EntityMeta, ParseError, XmlNode,
};
use crate::responses::report::{Severity, SeverityCount};

/// Full and filtered result counts from a structured vulnerability report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanReportResultCount {
    pub total: Option<u32>,
    pub full: Option<u32>,
    pub filtered: Option<u32>,
    pub critical: Option<SeverityCount>,
    pub high: Option<SeverityCount>,
    pub medium: Option<SeverityCount>,
    pub low: Option<SeverityCount>,
    pub log: Option<SeverityCount>,
    pub false_positive: Option<SeverityCount>,
}

/// A structured vulnerability-report summary.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanReport {
    pub meta: EntityMeta,
    pub scan_run_status: Option<String>,
    pub resources: StructuredReportResourceCounts,
    pub task: Option<StructuredReportTask>,
    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub timezone: Option<String>,
    pub timezone_abbrev: Option<String>,
    pub result_count: Option<ScanReportResultCount>,
    pub severity: Option<Severity>,
}

/// Typed `get_scan_report` response.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetScanReportResponse {
    pub status: u16,
    pub status_text: String,
    pub report: ScanReport,
    pub filter: Option<ReportFilter>,
    pub sort: Option<ReportSort>,
    pub page: ReportPage,
    pub counts: CountInfo,
}

impl GetScanReportResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let report = root
            .child("report")
            .ok_or_else(|| ParseError::MissingElement("report".to_string()))
            .and_then(ScanReport::from_node)?;
        Ok(Self {
            status,
            status_text,
            report,
            filter: parse_filter(&root)?,
            sort: parse_sort(&root),
            page: parse_page(&root, "scan_report")?,
            counts: count_info(&root, "scan_report_count")?,
        })
    }
}

impl ScanReport {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            scan_run_status: node.optional_child_text("scan_run_status"),
            resources: StructuredReportResourceCounts {
                hosts: nested_optional_u32(node, "hosts", "count")?,
                closed_cves: nested_optional_u32(node, "closed_cves", "count")?,
                cves: nested_optional_u32(node, "cves", "count")?,
                vulnerabilities: nested_optional_u32(node, "vulns", "count")?,
                operating_systems: nested_optional_u32(node, "os", "count")?,
                applications: nested_optional_u32(node, "apps", "count")?,
                tls_certificates: nested_optional_u32(node, "ssl_certs", "count")?,
                ports: nested_optional_u32(node, "ports", "count")?,
                errors: nested_optional_u32(node, "errors", "count")?,
            },
            task: node.child("task").map(parse_task).transpose()?,
            timestamp: node.optional_child_text("timestamp"),
            scan_start: node.optional_child_text("scan_start"),
            scan_end: node.optional_child_text("scan_end"),
            timezone: node.optional_child_text("timezone"),
            timezone_abbrev: node.optional_child_text("timezone_abbrev"),
            result_count: node
                .child("result_count")
                .map(parse_result_count)
                .transpose()?,
            severity: node.child("severity").map(|severity| Severity {
                full: severity.optional_child_text("full"),
                filtered: severity.optional_child_text("filtered"),
            }),
        })
    }
}

fn parse_result_count(node: &XmlNode) -> Result<ScanReportResultCount, ParseError> {
    Ok(ScanReportResultCount {
        total: (!node.text.is_empty())
            .then(|| parse_u32(&node.text, "result_count"))
            .transpose()?,
        full: optional_u32(node, "full", "result_count.full")?,
        filtered: optional_u32(node, "filtered", "result_count.filtered")?,
        critical: parse_severity_count(node, "critical", None)?,
        high: parse_severity_count(node, "high", Some("hole"))?,
        medium: parse_severity_count(node, "medium", Some("warning"))?,
        low: parse_severity_count(node, "low", Some("info"))?,
        log: parse_severity_count(node, "log", None)?,
        false_positive: parse_severity_count(node, "false_positive", None)?,
    })
}

fn parse_severity_count(
    node: &XmlNode,
    canonical: &str,
    alias: Option<&str>,
) -> Result<Option<SeverityCount>, ParseError> {
    let Some(bucket) = node
        .child(canonical)
        .or_else(|| alias.and_then(|name| node.child(name)))
    else {
        return Ok(None);
    };
    Ok(Some(SeverityCount {
        full: optional_u32(bucket, "full", &format!("result_count.{canonical}.full"))?,
        filtered: optional_u32(
            bucket,
            "filtered",
            &format!("result_count.{canonical}.filtered"),
        )?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_gvmd_scan_report_example() {
        // Copied from greenbone/gvmd GMP.xml.in at
        // 55e5d4c657c48ce52ee340c2439680418bfe1a4d.
        let parsed = GetScanReportResponse::from_response(&Response::from(include_str!(
            "../../tests/data/get_scan_report.xml"
        )))
        .expect("upstream-derived scan report fixture parses");

        assert_eq!(parsed.report.meta.name, "2026-06-15T11:24:38Z");
        assert_eq!(parsed.report.scan_run_status.as_deref(), Some("Done"));
        assert_eq!(parsed.report.resources.hosts, Some(1));
        assert_eq!(parsed.report.resources.vulnerabilities, Some(32));
        let task = parsed.report.task.as_ref().expect("task");
        assert_eq!(task.name, "test-full-fast");
        assert_eq!(
            task.target.as_ref().map(|target| target.name.as_str()),
            Some("test-target")
        );
        let counts = parsed.report.result_count.as_ref().expect("result counts");
        assert_eq!(counts.total, Some(56));
        assert_eq!(counts.full, Some(56));
        assert_eq!(counts.filtered, Some(3));
        assert_eq!(
            counts.low,
            Some(SeverityCount {
                full: Some(2),
                filtered: Some(2),
            })
        );
        assert_eq!(
            parsed.report.severity,
            Some(Severity {
                full: Some("5.0".into()),
                filtered: Some("5.0".into()),
            })
        );
        assert_eq!(
            parsed.filter.as_ref().map(|filter| filter.keywords.len()),
            Some(4)
        );
        assert_eq!(
            parsed.sort.as_ref().map(|sort| sort.field.as_str()),
            Some("severity")
        );
        assert_eq!(parsed.page.start, Some(1));
        assert_eq!(parsed.page.max, Some(1));
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn parses_minimal_and_empty_count_response() {
        let response = Response::from(
            r#"<get_scan_report_response status="200" status_text="OK">
                <report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0">
                    <name>Minimal</name>
                    <result_count/>
                    <severity/>
                </report>
            </get_scan_report_response>"#,
        );

        let parsed = GetScanReportResponse::from_response(&response).expect("minimal parses");
        assert_eq!(
            parsed.report.result_count,
            Some(ScanReportResultCount::default())
        );
        assert_eq!(
            parsed.report.severity,
            Some(Severity {
                full: None,
                filtered: None,
            })
        );
        assert_eq!(parsed.report.task, None);
        assert_eq!(parsed.filter, None);
        assert_eq!(parsed.sort, None);
        assert_eq!(parsed.page, ReportPage::default());
        assert_eq!(parsed.counts, CountInfo::default());
    }

    #[test]
    fn prefers_canonical_result_buckets_over_deprecated_aliases() {
        let response = Response::from(
            r#"<get_scan_report_response status="200" status_text="OK">
                <report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0">
                    <name>Aliases</name>
                    <result_count>
                        <hole><full>99</full><filtered>99</filtered></hole>
                        <high><full>2</full><filtered>1</filtered></high>
                        <info><full>99</full><filtered>99</filtered></info>
                        <low><full>4</full><filtered>3</filtered></low>
                        <warning><full>99</full><filtered>99</filtered></warning>
                        <medium><full>6</full><filtered>5</filtered></medium>
                    </result_count>
                </report>
            </get_scan_report_response>"#,
        );

        let parsed = GetScanReportResponse::from_response(&response).expect("aliases parse");
        let counts = parsed.report.result_count.expect("result counts");
        assert_eq!(counts.high.and_then(|count| count.full), Some(2));
        assert_eq!(counts.low.and_then(|count| count.full), Some(4));
        assert_eq!(counts.medium.and_then(|count| count.full), Some(6));
    }

    #[test]
    fn rejects_missing_report_and_malformed_numeric_values() {
        let missing =
            Response::from(r#"<get_scan_report_response status="200" status_text="OK"/>"#);
        assert!(matches!(
            GetScanReportResponse::from_response(&missing),
            Err(ParseError::MissingElement(field)) if field == "report"
        ));

        for (xml, expected_field) in [
            (
                r#"<get_scan_report_response status="200" status_text="OK"><report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0"><name>Bad</name><hosts><count>many</count></hosts></report></get_scan_report_response>"#,
                "hosts.count",
            ),
            (
                r#"<get_scan_report_response status="200" status_text="OK"><report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0"><name>Bad</name><result_count><high><full>many</full></high></result_count></report></get_scan_report_response>"#,
                "result_count.high.full",
            ),
            (
                r#"<get_scan_report_response status="200" status_text="OK"><report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0"><name>Bad</name></report><scan_report_count>many</scan_report_count></get_scan_report_response>"#,
                "scan_report_count",
            ),
        ] {
            let error = GetScanReportResponse::from_response(&Response::from(xml))
                .expect_err("malformed number must fail");
            assert!(matches!(error, ParseError::InvalidValue { field, value }
                    if field == expected_field && value == "many"));
        }
    }
}
