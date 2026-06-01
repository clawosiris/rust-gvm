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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportVulnerability {
    pub id: Option<String>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<String>,
    pub family: Option<String>,
    pub cves: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportTlsCertificate {
    pub id: Option<String>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportError {
    pub id: Option<String>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub description: Option<String>,
    pub nvt_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportClosedCve {
    pub id: Option<String>,
    pub name: Option<String>,
    pub cve: Option<String>,
    pub host: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportVulnsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportVulnerability>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportTlsCertificatesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportTlsCertificate>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportErrorsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportError>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportClosedCvesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportClosedCve>,
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

impl ReportVulnerability {
    fn from_node(node: &crate::responses::common::XmlNode) -> Self {
        Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.optional_child_text("name"),
            host: node.optional_child_text("host"),
            port: node.optional_child_text("port"),
            threat: node.optional_child_text("threat"),
            severity: node.optional_child_text("severity"),
            family: node.optional_child_text("family"),
            cves: node
                .children_named("cve")
                .map(|cve| cve.text.clone())
                .collect(),
        }
    }
}

impl ReportTlsCertificate {
    fn from_node(node: &crate::responses::common::XmlNode) -> Self {
        Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.optional_child_text("name"),
            host: node.optional_child_text("host"),
            port: node.optional_child_text("port"),
            subject: node.optional_child_text("subject"),
            issuer: node.optional_child_text("issuer"),
            serial: node.optional_child_text("serial"),
            activation_time: node.optional_child_text("activation_time"),
            expiration_time: node.optional_child_text("expiration_time"),
        }
    }
}

impl ReportError {
    fn from_node(node: &crate::responses::common::XmlNode) -> Self {
        Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.optional_child_text("name"),
            host: node.optional_child_text("host"),
            port: node.optional_child_text("port"),
            description: node.optional_child_text("description"),
            nvt_name: node
                .child("nvt")
                .and_then(|nvt| nvt.optional_child_text("name")),
        }
    }
}

impl ReportClosedCve {
    fn from_node(node: &crate::responses::common::XmlNode) -> Self {
        Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.optional_child_text("name"),
            cve: node
                .optional_child_text("cve")
                .or_else(|| node.optional_child_text("name")),
            host: node.optional_child_text("host"),
            severity: node.optional_child_text("severity"),
        }
    }
}

macro_rules! impl_report_detail_response {
    ($response:ident, $item:ident, [$($item_name:literal),+], $count_name:literal) => {
        impl $response {
            pub fn from_response(response: &Response) -> Result<Self, ParseError> {
                let (status, status_text) = status_from_response(response)?;
                let root = parse_document(response.data())?;
                let mut items = Vec::new();
                $(
                    items.extend(root.children_named($item_name).map($item::from_node));
                )+
                Ok(Self {
                    status,
                    status_text,
                    items,
                    counts: count_info(&root, $count_name)?,
                })
            }
        }
    };
}

impl_report_detail_response!(
    GetReportVulnsResponse,
    ReportVulnerability,
    ["vuln", "vulnerability"],
    "vuln_count"
);
impl_report_detail_response!(
    GetReportTlsCertificatesResponse,
    ReportTlsCertificate,
    ["tls_certificate", "certificate"],
    "tls_certificate_count"
);
impl_report_detail_response!(
    GetReportErrorsResponse,
    ReportError,
    ["error"],
    "error_count"
);
impl_report_detail_response!(
    GetReportClosedCvesResponse,
    ReportClosedCve,
    ["closed_cve", "cve"],
    "closed_cve_count"
);

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

    #[test]
    fn parses_report_vulns_response() {
        let response = Response::from(
            r#"<get_report_vulns_response status="200" status_text="OK">
                <vuln id="vuln-1">
                    <name>OpenSSL Vulnerability</name>
                    <host>192.0.2.10</host>
                    <port>443/tcp</port>
                    <threat>High</threat>
                    <severity>8.2</severity>
                    <family>General</family>
                    <cve>CVE-2026-0001</cve>
                </vuln>
                <vuln_count>1<filtered>1</filtered></vuln_count>
            </get_report_vulns_response>"#,
        );

        let parsed = GetReportVulnsResponse::from_response(&response).expect("vulns parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.counts.total, Some(1));
        assert_eq!(parsed.items[0].host.as_deref(), Some("192.0.2.10"));
        assert_eq!(parsed.items[0].cves, vec!["CVE-2026-0001"]);
    }

    #[test]
    fn parses_report_tls_certificates_response() {
        let response = Response::from(
            r#"<get_report_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tls-1">
                    <name>example.com</name>
                    <host>192.0.2.10</host>
                    <port>443/tcp</port>
                    <subject>CN=example.com</subject>
                    <issuer>CN=Example CA</issuer>
                    <serial>01</serial>
                    <expiration_time>2027-01-01T00:00:00Z</expiration_time>
                </tls_certificate>
                <tls_certificate_count>1<filtered>1</filtered></tls_certificate_count>
            </get_report_tls_certificates_response>"#,
        );

        let parsed = GetReportTlsCertificatesResponse::from_response(&response)
            .expect("tls certificates parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].issuer.as_deref(), Some("CN=Example CA"));
        assert_eq!(
            parsed.items[0].expiration_time.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parses_report_errors_response() {
        let response = Response::from(
            r#"<get_report_errors_response status="200" status_text="OK">
                <error id="err-1">
                    <name>Host dead</name>
                    <host>192.0.2.20</host>
                    <port>general/tcp</port>
                    <description>Could not reach host.</description>
                    <nvt><name>Ping Host</name></nvt>
                </error>
                <error_count>1<filtered>1</filtered></error_count>
            </get_report_errors_response>"#,
        );

        let parsed = GetReportErrorsResponse::from_response(&response).expect("errors parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(
            parsed.items[0].description.as_deref(),
            Some("Could not reach host.")
        );
        assert_eq!(parsed.items[0].nvt_name.as_deref(), Some("Ping Host"));
    }

    #[test]
    fn parses_report_closed_cves_response() {
        let response = Response::from(
            r#"<get_report_closed_cves_response status="200" status_text="OK">
                <closed_cve id="closed-1">
                    <name>CVE-2025-9999</name>
                    <host>192.0.2.30</host>
                    <severity>5.0</severity>
                </closed_cve>
                <closed_cve_count>1<filtered>1</filtered></closed_cve_count>
            </get_report_closed_cves_response>"#,
        );

        let parsed =
            GetReportClosedCvesResponse::from_response(&response).expect("closed cves parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].cve.as_deref(), Some("CVE-2025-9999"));
        assert_eq!(parsed.items[0].severity.as_deref(), Some("5.0"));
    }
}
