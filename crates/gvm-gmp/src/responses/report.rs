// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report response models.

use base64::Engine as _;
use gvm_protocol::Response;
use quick_xml::events::Event;
use quick_xml::Writer;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
    parse_named_entity, status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity,
    ParseError,
};
use crate::{GmpResponse, GmpVersion};

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
    pub high: Option<SeverityCount>,
    pub medium: Option<SeverityCount>,
    pub low: Option<SeverityCount>,
    pub log: Option<SeverityCount>,
    pub debug: Option<SeverityCount>,
    pub false_positive: Option<SeverityCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeverityCount {
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateReportResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

/// Response from an asynchronous `export_scan_report` request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExportScanReportResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
    /// Current processing status for a reused export. Newly created exports
    /// omit this attribute in current gvmd responses.
    pub export_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportVulnerability {
    pub id: Option<String>,
    pub nvt_oid: Option<String>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub threat: Option<String>,
    pub severity: Option<String>,
    pub family: Option<String>,
    pub cves: Vec<String>,
    pub hosts_count: Option<u32>,
    pub occurrences: Option<u32>,
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
    pub sha256_fingerprint: Option<String>,
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
    pub nvt_oid: Option<String>,
    pub name: Option<String>,
    pub cve: Option<String>,
    pub host: Option<String>,
    pub severity: Option<String>,
    pub threat: Option<String>,
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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportHostSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportPortSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportApplicationSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportOperatingSystemSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportCveSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportHostsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportHostSummary>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportPortsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportPortSummary>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportApplicationsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportApplicationSummary>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportOperatingSystemsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportOperatingSystemSummary>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetReportCvesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ReportCveSummary>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportExport {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub extension: Option<String>,
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
                        high: parse_severity_count(count, &["high", "hole"])?,
                        medium: parse_severity_count(count, &["medium", "warning"])?,
                        low: parse_severity_count(count, &["low", "info"])?,
                        log: parse_severity_count(count, &["log"])?,
                        debug: parse_severity_count(count, &["debug"])?,
                        false_positive: parse_severity_count(count, &["false_positive"])?,
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

fn parse_severity_count(
    node: &crate::responses::common::XmlNode,
    field_names: &[&str],
) -> Result<Option<SeverityCount>, ParseError> {
    let Some(bucket) = field_names.iter().find_map(|name| node.child(name)) else {
        return Ok(None);
    };

    Ok(Some(SeverityCount {
        full: bucket
            .optional_child_text("full")
            .map(|value| {
                value.parse::<u32>().map_err(|_| ParseError::InvalidValue {
                    field: format!("{}.full", field_names[0]),
                    value,
                })
            })
            .transpose()?,
        filtered: optional_u32(bucket, "filtered", &format!("{}.filtered", field_names[0]))?,
    }))
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

impl CreateReportResponse {
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

impl ExportScanReportResponse {
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
            export_status: root.attr("export_status").map(ToString::to_string),
        })
    }
}

impl GmpResponse for ExportScanReportResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

macro_rules! impl_report_gmp_response {
    ($($response:ty),+ $(,)?) => {
        $(
            impl GmpResponse for $response {
                fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
                    Self::from_response(response)
                }
            }
        )+
    };
}

impl_report_gmp_response!(
    CreateReportResponse,
    GetReportsResponse,
    GetReportVulnsResponse,
    GetReportTlsCertificatesResponse,
    GetReportErrorsResponse,
    GetReportClosedCvesResponse,
    GetReportHostsResponse,
    GetReportPortsResponse,
    GetReportApplicationsResponse,
    GetReportOperatingSystemsResponse,
    GetReportCvesResponse,
    ReportExport,
);

impl ReportVulnerability {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let nvt = node.child("nvt");
        let cves = node.child("cves").unwrap_or(node);
        Ok(Self {
            id: node.attr("id").map(ToString::to_string),
            nvt_oid: nvt.and_then(|nvt| nvt.attr("oid")).map(ToString::to_string),
            name: nvt
                .and_then(|nvt| nvt.optional_child_text("name"))
                .or_else(|| node.optional_child_text("name")),
            host: node.optional_child_text("host"),
            port: node.optional_child_text("port"),
            threat: node.optional_child_text("threat"),
            severity: node.optional_child_text("severity"),
            family: node.optional_child_text("family"),
            cves: cves
                .children_named("cve")
                .map(|cve| cve.text.clone())
                .collect(),
            hosts_count: optional_u32(node, "hosts_count", "vuln.hosts_count")?,
            occurrences: optional_u32(node, "occurrences", "vuln.occurrences")?,
        })
    }
}

impl ReportTlsCertificate {
    fn from_node(node: &crate::responses::common::XmlNode) -> Self {
        Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.optional_child_text("name"),
            host: node
                .child("host")
                .and_then(|host| host.optional_child_text("ip"))
                .or_else(|| node.optional_child_text("host")),
            port: node
                .child("ports")
                .and_then(|ports| ports.optional_child_text("port"))
                .or_else(|| node.optional_child_text("port")),
            subject: node
                .optional_child_text("subject_dn")
                .or_else(|| node.optional_child_text("subject")),
            issuer: node
                .optional_child_text("issuer_dn")
                .or_else(|| node.optional_child_text("issuer")),
            serial: node.optional_child_text("serial"),
            sha256_fingerprint: node.optional_child_text("sha256_fingerprint"),
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
        let nvt = node.child("nvt");
        Self {
            id: node.attr("id").map(ToString::to_string),
            nvt_oid: nvt.and_then(|nvt| nvt.attr("oid")).map(ToString::to_string),
            name: nvt
                .and_then(|nvt| nvt.optional_child_text("name"))
                .or_else(|| node.optional_child_text("name")),
            cve: node
                .optional_child_text("cve")
                .or_else(|| node.optional_child_text("name")),
            host: node.optional_child_text("host"),
            severity: node.optional_child_text("severity"),
            threat: node.optional_child_text("threat"),
        }
    }
}

macro_rules! impl_report_summary {
    ($item:ident) => {
        impl $item {
            fn from_node(node: &crate::responses::common::XmlNode) -> Self {
                Self {
                    id: node.attr("id").map(ToString::to_string),
                    name: node.optional_child_text("name"),
                    severity: node.optional_child_text("severity"),
                }
            }
        }
    };
}

impl_report_summary!(ReportHostSummary);
impl_report_summary!(ReportPortSummary);
impl_report_summary!(ReportApplicationSummary);
impl_report_summary!(ReportOperatingSystemSummary);
impl_report_summary!(ReportCveSummary);

fn report_detail_count_info(
    root: &crate::responses::common::XmlNode,
    current_name: &str,
    legacy_name: &str,
) -> Result<CountInfo, ParseError> {
    if root.child(current_name).is_some() {
        count_info(root, current_name)
    } else {
        count_info(root, legacy_name)
    }
}

impl GetReportVulnsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let container = root.child("vulns").unwrap_or(&root);
        let items = container
            .children_named("vuln")
            .chain(container.children_named("vulnerability"))
            .map(ReportVulnerability::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: report_detail_count_info(&root, "report_vuln_count", "vuln_count")?,
        })
    }
}

impl GetReportClosedCvesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let container = root.child("closed_cves").unwrap_or(&root);
        let items = container
            .children_named("closed_cve")
            .chain(container.children_named("cve"))
            .map(ReportClosedCve::from_node)
            .collect();
        Ok(Self {
            status,
            status_text,
            items,
            counts: report_detail_count_info(&root, "report_closed_cve_count", "closed_cve_count")?,
        })
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
    GetReportErrorsResponse,
    ReportError,
    ["error"],
    "error_count"
);
impl_report_detail_response!(
    GetReportHostsResponse,
    ReportHostSummary,
    ["host"],
    "host_count"
);
impl_report_detail_response!(
    GetReportPortsResponse,
    ReportPortSummary,
    ["port"],
    "port_count"
);
impl_report_detail_response!(
    GetReportApplicationsResponse,
    ReportApplicationSummary,
    ["application"],
    "application_count"
);
impl_report_detail_response!(
    GetReportOperatingSystemsResponse,
    ReportOperatingSystemSummary,
    ["operating_system"],
    "operating_system_count"
);
impl_report_detail_response!(
    GetReportCvesResponse,
    ReportCveSummary,
    ["cve"],
    "cve_count"
);

impl GetReportTlsCertificatesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let container = root.child("tls_certificates");
        let mut items = Vec::new();
        items.extend(
            root.children_named("tls_certificate")
                .map(ReportTlsCertificate::from_node),
        );
        if let Some(container) = container {
            items.extend(
                container
                    .children_named("tls_certificate")
                    .map(ReportTlsCertificate::from_node),
            );
        }

        Ok(Self {
            status,
            status_text,
            items,
            counts: report_tls_certificate_count_info(&root, container)?,
        })
    }
}

fn report_tls_certificate_count_info(
    root: &crate::responses::common::XmlNode,
    container: Option<&crate::responses::common::XmlNode>,
) -> Result<CountInfo, ParseError> {
    let legacy_counts = count_info(root, "tls_certificate_count")?;
    if legacy_counts != CountInfo::default() {
        return Ok(legacy_counts);
    }

    Ok(CountInfo {
        total: container
            .map(|node| optional_u32(node, "count", "tls_certificates.count"))
            .transpose()?
            .flatten(),
        filtered: None,
        page: None,
    })
}

impl ReportExport {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let text = std::str::from_utf8(response.data())?;
        let mut reader = quick_xml::Reader::from_str(text);
        reader.config_mut().trim_text(false);

        let mut saw_report = false;
        let mut envelope_depth = 0usize;
        let mut xml_depth = 0usize;
        let mut nested_xml = Vec::new();
        let mut base64_body = String::new();
        let mut content_type = None;
        let mut extension = None;

        loop {
            match reader.read_event()? {
                Event::Start(event) if event.name().as_ref() == "get_reports_response" => {
                    ensure_success_response(&event)?;
                }
                Event::Empty(event) if event.name().as_ref() == "get_reports_response" => {
                    ensure_success_response(&event)?;
                }
                Event::Start(event) if event.name().as_ref() == "report" && !saw_report => {
                    saw_report = true;
                    content_type = parse_string_attr(&event, "content_type");
                    extension = parse_string_attr(&event, "extension");
                }
                Event::Start(event) if saw_report => {
                    if xml_depth > 0 {
                        xml_depth += 1;
                        serialize_event(&mut nested_xml, Event::Start(event.into_owned()))?;
                    } else if envelope_depth == 0 && event.name().as_ref() == "report" {
                        xml_depth = 1;
                        serialize_event(&mut nested_xml, Event::Start(event.into_owned()))?;
                    } else {
                        envelope_depth += 1;
                    }
                }
                Event::Empty(event)
                    if saw_report
                        && (xml_depth > 0
                            || (envelope_depth == 0 && event.name().as_ref() == "report")) =>
                {
                    serialize_event(&mut nested_xml, Event::Empty(event.into_owned()))?;
                }
                Event::End(event) if saw_report => {
                    if event.name().as_ref() == "report" && envelope_depth == 0 && xml_depth == 0 {
                        break;
                    }
                    if xml_depth > 0 {
                        serialize_event(&mut nested_xml, Event::End(event.into_owned()))?;
                        xml_depth = xml_depth.saturating_sub(1);
                    } else {
                        envelope_depth = envelope_depth.saturating_sub(1);
                    }
                }
                Event::Text(event) if saw_report => {
                    if xml_depth > 0 {
                        serialize_event(&mut nested_xml, Event::Text(event.into_owned()))?;
                    } else if envelope_depth == 0 {
                        let chunk = event.as_ref();
                        if !chunk.trim().is_empty() {
                            base64_body.push_str(chunk);
                        }
                    }
                }
                Event::CData(event) if saw_report => {
                    if xml_depth > 0 {
                        serialize_event(&mut nested_xml, Event::CData(event.into_owned()))?;
                    } else if envelope_depth == 0 {
                        let chunk = event.as_ref();
                        if !chunk.trim().is_empty() {
                            base64_body.push_str(chunk);
                        }
                    }
                }
                Event::Eof => break,
                Event::Decl(_)
                | Event::PI(_)
                | Event::DocType(_)
                | Event::Comment(_)
                | Event::GeneralRef(_) => {}
                _ => {}
            }
        }

        if !saw_report {
            return Err(ParseError::MissingElement("report".to_string()));
        }

        let encoded_body = strip_ascii_whitespace(&base64_body);
        let bytes = if encoded_body.is_empty() && !nested_xml.is_empty() {
            nested_xml
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(&encoded_body)
                .map_err(|_| ParseError::InvalidValue {
                    field: "report export".to_string(),
                    value: base64_body,
                })?
        };

        Ok(Self {
            bytes,
            content_type,
            extension,
        })
    }
}

fn ensure_success_response(event: &quick_xml::events::BytesStart<'_>) -> Result<(), ParseError> {
    let status = parse_status_attr(event, "status")?
        .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
    let status_text = parse_string_attr(event, "status_text")
        .ok_or_else(|| ParseError::MissingElement("status_text".to_string()))?;
    if !(200..300).contains(&status) {
        return Err(ParseError::ServerError {
            status,
            message: status_text,
        });
    }
    Ok(())
}

fn parse_status_attr(
    event: &quick_xml::events::BytesStart<'_>,
    name: &str,
) -> Result<Option<u16>, ParseError> {
    parse_string_attr(event, name)
        .map(|value| {
            value.parse::<u16>().map_err(|_| ParseError::InvalidValue {
                field: name.to_string(),
                value,
            })
        })
        .transpose()
}

fn parse_string_attr(event: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    event
        .attributes()
        .flatten()
        .find(|attribute| attribute.key.as_ref() == name)
        .map(|attribute| attribute.value.into_owned())
}

fn serialize_event(buffer: &mut Vec<u8>, event: Event<'_>) -> Result<(), ParseError> {
    let mut writer = Writer::new(buffer);
    writer
        .write_event(event)
        .map_err(|error| ParseError::InvalidValue {
            field: "report export xml".to_string(),
            value: error.to_string(),
        })?;
    Ok(())
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
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
    fn associated_decoder_handles_large_repeated_report_response() {
        const REPORTS: usize = 10_000;
        let mut xml = String::from(r#"<get_reports_response status="200" status_text="OK">"#);
        for index in 0..REPORTS {
            xml.push_str(&format!(
                r#"<report id="report-{index}"><name>Report {index}</name><report><scan_start>2026-09-01T00:00:00Z</scan_start><result_count><full>1</full><filtered>1</filtered></result_count></report></report>"#
            ));
        }
        xml.push_str(&format!(
            "<report_count>{REPORTS}<filtered>{REPORTS}</filtered></report_count></get_reports_response>"
        ));

        let response = Response::new(xml.into_bytes());
        let parsed = <GetReportsResponse as GmpResponse>::decode(&response, GmpVersion(22, 8))
            .expect("large associated response decodes");

        assert_eq!(parsed.items.len(), REPORTS);
        assert_eq!(parsed.counts.total, Some(REPORTS as u32));
        assert_eq!(parsed.items[REPORTS - 1].meta.id.as_str(), "report-9999");
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
    fn parses_create_report_response() {
        let response = Response::from(
            r#"<create_report_response status="201" status_text="OK, resource created" id="report-1"/>"#,
        );

        let parsed = CreateReportResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.id.as_str(), "report-1");
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
    fn parses_report_result_count_severity_buckets() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="rpt-1">
                    <name>Bucketed Report</name>
                    <report id="rpt-1">
                        <result_count>
                            <full>11</full>
                            <filtered>8</filtered>
                            <hole><full>2</full><filtered>1</filtered></hole>
                            <warning><full>3</full><filtered>2</filtered></warning>
                            <info><full>4</full><filtered>3</filtered></info>
                            <log><full>1</full><filtered>1</filtered></log>
                            <debug><full>5</full><filtered>4</filtered></debug>
                            <false_positive><full>1</full><filtered>1</filtered></false_positive>
                        </result_count>
                    </report>
                </report>
            </get_reports_response>"#,
        );

        let parsed = GetReportsResponse::from_response(&response).expect("reports parse");
        let count = parsed.items[0].result_count.as_ref().expect("result count");

        assert_eq!(count.full, Some(11));
        assert_eq!(count.filtered, Some(8));
        assert_eq!(count.high.as_ref().and_then(|bucket| bucket.full), Some(2));
        assert_eq!(
            count.medium.as_ref().and_then(|bucket| bucket.filtered),
            Some(2)
        );
        assert_eq!(count.low.as_ref().and_then(|bucket| bucket.full), Some(4));
        assert_eq!(count.log.as_ref().and_then(|bucket| bucket.full), Some(1));
        assert_eq!(
            count.debug.as_ref().and_then(|bucket| bucket.filtered),
            Some(4)
        );
        assert_eq!(
            count
                .false_positive
                .as_ref()
                .and_then(|bucket| bucket.filtered),
            Some(1)
        );
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
                <vulns>
                    <vuln>
                        <nvt oid="1.3.6.1.4.1.25623.1.0.117761">
                            <name>SSL/TLS Renegotiation Vulnerability</name>
                        </nvt>
                        <cves>
                            <cve>CVE-2011-1473</cve>
                            <cve>CVE-2011-5094</cve>
                        </cves>
                        <hosts_count>2</hosts_count>
                        <occurrences>3</occurrences>
                        <severity>5.0</severity>
                        <threat>Medium</threat>
                    </vuln>
                </vulns>
                <report_vuln_count>1<filtered>1</filtered><page>1</page></report_vuln_count>
            </get_report_vulns_response>"#,
        );

        let parsed = GetReportVulnsResponse::from_response(&response).expect("vulns parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.counts.total, Some(1));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0].nvt_oid.as_deref(),
            Some("1.3.6.1.4.1.25623.1.0.117761")
        );
        assert_eq!(
            parsed.items[0].name.as_deref(),
            Some("SSL/TLS Renegotiation Vulnerability")
        );
        assert_eq!(parsed.items[0].cves, vec!["CVE-2011-1473", "CVE-2011-5094"]);
        assert_eq!(parsed.items[0].hosts_count, Some(2));
        assert_eq!(parsed.items[0].occurrences, Some(3));
        assert_eq!(parsed.items[0].severity.as_deref(), Some("5.0"));
        assert_eq!(parsed.items[0].threat.as_deref(), Some("Medium"));
    }

    #[test]
    fn parses_report_tls_certificates_response() {
        let response = Response::from(
            r#"<get_report_tls_certificates_response status="200" status_text="OK">
                <tls_certificates>
                    <tls_certificate>
                        <name>ee:ff:00:11</name>
                        <host><ip>192.0.2.10</ip><hostname>example.com</hostname></host>
                        <ports><port>443/tcp</port></ports>
                        <subject_dn>CN=example.com</subject_dn>
                        <issuer_dn>CN=Example CA</issuer_dn>
                        <serial>01</serial>
                        <sha256_fingerprint>ee:ff:00:11</sha256_fingerprint>
                        <expiration_time>2027-01-01T00:00:00Z</expiration_time>
                    </tls_certificate>
                </tls_certificates>
            </get_report_tls_certificates_response>"#,
        );

        let parsed = GetReportTlsCertificatesResponse::from_response(&response)
            .expect("tls certificates parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].host.as_deref(), Some("192.0.2.10"));
        assert_eq!(parsed.items[0].port.as_deref(), Some("443/tcp"));
        assert_eq!(parsed.items[0].subject.as_deref(), Some("CN=example.com"));
        assert_eq!(parsed.items[0].issuer.as_deref(), Some("CN=Example CA"));
        assert_eq!(
            parsed.items[0].expiration_time.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
        assert_eq!(
            parsed.items[0].sha256_fingerprint.as_deref(),
            Some("ee:ff:00:11")
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
                <closed_cves>
                    <closed_cve>
                        <host>192.0.2.30</host>
                        <cve>CVE-2025-9999</cve>
                        <nvt oid="1.3.6.1.4.1.25623.1.0.100000">
                            <name>Closed vulnerability check</name>
                        </nvt>
                        <severity>5.0</severity>
                        <threat>Medium</threat>
                    </closed_cve>
                </closed_cves>
                <report_closed_cve_count>1<filtered>1</filtered></report_closed_cve_count>
            </get_report_closed_cves_response>"#,
        );

        let parsed =
            GetReportClosedCvesResponse::from_response(&response).expect("closed cves parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].cve.as_deref(), Some("CVE-2025-9999"));
        assert_eq!(
            parsed.items[0].nvt_oid.as_deref(),
            Some("1.3.6.1.4.1.25623.1.0.100000")
        );
        assert_eq!(
            parsed.items[0].name.as_deref(),
            Some("Closed vulnerability check")
        );
        assert_eq!(parsed.items[0].host.as_deref(), Some("192.0.2.30"));
        assert_eq!(parsed.items[0].severity.as_deref(), Some("5.0"));
        assert_eq!(parsed.items[0].threat.as_deref(), Some("Medium"));
    }

    #[test]
    fn parses_report_vulnerability_and_closed_cve_summaries_and_empty_details() {
        let vuln_summary = Response::from(
            r#"<get_report_vulns_response status="200" status_text="OK">
                <vulns><count>3</count></vulns>
                <report_vuln_count>3<filtered>2</filtered></report_vuln_count>
            </get_report_vulns_response>"#,
        );
        let parsed =
            GetReportVulnsResponse::from_response(&vuln_summary).expect("vuln summary parses");
        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(3));
        assert_eq!(parsed.counts.filtered, Some(2));

        let closed_summary = Response::from(
            r#"<get_report_closed_cves_response status="200" status_text="OK">
                <closed_cves><count>4</count></closed_cves>
                <report_closed_cve_count>4<filtered>4</filtered></report_closed_cve_count>
            </get_report_closed_cves_response>"#,
        );
        let parsed = GetReportClosedCvesResponse::from_response(&closed_summary)
            .expect("closed-CVE summary parses");
        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(4));

        let empty_vulns = Response::from(
            r#"<get_report_vulns_response status="200" status_text="OK">
                <vulns/>
                <report_vuln_count>0<filtered>0</filtered></report_vuln_count>
            </get_report_vulns_response>"#,
        );
        assert!(GetReportVulnsResponse::from_response(&empty_vulns)
            .expect("empty vulns parse")
            .items
            .is_empty());

        let empty_closed_cves = Response::from(
            r#"<get_report_closed_cves_response status="200" status_text="OK">
                <closed_cves/>
                <report_closed_cve_count>0<filtered>0</filtered></report_closed_cve_count>
            </get_report_closed_cves_response>"#,
        );
        assert!(
            GetReportClosedCvesResponse::from_response(&empty_closed_cves)
                .expect("empty closed CVEs parse")
                .items
                .is_empty()
        );
    }

    #[test]
    fn parses_report_summary_drilldowns() {
        let hosts = GetReportHostsResponse::from_response(&Response::from(
            r#"<get_report_hosts_response status="200" status_text="OK">
                <host id="host-1"><name>192.0.2.10</name><severity>7.5</severity></host>
                <host_count>1<filtered>1</filtered><page>1</page></host_count>
            </get_report_hosts_response>"#,
        ))
        .expect("hosts parse");
        assert_eq!(hosts.items[0].name.as_deref(), Some("192.0.2.10"));
        assert_eq!(hosts.items[0].severity.as_deref(), Some("7.5"));
        assert_eq!(hosts.counts.page, Some(1));

        let ports = GetReportPortsResponse::from_response(&Response::from(
            r#"<get_report_ports_response status="200" status_text="OK">
                <port id="port-1"><name>443/tcp</name><severity>4.2</severity></port>
                <port_count>1<filtered>1</filtered></port_count>
            </get_report_ports_response>"#,
        ))
        .expect("ports parse");
        assert_eq!(ports.items[0].name.as_deref(), Some("443/tcp"));

        let applications = GetReportApplicationsResponse::from_response(&Response::from(
            r#"<get_report_applications_response status="200" status_text="OK">
                <application id="app-1"><name>OpenSSH</name><severity>6.5</severity></application>
                <application_count>1<filtered>1</filtered></application_count>
            </get_report_applications_response>"#,
        ))
        .expect("applications parse");
        assert_eq!(applications.items[0].name.as_deref(), Some("OpenSSH"));

        let operating_systems =
            GetReportOperatingSystemsResponse::from_response(&Response::from(
                r#"<get_report_operating_systems_response status="200" status_text="OK">
                    <operating_system id="os-1"><name>Debian</name><severity>5.5</severity></operating_system>
                    <operating_system_count>1<filtered>1</filtered></operating_system_count>
                </get_report_operating_systems_response>"#,
            ))
            .expect("operating systems parse");
        assert_eq!(operating_systems.items[0].name.as_deref(), Some("Debian"));

        let cves = GetReportCvesResponse::from_response(&Response::from(
            r#"<get_report_cves_response status="200" status_text="OK">
                <cve id="cve-1"><name>CVE-2026-0001</name><severity>8.0</severity></cve>
                <cve_count>1<filtered>1</filtered></cve_count>
            </get_report_cves_response>"#,
        ))
        .expect("cves parse");
        assert_eq!(cves.items[0].name.as_deref(), Some("CVE-2026-0001"));
    }

    #[test]
    fn parses_empty_report_summary_drilldown() {
        let response = Response::from(
            r#"<get_report_hosts_response status="200" status_text="OK"><host_count>0<filtered>0</filtered></host_count></get_report_hosts_response>"#,
        );

        let parsed = GetReportHostsResponse::from_response(&response).expect("hosts parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
        assert_eq!(parsed.counts.filtered, Some(0));
    }

    #[test]
    fn parses_base64_report_export() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="report-1" format_id="format-1" extension="pdf" content_type="application/pdf">SGVsbG8gUERG</report>
            </get_reports_response>"#,
        );

        let export = ReportExport::from_response(&response).expect("export parse");

        assert_eq!(export.bytes, b"Hello PDF");
        assert_eq!(export.content_type.as_deref(), Some("application/pdf"));
        assert_eq!(export.extension.as_deref(), Some("pdf"));
    }

    #[test]
    fn associated_decoder_preserves_arbitrary_binary_export_bytes() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK"><report extension="bin" content_type="application/octet-stream">AP8B/g==</report></get_reports_response>"#,
        );

        let export = <ReportExport as GmpResponse>::decode(&response, GmpVersion(22, 8))
            .expect("binary export decodes");

        assert_eq!(export.bytes, [0, 255, 1, 254]);
        assert_eq!(
            export.content_type.as_deref(),
            Some("application/octet-stream")
        );
    }

    #[test]
    fn associated_decoder_accepts_mixed_repeated_vulnerability_elements() {
        let response = Response::from(
            r#"<get_report_vulns_response status="200" status_text="OK"><vulns><vuln id="one"><name>First</name></vuln><vulnerability id="two"><name>Second</name></vulnerability><vuln id="three"><name>Third</name></vuln></vulns><report_vuln_count>3<filtered>3</filtered></report_vuln_count></get_report_vulns_response>"#,
        );

        let parsed = <GetReportVulnsResponse as GmpResponse>::decode(&response, GmpVersion(22, 8))
            .expect("mixed repeated vulnerability elements decode");

        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.items[1].id.as_deref(), Some("three"));
        assert_eq!(parsed.items[2].name.as_deref(), Some("Second"));
    }

    #[test]
    fn parses_created_asynchronous_scan_report_export_without_status() {
        let response = Response::from(
            r#"<export_scan_report_response status="201" status_text="OK, resource created" id="e6e2f6e1-daa9-411d-aa5a-1321c9894ab9"/>"#,
        );

        let parsed = ExportScanReportResponse::from_response(&response).expect("created parse");

        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.id.as_str(), "e6e2f6e1-daa9-411d-aa5a-1321c9894ab9");
        assert_eq!(parsed.export_status, None);
    }

    #[test]
    fn parses_reused_asynchronous_scan_report_export_with_status() {
        let response = Response::from(
            r#"<export_scan_report_response status="200" status_text="OK" id="e6e2f6e1-daa9-411d-aa5a-1321c9894ab9" export_status="pending"/>"#,
        );

        let parsed = ExportScanReportResponse::from_response(&response).expect("reused parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.export_status.as_deref(), Some("pending"));
    }

    #[test]
    fn rejects_asynchronous_scan_report_export_error_response() {
        let response = Response::from(
            r#"<export_scan_report_response status="400" status_text="Missing or invalid report_id"/>"#,
        );

        let error = ExportScanReportResponse::from_response(&response).expect_err("server error");

        assert!(matches!(
            error,
            ParseError::ServerError { status: 400, message }
                if message == "Missing or invalid report_id"
        ));
    }

    #[test]
    fn parses_base64_report_export_after_metadata_prefix() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="report-1" format_id="c402cc3e-b531-11e1-9163-406186ea4fc5" extension="pdf" content_type="application/pdf">
                    <owner><name>admin</name></owner>
                    <name>2026-06-30T18:13:23Z</name>
                    <comment></comment>
                    <creation_time>2026-06-30T18:13:23Z</creation_time>
                    <modification_time>2026-06-30T18:13:45Z</modification_time>
                    <writable>0</writable>
                    <in_use>0</in_use>
                    <task id="task-1"><name>scan-task</name></task>
                    <report_format id="c402cc3e-b531-11e1-9163-406186ea4fc5"><name>PDF</name></report_format>
                    JVBERi0xLjcK
                </report>
            </get_reports_response>"#,
        );

        let export = ReportExport::from_response(&response).expect("export parse");

        assert!(export.bytes.starts_with(b"%PDF-1.7\n"));
        assert_eq!(export.content_type.as_deref(), Some("application/pdf"));
        assert_eq!(export.extension.as_deref(), Some("pdf"));
    }

    #[test]
    fn parses_nested_xml_report_export() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="report-1" format_id="format-xml" extension="xml" content_type="text/xml"><report id="report-1"><results><result id="r1"/></results></report></report>
            </get_reports_response>"#,
        );

        let export = ReportExport::from_response(&response).expect("export parse");
        let xml = String::from_utf8(export.bytes).expect("utf8 xml");

        assert_eq!(export.content_type.as_deref(), Some("text/xml"));
        assert_eq!(export.extension.as_deref(), Some("xml"));
        assert!(xml.contains(r#"<report id="report-1">"#));
        assert!(xml.contains(r#"<result id="r1"/>"#));
    }

    #[test]
    fn parses_nested_xml_report_export_after_metadata_prefix() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="report-1" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
                    <owner><name>admin</name></owner>
                    <name>2026-06-30T18:13:23Z</name>
                    <comment></comment>
                    <creation_time>2026-06-30T18:13:23Z</creation_time>
                    <modification_time>2026-06-30T18:13:45Z</modification_time>
                    <writable>0</writable>
                    <in_use>0</in_use>
                    <task id="task-1"><name>scan-task</name></task>
                    <report_format id="a994b278-1f62-11e1-96ac-406186ea4fc5"><name>XML</name></report_format>
                    <report id="report-1"><results><result id="r1"/></results></report>
                </report>
            </get_reports_response>"#,
        );

        let export = ReportExport::from_response(&response).expect("export parse");
        let xml = String::from_utf8(export.bytes).expect("utf8 xml");

        assert_eq!(export.content_type.as_deref(), Some("text/xml"));
        assert_eq!(export.extension.as_deref(), Some("xml"));
        assert!(xml.starts_with(r#"<report id="report-1">"#));
        assert!(xml.contains(r#"<result id="r1"/>"#));
        assert!(!xml.contains("<owner>"));
        assert!(!xml.contains("<report_format"));
    }

    #[test]
    fn rejects_invalid_base64_report_export() {
        let response = Response::from(
            r#"<get_reports_response status="200" status_text="OK">
                <report id="report-1">not-base64***</report>
            </get_reports_response>"#,
        );

        let error = ReportExport::from_response(&response).expect_err("invalid base64");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, .. } if field == "report export"
        ));
    }

    #[test]
    fn rejects_self_closing_permission_denied_report_export() {
        let response = Response::from(
            r#"<get_reports_response status="400" status_text="Permission denied"/>"#,
        );

        let error = ReportExport::from_response(&response).expect_err("server error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Permission denied"
        ));
    }

    #[test]
    fn rejects_self_closing_unauthorized_report_export() {
        let response = Response::from(
            r#"<get_reports_response status="401" status_text="Authentication required"/>"#,
        );

        let error = ReportExport::from_response(&response).expect_err("server error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 401,
                message
            } if message == "Authentication required"
        ));
    }
}
