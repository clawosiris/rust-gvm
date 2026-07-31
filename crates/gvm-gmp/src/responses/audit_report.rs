// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Structured audit-report response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    parse_i32, parse_u32, status_from_response, CountInfo, EntityMeta, ParseError, XmlNode,
};
use crate::EntityId;

/// An open compliance value used by audit reports and host summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ComplianceValue {
    Yes,
    No,
    Incomplete,
    Undefined,
    Other(String),
}

impl ComplianceValue {
    fn from_text(value: String) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "yes" => Self::Yes,
            "no" => Self::No,
            "incomplete" => Self::Incomplete,
            "undefined" => Self::Undefined,
            _ => Self::Other(value),
        }
    }
}

/// Full and filtered counts for one compliance class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditComplianceClassCount {
    pub full: Option<u32>,
    pub filtered: Option<u32>,
}

/// Compliance counts from a structured audit-report summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportComplianceCounts {
    pub total: Option<u32>,
    pub full: Option<u32>,
    pub filtered: Option<u32>,
    pub yes: AuditComplianceClassCount,
    pub no: AuditComplianceClassCount,
    pub incomplete: AuditComplianceClassCount,
    pub undefined: AuditComplianceClassCount,
}

/// Full and filtered overall compliance values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportCompliance {
    pub full: Option<ComplianceValue>,
    pub filtered: Option<ComplianceValue>,
}

/// Counts of resources summarized by a structured report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StructuredReportResourceCounts {
    pub hosts: Option<u32>,
    pub closed_cves: Option<u32>,
    pub cves: Option<u32>,
    pub vulnerabilities: Option<u32>,
    pub operating_systems: Option<u32>,
    pub applications: Option<u32>,
    pub tls_certificates: Option<u32>,
    pub ports: Option<u32>,
    pub errors: Option<u32>,
}

/// Target reference nested below an audit-report task.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StructuredReportTarget {
    pub id: Option<EntityId>,
    pub name: String,
    pub comment: Option<String>,
    pub trash: Option<bool>,
    pub target_type: Option<String>,
}

/// Task reference nested in a structured audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StructuredReportTask {
    pub id: Option<EntityId>,
    pub name: String,
    pub comment: Option<String>,
    pub target: Option<StructuredReportTarget>,
    pub progress: Option<i32>,
}

/// A structured audit-report summary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReport {
    pub meta: EntityMeta,
    pub scan_run_status: Option<String>,
    pub resources: StructuredReportResourceCounts,
    pub task: Option<StructuredReportTask>,
    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub timezone: Option<String>,
    pub timezone_abbrev: Option<String>,
    pub compliance_counts: AuditReportComplianceCounts,
    pub compliance: AuditReportCompliance,
}

/// One parsed filter keyword from structured-report response metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportFilterKeyword {
    pub column: String,
    pub relation: String,
    pub value: String,
}

/// Resolved filter metadata returned by gvmd.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportFilter {
    pub id: Option<EntityId>,
    pub term: String,
    pub keywords: Vec<ReportFilterKeyword>,
}

/// Sort metadata returned by a structured-report command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportSort {
    pub field: String,
    pub order: Option<String>,
}

/// Page attributes returned alongside a structured-report response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportPage {
    pub start: Option<u32>,
    pub max: Option<i32>,
}

/// Typed `get_audit_report` response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAuditReportResponse {
    pub status: u16,
    pub status_text: String,
    pub report: AuditReport,
    pub filter: Option<ReportFilter>,
    pub sort: Option<ReportSort>,
    pub page: ReportPage,
    pub counts: CountInfo,
}

/// A source attached to one audit-report host detail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportHostDetailSource {
    pub source_type: Option<String>,
    pub name: String,
    pub description: Option<String>,
}

/// One optional detail attached to an audit-report host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportHostDetail {
    pub name: String,
    pub value: String,
    pub source: Option<AuditReportHostDetailSource>,
    pub extra: Option<String>,
}

/// Page counts by compliance class for one audit-report host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportHostComplianceCounts {
    pub page: Option<u32>,
    pub yes: Option<u32>,
    pub no: Option<u32>,
    pub incomplete: Option<u32>,
    pub undefined: Option<u32>,
}

/// A host returned by `get_audit_report_hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditReportHost {
    pub ip: String,
    pub asset_id: Option<EntityId>,
    pub asset_snapshot_key: Option<EntityId>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub port_count: CountInfo,
    pub compliance_counts: AuditReportHostComplianceCounts,
    pub compliance: Option<ComplianceValue>,
    pub application_count: CountInfo,
    pub hostname: Option<String>,
    pub details: Vec<AuditReportHostDetail>,
}

/// Typed `get_audit_report_hosts` response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAuditReportHostsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<AuditReportHost>,
    pub filter: Option<ReportFilter>,
    pub sort: Option<ReportSort>,
    pub page: ReportPage,
    pub counts: CountInfo,
}

impl GetAuditReportResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let report = root
            .child("report")
            .ok_or_else(|| ParseError::MissingElement("report".to_string()))
            .and_then(AuditReport::from_node)?;
        Ok(Self {
            status,
            status_text,
            report,
            filter: parse_filter(&root)?,
            sort: parse_sort(&root),
            page: parse_page(&root, "audit_report")?,
            counts: count_info(&root, "audit_report_count")?,
        })
    }
}

impl AuditReport {
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
            compliance_counts: node
                .child("compliance_count")
                .map(parse_report_compliance_counts)
                .transpose()?
                .unwrap_or_default(),
            compliance: node
                .child("compliance")
                .map(parse_report_compliance)
                .unwrap_or_default(),
        })
    }
}

impl GetAuditReportHostsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("host")
            .map(AuditReportHost::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            filter: parse_filter(&root)?,
            sort: parse_sort(&root),
            page: parse_page(&root, "audit_report_hosts")?,
            counts: count_info(&root, "audit_report_host_count")?,
        })
    }
}

impl AuditReportHost {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            ip: node.required_child_text("ip")?,
            asset_id: parse_optional_attr_id(node.child("asset"), "asset_id", "asset.asset_id")?,
            asset_snapshot_key: parse_optional_attr_id(
                node.child("asset_snapshot"),
                "asset_key",
                "asset_snapshot.asset_key",
            )?,
            start: node.optional_child_text("start"),
            end: node.optional_child_text("end"),
            port_count: count_info(node, "port_count")?,
            compliance_counts: node
                .child("compliance_count")
                .map(parse_host_compliance_counts)
                .transpose()?
                .unwrap_or_default(),
            compliance: node
                .optional_child_text("host_compliance")
                .map(ComplianceValue::from_text),
            application_count: count_info(node, "app_count")?,
            hostname: node.optional_child_text("hostname"),
            details: node
                .children_named("detail")
                .map(parse_host_detail)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

pub(crate) fn nested_optional_u32(
    node: &XmlNode,
    container: &str,
    field: &str,
) -> Result<Option<u32>, ParseError> {
    node.child(container)
        .map(|node| optional_u32(node, field, &format!("{container}.{field}")))
        .transpose()
        .map(Option::flatten)
}

pub(crate) fn parse_task(node: &XmlNode) -> Result<StructuredReportTask, ParseError> {
    Ok(StructuredReportTask {
        id: parse_optional_id_value(node.attr("id"), "task.id")?,
        name: node.optional_child_text("name").unwrap_or_default(),
        comment: node.child_text("comment"),
        target: node.child("target").map(parse_target).transpose()?,
        progress: node
            .optional_child_text("progress")
            .map(|value| parse_i32(&value, "task.progress"))
            .transpose()?,
    })
}

fn parse_target(node: &XmlNode) -> Result<StructuredReportTarget, ParseError> {
    Ok(StructuredReportTarget {
        id: parse_optional_id_value(node.attr("id"), "target.id")?,
        name: node.optional_child_text("name").unwrap_or_default(),
        comment: node.child_text("comment"),
        trash: node
            .optional_child_text("trash")
            .map(|value| parse_bool(&value, "target.trash"))
            .transpose()?,
        target_type: node.optional_child_text("target_type"),
    })
}

fn parse_report_compliance_counts(
    node: &XmlNode,
) -> Result<AuditReportComplianceCounts, ParseError> {
    Ok(AuditReportComplianceCounts {
        total: (!node.text.is_empty())
            .then(|| parse_u32(&node.text, "compliance_count"))
            .transpose()?,
        full: optional_u32(node, "full", "compliance_count.full")?,
        filtered: optional_u32(node, "filtered", "compliance_count.filtered")?,
        yes: parse_compliance_class_count(node, "yes")?,
        no: parse_compliance_class_count(node, "no")?,
        incomplete: parse_compliance_class_count(node, "incomplete")?,
        undefined: parse_compliance_class_count(node, "undefined")?,
    })
}

fn parse_compliance_class_count(
    node: &XmlNode,
    class: &str,
) -> Result<AuditComplianceClassCount, ParseError> {
    let Some(node) = node.child(class) else {
        return Ok(AuditComplianceClassCount::default());
    };
    Ok(AuditComplianceClassCount {
        full: optional_u32(node, "full", &format!("compliance_count.{class}.full"))?,
        filtered: optional_u32(
            node,
            "filtered",
            &format!("compliance_count.{class}.filtered"),
        )?,
    })
}

fn parse_report_compliance(node: &XmlNode) -> AuditReportCompliance {
    AuditReportCompliance {
        full: node
            .optional_child_text("full")
            .map(ComplianceValue::from_text),
        filtered: node
            .optional_child_text("filtered")
            .map(ComplianceValue::from_text),
    }
}

pub(crate) fn parse_filter(root: &XmlNode) -> Result<Option<ReportFilter>, ParseError> {
    root.child("filters")
        .map(|node| {
            let keywords = node
                .child("keywords")
                .into_iter()
                .flat_map(|keywords| keywords.children_named("keyword"))
                .map(|keyword| {
                    Ok(ReportFilterKeyword {
                        column: keyword.required_child_text("column")?,
                        relation: keyword.required_child_text("relation")?,
                        value: keyword.required_child_text("value")?,
                    })
                })
                .collect::<Result<Vec<_>, ParseError>>()?;
            Ok(ReportFilter {
                id: parse_optional_id_value(node.attr("id"), "filters.id")?,
                term: node.child_text("term").unwrap_or_default(),
                keywords,
            })
        })
        .transpose()
}

pub(crate) fn parse_sort(root: &XmlNode) -> Option<ReportSort> {
    let field = root.child("sort")?.child("field")?;
    Some(ReportSort {
        field: field.text.clone(),
        order: field.optional_child_text("order"),
    })
}

pub(crate) fn parse_page(root: &XmlNode, name: &str) -> Result<ReportPage, ParseError> {
    let Some(node) = root.child(name) else {
        return Ok(ReportPage::default());
    };
    Ok(ReportPage {
        start: node
            .attr("start")
            .map(|value| parse_u32(value, &format!("{name}.start")))
            .transpose()?,
        max: node
            .attr("max")
            .map(|value| parse_i32(value, &format!("{name}.max")))
            .transpose()?,
    })
}

fn parse_optional_attr_id(
    node: Option<&XmlNode>,
    attribute: &str,
    field: &str,
) -> Result<Option<EntityId>, ParseError> {
    parse_optional_id_value(node.and_then(|node| node.attr(attribute)), field)
}

fn parse_optional_id_value(
    value: Option<&str>,
    field: &str,
) -> Result<Option<EntityId>, ParseError> {
    value
        .filter(|value| !value.is_empty() && *value != "0")
        .map(|value| parse_entity_id(value, field))
        .transpose()
}

fn parse_host_compliance_counts(
    node: &XmlNode,
) -> Result<AuditReportHostComplianceCounts, ParseError> {
    Ok(AuditReportHostComplianceCounts {
        page: optional_u32(node, "page", "compliance_count.page")?,
        yes: nested_optional_u32(node, "yes", "page")?,
        no: nested_optional_u32(node, "no", "page")?,
        incomplete: nested_optional_u32(node, "incomplete", "page")?,
        undefined: nested_optional_u32(node, "undefined", "page")?,
    })
}

fn parse_host_detail(node: &XmlNode) -> Result<AuditReportHostDetail, ParseError> {
    Ok(AuditReportHostDetail {
        name: node.required_child_text("name")?,
        value: node.required_child_text("value")?,
        source: node
            .child("source")
            .map(
                |source| -> Result<AuditReportHostDetailSource, ParseError> {
                    Ok(AuditReportHostDetailSource {
                        source_type: source.optional_child_text("type"),
                        name: source.required_child_text("name")?,
                        description: source.optional_child_text("description"),
                    })
                },
            )
            .transpose()?,
        extra: node.optional_child_text("extra"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_audit_report_example() {
        let parsed = GetAuditReportResponse::from_response(&Response::from(include_str!(
            "../../tests/data/get_audit_report.xml"
        )))
        .expect("upstream-derived audit report fixture parses");

        assert_eq!(parsed.report.resources.hosts, Some(1));
        assert_eq!(parsed.report.compliance_counts.full, Some(10));
        assert_eq!(parsed.report.compliance_counts.filtered, Some(8));
        assert_eq!(
            parsed.report.compliance,
            AuditReportCompliance {
                full: Some(ComplianceValue::No),
                filtered: Some(ComplianceValue::No),
            }
        );
        assert_eq!(
            parsed.filter.as_ref().map(|filter| filter.keywords.len()),
            Some(2)
        );
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn parses_full_and_lean_audit_host_fixtures() {
        let full = GetAuditReportHostsResponse::from_response(&Response::from(include_str!(
            "../../tests/data/get_audit_report_hosts.xml"
        )))
        .expect("upstream-derived host fixture parses");
        assert_eq!(full.items.len(), 1);
        assert_eq!(full.items[0].compliance, Some(ComplianceValue::No));
        assert_eq!(full.items[0].compliance_counts.incomplete, Some(145));
        assert_eq!(full.items[0].details.len(), 1);

        let lean = GetAuditReportHostsResponse::from_response(&Response::from(include_str!(
            "../../tests/data/get_audit_report_hosts_lean.xml"
        )))
        .expect("lean host fixture parses");
        assert_eq!(lean.items.len(), 1);
        assert!(lean.items[0].asset_id.is_none());
        assert!(lean.items[0].details[0]
            .source
            .as_ref()
            .and_then(|source| source.source_type.as_ref())
            .is_none());
    }

    #[test]
    fn parses_empty_metadata_only_audit_host_response() {
        let response = Response::from(
            r#"<get_audit_report_hosts_response status="200" status_text="OK"><filters id=""><term></term><keywords/></filters><audit_report_hosts start="1" max="0"/><audit_report_host_count>0<filtered>0</filtered><page>0</page></audit_report_host_count></get_audit_report_hosts_response>"#,
        );
        let parsed =
            GetAuditReportHostsResponse::from_response(&response).expect("empty response parses");
        assert!(parsed.items.is_empty());
        assert_eq!(parsed.page.max, Some(0));
        assert_eq!(
            parsed.counts,
            CountInfo {
                total: Some(0),
                filtered: Some(0),
                page: Some(0),
            }
        );
    }

    #[test]
    fn parses_unlimited_audit_host_page_max() {
        let response = Response::from(
            r#"<get_audit_report_hosts_response status="200" status_text="OK"><audit_report_hosts start="1" max="-1"/><audit_report_host_count>3<filtered>3</filtered><page>3</page></audit_report_host_count></get_audit_report_hosts_response>"#,
        );
        let parsed = GetAuditReportHostsResponse::from_response(&response)
            .expect("unlimited response parses");
        assert_eq!(parsed.page.start, Some(1));
        assert_eq!(parsed.page.max, Some(-1));
        assert_eq!(parsed.counts.page, Some(3));
    }

    #[test]
    fn parses_negative_structured_task_progress() {
        let response = Response::from(
            r#"<get_audit_report_response status="200" status_text="OK"><report id="c00e2b2b-6b3a-4be9-a6df-337f76262fe0"><name>Audit</name><writable>0</writable><in_use>0</in_use><task><progress>-1</progress></task></report></get_audit_report_response>"#,
        );
        let parsed =
            GetAuditReportResponse::from_response(&response).expect("negative progress parses");
        assert_eq!(parsed.report.task.and_then(|task| task.progress), Some(-1));
    }
}
