// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_optional_id_element, bool_str, set_optional_bool_attr,
    validate_single_xml_document,
};
use crate::responses::ParseError;
use crate::types::EntityId;

/// Optional fields for `create_report` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateReportOpts {
    /// Optional report format identifier.
    pub format_id: Option<EntityId>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

/// Optional fields for `import_report` requests.
#[derive(Debug, Clone, Default)]
pub struct ImportReportOpts {
    /// Whether to import assets embedded in the report XML.
    pub in_assets: Option<bool>,
}

/// Options for `get_reports` requests.
#[derive(Debug, Clone, Default)]
pub struct GetReportsOpts {
    /// Optional report identifier for a single-report request.
    pub report_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

/// Options for `get_scan_report` requests.
#[derive(Debug, Clone, Default)]
pub struct GetScanReportOpts {
    /// Optional inline result filter expression.
    pub filter_string: Option<String>,
    /// Optional saved result filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_reports` report-format export requests.
#[derive(Debug, Clone)]
pub struct GetReportExportOpts {
    /// Required report format identifier.
    pub report_format_id: EntityId,
    /// Optional report configuration identifier.
    pub report_config_id: Option<EntityId>,
    /// Optional inline result filter expression.
    pub filter_string: Option<String>,
    /// Optional saved result filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether pagination should be ignored. Defaults to true when omitted.
    pub ignore_pagination: Option<bool>,
}

impl GetReportExportOpts {
    /// Create export options for a report format.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self {
            report_format_id,
            report_config_id: None,
            filter_string: None,
            filter_id: None,
            ignore_pagination: None,
        }
    }
}

struct ReportExportCommand(XmlCommand);

impl Request for ReportExportCommand {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("get_report_export")
    }
}

/// Shared options for `get_report_*` helper requests.
#[derive(Debug, Clone, Default)]
pub struct GetReportDetailsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether to request detailed output. Defaults to true when omitted.
    pub details: Option<bool>,
}

/// Build a `create_report` request.
#[must_use]
pub fn create_report(task_id: &EntityId, opts: CreateReportOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_report");
    add_optional_id_element(&mut cmd, "report_format", opts.format_id.as_ref());
    cmd.add_element("task")
        .set_attribute("id", task_id.as_str());
    add_optional_id_element(&mut cmd, "filter", opts.filter_id.as_ref());
    if let Some(ignore_pagination) = opts.ignore_pagination {
        cmd.set_attribute("ignore_pagination", bool_str(ignore_pagination));
    }
    cmd
}

/// Build a `create_report` request that imports existing report XML.
///
/// # Errors
/// Returns an error if `report_xml` is not a single well-formed XML document.
pub fn import_report(
    report_xml: &str,
    task_id: &EntityId,
    opts: ImportReportOpts,
) -> Result<impl Request, ParseError> {
    validate_single_xml_document(report_xml, "report_xml", Some("report"))?;
    let in_assets_len = opts
        .in_assets
        .map(|_| "<in_assets>0</in_assets>".len())
        .unwrap_or_default();
    let mut request = Vec::with_capacity(
        "<create_report><task id=\"\"/></create_report>".len()
            + task_id.as_str().len()
            + in_assets_len
            + report_xml.len(),
    );
    request.extend_from_slice(b"<create_report><task id=\"");
    request.extend_from_slice(task_id.as_str().as_bytes());
    request.extend_from_slice(b"\"/>");
    if let Some(in_assets) = opts.in_assets {
        request.extend_from_slice(b"<in_assets>");
        request.extend_from_slice(bool_str(in_assets).as_bytes());
        request.extend_from_slice(b"</in_assets>");
    }
    request.extend_from_slice(report_xml.as_bytes());
    request.extend_from_slice(b"</create_report>");
    Ok(request)
}

/// Build a `get_reports` request.
#[must_use]
pub fn get_reports(opts: GetReportsOpts) -> impl Request {
    get_reports_with_usage(opts, None)
}

fn get_reports_with_usage(opts: GetReportsOpts, usage_type: Option<UsageType>) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_reports");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(report_id) = opts.report_id {
        cmd.set_attribute("report_id", report_id.as_str());
    }
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    if let Some(usage_type) = usage_type {
        cmd.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    cmd
}

/// Build a `get_report` request.
#[must_use]
pub fn get_report(report_id: &EntityId) -> impl Request {
    XmlCommand::new("get_reports")
        .attribute("report_id", report_id.as_str())
        .attribute("details", "1")
}

/// Build a `get_scan_report` request for a structured vulnerability report.
#[must_use]
pub fn get_scan_report(scan_report_id: &EntityId, opts: GetScanReportOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("get_scan_report").attribute("scan_report_id", scan_report_id.as_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_reports` export request for a specific report format.
#[must_use]
pub fn get_report_export(report_id: &EntityId, report_format_id: &EntityId) -> impl Request {
    get_report_export_with_opts(
        report_id,
        GetReportExportOpts::new(report_format_id.clone()),
    )
}

/// Build a `get_reports` export request with report format export options.
#[must_use]
pub fn get_report_export_with_opts(
    report_id: &EntityId,
    opts: GetReportExportOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("get_reports")
        .attribute("report_id", report_id.as_str())
        .attribute("format_id", opts.report_format_id.as_str())
        .attribute("details", "1")
        .attribute(
            "ignore_pagination",
            bool_str(opts.ignore_pagination.unwrap_or(true)),
        );
    if let Some(report_config_id) = opts.report_config_id {
        cmd.set_attribute("config_id", report_config_id.as_str());
    }
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    ReportExportCommand(cmd)
}

/// Build a `delete_report` request.
#[must_use]
pub fn delete_report(report_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_report")
        .attribute("report_id", report_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `get_reports` request scoped to audit reports.
#[must_use]
pub fn get_audit_reports(opts: GetReportsOpts) -> impl Request {
    get_reports_with_usage(opts, Some(UsageType::Audit))
}

/// Build a `delete_report` request for an audit report.
#[must_use]
pub fn delete_audit_report(report_id: &EntityId) -> impl Request {
    delete_report(report_id, false)
}

fn get_report_detail_command(
    command_name: &str,
    report_id: &EntityId,
    opts: GetReportDetailsOpts,
) -> XmlCommand {
    let mut cmd = XmlCommand::new(command_name).attribute("report_id", report_id.as_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    set_optional_bool_attr(&mut cmd, "details", Some(opts.details.unwrap_or(true)));
    cmd
}

/// Build a `get_report_hosts` request.
#[must_use]
pub fn get_report_hosts(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_hosts", report_id, opts)
}

/// Build a `get_report_ports` request.
#[must_use]
pub fn get_report_ports(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_ports", report_id, opts)
}

/// Build a `get_report_applications` request.
#[must_use]
pub fn get_report_applications(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_applications", report_id, opts)
}

/// Build a `get_report_operating_systems` request.
#[must_use]
pub fn get_report_operating_systems(
    report_id: &EntityId,
    opts: GetReportDetailsOpts,
) -> impl Request {
    get_report_detail_command("get_report_operating_systems", report_id, opts)
}

/// Build a `get_report_cves` request.
#[must_use]
pub fn get_report_cves(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_cves", report_id, opts)
}

/// Build a `get_report_vulns` request.
#[must_use]
pub fn get_report_vulns(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_vulns", report_id, opts)
}

/// Build a `get_report_vulns` request using python-gvm's descriptive helper name.
#[must_use]
pub fn get_report_vulnerabilities(
    report_id: &EntityId,
    opts: GetReportDetailsOpts,
) -> impl Request {
    get_report_vulns(report_id, opts)
}

/// Build a `get_report_tls_certificates` request.
#[must_use]
pub fn get_report_tls_certificates(
    report_id: &EntityId,
    opts: GetReportDetailsOpts,
) -> impl Request {
    get_report_detail_command("get_report_tls_certificates", report_id, opts)
}

/// Build a `get_report_errors` request.
#[must_use]
pub fn get_report_errors(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_errors", report_id, opts)
}

/// Build a `get_report_closed_cves` request.
#[must_use]
pub fn get_report_closed_cves(report_id: &EntityId, opts: GetReportDetailsOpts) -> impl Request {
    get_report_detail_command("get_report_closed_cves", report_id, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn report_commands_build_xml() {
        let export = get_report_export(&id("r1"), &id("rf1"));
        assert_eq!(export.semantic_command_name(), Some("get_report_export"));
        let rendered = xml(create_report(
            &id("t1"),
            CreateReportOpts {
                format_id: Some(id("rf1")),
                filter_id: Some(id("f1")),
                ignore_pagination: Some(true),
            },
        ));
        assert!(rendered.contains("<report_format id=\"rf1\"/>"));
        assert!(rendered.contains("<task id=\"t1\"/>"));
        assert_eq!(
            xml(get_report(&id("r1"))),
            "<get_reports details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(export),
            "<get_reports details=\"1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
        );
    }

    #[test]
    fn report_get_delete_build_xml() {
        assert_eq!(
            xml(get_reports(GetReportsOpts {
                report_id: Some(id("r1")),
                details: Some(false),
                ..Default::default()
            })),
            "<get_reports details=\"0\" report_id=\"r1\"/>"
        );
        let rendered = xml(get_reports(GetReportsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        assert_eq!(
            xml(delete_report(&id("r1"), false)),
            "<delete_report report_id=\"r1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn audit_report_commands_build_xml() {
        assert_eq!(
            xml(get_audit_reports(GetReportsOpts::default())),
            "<get_reports usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(delete_audit_report(&id("r1"))),
            "<delete_report report_id=\"r1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn report_helper_commands_build_xml() {
        let opts = GetReportDetailsOpts {
            filter_string: Some("severity>5".into()),
            filter_id: Some(id("f1")),
            ignore_pagination: Some(true),
            details: Some(false),
        };
        assert_eq!(
            xml(get_report_hosts(&id("r1"), opts.clone())),
            "<get_report_hosts details=\"0\" filt_id=\"f1\" filter=\"severity&gt;5\" ignore_pagination=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_ports(&id("r1"), GetReportDetailsOpts::default())),
            "<get_report_ports details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_applications(
                &id("r1"),
                GetReportDetailsOpts::default()
            )),
            "<get_report_applications details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_operating_systems(
                &id("r1"),
                GetReportDetailsOpts::default()
            )),
            "<get_report_operating_systems details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_cves(&id("r1"), GetReportDetailsOpts::default())),
            "<get_report_cves details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_vulns(&id("r1"), GetReportDetailsOpts::default())),
            "<get_report_vulns details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_vulnerabilities(
                &id("r1"),
                GetReportDetailsOpts {
                    filter_string: Some("name=foo".into()),
                    ..Default::default()
                },
            )),
            "<get_report_vulns details=\"1\" filter=\"name=foo\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_tls_certificates(
                &id("r1"),
                GetReportDetailsOpts::default()
            )),
            "<get_report_tls_certificates details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_errors(
                &id("r1"),
                GetReportDetailsOpts::default()
            )),
            "<get_report_errors details=\"1\" report_id=\"r1\"/>"
        );
        assert_eq!(
            xml(get_report_closed_cves(
                &id("r1"),
                GetReportDetailsOpts::default()
            )),
            "<get_report_closed_cves details=\"1\" report_id=\"r1\"/>"
        );
    }
}
