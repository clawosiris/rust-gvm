// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_optional_id_element, bool_str, set_optional_bool_attr,
    validate_single_xml_document,
};
use crate::responses::{
    CreateReportResponse, DeleteReportResponse, ExportScanReportResponse,
    GetAuditReportHostsResponse, GetAuditReportResponse, GetReportApplicationsResponse,
    GetReportClosedCvesResponse, GetReportCvesResponse, GetReportErrorsResponse,
    GetReportHostsResponse, GetReportOperatingSystemsResponse, GetReportPortsResponse,
    GetReportTlsCertificatesResponse, GetReportVulnsResponse, GetReportsResponse,
    GetScanReportResponse, ParseError, ReportExport,
};
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for creating a report.
#[derive(Debug, Clone)]
pub struct CreateReportRequest {
    task_id: EntityId,
    opts: CreateReportOpts,
}

impl CreateReportRequest {
    /// Create a report-creation request.
    #[must_use]
    pub fn new(task_id: EntityId, opts: CreateReportOpts) -> Self {
        Self { task_id, opts }
    }
}

impl Request for CreateReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_report(&self.task_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateReportRequest {
    type Response = CreateReportResponse;
}

/// Semantic request for importing report XML.
#[derive(Debug, Clone)]
pub struct ImportReportRequest {
    bytes: Vec<u8>,
}

impl ImportReportRequest {
    /// Validate report XML and create a report-import request.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`import_report`].
    pub fn new(
        report_xml: &str,
        task_id: &EntityId,
        opts: ImportReportOpts,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            bytes: import_report(report_xml, task_id, opts)?.to_bytes(),
        })
    }
}

impl Request for ImportReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl GmpRequest for ImportReportRequest {
    type Response = CreateReportResponse;
}

/// Semantic request for deleting a report.
#[derive(Debug, Clone)]
pub struct DeleteReportRequest {
    report_id: EntityId,
    ultimate: bool,
}

impl DeleteReportRequest {
    /// Create a report-deletion request.
    #[must_use]
    pub fn new(report_id: EntityId, ultimate: bool) -> Self {
        Self {
            report_id,
            ultimate,
        }
    }
}

impl Request for DeleteReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_report(&self.report_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteReportRequest {
    type Response = DeleteReportResponse;
}

/// Semantic request for deleting an audit report.
#[derive(Debug, Clone)]
pub struct DeleteAuditReportRequest {
    report_id: EntityId,
}

impl DeleteAuditReportRequest {
    /// Create an audit-report deletion request.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self { report_id }
    }
}

impl Request for DeleteAuditReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_audit_report(&self.report_id).to_bytes()
    }
}

impl GmpRequest for DeleteAuditReportRequest {
    type Response = DeleteReportResponse;
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

/// Options for `get_audit_report` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAuditReportOpts {
    /// Optional inline result filter expression.
    pub filter_string: Option<String>,
    /// Optional saved result filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_audit_report_hosts` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAuditReportHostsOpts {
    /// Optional inline result and host filter expression.
    pub filter_string: Option<String>,
    /// Optional saved result filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to omit selected empty or redundant host details.
    pub lean: Option<bool>,
    /// Whether to include host entries rather than count metadata only.
    pub details: Option<bool>,
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

/// Options for asynchronous `export_scan_report` requests.
#[derive(Debug, Clone, Default)]
pub struct ExportScanReportOpts {
    /// Optional report format identifier. gvmd defaults to the XML report
    /// format when this is omitted.
    pub format_id: Option<EntityId>,
    /// Optional report configuration identifier.
    pub config_id: Option<EntityId>,
    /// Optional inline result filter expression.
    pub filter_string: Option<String>,
    /// Whether pagination settings in the filter are ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether lean report data is generated.
    pub lean: Option<bool>,
    /// Whether note details are included.
    pub notes_details: Option<bool>,
    /// Whether override details are included.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
}

/// Semantic request for listing reports.
#[derive(Debug, Clone, Default)]
pub struct GetReportsRequest {
    opts: GetReportsOpts,
}

impl GetReportsRequest {
    /// Create a report-list request.
    #[must_use]
    pub fn new(opts: GetReportsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetReportsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_reports(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetReportsRequest {
    type Response = GetReportsResponse;
}

/// Semantic request for one detailed report.
#[derive(Debug, Clone)]
pub struct GetReportRequest {
    report_id: EntityId,
}

impl GetReportRequest {
    /// Create a detailed single-report request.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self { report_id }
    }
}

impl Request for GetReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_report(&self.report_id).to_bytes()
    }
}

impl GmpRequest for GetReportRequest {
    type Response = GetReportsResponse;
}

/// Semantic request for listing audit reports.
#[derive(Debug, Clone, Default)]
pub struct GetAuditReportsRequest {
    opts: GetReportsOpts,
}

impl GetAuditReportsRequest {
    /// Create an audit-report list request.
    #[must_use]
    pub fn new(opts: GetReportsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetAuditReportsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_audit_reports(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAuditReportsRequest {
    type Response = GetReportsResponse;
}

/// Semantic request for one structured vulnerability report.
#[derive(Debug, Clone)]
pub struct GetScanReportRequest {
    scan_report_id: EntityId,
    opts: GetScanReportOpts,
}

impl GetScanReportRequest {
    /// Create a structured vulnerability-report request.
    #[must_use]
    pub fn new(scan_report_id: EntityId, opts: GetScanReportOpts) -> Self {
        Self {
            scan_report_id,
            opts,
        }
    }
}

impl Request for GetScanReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_report(&self.scan_report_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanReportRequest {
    type Response = GetScanReportResponse;
}

/// Semantic request for one structured audit report.
#[derive(Debug, Clone)]
pub struct GetAuditReportRequest {
    audit_report_id: EntityId,
    opts: GetAuditReportOpts,
}

impl GetAuditReportRequest {
    /// Create a structured audit-report request.
    #[must_use]
    pub fn new(audit_report_id: EntityId, opts: GetAuditReportOpts) -> Self {
        Self {
            audit_report_id,
            opts,
        }
    }
}

impl Request for GetAuditReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_audit_report(&self.audit_report_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAuditReportRequest {
    type Response = GetAuditReportResponse;
}

/// Semantic request for structured audit-report host summaries.
#[derive(Debug, Clone)]
pub struct GetAuditReportHostsRequest {
    report_id: EntityId,
    opts: GetAuditReportHostsOpts,
}

impl GetAuditReportHostsRequest {
    /// Create an audit-report host request.
    #[must_use]
    pub fn new(report_id: EntityId, opts: GetAuditReportHostsOpts) -> Self {
        Self { report_id, opts }
    }
}

impl Request for GetAuditReportHostsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_audit_report_hosts(&self.report_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAuditReportHostsRequest {
    type Response = GetAuditReportHostsResponse;
}

/// Semantic request for a synchronous report-format export.
#[derive(Debug, Clone)]
pub struct GetReportExportRequest {
    report_id: EntityId,
    opts: GetReportExportOpts,
}

impl GetReportExportRequest {
    /// Create a synchronous report-format export request.
    #[must_use]
    pub fn new(report_id: EntityId, opts: GetReportExportOpts) -> Self {
        Self { report_id, opts }
    }
}

impl Request for GetReportExportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_report_export_with_opts(&self.report_id, self.opts.clone()).to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("get_report_export")
    }
}

impl GmpRequest for GetReportExportRequest {
    type Response = ReportExport;
}

macro_rules! report_detail_request {
    ($request:ident, $response:ty, $builder:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            report_id: EntityId,
            opts: GetReportDetailsOpts,
        }

        impl $request {
            /// Create the structured report-subresource request.
            #[must_use]
            pub fn new(report_id: EntityId, opts: GetReportDetailsOpts) -> Self {
                Self { report_id, opts }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.report_id, self.opts.clone()).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

report_detail_request!(
    GetReportHostsRequest,
    GetReportHostsResponse,
    get_report_hosts,
    "Semantic request for report host summaries."
);
report_detail_request!(
    GetReportPortsRequest,
    GetReportPortsResponse,
    get_report_ports,
    "Semantic request for report port summaries."
);
report_detail_request!(
    GetReportApplicationsRequest,
    GetReportApplicationsResponse,
    get_report_applications,
    "Semantic request for report application summaries."
);
report_detail_request!(
    GetReportOperatingSystemsRequest,
    GetReportOperatingSystemsResponse,
    get_report_operating_systems,
    "Semantic request for report operating-system summaries."
);
report_detail_request!(
    GetReportCvesRequest,
    GetReportCvesResponse,
    get_report_cves,
    "Semantic request for report CVE summaries."
);
report_detail_request!(
    GetReportVulnsRequest,
    GetReportVulnsResponse,
    get_report_vulns,
    "Semantic request for report vulnerability summaries."
);
report_detail_request!(
    GetReportTlsCertificatesRequest,
    GetReportTlsCertificatesResponse,
    get_report_tls_certificates,
    "Semantic request for report TLS-certificate summaries."
);
report_detail_request!(
    GetReportErrorsRequest,
    GetReportErrorsResponse,
    get_report_errors,
    "Semantic request for report errors."
);
report_detail_request!(
    GetReportClosedCvesRequest,
    GetReportClosedCvesResponse,
    get_report_closed_cves,
    "Semantic request for report closed-CVE summaries."
);

/// Semantic request for queuing or reusing an asynchronous report export.
#[derive(Debug, Clone)]
pub struct ExportScanReportRequest {
    report_id: EntityId,
    opts: ExportScanReportOpts,
}

impl ExportScanReportRequest {
    /// Create an asynchronous scan-report export request.
    #[must_use]
    pub fn new(report_id: EntityId, opts: ExportScanReportOpts) -> Self {
        Self { report_id, opts }
    }
}

impl Request for ExportScanReportRequest {
    fn to_bytes(&self) -> Vec<u8> {
        export_scan_report(&self.report_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ExportScanReportRequest {
    type Response = ExportScanReportResponse;
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

/// Build a `get_audit_report` request for a structured audit report.
#[must_use]
pub fn get_audit_report(audit_report_id: &EntityId, opts: GetAuditReportOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("get_audit_report").attribute("audit_report_id", audit_report_id.as_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_audit_report_hosts` request.
#[must_use]
pub fn get_audit_report_hosts(report_id: &EntityId, opts: GetAuditReportHostsOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("get_audit_report_hosts").attribute("report_id", report_id.as_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "lean", opts.lean);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
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

/// Build an asynchronous `export_scan_report` request.
///
/// The command was added without a distinct GMP version. Callers using the
/// high-level client must first confirm it through the server's XML `help`
/// command listing.
#[must_use]
pub fn export_scan_report(report_id: &EntityId, opts: ExportScanReportOpts) -> impl Request {
    let mut cmd = XmlCommand::new("export_scan_report").attribute("report_id", report_id.as_str());
    if let Some(format_id) = opts.format_id {
        cmd.set_attribute("format_id", format_id.as_str());
    }
    if let Some(config_id) = opts.config_id {
        cmd.set_attribute("config_id", config_id.as_str());
    }
    if let Some(filter_string) = opts.filter_string {
        cmd.set_attribute("filter", &filter_string);
    }
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    set_optional_bool_attr(&mut cmd, "lean", opts.lean);
    set_optional_bool_attr(&mut cmd, "notes_details", opts.notes_details);
    set_optional_bool_attr(&mut cmd, "overrides_details", opts.overrides_details);
    set_optional_bool_attr(&mut cmd, "result_tags", opts.result_tags);
    cmd
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
    use crate::GmpResponse;

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
    fn semantic_scan_report_export_matches_legacy_builder_bytes() {
        let report_id = id("report-1");
        let opts = ExportScanReportOpts {
            format_id: Some(id("format-1")),
            config_id: Some(id("config-1")),
            filter_string: Some("severity>5".into()),
            ignore_pagination: Some(true),
            lean: Some(false),
            notes_details: Some(true),
            overrides_details: Some(false),
            result_tags: Some(true),
        };

        let semantic = ExportScanReportRequest::new(report_id.clone(), opts.clone());
        let legacy = export_scan_report(&report_id, opts);

        assert_eq!(semantic.to_bytes(), legacy.to_bytes());
        assert_eq!(
            semantic.to_bytes(),
            br#"<export_scan_report config_id="config-1" filter="severity&gt;5" format_id="format-1" ignore_pagination="1" lean="0" notes_details="1" overrides_details="0" report_id="report-1" result_tags="1"/>"#
        );
    }

    fn assert_associated_response<R, T>()
    where
        R: GmpRequest<Response = T>,
        T: GmpResponse,
    {
    }

    #[test]
    fn semantic_report_requests_have_fixed_response_types() {
        assert_associated_response::<CreateReportRequest, CreateReportResponse>();
        assert_associated_response::<ImportReportRequest, CreateReportResponse>();
        assert_associated_response::<DeleteReportRequest, DeleteReportResponse>();
        assert_associated_response::<DeleteAuditReportRequest, DeleteReportResponse>();
        assert_associated_response::<GetReportsRequest, GetReportsResponse>();
        assert_associated_response::<GetReportRequest, GetReportsResponse>();
        assert_associated_response::<GetAuditReportsRequest, GetReportsResponse>();
        assert_associated_response::<GetScanReportRequest, GetScanReportResponse>();
        assert_associated_response::<GetAuditReportRequest, GetAuditReportResponse>();
        assert_associated_response::<GetAuditReportHostsRequest, GetAuditReportHostsResponse>();
        assert_associated_response::<GetReportExportRequest, ReportExport>();
        assert_associated_response::<GetReportHostsRequest, GetReportHostsResponse>();
        assert_associated_response::<GetReportPortsRequest, GetReportPortsResponse>();
        assert_associated_response::<GetReportApplicationsRequest, GetReportApplicationsResponse>();
        assert_associated_response::<
            GetReportOperatingSystemsRequest,
            GetReportOperatingSystemsResponse,
        >();
        assert_associated_response::<GetReportCvesRequest, GetReportCvesResponse>();
        assert_associated_response::<GetReportVulnsRequest, GetReportVulnsResponse>();
        assert_associated_response::<
            GetReportTlsCertificatesRequest,
            GetReportTlsCertificatesResponse,
        >();
        assert_associated_response::<GetReportErrorsRequest, GetReportErrorsResponse>();
        assert_associated_response::<GetReportClosedCvesRequest, GetReportClosedCvesResponse>();
        assert_associated_response::<ExportScanReportRequest, ExportScanReportResponse>();
    }

    #[test]
    fn semantic_report_mutation_requests_match_legacy_builder_bytes() {
        let task_id = id("task-1");
        let create_opts = CreateReportOpts {
            format_id: Some(id("format-1")),
            filter_id: Some(id("filter-1")),
            ignore_pagination: Some(true),
        };
        assert_eq!(
            CreateReportRequest::new(task_id.clone(), create_opts.clone()).to_bytes(),
            create_report(&task_id, create_opts).to_bytes()
        );

        let report_xml = r#"<report id="imported-report"><name>Imported</name></report>"#;
        let import_opts = ImportReportOpts {
            in_assets: Some(true),
        };
        assert_eq!(
            ImportReportRequest::new(report_xml, &task_id, import_opts.clone())
                .expect("valid report XML")
                .to_bytes(),
            import_report(report_xml, &task_id, import_opts)
                .expect("valid report XML")
                .to_bytes()
        );
        assert!(ImportReportRequest::new("<not-report/>", &task_id, Default::default()).is_err());

        let report_id = id("report-1");
        assert_eq!(
            DeleteReportRequest::new(report_id.clone(), true).to_bytes(),
            delete_report(&report_id, true).to_bytes()
        );
        assert_eq!(
            DeleteAuditReportRequest::new(report_id.clone()).to_bytes(),
            delete_audit_report(&report_id).to_bytes()
        );
    }

    #[test]
    fn semantic_report_requests_match_legacy_builder_bytes() {
        let report_id = id("report-1");
        let list_opts = GetReportsOpts {
            filter_string: Some("severity>5".into()),
            details: Some(true),
            ..Default::default()
        };
        assert_eq!(
            GetReportsRequest::new(list_opts.clone()).to_bytes(),
            get_reports(list_opts.clone()).to_bytes()
        );
        assert_eq!(
            GetReportRequest::new(report_id.clone()).to_bytes(),
            get_report(&report_id).to_bytes()
        );
        assert_eq!(
            GetAuditReportsRequest::new(list_opts.clone()).to_bytes(),
            get_audit_reports(list_opts).to_bytes()
        );

        let scan_opts = GetScanReportOpts {
            filter_string: Some("levels=chml".into()),
            filter_id: Some(id("filter-1")),
        };
        assert_eq!(
            GetScanReportRequest::new(report_id.clone(), scan_opts.clone()).to_bytes(),
            get_scan_report(&report_id, scan_opts).to_bytes()
        );
        let audit_opts = GetAuditReportOpts {
            filter_string: Some("compliance_levels=yniu".into()),
            filter_id: Some(id("filter-2")),
        };
        assert_eq!(
            GetAuditReportRequest::new(report_id.clone(), audit_opts.clone()).to_bytes(),
            get_audit_report(&report_id, audit_opts).to_bytes()
        );
        let audit_hosts_opts = GetAuditReportHostsOpts {
            filter_string: Some("rows=25".into()),
            filter_id: None,
            lean: Some(true),
            details: Some(false),
        };
        assert_eq!(
            GetAuditReportHostsRequest::new(report_id.clone(), audit_hosts_opts.clone()).to_bytes(),
            get_audit_report_hosts(&report_id, audit_hosts_opts).to_bytes()
        );

        let mut export_opts = GetReportExportOpts::new(id("format-1"));
        export_opts.report_config_id = Some(id("config-1"));
        export_opts.ignore_pagination = Some(false);
        let export = GetReportExportRequest::new(report_id.clone(), export_opts.clone());
        assert_eq!(
            export.to_bytes(),
            get_report_export_with_opts(&report_id, export_opts).to_bytes()
        );
        assert_eq!(export.semantic_command_name(), Some("get_report_export"));

        let detail_opts = GetReportDetailsOpts {
            filter_string: Some("rows=10".into()),
            filter_id: Some(id("filter-3")),
            ignore_pagination: Some(true),
            details: Some(false),
        };
        macro_rules! assert_detail_bytes {
            ($request:ident, $builder:ident) => {
                assert_eq!(
                    $request::new(report_id.clone(), detail_opts.clone()).to_bytes(),
                    $builder(&report_id, detail_opts.clone()).to_bytes()
                );
            };
        }
        assert_detail_bytes!(GetReportHostsRequest, get_report_hosts);
        assert_detail_bytes!(GetReportPortsRequest, get_report_ports);
        assert_detail_bytes!(GetReportApplicationsRequest, get_report_applications);
        assert_detail_bytes!(
            GetReportOperatingSystemsRequest,
            get_report_operating_systems
        );
        assert_detail_bytes!(GetReportCvesRequest, get_report_cves);
        assert_detail_bytes!(GetReportVulnsRequest, get_report_vulns);
        assert_detail_bytes!(GetReportTlsCertificatesRequest, get_report_tls_certificates);
        assert_detail_bytes!(GetReportErrorsRequest, get_report_errors);
        assert_detail_bytes!(GetReportClosedCvesRequest, get_report_closed_cves);
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
        assert_eq!(
            xml(get_audit_report(
                &id("r1"),
                GetAuditReportOpts {
                    filter_string: Some("compliance_levels=yniu min_qod=70".into()),
                    filter_id: Some(id("f1")),
                }
            )),
            "<get_audit_report audit_report_id=\"r1\" filt_id=\"f1\" filter=\"compliance_levels=yniu min_qod=70\"/>"
        );
        assert_eq!(
            xml(get_audit_report_hosts(
                &id("r1"),
                GetAuditReportHostsOpts {
                    filter_string: Some("levels=yniu rows=10 first=1".into()),
                    filter_id: None,
                    lean: Some(true),
                    details: Some(false),
                }
            )),
            "<get_audit_report_hosts details=\"0\" filter=\"levels=yniu rows=10 first=1\" lean=\"1\" report_id=\"r1\"/>"
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
