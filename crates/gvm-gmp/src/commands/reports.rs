// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{add_filter_attrs, add_optional_id_element, bool_str, set_optional_bool_attr};
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

/// Options for `get_reports` requests.
#[derive(Debug, Clone, Default)]
pub struct GetReportsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether report content should be omitted.
    pub no_report: Option<bool>,
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
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    set_optional_bool_attr(&mut cmd, "no_report", opts.no_report);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn report_commands_build_xml() {
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
    }

    #[test]
    fn report_get_delete_build_xml() {
        let rendered = xml(get_reports(GetReportsOpts {
            details: Some(true),
            no_report: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("no_report=\"1\""));
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
    }
}
