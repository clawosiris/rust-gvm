// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report command builders.

use gvm_protocol::{Request, XmlCommand};

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
    let mut cmd = XmlCommand::new("get_reports");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    set_optional_bool_attr(&mut cmd, "no_report", opts.no_report);
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
}
