// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Alert command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{AlertCondition, AlertEvent, AlertMethod};
use crate::types::EntityId;

/// A name/value entry nested below an alert event, condition, or method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertData {
    /// Protocol-defined data name.
    pub name: String,
    /// Data value.
    pub value: String,
}

impl AlertData {
    /// Create an alert data entry.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Optional fields for alert create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct AlertOpts {
    /// Optional replacement name used by modify requests.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional alert event value.
    pub event: Option<AlertEvent>,
    /// Data entries applied when `event` is present.
    pub event_data: Vec<AlertData>,
    /// Optional alert condition value.
    pub condition: Option<AlertCondition>,
    /// Data entries applied when `condition` is present.
    pub condition_data: Vec<AlertData>,
    /// Optional alert delivery method.
    pub method: Option<AlertMethod>,
    /// Data entries applied when `method` is present.
    pub method_data: Vec<AlertData>,
    /// Optional saved filter identifier.
    ///
    /// When modifying an alert, gvmd clears the current filter binding if this
    /// field is omitted. Pass the existing filter ID to preserve the binding.
    pub filter_id: Option<EntityId>,
    /// Whether the alert is enabled.
    ///
    /// When modifying an alert, omitting this field preserves its current
    /// active state.
    pub active: Option<bool>,
}

/// Options for `get_alerts` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAlertsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Options for `trigger_alert` requests.
#[derive(Debug, Clone, Default)]
pub struct TriggerAlertOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Optional report format identifier.
    pub report_format_id: Option<EntityId>,
    /// Optional delta report identifier.
    pub delta_report_id: Option<EntityId>,
}

/// Build a clone request for an existing alert.
#[must_use]
pub fn clone_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("create_alert").child_with_text("copy", alert_id.as_str())
}

/// Build a `create_alert` request.
#[must_use]
pub fn create_alert(name: &str, opts: AlertOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_alert");
    cmd.add_element_with_text("name", name);
    add_alert_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_alerts` request.
#[must_use]
pub fn get_alerts(opts: GetAlertsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_alerts");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_alert` request.
#[must_use]
pub fn get_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("get_alerts")
        .attribute("alert_id", alert_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_alert` request.
#[must_use]
pub fn modify_alert(alert_id: &EntityId, opts: AlertOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_alert").attribute("alert_id", alert_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_alert_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_alert` request.
#[must_use]
pub fn delete_alert(alert_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_alert")
        .attribute("alert_id", alert_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `test_alert` request.
#[must_use]
pub fn test_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("test_alert").attribute("alert_id", alert_id.as_str())
}

/// Build a `trigger_alert` request.
#[must_use]
pub fn trigger_alert(
    alert_id: &EntityId,
    report_id: &EntityId,
    opts: TriggerAlertOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("get_reports")
        .attribute("report_id", report_id.as_str())
        .attribute("alert_id", alert_id.as_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(report_format_id) = opts.report_format_id.as_ref() {
        cmd = cmd.attribute("format_id", report_format_id.as_str());
    }
    if let Some(delta_report_id) = opts.delta_report_id.as_ref() {
        cmd = cmd.attribute("delta_report_id", delta_report_id.as_str());
    }
    cmd
}

fn add_alert_body(cmd: &mut XmlCommand, opts: &AlertOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_alert_field(
        cmd,
        "event",
        opts.event.map(AlertEvent::as_alert_name),
        &opts.event_data,
    );
    add_alert_field(
        cmd,
        "condition",
        opts.condition.map(AlertCondition::as_alert_name),
        &opts.condition_data,
    );
    add_alert_field(
        cmd,
        "method",
        opts.method.map(AlertMethod::as_alert_name),
        &opts.method_data,
    );
    if let Some(filter_id) = opts.filter_id.as_ref() {
        cmd.add_element("filter")
            .set_attribute("id", filter_id.as_str());
    }
    if let Some(active) = opts.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
}

fn add_alert_field(
    cmd: &mut XmlCommand,
    field_name: &str,
    field_value: Option<&str>,
    data: &[AlertData],
) {
    let Some(field_value) = field_value else {
        return;
    };
    let field = cmd.add_element(field_name);
    field.set_text(field_value);
    for entry in data {
        let data_element = field.add_child("data");
        data_element.set_text(&entry.value);
        data_element.add_child_with_text("name", &entry.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn alert_commands_build_xml() {
        let rendered = xml(create_alert(
            "alert",
            AlertOpts {
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: vec![AlertData::new("status", "Done")],
                condition: Some(AlertCondition::Always),
                method: Some(AlertMethod::Email),
                method_data: vec![AlertData::new("to_address", "ops@example.com")],
                filter_id: Some(id("f1")),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<create_alert><name>alert</name><event>Task run status changed<data>Done<name>status</name></data></event><condition>Always</condition><method>Email<data>ops@example.com<name>to_address</name></data></method><filter id=\"f1\"/></create_alert>"
        );
        assert_eq!(
            xml(clone_alert(&id("a1"))),
            "<create_alert><copy>a1</copy></create_alert>"
        );
        let rendered = xml(get_alert(&id("a1")));
        assert!(rendered.contains("<get_alerts "));
        assert!(rendered.contains("alert_id=\"a1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn alert_get_modify_delete_test_build_xml() {
        let rendered = xml(get_alerts(GetAlertsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_alert(
            &id("a1"),
            AlertOpts {
                name: Some("Renamed & Escaped".into()),
                comment: Some("updated".into()),
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: vec![AlertData::new("key&name", "value <&>")],
                method: Some(AlertMethod::SysLog),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_alert alert_id=\"a1\"><name>Renamed &amp; Escaped</name><comment>updated</comment><event>Task run status changed<data>value &lt;&amp;&gt;<name>key&amp;name</name></data></event><method>Syslog</method></modify_alert>"
        );
        assert_eq!(
            xml(modify_alert(&id("a1"), AlertOpts::default())),
            "<modify_alert alert_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_alert(&id("a1"), false)),
            "<delete_alert alert_id=\"a1\" ultimate=\"0\"/>"
        );
        assert_eq!(xml(test_alert(&id("a1"))), "<test_alert alert_id=\"a1\"/>");
        assert_eq!(
            xml(trigger_alert(
                &id("a1"),
                &id("r1"),
                TriggerAlertOpts::default()
            )),
            "<get_reports alert_id=\"a1\" report_id=\"r1\"/>"
        );
    }
}
