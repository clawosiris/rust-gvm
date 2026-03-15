// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Schedule command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Optional fields for schedule create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct ScheduleOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional first execution time.
    pub first_time: Option<String>,
    /// Optional recurrence period.
    pub period: Option<String>,
    /// Optional timezone name.
    pub timezone: Option<String>,
}

/// Options for `get_schedules` requests.
#[derive(Debug, Clone, Default)]
pub struct GetSchedulesOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing schedule.
pub fn clone_schedule(schedule_id: &EntityId) -> impl Request {
    XmlCommand::new("create_schedule").child_with_text("copy", schedule_id.as_str())
}

/// Build a `create_schedule` request.
pub fn create_schedule(name: &str, opts: ScheduleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_schedule");
    cmd.add_element_with_text("name", name);
    add_schedule_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_schedules` request.
pub fn get_schedules(opts: GetSchedulesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_schedules");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_schedule` request.
pub fn get_schedule(schedule_id: &EntityId) -> impl Request {
    XmlCommand::new("get_schedules")
        .attribute("schedule_id", schedule_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_schedule` request.
pub fn modify_schedule(schedule_id: &EntityId, opts: ScheduleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_schedule").attribute("schedule_id", schedule_id.as_str());
    add_schedule_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_schedule` request.
pub fn delete_schedule(schedule_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_schedule")
        .attribute("schedule_id", schedule_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_schedule_body(cmd: &mut XmlCommand, opts: &ScheduleOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "first_time", opts.first_time.as_deref());
    add_text_element(cmd, "period", opts.period.as_deref());
    add_text_element(cmd, "timezone", opts.timezone.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn schedule_commands_build_xml() {
        let rendered = xml(create_schedule(
            "sched",
            ScheduleOpts {
                timezone: Some("UTC".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<name>sched</name>"));
        assert!(rendered.contains("<timezone>UTC</timezone>"));
        assert_eq!(
            xml(clone_schedule(&id("sc1"))),
            "<create_schedule><copy>sc1</copy></create_schedule>"
        );
        assert_eq!(
            xml(get_schedule(&id("sc1"))),
            "<get_schedules details=\"1\" schedule_id=\"sc1\"/>"
        );
    }

    #[test]
    fn schedule_get_modify_delete_build_xml() {
        let rendered = xml(get_schedules(GetSchedulesOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_schedule(
            &id("sc1"),
            ScheduleOpts {
                period: Some("3600".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_schedule schedule_id=\"sc1\"><period>3600</period></modify_schedule>"
        );
        assert_eq!(
            xml(delete_schedule(&id("sc1"), false)),
            "<delete_schedule schedule_id=\"sc1\" ultimate=\"0\"/>"
        );
    }
}
