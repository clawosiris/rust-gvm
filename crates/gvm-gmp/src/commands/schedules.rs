// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Schedule command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::schedule::ScheduleInput;
use crate::types::EntityId;

/// Optional fields for schedule create and modify requests.
///
/// GMP 22.4+ requires an iCalendar (RFC 5545) payload instead of
/// the legacy `first_time` / `period` elements.
#[derive(Debug, Clone, Default)]
pub struct ScheduleOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// iCalendar (RFC 5545) data describing the schedule.
    ///
    /// Required for `create_schedule`; optional for `modify_schedule`.
    pub icalendar: Option<String>,
    /// Timezone applied to iCalendar events when they lack timezone
    /// information (e.g. `"Europe/Berlin"`).
    ///
    /// Required for `create_schedule`; optional for `modify_schedule`.
    pub timezone: Option<String>,
    /// Optional schedule name override (used in `modify_schedule`).
    pub name: Option<String>,
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
    /// Whether to include tasks using the schedules.
    pub tasks: Option<bool>,
}

/// Build a clone request for an existing schedule.
#[must_use]
pub fn clone_schedule(schedule_id: &EntityId) -> impl Request {
    XmlCommand::new("create_schedule").child_with_text("copy", schedule_id.as_str())
}

/// Build a `create_schedule` request.
///
/// The caller **must** set `icalendar` and `timezone` in `opts`; gvmd will
/// reject requests that lack an iCalendar entity.
#[must_use]
pub fn create_schedule(name: &str, opts: ScheduleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_schedule");
    cmd.add_element_with_text("name", name);
    add_schedule_body(&mut cmd, &opts);
    cmd
}

/// Build a `create_schedule` request from typed first-run and recurrence input.
#[must_use]
pub fn create_typed_schedule(name: &str, input: ScheduleInput) -> impl Request {
    create_schedule(name, input.into_raw())
}

/// Build a `get_schedules` request.
#[must_use]
pub fn get_schedules(opts: GetSchedulesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_schedules");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "tasks", opts.tasks);
    cmd
}

/// Build a `get_schedule` request.
#[must_use]
pub fn get_schedule(schedule_id: &EntityId) -> impl Request {
    XmlCommand::new("get_schedules")
        .attribute("schedule_id", schedule_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_schedule` request.
#[must_use]
pub fn modify_schedule(schedule_id: &EntityId, opts: ScheduleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_schedule").attribute("schedule_id", schedule_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_schedule_body(&mut cmd, &opts);
    cmd
}

/// Build a `modify_schedule` request from typed first-run and recurrence input.
#[must_use]
pub fn modify_typed_schedule(schedule_id: &EntityId, input: ScheduleInput) -> impl Request {
    modify_schedule(schedule_id, input.into_raw())
}

/// Build a `delete_schedule` request.
#[must_use]
pub fn delete_schedule(schedule_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_schedule")
        .attribute("schedule_id", schedule_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_schedule_body(cmd: &mut XmlCommand, opts: &ScheduleOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "icalendar", opts.icalendar.as_deref());
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
    fn schedule_create_with_icalendar() {
        let ical = "BEGIN:VCALENDAR\r\nEND:VCALENDAR";
        let rendered = xml(create_schedule(
            "daily-scan",
            ScheduleOpts {
                icalendar: Some(ical.into()),
                timezone: Some("UTC".into()),
                comment: Some("test".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<name>daily-scan</name>"));
        assert!(rendered.contains("<icalendar>"));
        assert!(rendered.contains("<timezone>UTC</timezone>"));
        assert!(rendered.contains("<comment>test</comment>"));
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
                icalendar: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR".into()),
                timezone: Some("Europe/Berlin".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("schedule_id=\"sc1\""));
        assert!(rendered.contains("<icalendar>"));
        assert!(rendered.contains("<timezone>Europe/Berlin</timezone>"));
        assert_eq!(
            xml(delete_schedule(&id("sc1"), false)),
            "<delete_schedule schedule_id=\"sc1\" ultimate=\"0\"/>"
        );
    }
}
