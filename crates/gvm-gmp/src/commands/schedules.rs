// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Schedule command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateScheduleResponse, DeleteScheduleResponse, GetSchedulesResponse, ModifyScheduleResponse,
};
use crate::schedule::ScheduleInput;
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for listing schedules.
#[derive(Debug, Clone, Default)]
pub struct GetSchedulesRequest {
    opts: GetSchedulesOpts,
}

impl GetSchedulesRequest {
    /// Create a schedule-list request.
    #[must_use]
    pub fn new(opts: GetSchedulesOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetSchedulesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_schedules(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetSchedulesRequest {
    type Response = GetSchedulesResponse;
}

/// Semantic request for one detailed schedule.
#[derive(Debug, Clone)]
pub struct GetScheduleRequest {
    schedule_id: EntityId,
}

impl GetScheduleRequest {
    /// Create a detailed single-schedule request.
    #[must_use]
    pub fn new(schedule_id: EntityId) -> Self {
        Self { schedule_id }
    }
}

impl Request for GetScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_schedule(&self.schedule_id).to_bytes()
    }
}

impl GmpRequest for GetScheduleRequest {
    type Response = GetSchedulesResponse;
}

/// Semantic request for creating a schedule with raw compatibility options.
#[derive(Debug, Clone)]
pub struct CreateScheduleRequest {
    name: String,
    opts: ScheduleOpts,
}

impl CreateScheduleRequest {
    /// Create a raw-option schedule-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: ScheduleOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_schedule(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateScheduleRequest {
    type Response = CreateScheduleResponse;
}

/// Semantic request for creating a schedule with typed recurrence input.
#[derive(Debug, Clone)]
pub struct CreateTypedScheduleRequest {
    name: String,
    input: ScheduleInput,
}

impl CreateTypedScheduleRequest {
    /// Create a typed-input schedule-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, input: ScheduleInput) -> Self {
        Self {
            name: name.into(),
            input,
        }
    }
}

impl Request for CreateTypedScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_typed_schedule(&self.name, self.input.clone()).to_bytes()
    }
}

impl GmpRequest for CreateTypedScheduleRequest {
    type Response = CreateScheduleResponse;
}

/// Semantic request for cloning a schedule.
#[derive(Debug, Clone)]
pub struct CloneScheduleRequest {
    schedule_id: EntityId,
}

impl CloneScheduleRequest {
    /// Create a schedule-clone request.
    #[must_use]
    pub fn new(schedule_id: EntityId) -> Self {
        Self { schedule_id }
    }
}

impl Request for CloneScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_schedule(&self.schedule_id).to_bytes()
    }
}

impl GmpRequest for CloneScheduleRequest {
    type Response = CreateScheduleResponse;
}

/// Semantic request for modifying a schedule with raw compatibility options.
#[derive(Debug, Clone)]
pub struct ModifyScheduleRequest {
    schedule_id: EntityId,
    opts: ScheduleOpts,
}

impl ModifyScheduleRequest {
    /// Create a raw-option schedule-modification request.
    #[must_use]
    pub fn new(schedule_id: EntityId, opts: ScheduleOpts) -> Self {
        Self { schedule_id, opts }
    }
}

impl Request for ModifyScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_schedule(&self.schedule_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyScheduleRequest {
    type Response = ModifyScheduleResponse;
}

/// Semantic request for modifying a schedule with typed recurrence input.
#[derive(Debug, Clone)]
pub struct ModifyTypedScheduleRequest {
    schedule_id: EntityId,
    input: ScheduleInput,
}

impl ModifyTypedScheduleRequest {
    /// Create a typed-input schedule-modification request.
    #[must_use]
    pub fn new(schedule_id: EntityId, input: ScheduleInput) -> Self {
        Self { schedule_id, input }
    }
}

impl Request for ModifyTypedScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_typed_schedule(&self.schedule_id, self.input.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyTypedScheduleRequest {
    type Response = ModifyScheduleResponse;
}

/// Semantic request for deleting a schedule.
#[derive(Debug, Clone)]
pub struct DeleteScheduleRequest {
    schedule_id: EntityId,
    ultimate: bool,
}

impl DeleteScheduleRequest {
    /// Create a schedule-deletion request.
    #[must_use]
    pub fn new(schedule_id: EntityId, ultimate: bool) -> Self {
        Self {
            schedule_id,
            ultimate,
        }
    }
}

impl Request for DeleteScheduleRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_schedule(&self.schedule_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteScheduleRequest {
    type Response = DeleteScheduleResponse;
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
    use crate::{ScheduleDefinition, ScheduleRecurrence, ScheduleTimestamp, ScheduleTimezone};

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn typed_input() -> ScheduleInput {
        ScheduleInput::new(
            ScheduleDefinition {
                first_run: ScheduleTimestamp::parse("2030-01-01T00:00:00Z")
                    .expect("valid timestamp"),
                recurrence: ScheduleRecurrence::Daily,
            },
            ScheduleTimezone::new("UTC").expect("valid timezone"),
        )
    }

    #[test]
    fn semantic_schedule_requests_match_builder_bytes_and_responses() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let schedule_id = id("schedule-1");
        let list_opts = GetSchedulesOpts {
            details: Some(true),
            ..Default::default()
        };
        let raw_opts = ScheduleOpts {
            icalendar: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR".into()),
            timezone: Some("UTC".into()),
            ..Default::default()
        };

        let list = GetSchedulesRequest::new(list_opts.clone());
        assert_eq!(list.to_bytes(), get_schedules(list_opts).to_bytes());
        assert_response::<_, GetSchedulesResponse>(&list);

        let get = GetScheduleRequest::new(schedule_id.clone());
        assert_eq!(get.to_bytes(), get_schedule(&schedule_id).to_bytes());
        assert_response::<_, GetSchedulesResponse>(&get);

        let create = CreateScheduleRequest::new("schedule", raw_opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_schedule("schedule", raw_opts.clone()).to_bytes()
        );
        assert_response::<_, CreateScheduleResponse>(&create);

        let typed_create = CreateTypedScheduleRequest::new("typed", typed_input());
        let typed_create_xml = String::from_utf8(typed_create.to_bytes()).expect("request XML");
        assert!(typed_create_xml.starts_with("<create_schedule>"));
        assert!(typed_create_xml.contains("<name>typed</name>"));
        assert!(typed_create_xml.contains("<timezone>UTC</timezone>"));
        assert_response::<_, CreateScheduleResponse>(&typed_create);

        let clone = CloneScheduleRequest::new(schedule_id.clone());
        assert_eq!(clone.to_bytes(), clone_schedule(&schedule_id).to_bytes());
        assert_response::<_, CreateScheduleResponse>(&clone);

        let modify = ModifyScheduleRequest::new(schedule_id.clone(), raw_opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_schedule(&schedule_id, raw_opts).to_bytes()
        );
        assert_response::<_, ModifyScheduleResponse>(&modify);

        let typed_modify = ModifyTypedScheduleRequest::new(schedule_id.clone(), typed_input());
        let typed_modify_xml = String::from_utf8(typed_modify.to_bytes()).expect("request XML");
        assert!(typed_modify_xml.starts_with("<modify_schedule schedule_id=\"schedule-1\">"));
        assert!(typed_modify_xml.contains("<timezone>UTC</timezone>"));
        assert_response::<_, ModifyScheduleResponse>(&typed_modify);

        let delete = DeleteScheduleRequest::new(schedule_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_schedule(&schedule_id, true).to_bytes()
        );
        assert_response::<_, DeleteScheduleResponse>(&delete);
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
